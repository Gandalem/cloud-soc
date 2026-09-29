param(
    [string]$Root = (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Cloud-SOC-Agent'),
    [string]$BackupId = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Add-SocVerificationCheck($Checks, [string]$Id, [bool]$Required, [bool]$Passed, [string]$Summary) {
    $Checks.Add([pscustomobject][ordered]@{
        id = $Id
        required = $Required
        status = if ($Passed) { 'pass' } else { 'fail' }
        summary = $Summary
    }) | Out-Null
}

function Get-SocVerificationHash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Test-SocVerificationLinked([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $true }
    return [bool]($item.PSObject.Properties['LinkType'] -and $item.LinkType)
}

function Test-SocVerificationPathChainUnlinked([string]$Path, [string]$Boundary) {
    $full = [IO.Path]::GetFullPath($Path)
    $base = [IO.Path]::GetFullPath($Boundary).TrimEnd('\','/')
    $separator = [IO.Path]::DirectorySeparatorChar
    if ($full -ine $base -and -not $full.StartsWith($base + $separator, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $cursor = $full
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and (Test-SocVerificationLinked $cursor)) { return $false }
        if ($cursor.TrimEnd('\','/') -ieq $base) { return $true }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if (-not $parent -or $parent -eq $cursor) { return $false }
        $cursor = $parent
    }
    return $false
}

function Test-SocVerificationProtectedAcl([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544') -or -not $acl.AreAccessRulesProtected) { return $false }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { return $false }
    }
    return $true
}

function Test-SocVerificationAdmin {
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) { return $false }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SocExecutionPolicySnapshot {
    $result = [ordered]@{}
    foreach ($scope in @('MachinePolicy','UserPolicy','Process','CurrentUser','LocalMachine')) {
        try { $result[$scope] = [string](Get-ExecutionPolicy -Scope $scope -ErrorAction Stop) }
        catch { $result[$scope] = 'Unavailable' }
    }
    return [pscustomobject]$result
}

function Test-SocExecutionPolicySame($Before, $After) {
    foreach ($scope in @('MachinePolicy','UserPolicy','Process','CurrentUser','LocalMachine')) {
        if ([string]$Before.$scope -cne [string]$After.$scope) { return $false }
    }
    return $true
}

function Get-SocTaskInvariant([string]$Xml) {
    $document = [xml]$Xml
    foreach ($node in @($document.SelectNodes('/*[local-name()="Task"]/*[local-name()="Settings"]/*[local-name()="Enabled"]'))) {
        $null = $node.ParentNode.RemoveChild($node)
    }
    return $document.OuterXml
}

function Get-SocLivePathSummary([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject][ordered]@{ exists = $false; linked = $false; kind = 'missing'; size_bytes = $null; child_count = $null }
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $linked = Test-SocVerificationLinked $Path
    if ($item.PSIsContainer) {
        $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        return [pscustomobject][ordered]@{ exists = $true; linked = $linked; kind = 'directory'; size_bytes = $null; child_count = $children.Count }
    }
    return [pscustomobject][ordered]@{ exists = $true; linked = $linked; kind = 'file'; size_bytes = [int64]$item.Length; child_count = $null }
}

function Invoke-SocDiscoveryUpdateVerification {
    param([string]$Root, [string]$BackupId)

    $checks = New-Object 'Collections.Generic.List[object]'
    $policyBefore = Get-SocExecutionPolicySnapshot
    $serviceEvidence = [ordered]@{ found = $false }
    $taskEvidence = [ordered]@{ found = $false }
    $backupEvidence = [ordered]@{ backup_id = $BackupId; manifest_valid = $false; file_hashes_match = $false; guard_matches_current = $false; task_hash_matches = $false; task_definition_matches_current = $false; acl_protected = $false }
    $nativeEvidence = [ordered]@{ manifest_valid = $false; source_sha256 = $null; exe_sha256 = $null; manifest_sha256 = $null }
    $traceEvidence = [ordered]@{ root_pending_count = $null; staging_probe_marker_count = $null; preflight_task_count = $null }

    $admin = $false
    try { $admin = [bool](Test-SocVerificationAdmin) } catch { $admin = $false }
    Add-SocVerificationCheck $checks 'administrator_64bit' $true $admin 'Run from an elevated 64-bit Windows PowerShell process.'

    $rootOkay = $false
    try {
        $rootOkay = (Test-Path -LiteralPath $Root -PathType Container) -and -not (Test-SocVerificationLinked $Root)
    } catch { $rootOkay = $false }
    Add-SocVerificationCheck $checks 'agent_root_local_unlinked' $true $rootOkay 'Agent root exists and is not a reparse/link target.'

    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='cloud-soc-filebeat'" -ErrorAction Stop
        if ($service) {
            $serviceEvidence = [ordered]@{
                found = $true
                state = [string]$service.State
                start_mode = [string]$service.StartMode
                process_present = ([int64]$service.ProcessId -gt 0)
                account_is_system = ([string]$service.StartName -in @('LocalSystem','NT AUTHORITY\SYSTEM'))
            }
        }
        $servicePass = $service -and $service.State -eq 'Running' -and $service.StartMode -eq 'Auto' -and
            [int64]$service.ProcessId -gt 0 -and [string]$service.StartName -in @('LocalSystem','NT AUTHORITY\SYSTEM')
        Add-SocVerificationCheck $checks 'filebeat_running_auto' $true ([bool]$servicePass) 'Filebeat must be Running, Auto and owned by SYSTEM/LocalSystem.'
    } catch {
        Add-SocVerificationCheck $checks 'filebeat_running_auto' $true $false 'Filebeat service could not be read or did not meet the expected state.'
    }

    $currentTaskXml = $null
    try {
        $tasks = @(Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop)
        $taskPass = $false
        if ($tasks.Count -eq 1) {
            $task = $tasks[0]
            $actions = @($task.Actions)
            $expectedExe = Join-Path $Root 'cloud-soc-discovery.exe'
            $expectedArgs = '--root "{0}"' -f $Root
            $taskPass = $actions.Count -eq 1 -and $actions[0].Execute -ieq $expectedExe -and
                $actions[0].Arguments -ceq $expectedArgs -and
                $actions[0].WorkingDirectory -ieq $Root -and
                $task.Principal.UserId -in @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -and
                [string]$task.Principal.LogonType -in @('ServiceAccount','5') -and
                [string]$task.Principal.RunLevel -in @('Highest','1') -and
                [bool]$task.Settings.Enabled -and [string]$task.State -in @('Ready','Running')
            $info = Get-ScheduledTaskInfo -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
            $taskEvidence = [ordered]@{
                found = $true
                state = [string]$task.State
                enabled = [bool]$task.Settings.Enabled
                native_action = ($actions.Count -eq 1 -and $actions[0].Execute -ieq $expectedExe -and $actions[0].Arguments -ceq $expectedArgs)
                system_highest = ($task.Principal.UserId -in @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -and [string]$task.Principal.RunLevel -in @('Highest','1'))
                last_task_result = [int64]$info.LastTaskResult
            }
            $currentTaskXml = Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
        }
        Add-SocVerificationCheck $checks 'discovery_task_native_enabled' $true ([bool]$taskPass) 'Discovery task must be the recognized enabled native SYSTEM task and be Ready or Running.'
    } catch {
        Add-SocVerificationCheck $checks 'discovery_task_native_enabled' $true $false 'Discovery task could not be read or did not match the native task contract.'
    }

    $backupPath = $null
    $manifest = $null
    $backupStructurePass = $false
    if ($BackupId -notmatch '^[a-f0-9]{32}$') {
        Add-SocVerificationCheck $checks 'backup_acl_protected' $true $false 'Backup ACL was not checked because BackupId is invalid.'
        Add-SocVerificationCheck $checks 'backup_manifest_structure' $true $false 'BackupId must be the exact 32-character update backup identifier.'
        Add-SocVerificationCheck $checks 'backup_files_integrity' $true $false 'Backup files were not checked because BackupId is invalid.'
        Add-SocVerificationCheck $checks 'pre_update_guard_matches_current' $true $false 'Pre-update guard was not checked because BackupId is invalid.'
        Add-SocVerificationCheck $checks 'backup_task_integrity' $true $false 'Backup task XML was not checked because BackupId is invalid.'
        Add-SocVerificationCheck $checks 'backup_task_matches_current' $true $false 'Task definition comparison was not checked because BackupId is invalid.'
    } else {
        try {
            $backupPath = Join-Path (Join-Path $env:ProgramData 'Cloud-SOC\updates') $BackupId
            if (-not (Test-Path -LiteralPath $backupPath -PathType Container) -or -not (Test-SocVerificationPathChainUnlinked $backupPath (Join-Path $env:ProgramData 'Cloud-SOC\updates'))) { throw 'invalid backup root' }
            $backupAclPass = Test-SocVerificationProtectedAcl $backupPath
            $backupEvidence.acl_protected = [bool]$backupAclPass
            Add-SocVerificationCheck $checks 'backup_acl_protected' $true ([bool]$backupAclPass) 'Update backup directory keeps the protected Administrators/SYSTEM-only ACL.'
            $manifestPath = Join-Path $backupPath 'manifest.json'
            $manifestItem = Get-Item -LiteralPath $manifestPath -Force -ErrorAction Stop
            if ($manifestItem.Length -gt 1048576 -or (Test-SocVerificationLinked $manifestPath)) { throw 'invalid manifest' }
            $manifest = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $allowedFiles = @('discovery-native.cs','cloud-soc-discovery.exe','discovery-native.json','inputs\discovered.yml','inputs\health.yml')
            $entries = @($manifest.files)
            $paths = @($entries | ForEach-Object { [string]$_.path })
            $guardNames = @('filebeat.yml','ca.crt','data\filebeat.keystore','discovery-settings.json','privacy.js','collection-policy.txt')
            $guardProperties = @($manifest.guard.PSObject.Properties.Name)
            $backupStructurePass = $manifest.schema -eq 1 -and $manifest.queue_restore -eq $false -and
                $entries.Count -eq $allowedFiles.Count -and @($paths | Sort-Object -Unique).Count -eq $allowedFiles.Count -and
                @($allowedFiles | Where-Object { $_ -notin $paths }).Count -eq 0 -and
                @($paths | Where-Object { $_ -notin $allowedFiles }).Count -eq 0 -and
                @($guardNames | Where-Object { $_ -notin $guardProperties }).Count -eq 0 -and
                @($guardProperties | Where-Object { $_ -notin $guardNames }).Count -eq 0 -and
                [string]$manifest.task_sha256 -match '^[A-Fa-f0-9]{64}$'
            $backupEvidence.manifest_valid = [bool]$backupStructurePass
            Add-SocVerificationCheck $checks 'backup_manifest_structure' $true ([bool]$backupStructurePass) 'Update backup manifest has the expected fixed file/guard set and queue_restore=false.'

            $filesPass = $backupStructurePass
            if ($filesPass) {
                foreach ($name in $allowedFiles) {
                    $entry = @($entries | Where-Object { [string]$_.path -ceq $name })[0]
                    $target = Join-Path $backupPath $name
                    $expected = [string]$entry.sha256
                    if ([string]::IsNullOrWhiteSpace($expected)) {
                        if (Test-Path -LiteralPath $target) { $filesPass = $false; break }
                    } elseif ($expected -notmatch '^[A-Fa-f0-9]{64}$' -or -not (Test-Path -LiteralPath $target -PathType Leaf) -or
                        -not (Test-SocVerificationPathChainUnlinked $target $backupPath) -or (Get-SocVerificationHash $target) -cne $expected.ToLowerInvariant()) {
                        $filesPass = $false; break
                    }
                }
            }
            $backupEvidence.file_hashes_match = [bool]$filesPass
            Add-SocVerificationCheck $checks 'backup_files_integrity' $true ([bool]$filesPass) 'Every backed-up native/input file matches the SHA-256 recorded before replacement.'

            $guardPass = $backupStructurePass
            if ($guardPass) {
                foreach ($name in $guardNames) {
                    $expected = [string]$manifest.guard.$name
                    $target = Join-Path $Root $name
                    if ([string]::IsNullOrWhiteSpace($expected)) {
                        if (Test-Path -LiteralPath $target) { $guardPass = $false; break }
                    } elseif ($expected -notmatch '^[A-Fa-f0-9]{64}$' -or -not (Test-Path -LiteralPath $target -PathType Leaf) -or
                        -not (Test-SocVerificationPathChainUnlinked $target $Root) -or (Get-SocVerificationHash $target) -cne $expected.ToLowerInvariant()) {
                        $guardPass = $false; break
                    }
                }
            }
            $backupEvidence.guard_matches_current = [bool]$guardPass
            Add-SocVerificationCheck $checks 'pre_update_guard_matches_current' $true ([bool]$guardPass) 'Current config/CA/keystore/discovery settings/privacy/policy match the pre-update guard hashes.'

            $taskPath = Join-Path $backupPath 'task.xml'
            $taskHashPass = $backupStructurePass -and (Test-Path -LiteralPath $taskPath -PathType Leaf) -and (Test-SocVerificationPathChainUnlinked $taskPath $backupPath) -and
                (Get-SocVerificationHash $taskPath) -ceq ([string]$manifest.task_sha256).ToLowerInvariant()
            $backupEvidence.task_hash_matches = [bool]$taskHashPass
            Add-SocVerificationCheck $checks 'backup_task_integrity' $true ([bool]$taskHashPass) 'Backed-up task.xml matches the SHA-256 recorded in the update manifest.'

            $taskDefinitionPass = $false
            if ($taskHashPass -and $currentTaskXml) {
                $backupTaskXml = Get-Content -LiteralPath $taskPath -Raw -ErrorAction Stop
                $taskDefinitionPass = (Get-SocTaskInvariant $backupTaskXml) -ceq (Get-SocTaskInvariant $currentTaskXml)
            }
            $backupEvidence.task_definition_matches_current = [bool]$taskDefinitionPass
            Add-SocVerificationCheck $checks 'backup_task_matches_current' $true ([bool]$taskDefinitionPass) 'Current Discovery task definition matches the protected pre-update XML, ignoring only Enabled.'
        } catch {
            if (-not @($checks | Where-Object id -eq 'backup_acl_protected').Count) { Add-SocVerificationCheck $checks 'backup_acl_protected' $true $false 'Protected backup ACL could not be validated.' }
            if (-not @($checks | Where-Object id -eq 'backup_manifest_structure').Count) { Add-SocVerificationCheck $checks 'backup_manifest_structure' $true $false 'Update backup manifest could not be read or validated.' }
            if (-not @($checks | Where-Object id -eq 'backup_files_integrity').Count) { Add-SocVerificationCheck $checks 'backup_files_integrity' $true $false 'Update backup file hashes could not be validated.' }
            if (-not @($checks | Where-Object id -eq 'pre_update_guard_matches_current').Count) { Add-SocVerificationCheck $checks 'pre_update_guard_matches_current' $true $false 'Pre-update guard hashes could not be compared with the current protected files.' }
            if (-not @($checks | Where-Object id -eq 'backup_task_integrity').Count) { Add-SocVerificationCheck $checks 'backup_task_integrity' $true $false 'Backed-up task XML hash could not be validated.' }
            if (-not @($checks | Where-Object id -eq 'backup_task_matches_current').Count) { Add-SocVerificationCheck $checks 'backup_task_matches_current' $true $false 'Current task could not be compared with the backed-up task definition.' }
        }
    }

    try {
        $nativeManifestPath = Join-Path $Root 'discovery-native.json'
        $sourcePath = Join-Path $Root 'discovery-native.cs'
        $exePath = Join-Path $Root 'cloud-soc-discovery.exe'
        foreach ($path in @($nativeManifestPath,$sourcePath,$exePath)) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Test-SocVerificationLinked $path)) { throw 'native file unavailable' }
        }
        $nativeManifest = Get-Content -LiteralPath $nativeManifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $sourceHash = Get-SocVerificationHash $sourcePath
        $exeHash = Get-SocVerificationHash $exePath
        $manifestHash = Get-SocVerificationHash $nativeManifestPath
        $nativePass = $nativeManifest.schema -eq 1 -and $nativeManifest.worker -eq 'native-v1' -and
            [string]$nativeManifest.source_sha256 -ieq $sourceHash -and [string]$nativeManifest.exe_sha256 -ieq $exeHash
        $nativeEvidence = [ordered]@{ manifest_valid = [bool]$nativePass; source_sha256 = $sourceHash; exe_sha256 = $exeHash; manifest_sha256 = $manifestHash }
        Add-SocVerificationCheck $checks 'native_integrity' $true ([bool]$nativePass) 'Current source and EXE SHA-256 values match discovery-native.json.'
    } catch {
        Add-SocVerificationCheck $checks 'native_integrity' $true $false 'Current native Discovery files or manifest could not be validated.'
    }

    try {
        $rootMarkers = @('discovery-update-pending.json','recovery-pending.json','probe-active.txt')
        $rootPending = @($rootMarkers | Where-Object { Test-Path -LiteralPath (Join-Path $Root $_) }).Count
        $stagingProbe = 0
        $staging = Join-Path $env:ProgramData 'Cloud-SOC\staging'
        if (Test-Path -LiteralPath $staging -PathType Container) {
            if (Test-SocVerificationLinked $staging) { throw 'linked staging root' }
            foreach ($dir in @(Get-ChildItem -LiteralPath $staging -Directory -Force -ErrorAction Stop)) {
                if (Test-SocVerificationLinked $dir.FullName) { throw 'linked staging directory' }
                if (Test-Path -LiteralPath (Join-Path $dir.FullName 'probe-active.txt')) { $stagingProbe++ }
            }
        }
        $preflightTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskName -like 'Cloud-SOC-Preflight-*' }).Count
        $tracePass = $rootPending -eq 0 -and $stagingProbe -eq 0 -and $preflightTasks -eq 0
        $traceEvidence = [ordered]@{ root_pending_count = $rootPending; staging_probe_marker_count = $stagingProbe; preflight_task_count = $preflightTasks }
        Add-SocVerificationCheck $checks 'no_pending_or_probe_traces' $true ([bool]$tracePass) 'No update/recovery pending marker, probe marker, or temporary preflight task remains.'
    } catch {
        Add-SocVerificationCheck $checks 'no_pending_or_probe_traces' $true $false 'Pending/probe traces could not be fully enumerated.'
    }

    $liveState = [ordered]@{}
    try { $liveState.registry = Get-SocLivePathSummary (Join-Path $Root 'data\registry') } catch { $liveState.registry = [ordered]@{ exists = $false; observation_failed = $true } }
    try { $liveState.queue = Get-SocLivePathSummary (Join-Path $Root 'data\queue') } catch { $liveState.queue = [ordered]@{ exists = $false; observation_failed = $true } }
    $liveState.note = 'Read-only presence/shape only. The update manifest has no pre-update registry/queue digest, and a running Filebeat may change these paths while this check runs.'

    $policyAfter = Get-SocExecutionPolicySnapshot
    $policySame = Test-SocExecutionPolicySame $policyBefore $policyAfter
    Add-SocVerificationCheck $checks 'execution_policy_unchanged' $true ([bool]$policySame) 'Execution-policy scope values are identical before and after the diagnostic reads.'

    $checkArray = $checks.ToArray()
    $required = @($checkArray | Where-Object { $_.required })
    $failed = @($required | Where-Object { $_.status -ne 'pass' })
    $status = if ($failed.Count -eq 0) { 'pass' } else { 'fail' }
    $successCriteria = @()
    foreach ($item in $required) {
        $successCriteria += [string]$item.id
    }

    return [pscustomobject][ordered]@{
        schema = 1
        tool = 'cloud-soc-p2c07-readonly-admin-verify'
        generated_at = [DateTime]::UtcNow.ToString('o')
        overall = [ordered]@{
            status = $status
            required_total = $required.Count
            required_passed = $required.Count - $failed.Count
            required_failed = $failed.Count
        }
        success_criteria = $successCriteria
        checks = $checkArray
        evidence = [ordered]@{
            service = $serviceEvidence
            discovery_task = $taskEvidence
            backup = $backupEvidence
            native = $nativeEvidence
            pending_probe = $traceEvidence
            execution_policy_before = $policyBefore
            execution_policy_after = $policyAfter
            live_registry_queue = $liveState
        }
        privacy = [ordered]@{
            hostname_included = $false
            usernames_included = $false
            service_command_included = $false
            task_xml_included = $false
            keys_or_config_contents_included = $false
            raw_logs_read = $false
            raw_logs_included = $false
        }
        limitations = @(
            'This local diagnostic does not query central ingestion or the browser UI.',
            'Backup integrity is internal SHA-256 consistency; it is not an external signature/authenticity proof.',
            'Pre-update registry/queue equality cannot be proven because the update manifest intentionally does not store their digests.'
        )
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $result = Invoke-SocDiscoveryUpdateVerification -Root $Root -BackupId $BackupId
    $result | ConvertTo-Json -Depth 12
}
