# Recovery never recreates a keystore or restores an old queue over current data.
. (Join-Path $PSScriptRoot 'bundle-resume-windows.ps1')
function Get-SocBundleStableNames([string]$Beat) {
    if ($Beat -notin @('filebeat','packetbeat')) { throw 'Unknown bundle member.' }
    $names = @("$Beat.yml", 'ca.crt', 'privacy.js', "data\$Beat.keystore")
    if ($Beat -eq 'filebeat') {
        $names += @('discovery-settings.json','discovery-native.cs','cloud-soc-discovery.exe','discovery-native.json')
    }
    return $names
}

function Get-SocBundleStableHashes([string]$Root, [string]$Beat) {
    $hashes=@{}
    foreach ($name in Get-SocBundleStableNames $Beat) {
        $file=Join-Path $Root $name
        Assert-SocLocalPath $file
        Assert-SocRepairAcl $file
        $hashes[$name]=(Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    return $hashes
}

function Assert-SocBundleStableFiles($Member) {
    $now=Get-SocBundleStableHashes $Member.Root $Member.Beat
    foreach ($name in $Member.Stable.Keys) {
        if ($now[$name] -cne $Member.Stable[$name]) { throw 'Collector configuration/key/code changed during recovery; no overwrite was attempted.' }
    }
}

function Save-SocBundleRecoveryIdentity($Transaction, $Members) {
    $records = @()
    foreach ($member in $Members) {
        $hashes = Get-SocBundleStableHashes $member.Root $member.Beat
        $records += @{ kind=$member.Kind; root=$member.Root; token=$member.Prepared.token; files=$hashes }
    }
    $path = Join-Path $Transaction.Path 'bundle-recovery.json'
    Assert-SocLocalPath $path
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes((@{schema=1;transaction=$Transaction.Token;members=$records} | ConvertTo-Json -Depth 6))
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Read-SocBundleRepairJson([string]$Path, [int]$MaxBytes = 65536) {
    Assert-SocLocalPath $Path
    Assert-SocRepairAcl $Path
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.PSObject.Properties['LinkType'] -and $item.LinkType)) { throw 'Recovery refused a linked/non-file record.' }
    if ($item.Length -gt $MaxBytes) { throw 'Recovery record exceeds its limit.' }
    return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
}

function Get-SocBundlePendingRecovery($Members) {
    $pending = Join-Path $env:ProgramData 'Cloud-SOC\bundle-pending.json'
    Assert-SocLocalPath $pending
    if (-not (Test-Path -LiteralPath $pending)) { return $null }
    Assert-SocRepairAcl $pending
    if ((Get-Item -LiteralPath $pending).Length -ne 32) { throw 'Invalid pending bundle identity; state retained.' }
    $token = [IO.File]::ReadAllText($pending)
    if ($token -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid pending bundle identity; state retained.' }
    $root = Join-Path (Join-Path $env:ProgramData 'Cloud-SOC\staging') $token
    Assert-SocLocalPath $root
    Assert-SocRepairAcl $root
    foreach ($item in Get-SocRepairTree $root) { Assert-SocRepairAcl $item.FullName }
    if ([IO.File]::ReadAllText((Join-Path $root 'install-owner.txt')) -cne $token) { throw 'Bundle transaction ownership changed.' }
    $state = Read-SocBundleRepairJson (Join-Path $root 'bundle-state.json')
    if ($state.schema -ne 1 -or $state.transaction -cne $token -or $state.start_attempted -isnot [bool] -or
        $state.phase -notin @('prepared','starting','retained_recovery_required','committed_receipt_unverified') -or
        (-not $state.start_attempted -and $state.phase -notin @('prepared','retained_recovery_required'))) {
        throw 'Only a verified final-ready bundle pair can be recovered; other interrupted state is retained.'
    }
    $identity = Read-SocBundleRepairJson (Join-Path $root 'bundle-recovery.json')
    if ($identity.schema -ne 1 -or $identity.transaction -cne $token -or @($identity.members).Count -ne 2) { throw 'Bundle recovery identity differs.' }
    foreach ($member in $Members) {
        Assert-SocLocalPath $member.Root
        Assert-SocRepairAcl $member.Root
        foreach ($item in Get-SocRepairTree $member.Root) { Assert-SocRepairAcl $item.FullName }
        $records = @($identity.members | Where-Object kind -CEQ $member.Kind)
        if ($records.Count -ne 1 -or $records[0].root -ine $member.Root -or $records[0].token -cnotmatch '^[a-f0-9]{32}$') { throw 'Bundle member identity differs.' }
        $record = $records[0]
        if ([IO.File]::ReadAllText((Join-Path $member.Root 'install-owner.txt')) -cne $record.token) { throw 'Bundle member ownership changed.' }
        $names = @(Get-SocBundleStableNames $member.Beat)
        if (@($record.files.PSObject.Properties).Count -ne $names.Count) { throw 'Bundle recovery file set differs.' }
        foreach ($name in $names) {
            $entry = $record.files.PSObject.Properties[$name]
            if (-not $entry -or $entry.Value -cnotmatch '^[A-Fa-f0-9]{64}$' -or
                (Get-FileHash -LiteralPath (Join-Path $member.Root $name) -Algorithm SHA256 -ErrorAction Stop).Hash -cne $entry.Value) {
                throw 'Bundle recovery file changed; keys/configuration were not replaced.'
            }
        }
    }
    return @{Path=$root;Token=$token;Pending=$pending}
}

function Assert-SocBundleRepairMember($Member, [string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization, [switch]$AllowMissingService) {
    Assert-SocLocalPath $Member.Root
    Assert-SocRepairAcl $Member.Root
    foreach ($item in Get-SocRepairTree $Member.Root) { Assert-SocRepairAcl $item.FullName }
    foreach ($name in @('probe-active.txt','recovery-pending.json','discovery-update-pending.json')) {
        if (Test-Path -LiteralPath (Join-Path $Member.Root $name)) { throw 'Incomplete collector operation; retained state was not changed.' }
    }
    $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Member.Service) -ErrorAction Stop
    $missing = -not [bool]$service
    if ($missing) {
        if (-not $AllowMissingService) { throw 'Missing service requires a verified final-ready bundle identity; no service was created.' }
        $service = [pscustomobject]@{State='Stopped';ProcessId=0;StartMode='Disabled';StartName='LocalSystem';PathName=(Get-SocBundleCommand $Member.Root $Member.Beat)}
    }
    if ($Member.ContainsKey('InitiallyMissing') -and $Member.InitiallyMissing -ne $missing) { throw 'Collector service presence changed during recovery.' }
    if ($service.State -ne 'Stopped' -or $service.ProcessId -ne 0 -or
        $service.StartMode -notin @('Auto','Manual','Disabled')) { throw 'Combined recovery requires both recognized services stopped; running/missing services were not changed.' }
    if (-not $missing) { Assert-SocBundleService $Member }
    $config = Read-SocBundleRepairJson (Join-Path $Member.Root ($Member.Beat + '.yml'))
    if ($Member.Kind -eq 'host') {
        Assert-SocRepairIdentity $service $config (Get-SocBundleCommand $Member.Root $Member.Beat) $Endpoint $Organization $Member.Root
        $processors=@($config.processors)
        if ($processors.Count -ne 4 -or @($processors[0].PSObject.Properties).Count -ne 1 -or
            @($processors[0].add_host_metadata.PSObject.Properties).Count -ne 0 -or
            @($processors[1].PSObject.Properties).Count -ne 1 -or
            @($processors[1].add_fields.PSObject.Properties).Count -ne 2 -or
            $processors[1].add_fields.target -cne 'organization' -or @($processors[1].add_fields.fields.PSObject.Properties).Count -ne 1 -or
            @($processors[2].PSObject.Properties).Count -ne 1 -or @($processors[2].script.PSObject.Properties).Count -ne 4 -or
            $processors[2].script.lang -cne 'javascript' -or $processors[2].script.file -cne 'privacy.js' -or
            $processors[2].script.timeout -cne '50ms' -or $processors[2].script.tag_on_exception -cne '_privacy_error' -or
            ($processors[3] | ConvertTo-Json -Depth 6 -Compress) -cne '{"drop_event":{"when":{"contains":{"tags":"_privacy_error"}}}}') {
            throw 'Existing Filebeat privacy pipeline differs; recovery does not weaken or replace policy.'
        }
    } else {
        # Network recovery accepts only the reviewed metadata-only configuration, including its privacy processors.
        $expected = Get-Content -LiteralPath (Join-Path $Source 'packetbeat.base.json') -Raw | ConvertFrom-Json
        $expected.'packetbeat.interfaces'.device = $config.'packetbeat.interfaces'.device
        $expected.processors[1].add_fields.fields.id = $Organization
        $expected.processors[2].add_fields.fields.sensor_platform = 'windows'
        $expected.'output.elasticsearch'.hosts = @($Endpoint.TrimEnd('/'))
        $expected.'output.elasticsearch'.'ssl.certificate_authorities' = @((Join-Path $Member.Root 'ca.crt'))
        $expected.'output.elasticsearch'.index = 'soc-network-windows-9.5.2-%{+yyyy.MM.dd}'
        if (($config | ConvertTo-Json -Depth 16 -Compress) -cne ($expected | ConvertTo-Json -Depth 16 -Compress)) {
            throw 'Existing Packetbeat configuration differs from the approved metadata-only installation; no migration was attempted.'
        }
        if ($config.'packetbeat.interfaces'.device -cnotmatch '^\\Device\\NPF_\{([A-Fa-f0-9-]{36})\}$') { throw 'Existing capture interface is invalid.' }
        $Member.InterfaceGuid = ([guid]$Matches[1]).ToString()
        if ([guid]$Member.InterfaceGuid -eq [guid]::Empty) { throw 'Existing capture interface is invalid.' }
        if (-not $missing) {
            $dependencies = @((Get-Service -Name $Member.Service -ErrorAction Stop).ServicesDependedOn | ForEach-Object Name)
            if ($dependencies.Count -ne 1 -or $dependencies[0] -ine 'npcap') { throw 'Packetbeat service dependency changed.' }
        }
    }
    if ((Get-FileHash -LiteralPath (Join-Path $Member.Root 'ca.crt') -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath $CaPath -Algorithm SHA256).Hash) { throw 'CA differs; no key was sent.' }
    if ((Get-FileHash -LiteralPath (Join-Path $Member.Root 'privacy.js') -Algorithm SHA256).Hash -cne
        (Get-FileHash -LiteralPath (Join-Path $Source 'privacy.js') -Algorithm SHA256).Hash) { throw 'Privacy implementation differs; recovery does not replace policy.' }
    if (-not (Test-Path -LiteralPath (Join-Path $Member.Root ('data\' + $Member.Beat + '.keystore')) -PathType Leaf)) { throw 'Existing collector keystore is missing.' }
    Assert-SocRepairDistribution $Member.Root '9.5.2' $Member.Hash $Member.Beat
    if ($Member.ContainsKey('Stable')) { Assert-SocBundleStableFiles $Member }
    else { $Member.Stable=Get-SocBundleStableHashes $Member.Root $Member.Beat }
    if ($Member.ContainsKey('OriginalService')) {
        if ($Member.OriginalService.StartMode -cne $service.StartMode) { throw 'Collector service start mode changed during recovery.' }
    } else { $Member.OriginalService=$service; $Member.InitiallyMissing=$missing; $Member.RepairCreated=$false; $Member.RepairCreateAttempted=$false }
}

function Assert-SocBundleRepairNetwork([string]$InterfaceGuid) {
    $driver = Get-Service -Name npcap -ErrorAction Stop
    if ($driver.Status -ne 'Running' -or -not (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll') -PathType Leaf)) {
        throw 'Approved running x64 Npcap is required; no driver was installed or started.'
    }
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { ([guid]$_.InterfaceGuid).ToString() -ceq $InterfaceGuid })
    if ($adapters.Count -ne 1 -or $adapters[0].Status -ne 'Up') { throw 'Existing capture NIC is unavailable; recovery does not select a different NIC.' }
}

function Assert-SocBundleRepairQuiescent($Member, [switch]$IgnoreStartMode, [switch]$AllowUnregistered) {
    $service=Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Member.Service) -ErrorAction Stop
    if (-not $service) {
        if ($Member.InitiallyMissing -and ($AllowUnregistered -or -not $Member.RepairCreated)) { return }
        throw 'Collector disappeared during recovery; retained state was not adopted.'
    }
    if ($Member.InitiallyMissing -and -not $Member.RepairCreated) { throw 'Unowned collector appeared during recovery.' }
    Assert-SocBundleService $Member
    if ($service.State -ne 'Stopped' -or $service.ProcessId -ne 0) {
        throw 'Collector started outside recovery; it was not stopped or adopted.'
    }
    $expected=if ($Member.InitiallyMissing) {'Manual'} else {$Member.OriginalService.StartMode}
    if (-not $IgnoreStartMode -and $service.StartMode -cne $expected) { throw 'Collector start mode changed before recovery start.' }
    if ($Member.Kind -eq 'network') {
        $dependencies=@((Get-Service -Name $Member.Service -ErrorAction Stop).ServicesDependedOn | ForEach-Object Name)
        if ($dependencies.Count -ne 1 -or $dependencies[0] -ine 'npcap') { throw 'Packetbeat dependency changed before recovery start.' }
    }
}

function Assert-SocBundleRepairReady($Members) {
    foreach ($member in $Members) {
        Assert-SocBundleStableFiles $member
        Assert-SocBundleRepairQuiescent $member
    }
    if (@(Get-Process -ErrorAction Stop | Where-Object ProcessName -In @('filebeat','packetbeat','elastic-agent')).Count) {
        throw 'A collector process started during recovery; state retained.'
    }
}

function Invoke-SocBundleRepairCore([string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
    [string]$InterfaceGuid, [switch]$AllowUnavailableRevocation, [switch]$DryRun, [switch]$ResumeRepair) {
    Assert-SocAdministrator
    if ($Endpoint -cnotmatch '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:([0-9]{1,5}))?/?\z') { throw 'Use an HTTPS DNS/IPv4 endpoint without credentials, path, query or fragment.' }
    $port = $Matches[4]
    if ($port -and ([int]$port -lt 1 -or [int]$port -gt 65535)) { throw 'Invalid endpoint port.' }
    if ($Organization -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\z') { throw 'Invalid organization identifier.' }
    Assert-SocLocalPath $CaPath
    if ($ResumeRepair) {
        Resume-SocBundleRepair -Source $Source -Endpoint $Endpoint -CaPath $CaPath -Organization $Organization -InterfaceGuid $InterfaceGuid -DryRun:$DryRun
        if ($DryRun) { return }
    }
    $members = Get-SocBundleMembers
    $interrupted = Get-SocBundlePendingRecovery $members
    foreach ($member in $members) { Assert-SocBundleRepairMember $member $Source $Endpoint $CaPath $Organization -AllowMissingService:([bool]$interrupted) }
    if ($InterfaceGuid -and ([guid]$InterfaceGuid).ToString() -cne $members[1].InterfaceGuid) { throw 'Requested NIC differs; recovery is not network migration.' }
    if (@(Get-Process -ErrorAction Stop | Where-Object ProcessName -In @('filebeat','packetbeat','elastic-agent')).Count) { throw 'A collector process is active; no recovery changes made.' }
    Assert-SocNativeDiscovery $members[0].Root
    $task = Get-SocRepairDiscovery $members[0].Root -AllowEnabled
    $originalXml = $null
    $originalEnabled = $false
    if ($task) {
        if ([string]$task.State -in @('Running','Queued') -or $task.Actions[0].Execute -ine (Join-Path $members[0].Root 'cloud-soc-discovery.exe')) {
            throw 'Discovery must be an idle recognized native task; legacy/active tasks were not changed.'
        }
        $originalXml = Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
        $originalEnabled = [bool]$task.Settings.Enabled
    }
    $pending = Join-Path $env:ProgramData 'Cloud-SOC\bundle-repair-pending.json'
    Assert-SocLocalPath $pending
    if (Test-Path -LiteralPath $pending) { throw 'Interrupted Repair requires its protected backup; no automatic overwrite.' }
    if ($DryRun) {
        Write-Host 'DRY RUN: recognized stopped pair and local identities verified. No files, network, keys, tasks or services changed. Npcap/SYSTEM/authentication/central receipt are still pending.'
        return
    }
    Assert-SocBundleRepairNetwork $members[1].InterfaceGuid
    Test-SocServerTls -Endpoint $Endpoint -CaPath $CaPath -AllowUnavailableRevocation:$AllowUnavailableRevocation
    $transaction = New-SocStage
    $record = @{schema=2;transaction=$transaction.Token;auto_restore_queue=$false}
    $stream = [IO.File]::Open($pending, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Compress))
        $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true)
    } finally { $stream.Dispose() }
    $backups = @{}; $taskTouched=$false; $taskCreated=$false; $taskRegistrationAttempted=$false; $taskXml=$originalXml
    $startedMembers = New-Object 'Collections.Generic.List[object]'
    try {
        Save-SocRepairResumeRecord $transaction $members $Endpoint $Organization $backups $originalXml $taskXml 'reserved'
        if ($task) {
            Assert-SocBundleTask $originalXml
            $taskTouched=$true
            Disable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
            $taskXml=Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
            Save-SocRepairResumeRecord $transaction $members $Endpoint $Organization $backups $originalXml $taskXml 'quiesced'
            Assert-SocBundleTask $taskXml
            $idle = Get-SocRepairDiscovery $members[0].Root
            if (-not $idle) { throw 'Discovery disappeared during recovery.' }
        }
        foreach ($member in $members) {
            Assert-SocBundleRepairMember $member $Source $Endpoint $CaPath $Organization -AllowMissingService:([bool]$interrupted)
            $backups[$member.Kind] = Backup-SocRepair $member.Root $member.OriginalService
            @{schema=1;backups=$backups;original_task_xml=$originalXml;auto_restore_queue=$false} |
                ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $transaction.Path 'repair-backups.json') -Encoding UTF8
            Save-SocRepairResumeRecord $transaction $members $Endpoint $Organization $backups $originalXml $taskXml 'backing_up'
        }
        Write-Host '[1/3] Both protected backups verified; existing keys, configuration and queues retained.'
        Invoke-SocDiscoveryProbe $members[0].Root
        foreach ($member in $members) { Test-SocBundleMember $member.Root $member.Beat }
        Assert-SocBundleRepairReady $members
        Save-SocRepairResumeRecord $transaction $members $Endpoint $Organization $backups $originalXml $taskXml 'validated'
        foreach ($member in $members) {
            if ($member.InitiallyMissing) {
                if (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $member.Service) -ErrorAction Stop) { throw 'Missing collector service appeared before registration.' }
                $member.RepairCreateAttempted=$true
                Save-SocRepairResumeRecord $transaction $members $Endpoint $Organization $backups $originalXml $taskXml 'creating_services'
                $arguments=@{Name=$member.Service;DisplayName=('Cloud SOC ' + $member.Beat);BinaryPathName=(Get-SocBundleCommand $member.Root $member.Beat);StartupType='Manual'}
                if ($member.Kind -eq 'network') { $arguments.DependsOn='npcap' }
                New-Service @arguments | Out-Null
                $member.RepairCreated=$true
                Assert-SocBundleService $member
            }
        }
        if ($task) {
            Assert-SocBundleTask $taskXml
            Enable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
        } else {
            $taskRegistrationAttempted=$true
            Register-SocRepairDiscovery $members[0].Root
            $taskCreated=$true
        }
        $taskXml=Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
        Save-SocRepairResumeRecord $transaction $members $Endpoint $Organization $backups $originalXml $taskXml 'task_ready'
        $previousRun = (Get-ScheduledTaskInfo -TaskName 'Cloud-SOC-Discovery' -TaskPath '\').LastRunTime
        $started = (Get-Date).AddSeconds(-1)
        Start-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
        Wait-SocTask -Name 'Cloud-SOC-Discovery' -Started $started -PreviousRun $previousRun
        Assert-SocBundleFreshReport $members[0].Root $started
        Write-Host '[2/3] SYSTEM Discovery and both configuration/authentication checks passed.'
        Assert-SocBundleRepairReady $members
        Save-SocRepairResumeRecord $transaction $members $Endpoint $Organization $backups $originalXml $taskXml 'starting'
        foreach ($member in $members) {
            Assert-SocBundleStableFiles $member
            Assert-SocBundleRepairQuiescent $member
            $startedMembers.Add($member)
            Set-Service -Name $member.Service -StartupType Manual -ErrorAction Stop
            Start-Service -Name $member.Service -ErrorAction Stop
            (Get-Service -Name $member.Service -ErrorAction Stop).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
        }
        Start-Sleep -Seconds 3
        foreach ($member in $members) {
            Assert-SocBundleService $member
            if ((Get-Service -Name $member.Service -ErrorAction Stop).Status -ne 'Running') { throw 'Recovered collector did not remain running.' }
            Set-Service -Name $member.Service -StartupType Automatic -ErrorAction Stop
        }
        Assert-SocBundleTask $taskXml
        Save-SocRepairResumeRecord $transaction $members $Endpoint $Organization $backups $originalXml $taskXml 'committed_receipt_unverified'
        if ($interrupted) {
            $null = Get-SocBundlePendingRecovery $members
            Save-SocBundleJournal $interrupted 'committed_receipt_unverified' $true
            Remove-Item -LiteralPath $interrupted.Pending -ErrorAction Stop
        }
        Remove-Item -LiteralPath $pending -ErrorAction Stop
        Write-Host '[3/3] Both collectors recovered locally. Central document receipt is NOT yet verified.'
    } catch {
        $failure=$_; $safe=$true
        foreach ($member in $startedMembers) {
            try {
                Assert-SocBundleService $member
                Stop-Service -Name $member.Service -ErrorAction Stop
                (Get-Service -Name $member.Service -ErrorAction Stop).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
                Set-Service -Name $member.Service -StartupType (@{Auto='Automatic';Manual='Manual';Disabled='Disabled'}[$member.OriginalService.StartMode]) -ErrorAction Stop
            } catch { $safe=$false }
        }
        try {
            foreach ($member in $members) {
                if ($member.RepairCreateAttempted -and -not $member.RepairCreated -and
                    (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $member.Service) -ErrorAction Stop)) { throw 'Service registration returned an ambiguous failure; state retained.' }
                if ($member.RepairCreated -and -not $startedMembers.Contains($member)) {
                    Assert-SocBundleService $member
                    if ((Get-Service -Name $member.Service -ErrorAction Stop).Status -ne 'Stopped') { throw 'New collector service started unexpectedly.' }
                    Remove-SocBundleService $member
                }
            }
            if ($taskRegistrationAttempted -and -not $taskCreated -and
                (Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction SilentlyContinue)) {
                throw 'Task registration returned an ambiguous failure; definition/files retained.'
            }
            if ($taskTouched -or $taskCreated) {
                Assert-SocBundleTask $taskXml
                Disable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
                Stop-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
                if ((Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop).State -in @('Running','Queued')) { throw 'Discovery is still active.' }
                if ($taskCreated) { Unregister-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -Confirm:$false -ErrorAction Stop }
            }
            if (-not $safe -or (Test-Path -LiteralPath (Join-Path $members[0].Root 'probe-active.txt'))) { throw 'Collector/probe cleanup incomplete.' }
            foreach ($member in $members) {
                Assert-SocBundleStableFiles $member
                Assert-SocBundleRepairQuiescent $member -IgnoreStartMode -AllowUnregistered
            }
            if (@(Get-Process -ErrorAction Stop | Where-Object ProcessName -In @('filebeat','packetbeat','elastic-agent')).Count) {
                throw 'Active collector prevents file rollback; current files and backup retained.'
            }
            if ($backups.ContainsKey('host')) { Restore-SocRepairFiles $members[0].Root $backups.host }
            if ($taskTouched -and $originalEnabled) { Enable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null }
            if ($taskTouched) { Assert-SocBundleTask $originalXml }
            Remove-Item -LiteralPath $pending -ErrorAction Stop
            Write-Warning ('Recovery failed; owned changes rolled back, keys/queues retained. Protected backup record: ' + $transaction.Path)
        } catch { Write-Warning ('Recovery cleanup incomplete; keys/queues and protected backup retained: ' + $transaction.Path) }
        throw $failure
    }
}

function Invoke-SocBundleRepair([string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
    [string]$InterfaceGuid, [switch]$AllowUnavailableRevocation, [switch]$DryRun, [switch]$ResumeRepair) {
    $locks = @()
    try {
        foreach ($name in @('Global\Cloud-SOC-Bundle-Install','Global\Cloud-SOC-Filebeat-Recovery')) {
            $mutex = New-Object Threading.Mutex($false,$name)
            $held=$false
            try {
                try { $held=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held=$true }
                if (-not $held) { throw 'Another collector installation/update/recovery is active.' }
                $locks += $mutex
            } catch { if ($held) { $mutex.ReleaseMutex() }; $mutex.Dispose(); throw }
        }
        Invoke-SocBundleRepairCore @PSBoundParameters
    } finally { foreach ($mutex in $locks) { $mutex.ReleaseMutex(); $mutex.Dispose() } }
}
