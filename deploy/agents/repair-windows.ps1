# Narrow, opt-in recovery of a stopped, recognized Filebeat installation.
# No top-level host changes. Never restore an old queue over a newer queue.
function Get-SocRepairTree([string]$Root) {
    Assert-SocLocalPath $Root
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($Root)
    while ($pending.Count) {
        $directory = $pending.Pop()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Recovery refused a linked path.' }
            if ($item.PSObject.Properties['LinkType'] -and $item.LinkType) { throw 'Recovery refused a linked file.' }
            $item
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}

function Assert-SocRepairAcl([string]$Path) {
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owners = @('S-1-5-18', 'S-1-5-32-544', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $owners) { throw 'Recovery refused unexpected file ownership.' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
            throw 'Recovery requires administrator/SYSTEM-only installation access; permissions were not changed.'
        }
    }
}

function Assert-SocRepairIdentity($Service, $Config, [string]$Command, [string]$Endpoint, [string]$Organization, [string]$Root, [switch]$RunningUpdate) {
    if ($RunningUpdate) {
        if ($Service.State -ne 'Running' -or $Service.ProcessId -le 0 -or $Service.StartMode -ne 'Auto') {
            throw 'Discovery update requires a running automatic Filebeat service; use recovery for stopped installations.'
        }
    } elseif ($Service.State -ne 'Stopped' -or $Service.ProcessId -ne 0 -or $Service.StartMode -notin @('Disabled','Manual','Auto')) {
        throw 'Existing Filebeat must be stopped before recovery. Running installations are not modified.'
    }
    if ($Service.PathName -cne $Command -or $Service.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) {
        throw 'Existing service identity/path differs from the supported installation; no changes made.'
    }
    $output = $Config.'output.elasticsearch'
    if (@($output.hosts).Count -ne 1 -or $output.hosts[0].TrimEnd('/') -cne $Endpoint.TrimEnd('/') -or
        $output.'ssl.verification_mode' -ne 'full' -or $output.api_key -cne '${CLOUD_SOC_API_KEY}' -or
        @($output.'ssl.certificate_authorities').Count -ne 1 -or $output.'ssl.certificate_authorities'[0] -ine (Join-Path $Root 'ca.crt')) {
        throw 'Existing endpoint/TLS/keystore settings differ; migration is not recovery.'
    }
    $organizations = @($Config.processors | Where-Object { $_.PSObject.Properties['add_fields'] } |
        Where-Object { $_.add_fields.target -eq 'organization' } | ForEach-Object { $_.add_fields.fields.id })
    if ($organizations.Count -ne 1 -or $organizations[0] -cne $Organization) { throw 'Existing organization differs; no keys or data were changed.' }
    if ($Config.'filebeat.config.inputs'.path -ine (Join-Path $Root 'inputs\*.yml')) { throw 'Unsupported input configuration path.' }
}

function Assert-SocRepairDistribution([string]$Root, [string]$Version, [string]$Hash, [string]$Beat = 'filebeat') {
    if ($Beat -notin @('filebeat','packetbeat')) { throw 'Unsupported recovery distribution.' }
    $archive = Join-Path $Root "$Beat-$Version-windows-x86_64.zip"
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA512 -ErrorAction Stop).Hash -ine $Hash) { throw 'Existing distribution checksum mismatch; no code was executed.' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $expected = @{}
        foreach ($entry in $zip.Entries) {
            if (-not $entry.FullName.StartsWith("$Beat-$Version-windows-x86_64/", [StringComparison]::Ordinal) -or
                $entry.FullName -match '(^|/)\.\.(/|$)|[\\:]') { throw 'Invalid distribution member.' }
            if (-not $entry.Name) { continue }
            $path = Join-Path $Root ($entry.FullName.Replace('/', '\'))
            $stream = $entry.Open()
            try { $digest = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') } finally { $stream.Dispose() }
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -cne $digest) { throw 'Installed distribution was modified; automatic recovery refused.' }
            $expected[$path] = $true
        }
        foreach ($file in Get-SocRepairTree (Join-Path $Root "$Beat-$Version-windows-x86_64")) {
            if (-not $file.PSIsContainer -and -not $expected.ContainsKey($file.FullName)) { throw 'Unexpected installed distribution file.' }
        }
    } finally { $sha.Dispose(); $zip.Dispose() }
}

function Backup-SocRepair([string]$Root, $Service) {
    $items = @(Get-SocRepairTree $Root)
    $bytes = ($items | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum
    $volume = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($env:ProgramData))
    if ($volume.AvailableFreeSpace -lt ($bytes + 268435456)) { throw 'Insufficient space for verified recovery backup plus 256 MiB reserve; original installation unchanged.' }
    $parent = Join-Path $env:ProgramData 'Cloud-SOC'
    New-SocProtectedDirectory $parent -Reuse
    $parent = Join-Path $parent 'recovery'
    New-SocProtectedDirectory $parent -Reuse
    $backup = Join-Path $parent ([guid]::NewGuid().ToString('N'))
    New-SocProtectedDirectory $backup
    $snapshot = Join-Path $backup 'snapshot'
    New-SocProtectedDirectory $snapshot
    $manifest = @()
    foreach ($item in $items) {
        $relative = $item.FullName.Substring($Root.Length + 1)
        $target = Join-Path $snapshot $relative
        if ($item.PSIsContainer) { New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null; continue }
        $before = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $item.FullName -Destination $target -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -cne $before -or
            (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -cne $before) { throw 'Backup verification failed; original installation unchanged.' }
        $manifest += @{ path = $relative; sha256 = $before }
    }
    @{ files = $manifest; service_start_mode = $Service.StartMode; status = 'verified'; queues_restore_automatically = $false } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $backup 'manifest.json') -Encoding UTF8
    return $backup
}

function Invoke-SocRepairBeat([string]$Root, [string]$Version, [string]$Check) {
    $beatDirectory = Join-Path $Root "filebeat-$Version-windows-x86_64"
    $PSNativeCommandUseErrorActionPreference = $false
    & (Join-Path $beatDirectory 'filebeat.exe') --path.home $beatDirectory --path.config $Root --path.data (Join-Path $Root 'data') `
        --path.logs (Join-Path $Root 'logs') -c (Join-Path $Root 'filebeat.yml') test $Check
    if ($LASTEXITCODE -ne 0) { throw "Existing Filebeat $Check check failed (exit $LASTEXITCODE). Existing key was not replaced." }
}

function New-SocRepairDiscoveryAction([string]$Root) {
    New-SocNativeDiscoveryAction $Root
}

function Get-SocRepairDiscovery([string]$Root, [switch]$AllowEnabled) {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq 'Cloud-SOC-Discovery')
    if (-not $tasks.Count) { return $null }
    if ($tasks.Count -ne 1) { throw 'Multiple Discovery tasks; automatic recovery refused.' }
    $task = $tasks[0]
    $legacy = '-NoProfile -NonInteractive -File "{0}" -Refresh' -f (Join-Path $Root 'discover-windows.ps1')
    $current = $legacy + (' -DiscoveryRoot "{0}"' -f $Root)
    $actions = @($task.Actions)
    $recognized = $false
    if ($actions.Count -eq 1) {
        $recognized = ($actions[0].Execute -ieq (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -and $actions[0].Arguments -cin @($legacy,$current)) -or
            ($actions[0].Execute -ieq (Join-Path $Root 'cloud-soc-discovery.exe') -and $actions[0].Arguments -ceq ('--root "{0}"' -f $Root))
    }
    if ($task.TaskPath -cne '\' -or $actions.Count -ne 1 -or
        -not $recognized -or
        ($actions[0].WorkingDirectory -and $actions[0].WorkingDirectory -ine $Root) -or
        $task.Principal.UserId -notin @('SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') -or
        [string]$task.Principal.LogonType -notin @('ServiceAccount','5') -or
        [string]$task.Principal.RunLevel -notin @('Highest','1')) {
        throw 'Existing Discovery task identity differs; it was not changed.'
    }
    if (-not $AllowEnabled -and ($task.Settings.Enabled -or [string]$task.State -ne 'Disabled')) {
        throw 'Existing Discovery task must be disabled and idle before recovery; no task was stopped.'
    }
    return $task
}

function Get-SocRepairTaskInvariant([string]$Xml) {
    # Preserve every original task setting except the action and enabled flag we own.
    $document = [xml]$Xml
    foreach ($node in @($document.SelectNodes('/*[local-name()="Task"]/*[local-name()="Actions"] | /*[local-name()="Task"]/*[local-name()="Settings"]/*[local-name()="Enabled"]'))) {
        $null = $node.ParentNode.RemoveChild($node)
    }
    return $document.OuterXml
}

function Assert-SocRepairTaskUnchanged([string]$Root, [string]$OriginalXml) {
    $task = Get-SocRepairDiscovery $Root -AllowEnabled
    if (-not $task) { throw 'Discovery task disappeared during recovery.' }
    $now = Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
    if ((Get-SocRepairTaskInvariant $now) -cne (Get-SocRepairTaskInvariant $OriginalXml)) {
        throw 'Discovery definition changed during recovery; automatic replacement refused.'
    }
}

function Register-SocRepairDiscovery([string]$Root) {
    $action = New-SocRepairDiscoveryAction $Root
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable
    Register-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -Action $action -Principal $principal -Trigger $trigger -Settings $settings -ErrorAction Stop | Out-Null
}

function Restore-SocRepairFiles([string]$Root, [string]$Backup) {
    # Only files the recovery/Discovery phase can replace. Never rewind data/registry/queue/keystore.
    foreach ($name in @('discover-windows.ps1','discovery-native.cs','cloud-soc-discovery.exe','discovery-native.json','discovery-report.json','health.ndjson','health-previous.ndjson','inputs\discovered.yml','inputs\health.yml')) {
        $target = Join-Path $Root $name
        $source = Join-Path (Join-Path $Backup 'snapshot') $name
        Assert-SocLocalPath $target
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop }
        elseif (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force -ErrorAction Stop }
    }
}

function Invoke-SocFilebeatRepairCore {
    param([string]$Root, [string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
          [string]$Version, [string]$Hash, [switch]$Repair, [switch]$AllowUnavailableRevocation)
    Assert-SocAdministrator
    Write-Host '[1/4] Checking existing installation identity, permissions and distribution. No collector is started.'
    $service = Get-CimInstance Win32_Service -Filter "Name='cloud-soc-filebeat'" -ErrorAction Stop
    if (-not $service) { throw 'Recovery needs a recognized existing Filebeat service; no files were removed.' }
    $originalStartMode = $service.StartMode
    Assert-SocLocalPath $Root
    Assert-SocRepairAcl $Root
    $pendingPath = Join-Path $Root 'recovery-pending.json'
    if (Test-Path -LiteralPath (Join-Path $Root 'discovery-update-pending.json')) { throw 'Incomplete Discovery update; preserve its backup before attempting recovery.' }
    if (Test-Path -LiteralPath $pendingPath) { throw 'Interrupted/incomplete recovery is recorded; retained backup must be reviewed before retrying.' }
    foreach ($item in Get-SocRepairTree $Root) { Assert-SocRepairAcl $item.FullName }
    $beatDirectory = Join-Path $Root "filebeat-$Version-windows-x86_64"
    $command = '"{0}" --environment=windows_service --path.home "{1}" --path.config "{2}" --path.data "{3}" --path.logs "{4}" -c "{5}" -E logging.files.redirect_stderr=true' -f (Join-Path $beatDirectory 'filebeat.exe'), $beatDirectory, $Root, (Join-Path $Root 'data'), (Join-Path $Root 'logs'), (Join-Path $Root 'filebeat.yml')
    $config = Get-Content -LiteralPath (Join-Path $Root 'filebeat.yml') -Raw -ErrorAction Stop | ConvertFrom-Json
    Assert-SocRepairIdentity $service $config $command $Endpoint $Organization $Root
    $existingTask = Get-SocRepairDiscovery $Root
    $taskXml = $null
    if ($existingTask) { $taskXml = Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop }
    if (@(Get-Process -ErrorAction Stop | Where-Object { $_.ProcessName -eq 'filebeat' }).Count) { throw 'Filebeat process is still active; no changes made.' }
    foreach ($name in @('data\filebeat.keystore','discovery-settings.json','discover-windows.ps1','privacy.js')) {
        if (-not (Test-Path -LiteralPath (Join-Path $Root $name) -PathType Leaf)) { throw "Incomplete recovery prerequisite: $name" }
    }
    if ((Get-FileHash -LiteralPath (Join-Path $Root 'ca.crt')).Hash -ne (Get-FileHash -LiteralPath $CaPath).Hash) { throw 'CA differs; existing key must not be sent to a different server.' }
    if (Test-Path -LiteralPath (Join-Path $Root 'probe-active.txt')) { throw 'A previous SYSTEM probe has not been cleaned up; recovery will not overwrite it.' }
    Assert-SocRepairDistribution $Root $Version $Hash
    Test-SocServerTls -Endpoint $Endpoint -CaPath $CaPath -AllowUnavailableRevocation:$AllowUnavailableRevocation
    Write-Host 'Recognized stopped Filebeat; same server, organization and CA. Recovery preserves the existing key and queued data.'
    if (-not $Repair -and (Read-Host 'Back up and recover Filebeat + SYSTEM Discovery task? This starts log collection. [y/N]') -notmatch '^(?i:y|yes)$') {
        throw 'Recovery cancelled; existing installation unchanged.'
    }
    $backup = Backup-SocRepair $Root $service
    if ($existingTask) {
        $taskBackup = Join-Path $backup 'discovery-task.xml'
        [IO.File]::WriteAllText($taskBackup, $taskXml, [Text.Encoding]::Unicode)
        if ([IO.File]::ReadAllText($taskBackup) -cne $taskXml) { throw 'Discovery task backup verification failed.' }
        (Get-FileHash -LiteralPath $taskBackup -Algorithm SHA256).Hash | Set-Content -LiteralPath (Join-Path $backup 'discovery-task.sha256')
    }
    Write-Host "[2/4] Protected verified backup: $backup"
    $journal = [IO.File]::Open($pendingPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $record = @{ backup = $backup; start_mode = $originalStartMode; stage = 'prepared'; auto_restore_queue = $false } | ConvertTo-Json
        $bytes = [Text.Encoding]::UTF8.GetBytes($record)
        $journal.Write($bytes, 0, $bytes.Length)
        $journal.Flush($true)
    } finally { $journal.Dispose() }
    $taskCreated = $false; $taskTouched = $false; $serviceTouched = $false; $changed = $false
    try {
        $current = Get-CimInstance Win32_Service -Filter "Name='cloud-soc-filebeat'" -ErrorAction Stop
        Assert-SocRepairIdentity $current $config $command $Endpoint $Organization $Root
        if (@(Get-Process -ErrorAction Stop | Where-Object { $_.ProcessName -eq 'filebeat' }).Count) { throw 'Filebeat process appeared during backup; no recovery changes made.' }
        $nowTask = Get-SocRepairDiscovery $Root
        if ($existingTask) {
            if (-not $nowTask -or (Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop) -cne $taskXml) { throw 'Discovery task changed during preparation.' }
        } elseif ($nowTask) { throw 'Discovery task appeared during preparation.' }
        Write-Host '[3/4] Checking SYSTEM Discovery, existing configuration and server authentication.'
        # Keep the current configuration, organization, policy, keys and queues.
        $changed = $true
        Copy-Item -LiteralPath (Join-Path $Source 'discover-windows.ps1') -Destination (Join-Path $Root 'discover-windows.ps1') -Force -ErrorAction Stop
        Build-SocNativeDiscovery -Root $Root -Source $Source
        Invoke-SocDiscoveryProbe $Root
        Invoke-SocRepairBeat $Root $Version 'config'
        Invoke-SocRepairBeat $Root $Version 'output'
        if ($existingTask) {
            $null = Get-SocRepairDiscovery $Root
            Assert-SocRepairTaskUnchanged $Root $taskXml
            $taskTouched = $true
            Set-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -Action (New-SocRepairDiscoveryAction $Root) -ErrorAction Stop | Out-Null
            $updatedTask = Get-SocRepairDiscovery $Root
            if (-not $updatedTask -or $updatedTask.Actions[0].WorkingDirectory -ine $Root -or
                $updatedTask.Actions[0].Arguments -cne (New-SocRepairDiscoveryAction $Root).Arguments) { throw 'Discovery action update was not applied.' }
            Assert-SocRepairTaskUnchanged $Root $taskXml
            Enable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
            Assert-SocRepairTaskUnchanged $Root $taskXml
        } else {
            Register-SocRepairDiscovery $Root
            $taskCreated = $true
        }
        $previousRun = (Get-ScheduledTaskInfo -TaskName 'Cloud-SOC-Discovery' -TaskPath '\').LastRunTime
        $started = (Get-Date).AddSeconds(-1)
        Start-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
        try { Wait-SocTask -Name 'Cloud-SOC-Discovery' -Started $started -PreviousRun $previousRun }
        catch { Write-SocDiscoveryFailureSummary -Root $Root -Since $started; throw }
        $serviceTouched = $true
        Set-Service -Name 'cloud-soc-filebeat' -StartupType Manual -ErrorAction Stop
        Start-Service -Name 'cloud-soc-filebeat' -ErrorAction Stop
        (Get-Service 'cloud-soc-filebeat').WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        Start-Sleep -Seconds 3
        if ((Get-Service 'cloud-soc-filebeat').Status -ne 'Running') { throw 'Recovered service did not remain running.' }
        Set-Service -Name 'cloud-soc-filebeat' -StartupType Automatic -ErrorAction Stop
        Remove-Item -LiteralPath $pendingPath -ErrorAction Stop
        Write-Host '[4/4] Filebeat service and SYSTEM Discovery recovered. Server ingestion is NOT yet verified. Network collector is a separate step.'
    } catch {
        $failure = $_
        try {
            if ($serviceTouched) {
                Stop-Service -Name 'cloud-soc-filebeat' -ErrorAction Stop
                (Get-Service 'cloud-soc-filebeat').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                $mode = @{ Disabled = 'Disabled'; Manual = 'Manual'; Auto = 'Automatic' }[$originalStartMode]
                Set-Service -Name 'cloud-soc-filebeat' -StartupType $mode -ErrorAction Stop
            }
            if ($taskCreated) {
                Stop-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
                if ((Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\').State -in @('Running','Queued')) { throw 'Discovery cleanup still active.' }
                Unregister-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -Confirm:$false -ErrorAction Stop
            }
            if ($taskTouched) {
                Assert-SocRepairTaskUnchanged $Root $taskXml
                Disable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
                Stop-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
                $deadline = (Get-Date).AddSeconds(30)
                while ((Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop).State -in @('Running','Queued')) {
                    if ((Get-Date) -ge $deadline) { throw 'Existing Discovery cleanup still active.' }
                    Start-Sleep -Seconds 1
                }
                Assert-SocRepairTaskUnchanged $Root $taskXml
                Set-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -Action $existingTask.Actions -ErrorAction Stop | Out-Null
                if ((Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop) -cne $taskXml) { throw 'Original Discovery definition was not fully restored.' }
            }
            if (Test-Path -LiteralPath (Join-Path $Root 'probe-active.txt')) { throw 'SYSTEM probe cleanup incomplete.' }
            if ($changed) {
                $safeTask = Get-SocRepairDiscovery $Root
                if ($existingTask) {
                    if (-not $safeTask -or (Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop) -cne $taskXml) { throw 'Original task is not idle/unchanged; files retained.' }
                } elseif ($safeTask) { throw 'Unexpected task during rollback; files retained.' }
                Restore-SocRepairFiles $Root $backup
            }
            Remove-Item -LiteralPath $pendingPath -ErrorAction Stop
            Write-Warning "Recovery failed; owned changes rolled back, queues/keys retained. Backup: $backup"
        } catch { Write-Warning "Recovery cleanup incomplete. Files and backup retained at $backup; no queue rollback or deletion attempted." }
        throw $failure
    }
}

function Invoke-SocFilebeatRepair {
    param([string]$Root, [string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
          [string]$Version, [string]$Hash, [switch]$Repair, [switch]$AllowUnavailableRevocation)
    $mutex = New-Object Threading.Mutex($false, 'Global\Cloud-SOC-Filebeat-Recovery')
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] {
            $owned = $true
            throw 'Previous recovery was interrupted. Retained backup/state must be checked before retrying.'
        }
        if (-not $owned) { throw 'Another Filebeat recovery is already running.' }
        Invoke-SocFilebeatRepairCore @PSBoundParameters
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
