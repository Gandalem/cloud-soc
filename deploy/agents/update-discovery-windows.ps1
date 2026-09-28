# Loaded by the installer. Never starts/stops Filebeat or restores its live queue.
function Assert-SocUpdatePath([string]$Path) {
    Assert-SocLocalPath $Path
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSObject.Properties['LinkType'] -and $item.LinkType) { throw 'Discovery update refused a linked file.' }
        Assert-SocRepairAcl $Path
    }
}

function Get-SocUpdateTaskDefinition([string]$Xml) {
    $document = [xml]$Xml
    foreach ($node in @($document.SelectNodes('/*[local-name()="Task"]/*[local-name()="Settings"]/*[local-name()="Enabled"]'))) {
        $null = $node.ParentNode.RemoveChild($node)
    }
    return $document.OuterXml
}

function Assert-SocUpdateTask([string]$Root, [string]$OriginalXml) {
    $task = Get-SocRepairDiscovery $Root -AllowEnabled
    if (-not $task -or $task.Actions[0].Execute -ine (Join-Path $Root 'cloud-soc-discovery.exe') -or
        $task.Actions[0].WorkingDirectory -ine $Root) { throw 'Update supports the recognized native Discovery task only.' }
    if ($OriginalXml -and (Get-SocUpdateTaskDefinition (Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop)) -cne
        (Get-SocUpdateTaskDefinition $OriginalXml)) { throw 'Discovery task definition changed; automatic update/restore refused.' }
    return $task
}

function Wait-SocUpdateIdle([string]$Root, [string]$Xml, [int]$TimeoutSeconds = 300) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $task = Assert-SocUpdateTask $Root $Xml
        if ($task.Settings.Enabled) { throw 'Discovery task was externally enabled; update stopped.' }
        if ([string]$task.State -notin @('Running','Queued')) { return }
        if ((Get-Date) -ge $deadline) { throw 'Discovery is still running; no process was killed.' }
        Start-Sleep -Seconds 1
    } while ($true)
}

function Open-SocUpdateLock([string]$Root) {
    $path = Join-Path $Root 'discovery.lock'
    Assert-SocUpdatePath $path
    try { return [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None) }
    catch { throw 'Discovery/policy lock is busy or inaccessible; no competing process was stopped.' }
}

function Get-SocUpdateGuard([string]$Root) {
    $result = @{}
    foreach ($name in @('filebeat.yml','ca.crt','data\filebeat.keystore','discovery-settings.json','privacy.js','collection-policy.txt')) {
        $path = Join-Path $Root $name
        Assert-SocUpdatePath $path
        if ($name -ne 'collection-policy.txt' -and -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing update prerequisite: $name" }
        $result[$name] = if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path -ErrorAction Stop).Hash } else { $null }
    }
    return $result
}

function Assert-SocUpdateGuard([string]$Root, $Guard, $Service) {
    $now = Get-SocUpdateGuard $Root
    foreach ($name in $Guard.Keys) {
        if ($now[$name] -cne $Guard[$name]) { throw 'Protected configuration/key/policy changed during update; not overwritten.' }
    }
    $current = Get-CimInstance Win32_Service -Filter "Name='cloud-soc-filebeat'" -ErrorAction Stop
    foreach ($field in @('State','ProcessId','StartMode','StartName','PathName')) {
        if ($current.$field -cne $Service.$field) { throw 'Filebeat service changed during update; it was not restarted by this updater.' }
    }
}

function Copy-SocUpdateVerified([string]$Source, [string]$Target, [string]$Hash) {
    Assert-SocUpdatePath $Source
    Assert-SocUpdatePath $Target
    if ((Get-FileHash -LiteralPath $Source -ErrorAction Stop).Hash -cne $Hash) { throw 'Discovery update source/backup checksum mismatch.' }
    Copy-Item -LiteralPath $Source -Destination $Target -Force -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $Target -ErrorAction Stop).Hash -cne $Hash) { throw 'Discovery update copy verification failed.' }
}

function Assert-SocUpdateReport([string]$Root, [datetime]$Since) {
    $path = Join-Path $Root 'health.ndjson'
    Assert-SocUpdatePath $path
    if ((Get-Item -LiteralPath $path).Length -gt 8388608) { throw 'Discovery report exceeds validation limit.' }
    $report = Get-Content -LiteralPath $path -Tail 1 -ErrorAction Stop | ConvertFrom-Json
    $time = if ($report.generated_at -is [datetime]) { $report.generated_at.ToUniversalTime() }
            else { [DateTimeOffset]::Parse([string]$report.generated_at).UtcDateTime }
    if ($time -lt $Since.ToUniversalTime() -or $time -gt [DateTime]::UtcNow.AddSeconds(30) -or
        -not $report.PSObject.Properties['collector_metrics']) { throw 'Updated Discovery did not publish a fresh metrics-capable report.' }
}

function Invoke-SocDiscoveryUpdateCore {
    param([string]$Root, [string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
          [string]$Version, [string]$Hash, [switch]$DryRun)
    Assert-SocAdministrator
    Assert-SocUpdatePath $Root
    foreach ($name in @('recovery-pending.json','discovery-update-pending.json','probe-active.txt')) {
        if (Test-Path -LiteralPath (Join-Path $Root $name)) { throw "Incomplete operation ($name); preserve the backup and inspect before retrying." }
    }
    foreach ($name in @('discovery-native.cs','cloud-soc-discovery.exe','discovery-native.json','inputs','data','logs','discovery.lock',
                        'inputs\discovered.yml','inputs\health.yml','health.ndjson','health-previous.ndjson','discovery-report.json','discovery-diagnostic.json')) {
        Assert-SocUpdatePath (Join-Path $Root $name)
    }
    Assert-SocNativeDiscovery $Root
    $service = Get-CimInstance Win32_Service -Filter "Name='cloud-soc-filebeat'" -ErrorAction Stop
    if (-not $service) { throw 'Existing Filebeat service was not found.' }
    $beatHome = Join-Path $Root "filebeat-$Version-windows-x86_64"
    $command = '"{0}" --environment=windows_service --path.home "{1}" --path.config "{2}" --path.data "{3}" --path.logs "{4}" -c "{5}" -E logging.files.redirect_stderr=true' -f (Join-Path $beatHome 'filebeat.exe'), $beatHome, $Root, (Join-Path $Root 'data'), (Join-Path $Root 'logs'), (Join-Path $Root 'filebeat.yml')
    $guard = Get-SocUpdateGuard $Root
    $config = Get-Content -LiteralPath (Join-Path $Root 'filebeat.yml') -Raw | ConvertFrom-Json
    Assert-SocRepairIdentity $service $config $command $Endpoint $Organization $Root -RunningUpdate
    if ((Get-FileHash -LiteralPath $CaPath -ErrorAction Stop).Hash -cne $guard['ca.crt']) { throw 'Update CA differs; no key or data was changed.' }
    $task = Assert-SocUpdateTask $Root ''
    if (-not $task.Settings.Enabled) { throw 'Discovery update requires an enabled native task; use recovery for disabled installations.' }
    $xml = Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
    Assert-SocRepairDistribution $Root $Version $Hash
    $sourceFile = Join-Path $Source 'discovery-native.cs'
    Assert-SocLocalPath $sourceFile
    $sourceHash = (Get-FileHash -LiteralPath $sourceFile -ErrorAction Stop).Hash
    if ($DryRun) {
        Write-Host 'DRY RUN: recognized running installation; native Discovery update only. No writes, tasks, network, keys or service changes. SYSTEM validation is still pending.'
        return
    }
    if ((Read-Host 'Back up and update Discovery only? Filebeat keeps collecting; keys and queued data are preserved. [y/N]') -notmatch '^(?i:y|yes)$') { throw 'Discovery update cancelled; installation unchanged.' }

    $volume = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($env:ProgramData))
    if ($volume.AvailableFreeSpace -lt 268435456) { throw 'At least 256 MiB free space is required for Discovery staging and backup.' }
    $stage = New-SocStage
    $backup = $null; $locked = $null; $taskTouched = $false; $filesTouched = $false; $pendingWritten = $false
    $pending = Join-Path $Root 'discovery-update-pending.json'
    $names = @('discovery-native.cs','cloud-soc-discovery.exe','discovery-native.json','inputs\discovered.yml','inputs\health.yml')
    $manifest = @()
    try {
        New-SocProtectedDirectory (Join-Path $stage.Path 'inputs')
        foreach ($name in @('discovery-settings.json','collection-policy.txt')) {
            if ($guard[$name]) { Copy-SocUpdateVerified (Join-Path $Root $name) (Join-Path $stage.Path $name) $guard[$name] }
        }
        Build-SocNativeDiscovery -Root $stage.Path -Source $Source
        if ((Get-FileHash -LiteralPath (Join-Path $stage.Path 'discovery-native.cs')).Hash -cne $sourceHash) { throw 'Package source changed during staging.' }
        $candidate = @{}
        foreach ($name in $names[0..2]) { $candidate[$name] = (Get-FileHash -LiteralPath (Join-Path $stage.Path $name)).Hash }
        $started = (Get-Date).AddSeconds(-1)
        Invoke-SocDiscoveryProbe $stage.Path
        Assert-SocUpdateReport $stage.Path $started
        Assert-SocUpdateGuard $Root $guard $service
        $null = Assert-SocUpdateTask $Root $xml

        $parent = Join-Path $env:ProgramData 'Cloud-SOC\updates'
        New-SocProtectedDirectory $parent -Reuse
        $backup = Join-Path $parent ([guid]::NewGuid().ToString('N'))
        New-SocProtectedDirectory $backup
        New-SocProtectedDirectory (Join-Path $backup 'inputs')
        [IO.File]::WriteAllText((Join-Path $backup 'task.xml'), $xml)
        # A durable marker precedes disabling the schedule. Crashes never look like a completed update.
        @{ schema=1; backup=$backup; status='pending'; source_sha256=$sourceHash } | ConvertTo-Json |
            Set-Content -LiteralPath $pending -Encoding UTF8 -ErrorAction Stop
        $pendingWritten = $true
        $taskTouched = $true
        Disable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
        Wait-SocUpdateIdle $Root $xml
        $locked = Open-SocUpdateLock $Root
        Assert-SocUpdateGuard $Root $guard $service
        Assert-SocNativeDiscovery $Root
        foreach ($name in $names) {
            $path = Join-Path $Root $name
            Assert-SocUpdatePath $path
            $digest = if (Test-Path -LiteralPath $path) { (Get-FileHash -LiteralPath $path).Hash } else { $null }
            if ($digest) { Copy-SocUpdateVerified $path (Join-Path $backup $name) $digest }
            $manifest += @{ path=$name; sha256=$digest }
        }
        @{ schema=1; files=$manifest; task_sha256=(Get-FileHash -LiteralPath (Join-Path $backup 'task.xml')).Hash; guard=$guard; queue_restore=$false } |
            ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $backup 'manifest.json') -Encoding UTF8 -ErrorAction Stop
        Write-Host "Verified Discovery backup: $backup"
        $filesTouched = $true
        foreach ($name in $names[0..2]) { Copy-SocUpdateVerified (Join-Path $stage.Path $name) (Join-Path $Root $name) $candidate[$name] }
        Assert-SocNativeDiscovery $Root
        $locked.Dispose(); $locked = $null
        # Probe has its own temporary SYSTEM task; the regular schedule remains disabled until success.
        $started = (Get-Date).AddSeconds(-1)
        Invoke-SocDiscoveryProbe $Root
        Assert-SocUpdateReport $Root $started
        $locked = Open-SocUpdateLock $Root
        Assert-SocUpdateGuard $Root $guard $service
        $null = Assert-SocUpdateTask $Root $xml
        foreach ($name in $names[0..2]) {
            if ((Get-FileHash -LiteralPath (Join-Path $Root $name)).Hash -cne $candidate[$name]) { throw 'Installed Discovery changed during verification.' }
        }
        $locked.Dispose(); $locked = $null
        Enable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
        if (-not (Assert-SocUpdateTask $Root $xml).Settings.Enabled) { throw 'Discovery schedule did not resume.' }
        Remove-Item -LiteralPath $pending -ErrorAction Stop
        $pendingWritten = $false; $filesTouched = $false; $taskTouched = $false
        Write-Host 'Discovery update completed locally. Filebeat was not restarted. Server ingestion of new metrics is NOT yet verified.'
    } catch {
        $failure = $_
        try {
            if ($locked) { $locked.Dispose(); $locked = $null }
            if ($taskTouched) {
                $null = Assert-SocUpdateTask $Root $xml
                if ($filesTouched) {
                    Disable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
                    Wait-SocUpdateIdle $Root $xml
                    if (Test-Path -LiteralPath (Join-Path $Root 'probe-active.txt')) { throw 'Probe cleanup is incomplete; update backup retained.' }
                    $locked = Open-SocUpdateLock $Root
                    # Verify ALL backup bytes before restoring any, and never rewind the health spool/queue.
                    foreach ($entry in $manifest) {
                        if ($entry.sha256) {
                            $path = Join-Path $backup $entry.path
                            Assert-SocUpdatePath $path
                            if ((Get-FileHash -LiteralPath $path).Hash -cne $entry.sha256) { throw 'Backup checksum mismatch; automatic rollback stopped.' }
                        }
                    }
                    foreach ($entry in $manifest) {
                        $target = Join-Path $Root $entry.path
                        Assert-SocUpdatePath $target
                        if ($entry.sha256) { Copy-SocUpdateVerified (Join-Path $backup $entry.path) $target $entry.sha256 }
                        elseif (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -ErrorAction Stop }
                    }
                    Assert-SocNativeDiscovery $Root
                }
                if ($locked) { $locked.Dispose(); $locked = $null }
                Enable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
                if (-not (Assert-SocUpdateTask $Root $xml).Settings.Enabled) { throw 'Original Discovery schedule did not resume.' }
            }
            if ($pendingWritten) { Remove-Item -LiteralPath $pending -ErrorAction Stop; $pendingWritten = $false }
            if ($taskTouched) { Write-Warning "Owned Discovery changes rolled back; original schedule resumed. Keys and queues were not replaced. Backup: $backup" }
        } catch {
            throw "Discovery update/rollback incomplete. Backup: $backup. Pending marker retained; no keys/queues were restored. $($_.Exception.Message)"
        }
        throw $failure
    } finally {
        if ($locked) { $locked.Dispose() }
        if ($pendingWritten -or (Test-Path -LiteralPath (Join-Path $stage.Path 'probe-active.txt'))) {
            Write-Warning "Retained update staging: $($stage.Path). Do not remove it while a probe may still be running."
        } else {
            try { Remove-SocOwnedDirectory -Path $stage.Path -ExpectedPath $stage.Path -Token $stage.Token }
            catch { Write-Warning "Update scratch cleanup failed; protected staging retained: $($stage.Path)"; throw }
        }
    }
}

function Invoke-SocDiscoveryUpdate {
    param([string]$Root, [string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
          [string]$Version, [string]$Hash, [switch]$DryRun)
    $mutex = New-Object Threading.Mutex($false, 'Global\Cloud-SOC-Filebeat-Recovery')
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) { throw 'Another Filebeat recovery/update is active.' }
        Invoke-SocDiscoveryUpdateCore @PSBoundParameters
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
