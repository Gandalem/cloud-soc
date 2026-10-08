# Fresh installation and explicit recovery of a recognized stopped pair.
. (Join-Path $PSScriptRoot 'repair-windows.ps1')
. (Join-Path $PSScriptRoot 'bundle-repair-windows.ps1')

function Get-SocBundleMembers([switch]$HostOnly) {
    $members = @(
        @{Kind='host';Beat='filebeat';Service='cloud-soc-filebeat';Root=(Join-Path $env:ProgramFiles 'Cloud-SOC-Agent');Receipt=$null;Prepared=$null;Promoted=$false;Created=$false;
          Hash='cdb07ad1e39e7c65cefcd7c71e1dfcfa4f92b00daafc132c78490e3e04f664f67403cdb925c5873a8441058d6de08d29790bf6776748edc63582f50174c508c8'},
        @{Kind='network';Beat='packetbeat';Service='cloud-soc-packetbeat';Root=(Join-Path $env:ProgramFiles 'Cloud-SOC-Network');Receipt=$null;Prepared=$null;Promoted=$false;Created=$false;
          Hash='d85de062273901fef2a1fe00b5b1dc4da01d764a65be72ccd2ae0e6d473e6a8cc8525244cf1c64a5f568416041118cef5ee44a2cd927a16315b255bad130cbac'}
    )
    if ($HostOnly) { return @($members | Where-Object Kind -eq 'host') }
    return $members
}
function Assert-SocReceiptDestination([string]$Path) {
    Assert-SocLocalPath $Path
    $parent = Split-Path -Parent $Path
    $base = Join-Path $env:ProgramData 'Cloud-SOC\staging'
    if ((Split-Path -Parent $parent) -ine $base -or (Split-Path -Leaf $parent) -cnotmatch '^[a-f0-9]{32}$' -or
        (Split-Path -Leaf $Path) -notin @('host-prepared.json','network-prepared.json')) { throw 'Unexpected protected receipt destination.' }
    if (Test-Path -LiteralPath $Path) { throw 'Prepared receipt already exists.' }
    New-SocProtectedDirectory $parent -Reuse
}

function Get-SocBundleFiles([string]$Root) {
    Assert-SocRepairAcl $Root
    $files = @{}
    $count = 0
    foreach ($item in Get-SocRepairTree $Root) {
        if (++$count -gt 5000) { throw 'Prepared tree exceeds the entry limit.' }
        Assert-SocRepairAcl $item.FullName
        if (-not $item.PSIsContainer) {
            $files[$item.FullName.Substring($Root.Length + 1)] = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        }
    }
    return $files
}

function Write-SocPreparedReceipt([string]$Path, $Stage, [string]$Kind) {
    Assert-SocReceiptDestination $Path
    if ($Kind -notin @('host','network')) { throw 'Unknown prepared collector.' }
    $files = Get-SocBundleFiles $Stage.Path
    $receipt = @{ schema=1; kind=$Kind; path=$Stage.Path; token=$Stage.Token; files=$files }
    [IO.File]::WriteAllText($Path, ($receipt | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
}

function Read-SocPreparedReceipt([string]$Path, [string]$Kind) {
    Assert-SocLocalPath $Path
    Assert-SocRepairAcl $Path
    $receipt = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $base = Join-Path $env:ProgramData 'Cloud-SOC\staging'
    if ($receipt.schema -ne 1 -or $receipt.kind -cne $Kind -or $receipt.token -cnotmatch '^[a-f0-9]{32}$' -or
        $receipt.path -ine (Join-Path $base $receipt.token)) { throw 'Prepared receipt identity mismatch.' }
    Assert-SocLocalPath $receipt.path
    if ([IO.File]::ReadAllText((Join-Path $receipt.path 'install-owner.txt')) -cne $receipt.token -or
        (Test-Path -LiteralPath (Join-Path $receipt.path 'probe-active.txt'))) { throw 'Prepared ownership/probe mismatch.' }
    $files = Get-SocBundleFiles $receipt.path
    if ($files.Count -ne @($receipt.files.PSObject.Properties).Count) { throw 'Prepared tree changed.' }
    foreach ($entry in $receipt.files.PSObject.Properties) {
        if (-not $files.ContainsKey($entry.Name) -or $files[$entry.Name] -cne $entry.Value) { throw 'Prepared file changed.' }
    }
    return $receipt
}

function Get-SocBundleCommand([string]$Root, [string]$Beat) {
    $beatHome = Join-Path $Root "$Beat-9.5.2-windows-x86_64"
    return '"{0}" --environment=windows_service --path.home "{1}" --path.config "{2}" --path.data "{3}" --path.logs "{4}" -c "{5}" -E logging.files.redirect_stderr=true' -f
        (Join-Path $beatHome "$Beat.exe"), $beatHome, $Root, (Join-Path $Root 'data'), (Join-Path $Root 'logs'), (Join-Path $Root "$Beat.yml")
}

function Test-SocBundleMember([string]$Root, [string]$Beat) {
    $beatHome = Join-Path $Root "$Beat-9.5.2-windows-x86_64"
    foreach ($check in @('config','output')) {
        & (Join-Path $beatHome "$Beat.exe") --path.home $beatHome --path.config $Root --path.data (Join-Path $Root 'data') --path.logs (Join-Path $Root 'logs') -c (Join-Path $Root "$Beat.yml") test $check
        if ($LASTEXITCODE -ne 0) { throw "Prepared $Beat validation failed." }
    }
}

function Move-SocBundleMember($Member) {
    $receipt = Read-SocPreparedReceipt $Member.Receipt $Member.Kind
    Assert-SocLocalPath $Member.Root
    if (Test-Path -LiteralPath $Member.Root) { throw 'Bundle destination appeared during preparation.' }
    [IO.Directory]::Move($receipt.path, $Member.Root)
    $Member.Promoted = $true
    # Only generated absolute staging paths are rewritten; keys and data are not copied/restored.
    $config = Join-Path $Member.Root ($Member.Beat + '.yml')
    $text = [IO.File]::ReadAllText($config)
    $old = ($receipt.path | ConvertTo-Json -Compress).Trim('"')
    $new = ($Member.Root | ConvertTo-Json -Compress).Trim('"')
    [IO.File]::WriteAllText($config, $text.Replace($old, $new), (New-Object Text.UTF8Encoding($false)))
    if ($Member.Kind -eq 'host') { Invoke-SocNativeRefresh $Member.Root }
}

function Assert-SocBundleService($Member) {
    $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Member.Service)
    if (-not $service -or $service.PathName -cne (Get-SocBundleCommand $Member.Root $Member.Beat) -or
        $service.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')) { throw 'Bundle service ownership changed; no cleanup was attempted.' }
}

function Remove-SocBundleService($Member) {
    Assert-SocBundleService $Member
    & (Join-Path $env:WINDIR 'System32\sc.exe') delete $Member.Service | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Get-Service -Name $Member.Service -ErrorAction SilentlyContinue)) { throw 'Service removal incomplete.' }
}

function Save-SocBundleJournal($Transaction, [string]$Phase, [bool]$StartAttempted) {
    $path = Join-Path $Transaction.Path 'bundle-state.json'
    [IO.File]::WriteAllText($path, (@{schema=1;phase=$Phase;start_attempted=$StartAttempted;transaction=$Transaction.Token} |
        ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
}

function Assert-SocBundleTask([string]$OriginalXml) {
    $current = Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
    if (([xml]$current).OuterXml -cne ([xml]$OriginalXml).OuterXml) { throw 'Bundle task definition changed; no automatic replacement.' }
}

function Assert-SocBundleFreshReport([string]$Root, [datetime]$Started) {
    $report = Get-Content -LiteralPath (Join-Path $Root 'discovery-report.json') -Raw | ConvertFrom-Json
    $generated = if ($report.generated_at -is [datetime]) { $report.generated_at.ToUniversalTime() }
                 else { [DateTimeOffset]::Parse([string]$report.generated_at, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime }
    if ($generated -lt $Started.ToUniversalTime() -or $generated -gt [datetime]::UtcNow.AddSeconds(30)) { throw 'Bundle SYSTEM task did not publish a fresh report.' }
}

# This small sequencing boundary is exercised with failures at every step without host changes.
function Invoke-SocBundleSequence([scriptblock]$Prepare, [scriptblock]$Commit, [scriptblock]$Rollback) {
    try { & $Prepare; & $Commit }
    catch { $failure = $_; & $Rollback; throw $failure }
}

function Invoke-SocWindowsBundle([string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
    [string]$InterfaceGuid, [switch]$AllowUnavailableRevocation, [switch]$Repair, [switch]$DryRun, [switch]$ResumeRepair,
    [scriptblock]$EnrollmentStart, [scriptblock]$EnrollmentReceipt, [scriptblock]$EnrollmentAbort, [switch]$HostOnly) {
    if ($HostOnly -and ($Repair -or $ResumeRepair -or -not $EnrollmentStart)) { throw 'HostOnly is for a fresh log-only enrollment.' }
    if ($EnrollmentStart -and ($Repair -or $ResumeRepair -or -not $EnrollmentReceipt -or -not $EnrollmentAbort)) { throw 'Enrollment requires a fresh complete bundle and receipt/abort callbacks.' }
    if ($ResumeRepair -and -not $Repair) { throw 'Use -Repair -ResumeRepair together for verified interrupted recovery.' }
    if ($Repair) {
        Invoke-SocBundleRepair -Source $Source -Endpoint $Endpoint -CaPath $CaPath -Organization $Organization `
            -InterfaceGuid $InterfaceGuid -AllowUnavailableRevocation:$AllowUnavailableRevocation -DryRun:$DryRun -ResumeRepair:$ResumeRepair
        return
    }
    $common = @{Endpoint=$Endpoint;CaPath=$CaPath;Organization=$Organization;AllowUnavailableRevocation=$AllowUnavailableRevocation}
    $hostInstaller = Join-Path $Source 'install-windows.ps1'
    $networkInstaller = Join-Path $Source 'install-network-windows.ps1'
    if ($DryRun) {
        & $hostInstaller @common -DryRun
        if ($LASTEXITCODE -ne 0) { throw 'Host preview failed.' }
        if (-not $HostOnly) {
            & $networkInstaller @common -InterfaceGuid $InterfaceGuid -DryRun
            if ($LASTEXITCODE -ne 0) { throw 'Network preview failed.' }
        }
        return
    }
    Assert-SocAdministrator
    $mutex = New-Object Threading.Mutex($false, 'Global\Cloud-SOC-Bundle-Install')
    $held = $false
    $transaction = $null
    $pending = Join-Path $env:ProgramData 'Cloud-SOC\bundle-pending.json'
    $state = @{ Started=$false; TaskCreated=$false; TaskRegistrationAttempted=$false; TaskXml=$null; CleanupSafe=$true; Enrollment=$null }
    $members = @(Get-SocBundleMembers -HostOnly:$HostOnly)
    try {
        try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held=$true; throw 'Interrupted bundle detected. State retained; automatic adoption is not supported.' }
        if (-not $held) { throw 'Another bundle installation is active.' }
        Assert-SocLocalPath $pending
        if (Test-Path -LiteralPath $pending) { throw 'A protected bundle receipt requires recovery. No automatic replacement, deletion or collector startup.' }
        # Check both sides before downloading, requesting keys, or running permanent services.
        & $hostInstaller @common -PreflightOnly
        if ($LASTEXITCODE -ne 0) { throw 'Host preflight failed; no bundle committed.' }
        if (-not $HostOnly) {
            if (-not $InterfaceGuid) { $InterfaceGuid = Select-SocInterface }
            & $networkInstaller @common -InterfaceGuid $InterfaceGuid -PreflightOnly
            if ($LASTEXITCODE -ne 0) { throw 'Network preflight failed; no bundle committed.' }
        }
        $transaction = New-SocStage
        $reservation = [IO.File]::Open($pending, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($transaction.Token)
            $reservation.Write($bytes, 0, $bytes.Length)
            $reservation.Flush($true)
        } finally { $reservation.Dispose() }
        foreach ($member in $members) { $member.Receipt = Join-Path $transaction.Path ($member.Kind + '-prepared.json') }
        Save-SocBundleJournal $transaction 'preparing' $false
        $prepare = {
            if ($EnrollmentStart) { $state.Enrollment = & $EnrollmentStart }
            $hostOptions = @{}; $networkOptions = @{}
            if ($state.Enrollment) {
                $hostOptions=@{HostApiKey=$state.Enrollment.host;InstallationProbe=$state.Enrollment.Probe}
                if (-not $HostOnly) { $networkOptions=@{NetworkApiKey=$state.Enrollment.network;InstallationProbe=$state.Enrollment.Probe} }
            }
            & $hostInstaller @common @hostOptions -PrepareOnly -PreparedReceipt $members[0].Receipt
            if ($LASTEXITCODE -ne 0) { throw 'Host preparation failed.' }
            $members[0].Prepared = Read-SocPreparedReceipt $members[0].Receipt 'host'
            if (-not $HostOnly) {
                & $networkInstaller @common @networkOptions -InterfaceGuid $InterfaceGuid -PrepareOnly -PreparedReceipt $members[1].Receipt
                if ($LASTEXITCODE -ne 0) { throw 'Network preparation failed.' }
                $members[1].Prepared = Read-SocPreparedReceipt $members[1].Receipt 'network'
            }
            Save-SocBundleJournal $transaction 'prepared' $false
        }
        $commit = {
            foreach ($member in $members) {
                if (Get-Service -Name $member.Service -ErrorAction SilentlyContinue) { throw 'Collector service appeared during preparation.' }
                Move-SocBundleMember $member
            }
            # Both final configurations pass before any service is created or started.
            foreach ($member in $members) { Test-SocBundleMember $member.Root $member.Beat }
            Save-SocBundleRecoveryIdentity $transaction $members
            if (Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -ErrorAction SilentlyContinue) { throw 'Discovery task appeared during preparation.' }
            foreach ($member in $members) {
                $args = @{Name=$member.Service;DisplayName=('Cloud SOC ' + $member.Beat);BinaryPathName=(Get-SocBundleCommand $member.Root $member.Beat);StartupType='Manual'}
                if ($member.Kind -eq 'network') { $args.DependsOn='npcap' }
                $member.Created=$true
                New-Service @args | Out-Null
            }
            $action = New-SocNativeDiscoveryAction $members[0].Root
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable
            # No repeating trigger until both services survive startup.
            $state.TaskRegistrationAttempted=$true
            Register-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -Action $action -Principal $principal -Settings $settings | Out-Null
            $state.TaskCreated=$true
            $state.TaskXml=Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery'
            $previousRun = (Get-ScheduledTaskInfo -TaskName 'Cloud-SOC-Discovery').LastRunTime
            $started = (Get-Date).AddSeconds(-1)
            Start-ScheduledTask -TaskName 'Cloud-SOC-Discovery'
            Wait-SocTask -Name 'Cloud-SOC-Discovery' -Started $started -PreviousRun $previousRun
            Assert-SocBundleFreshReport $members[0].Root $started
            Save-SocBundleJournal $transaction 'starting' $true
            $state.Started=$true
            foreach ($member in $members) {
                Assert-SocBundleService $member
                Start-Service -Name $member.Service
                (Get-Service -Name $member.Service).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            }
            Start-Sleep -Seconds 3
            foreach ($member in $members) {
                if ((Get-Service -Name $member.Service).Status -ne 'Running') { throw 'A bundle collector stopped after startup.' }
                Assert-SocBundleService $member
                Set-SocServiceStartup $member.Service
            }
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
            Assert-SocBundleTask $state.TaskXml
            Set-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -Trigger $trigger | Out-Null
            $state.TaskXml=Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery'
            if ($EnrollmentReceipt) { & $EnrollmentReceipt $members }
            $phase = if ($EnrollmentReceipt) { 'committed_receipt_verified' } else { 'committed_receipt_unverified' }
            Save-SocBundleJournal $transaction $phase $true
            if ([IO.File]::ReadAllText($pending) -cne $transaction.Token) { throw 'Bundle reservation changed.' }
            Remove-Item -LiteralPath $pending
            if ($EnrollmentReceipt) { Write-Host 'Cloud SOC installation completed. Required collectors active and central receipt verified.' }
            else { Write-Host 'Both collectors active. Local SYSTEM/config/auth checks passed; central document receipt is NOT yet verified.' }
        }
        $rollback = {
            foreach ($member in $members) {
                if (-not $member.Prepared -and (Test-Path -LiteralPath $member.Receipt)) { $state.CleanupSafe=$false }
            }
            if ($state.TaskRegistrationAttempted -and -not $state.TaskCreated -and
                (Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -ErrorAction SilentlyContinue)) { $state.CleanupSafe=$false }
            if ($state.TaskCreated) {
                try {
                    Assert-SocBundleTask $state.TaskXml
                    Stop-ScheduledTask -TaskName 'Cloud-SOC-Discovery'
                    if ((Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery').State -in @('Running','Queued')) { throw 'Bundle task is still active.' }
                    Unregister-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -Confirm:$false
                } catch { $state.CleanupSafe=$false }
            }
            foreach ($member in $members) {
                if ($member.Created) {
                    try {
                        if (-not (Get-Service -Name $member.Service -ErrorAction SilentlyContinue)) { continue }
                        Assert-SocBundleService $member
                        Stop-Service -Name $member.Service -ErrorAction Stop
                        (Get-Service -Name $member.Service).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
                        Set-Service -Name $member.Service -StartupType Disabled
                        if (-not $state.Started) {
                            Remove-SocBundleService $member
                        }
                    } catch { $state.CleanupSafe=$false }
                }
            }
            if (-not $state.Started -and $state.CleanupSafe) {
                foreach ($member in $members) {
                    if ($member.Prepared) {
                        $path = if ($member.Promoted) { $member.Root } else { $member.Prepared.path }
                        Remove-SocOwnedDirectory $path $path $member.Prepared.token
                    }
                }
                Save-SocBundleJournal $transaction 'rolled_back' $false
                if ([IO.File]::ReadAllText($pending) -cne $transaction.Token) { throw 'Bundle reservation changed; receipt retained.' }
                Remove-Item -LiteralPath $pending
                Remove-SocOwnedDirectory $transaction.Path $transaction.Path $transaction.Token
            } else {
                Save-SocBundleJournal $transaction 'retained_recovery_required' $state.Started
                Write-Warning ('Bundle state/keys/queues retained; no automatic retry or deletion. Protected receipt: ' + $transaction.Path)
            }
        }
        Invoke-SocBundleSequence $prepare $commit $rollback
    } catch {
        if ($EnrollmentAbort) { & $EnrollmentAbort }
        throw
    } finally {
        if ($state.Enrollment) {
            $state.Enrollment.host.Dispose()
            if (-not $HostOnly) { $state.Enrollment.network.Dispose() }
            $state.Enrollment=$null
        }
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
