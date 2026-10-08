# Fully mocked host boundary: no downloads, credentials, tasks, services, NICs or capture.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Load before mocked host cmdlets and ProgramData can affect module auto-loading.
Import-Module Microsoft.PowerShell.Security -ErrorAction Stop
. (Join-Path $PSScriptRoot '../bundle-windows.ps1')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('cloud-soc-bundle-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$oldProgramData = $env:ProgramData
$env:ProgramData = $testRoot
function Step([string]$Name) {
    $global:Calls.Add($Name)
    if ($Name -ceq $global:Failure) { throw "Injected $Name" }
}
function Assert-SocAdministrator { Step 'admin' }
function Assert-SocLocalPath { param($Path) }
function Select-SocInterface { Step 'nic'; return '11111111-1111-1111-1111-111111111111' }
function New-SocStage {
    $token = [guid]::NewGuid().ToString('N')
    $path = Join-Path $testRoot ('Cloud-SOC\staging\' + $token)
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $path 'install-owner.txt'), $token)
    return @{Path=$path;Token=$token}
}
function Read-SocPreparedReceipt { param($Path,$Kind)
    Step ($Kind + '-receipt')
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
function Move-SocBundleMember { param($Member) Step ($Member.Kind + '-move'); $Member.Promoted=$true }
function Test-SocBundleMember { param($Root,$Beat) Step ($Beat + '-validate') }
function Assert-SocBundleService { param($Member) Step ($Member.Beat + '-ownership') }
function Remove-SocBundleService { param($Member) Step ($Member.Beat + '-delete'); $global:Services.Remove($Member.Service) }
function Remove-SocOwnedDirectory { param($Path,$ExpectedPath,$Token)
    Step 'remove-owned'
    # Simulated final roots must never be touched by this test harness.
    if ($Path.StartsWith($testRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        if ([IO.File]::ReadAllText((Join-Path $Path 'install-owner.txt')) -cne $Token) { throw 'Bad test ownership' }
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}
function Save-SocBundleJournal { param($Transaction,$Phase,$StartAttempted) Step ('journal-' + $Phase) }
function Save-SocBundleRecoveryIdentity { param($Transaction,$Members) Step 'recovery-identity' }
function Invoke-SocBundleRepair { param($Source,$Endpoint,$CaPath,$Organization,$InterfaceGuid,[switch]$AllowUnavailableRevocation,[switch]$DryRun,[switch]$ResumeRepair) Step 'repair-dispatch' }
function Get-Service { param($Name,$ErrorAction)
    if ($global:Services.ContainsKey($Name)) {
        $result = [pscustomobject]@{Status='Running'}
        $result | Add-Member ScriptMethod WaitForStatus { param($State,$Timeout) }
        return $result
    }
}
function New-Service { param($Name,$DisplayName,$BinaryPathName,$StartupType,$DependsOn)
    Step ($Name + '-create'); $global:Services[$Name]=$true
    Step ($Name + '-create-after')
}
function Start-Service { param($Name) Step ($Name + '-start') }
function Stop-Service { param($Name,$ErrorAction) Step ($Name + '-stop') }
function Set-Service { param($Name,$StartupType) Step ($Name + '-' + $StartupType) }
function Set-SocServiceStartup { param($Name,$StartMode='Auto',$DelayedAutoStart=$true) Step ($Name + '-Automatic') }
function Start-Sleep { param($Seconds) }
function Get-ScheduledTask { param($TaskName,$ErrorAction) if ($global:Task) { return @{State='Ready'} } }
function New-SocNativeDiscoveryAction { param($Root) return @{} }
function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel) return @{} }
function New-ScheduledTaskSettingsSet { param($MultipleInstances,$ExecutionTimeLimit,[switch]$StartWhenAvailable) return @{} }
function Register-ScheduledTask { param($TaskName,$Action,$Principal,$Settings) Step 'task-register'; $global:Task=$true; Step 'task-register-after' }
function Export-ScheduledTask { param($TaskName) return '<synthetic />' }
function Start-ScheduledTask { param($TaskName) Step 'task-start' }
function Get-ScheduledTaskInfo { param($TaskName) return @{LastRunTime=[datetime]'2000-01-01'} }
function Wait-SocTask { param($Name,$Started,$PreviousRun) Step 'task-wait' }
function Assert-SocBundleTask { param($OriginalXml) Step 'task-ownership' }
function Assert-SocBundleFreshReport { param($Root,$Started) Step 'task-report' }
function Stop-ScheduledTask { param($TaskName) Step 'task-stop' }
function Unregister-ScheduledTask { param($TaskName,$Confirm) Step 'task-delete'; $global:Task=$false }
function New-ScheduledTaskTrigger { param([switch]$Once,$At,$RepetitionInterval) return @{} }
function Set-ScheduledTask { param($TaskName,$Trigger) Step 'task-trigger' }
try {
    $stub = @'
param($Endpoint,$CaPath,$Organization,$InterfaceGuid,[switch]$AllowUnavailableRevocation,
    [switch]$PreflightOnly,[switch]$PrepareOnly,$PreparedReceipt,[switch]$DryRun,
    [Security.SecureString]$HostApiKey,[Security.SecureString]$NetworkApiKey,$InstallationProbe)
$kind = if ($PSCommandPath -like '*network*') { 'network' } else { 'host' }
$phase = if ($DryRun) { 'preview' } elseif ($PreflightOnly) { 'preflight' } else { 'prepare' }
Step ($kind + '-' + $phase)
if ($PrepareOnly) {
    $stage = New-SocStage
    @{path=$stage.Path;token=$stage.Token} | ConvertTo-Json | Set-Content -LiteralPath $PreparedReceipt
}
$global:LASTEXITCODE = 0
exit 0
'@
    foreach ($name in @('install-windows.ps1','install-network-windows.ps1')) {
        [IO.File]::WriteAllText((Join-Path $testRoot $name), $stub)
    }
    $canary = Join-Path $testRoot 'existing-queue-and-key.canary'
    [IO.File]::WriteAllText($canary,'existing-state-unchanged')
    foreach ($failure in @('', 'host-preflight','network-preflight','host-prepare','network-prepare',
        'host-move','network-move','filebeat-validate','packetbeat-validate','recovery-identity','cloud-soc-filebeat-create',
        'cloud-soc-packetbeat-create','cloud-soc-filebeat-create-after','cloud-soc-packetbeat-create-after','task-register','task-register-after','task-wait','task-report','cloud-soc-filebeat-start',
        'cloud-soc-packetbeat-start','cloud-soc-packetbeat-Automatic','task-trigger')) {
        $global:Calls = New-Object 'Collections.Generic.List[string]'
        $global:Failure = $failure
        $global:Services = @{}
        $global:Task = $false
        $failed = $false
        $pending = Join-Path $testRoot 'Cloud-SOC\bundle-pending.json'
        if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending }
        try {
            Invoke-SocWindowsBundle -Source $testRoot -Endpoint 'https://soc.example.invalid:9200' -CaPath 'C:\synthetic\ca.crt' -Organization 'synthetic'
        } catch { $failed=$true; if (-not $failure) { throw } }
        if ($failed -ne [bool]$failure) { throw "Wrong result for $failure" }
        $start = $Calls.IndexOf('cloud-soc-filebeat-start')
        if ($start -ge 0) {
            foreach ($step in @('host-prepare','network-prepare','filebeat-validate','packetbeat-validate','task-wait')) {
                if ($Calls.IndexOf($step) -lt 0 -or $Calls.IndexOf($step) -gt $start) { throw "Started before $step" }
            }
            if ($failed -and (($Calls -join ',') -match '(filebeat|packetbeat)-delete|remove-owned')) { throw 'Post-start data/service removed' }
            if ($failed -and -not (Test-Path -LiteralPath $pending)) { throw 'Post-start recovery receipt missing' }
        } elseif ($failed -and ($Calls -contains 'cloud-soc-packetbeat-start')) { throw 'Network started early' }
        if ([IO.File]::ReadAllText($canary) -cne 'existing-state-unchanged') { throw 'Existing state changed' }
        if ($failure -ceq 'task-register-after' -and (-not (Test-Path -LiteralPath $pending) -or $Calls -contains 'remove-owned')) {
            throw 'Ambiguous task registration allowed unsafe directory deletion'
        }
    }
    $global:Failure=''; $global:Calls.Clear()
    [IO.File]::WriteAllText($pending,'retained-interrupted-fixture')
    try { Invoke-SocWindowsBundle -Source $testRoot -Endpoint 'https://soc.example.invalid' -CaPath 'C:\synthetic\ca.crt' -Organization 'synthetic'; throw 'Missing block' }
    catch { if ($_.Exception.Message -notmatch 'receipt requires recovery') { throw } }
    if (($Calls -join ',') -match 'prepare|start|remove') { throw 'Interrupted state was adopted' }
    $global:Calls.Clear()
    Invoke-SocWindowsBundle -Source $testRoot -Endpoint 'https://soc.example.invalid' -CaPath 'C:\synthetic\ca.crt' -Organization 'synthetic' -Repair -DryRun
    if (($Calls -join ',') -cne 'repair-dispatch') { throw 'Repair preview entered the fresh-install flow' }
    foreach ($failure in @('','enrollment-start','network-prepare','enrollment-receipt')) {
        if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending }
        $global:Calls.Clear(); $global:Services=@{}; $global:Task=$false; $global:Failure=$failure
        $start = { Step 'enrollment-start'; return @{host=(ConvertTo-SecureString 'synthetic:host' -AsPlainText -Force);network=(ConvertTo-SecureString 'synthetic:network' -AsPlainText -Force);Probe=('a' * 64)} }
        $receipt = { param($Members) Step 'enrollment-receipt' }
        $abort = { Step 'enrollment-abort' }
        $failed=$false
        try {
            Invoke-SocWindowsBundle -Source $testRoot -Endpoint 'https://soc.example.invalid' -CaPath 'C:\synthetic\ca.crt' -Organization 'synthetic' `
                -EnrollmentStart $start -EnrollmentReceipt $receipt -EnrollmentAbort $abort
        } catch { $failed=$true; if (-not $failure) { throw } }
        if ($failed -ne [bool]$failure) { throw 'Wrong enrollment result.' }
        if ($Calls.IndexOf('enrollment-start') -lt $Calls.IndexOf('network-preflight')) { throw 'Token requested before both preflights.' }
        if ($failed -and -not ($Calls -contains 'enrollment-abort')) { throw 'Failed enrollment was not aborted.' }
        if (-not $failed -and (($Calls -contains 'enrollment-abort') -or -not ($Calls -contains 'journal-committed_receipt_verified'))) { throw 'Verified installation mishandled.' }
        if ($failure -eq 'enrollment-receipt' -and ((-not ($Calls -contains 'cloud-soc-filebeat-Disabled')) -or $Calls -contains 'remove-owned')) { throw 'Unverified started collectors were not safely retained/stopped.' }
    }
    foreach ($failure in @('', 'enrollment-receipt')) {
        if (Test-Path -LiteralPath $pending) { Remove-Item -LiteralPath $pending }
        $global:Calls.Clear(); $global:Services=@{}; $global:Task=$false; $global:Failure=$failure
        $start = { Step 'enrollment-start'; return @{host=(ConvertTo-SecureString 'synthetic:host' -AsPlainText -Force);Probe=('a' * 64)} }
        $failed=$false
        try {
            Invoke-SocWindowsBundle -Source $testRoot -Endpoint 'https://soc.example.invalid' -CaPath 'C:\synthetic\ca.crt' -Organization 'synthetic' `
                -EnrollmentStart $start -EnrollmentReceipt $receipt -EnrollmentAbort $abort -HostOnly
        } catch { $failed=$true; if (-not $failure) { throw } }
        if ($failed -ne [bool]$failure -or ($Calls -join ',') -match 'network-|packetbeat|nic') { throw 'Log-only entered a network path or lost failure handling.' }
        if ($failed -and ($Calls -contains 'remove-owned' -or -not ($Calls -contains 'cloud-soc-filebeat-Disabled'))) { throw 'Log-only failed receipt did not retain stopped state.' }
    }
    Write-Host 'Bundle mocked phase ordering, failures, preservation and retry guards: passed.'
} finally {
    $env:ProgramData = $oldProgramData
    # Exact test-owned temporary root, never Program Files or real ProgramData.
    if ((Split-Path -Leaf $testRoot) -cnotmatch '^cloud-soc-bundle-test-[a-f0-9]{32}$') { throw 'Unsafe test cleanup' }
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
