# Synthetic functions only. Never register tasks, start services, or capture packets.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; return }
    throw "Expected failure: $Pattern"
}
$root = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$token = [guid]::NewGuid().ToString('N')
try {
    [IO.File]::WriteAllText((Join-Path $root 'install-owner.txt'), $token)
    Assert-Throws { Remove-SocOwnedDirectory $root ($root + '-other') $token } 'mismatch'
    Assert-Throws { Remove-SocOwnedDirectory $root $root ('0' * 32) } 'ownership'
    [IO.File]::WriteAllText((Join-Path $root 'probe-active.txt'), 'synthetic')
    Assert-Throws { Remove-SocOwnedDirectory $root $root $token } 'Probe cleanup'
    Remove-Item -LiteralPath (Join-Path $root 'probe-active.txt')
    Assert-Throws { Assert-SocLocalPath 'C:\test\..\other' } 'Unsafe'
    Assert-Throws { Assert-SocLocalPath '\\server\share' } 'Unsafe'
    function Get-ChildItem { param($LiteralPath, [switch]$Force) return [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint } }
    Assert-Throws { Remove-SocOwnedDirectory $root $root $token } 'linked child'
    Remove-Item Function:\Get-ChildItem
    function Get-SystemCurl { return 'Mock-Curl' }
    function Mock-Curl {
        $script:CurlArguments = @($args)
        $global:LASTEXITCODE = 0
        return '401'
    }
    Test-SocServerTls 'https://soc.example.invalid:9200' 'C:\synthetic\ca.crt'
    if ($CurlArguments[0] -ne '--disable' -or '--cacert' -notin $CurlArguments -or '--max-time' -notin $CurlArguments -or '-k' -in $CurlArguments) { throw 'TLS validation weakened' }
    function Mock-Curl { $global:LASTEXITCODE = 60; return '000' }
    Assert-Throws { Test-SocServerTls 'https://soc.example.invalid' 'C:\synthetic\ca.crt' } 'TLS/connectivity'

    $script:Calls = New-Object 'Collections.Generic.List[string]'
    function New-ScheduledTaskAction { param($Execute, $Argument, $WorkingDirectory)
        if ($Argument -match 'ExecutionPolicy|Bypass' -or $Argument -notmatch 'DiscoveryRoot') { throw 'Unsafe task arguments' }
        if ($WorkingDirectory -ne $root) { throw 'Missing working directory' }
        return @{ Arguments = $Argument }
    }
    function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel)
        if ($UserId -ne 'SYSTEM' -or $LogonType -ne 'ServiceAccount') { throw 'Wrong identity' }; return @{}
    }
    function New-ScheduledTaskSettingsSet { param($ExecutionTimeLimit, $MultipleInstances) return @{} }
    function Register-ScheduledTask { param($TaskName, $Action, $Principal, $Settings) $script:Calls.Add('register'); $script:ProbeName = $TaskName }
    function Start-ScheduledTask { param($TaskName) $script:Calls.Add('start') }
    function Stop-ScheduledTask { param($TaskName, $ErrorAction) $script:Calls.Add('stop') }
    function Unregister-ScheduledTask { param($TaskName, $Confirm, $ErrorAction) $script:Calls.Add('unregister') }
    function Get-ScheduledTask { param($TaskName) return @{ State = 'Ready' } }
    function Start-Sleep { param($Seconds) }
    $script:ExitCode = 1
    function Get-ScheduledTaskInfo { param($TaskName) return @{ LastRunTime = Get-Date; LastTaskResult = $script:ExitCode } }
    Assert-Throws { Invoke-SocDiscoveryProbe $root } 'SYSTEM Discovery failed'
    if (($Calls -join ',') -ne 'register,start,stop,unregister') { throw 'Failure did not clean owned task' }
    if ($ProbeName -notmatch '^Cloud-SOC-Preflight-[a-f0-9]{32}$') { throw 'Task name not unique' }
    if (Test-Path -LiteralPath (Join-Path $root 'probe-active.txt')) { throw 'Probe marker not removed' }
    $script:ExitCode = 0
    $script:TaskPoll = 0
    function Get-ScheduledTask {
        param($TaskName)
        $script:TaskPoll++
        return @{ State = $(if ($script:TaskPoll -eq 1) { 'Queued' } else { 'Ready' }) }
    }
    Wait-SocTask -Name 'synthetic' -Started (Get-Date).AddSeconds(-1)
    if ($TaskPoll -lt 2) { throw 'Queued task was accepted as completed' }
    function Get-ScheduledTask { param($TaskName) return @{ State = 'Ready' } }
    function Get-ScheduledTaskInfo { param($TaskName) return @{ LastRunTime = [datetime]'2000-01-01'; LastTaskResult = 0 } }
    Assert-Throws { Wait-SocTask -Name 'synthetic' -Started (Get-Date) -TimeoutSeconds 0 } 'timed out'
    function Get-ScheduledTaskInfo { param($TaskName) return @{ LastRunTime = Get-Date; LastTaskResult = $script:ExitCode } }
    [IO.File]::WriteAllText((Join-Path $root 'discovery-report.json'), '{"generated_at":"2000-01-01T00:00:00Z"}')
    Assert-Throws { Invoke-SocDiscoveryProbe $root } 'fresh report'
    [IO.File]::WriteAllText((Join-Path $root 'discovery-report.json'), ('{"generated_at":"' + [DateTime]::UtcNow.ToString('o') + '"}'))
    Invoke-SocDiscoveryProbe $root
    function Stop-ScheduledTask { param($TaskName, $ErrorAction) throw 'Synthetic stop failure' }
    Assert-Throws { Invoke-SocDiscoveryProbe $root } 'stop failure'
    Assert-Throws { Remove-SocOwnedDirectory $root $root $token } 'Probe cleanup'
    # No real task was created. Removing this fixture marker is safe.
    Remove-Item -LiteralPath (Join-Path $root 'probe-active.txt')

    function Get-NetRoute { param($DestinationPrefix, $ErrorAction) return @{ InterfaceIndex = 5 } }
    function Get-NetAdapter { param([switch]$Physical)
        return @(@{ Status = 'Up'; ifIndex = 5; InterfaceGuid = '11111111-2222-3333-4444-555555555555'; InterfaceDescription = 'Synthetic physical NIC' },
                 @{ Status = 'Up'; ifIndex = 9; InterfaceGuid = '22222222-2222-3333-4444-555555555555'; InterfaceDescription = 'No default route' })
    }
    function Get-NetIPAddress { param($InterfaceIndex, $AddressFamily, $ErrorAction) return [pscustomobject]@{ IPAddress = '192.0.2.10' } }
    function Read-Host { param($Prompt) return 'yes' }
    if ((Select-SocInterface) -ne '11111111-2222-3333-4444-555555555555') { throw 'Wrong NIC selected' }
    function Read-Host { param($Prompt) return '' }
    Assert-Throws { Select-SocInterface } 'cancelled'
    function Get-NetAdapter { param([switch]$Physical) return @() }
    Assert-Throws { Select-SocInterface } 'No active'
    function Get-NetRoute { param($DestinationPrefix, $ErrorAction) return @() }
    Assert-Throws { Select-SocInterface } 'No active'

    Remove-SocOwnedDirectory $root $root $token
    if (Test-Path -LiteralPath $root) { throw 'Owned scratch was not removed' }
    Write-Output 'SYSTEM probe, ownership cleanup, cancelled NIC selection and failure preservation passed.'
} finally {
    # Only the exact fixture created above may be removed, and only through its owner check.
    if (Test-Path -LiteralPath $root) { Remove-SocOwnedDirectory $root $root $token }
}
