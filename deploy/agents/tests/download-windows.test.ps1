$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../download-windows.ps1')

function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        return
    }
    throw "Expected failure: $Pattern"
}
function Get-SystemCurl { return 'Mock-Curl' }
function Test-Path { param($LiteralPath) return $script:Existing }
function Start-Sleep { param($Seconds) $script:Sleeps += $Seconds }
function Mock-Curl {
    $script:Calls += ,@($args)
    if ($PSNativeCommandUseErrorActionPreference) { throw 'Native exit handling was not isolated.' }
    $global:LASTEXITCODE = $script:Codes[$script:Calls.Count - 1]
    return $script:Status
}
function Reset-Mock([int[]]$ExitCodes = @(0)) {
    $script:Calls = @()
    $script:Sleeps = @()
    $script:Codes = $ExitCodes
    $script:Existing = $false
    $script:Status = '200'
}
$uri = 'https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.5.2-windows-x86_64.zip'
$output = 'C:\synthetic folder\archive.zip'
$PSNativeCommandUseErrorActionPreference = $true
Reset-Mock
Receive-CloudSocArchive $uri $output
if (-not $PSNativeCommandUseErrorActionPreference) { throw 'Caller preference was changed.' }
$called = $Calls[0]
if ($called[0] -ne '--disable' -or $called[-1] -ne $uri) { throw 'curl defaults or URL handling is unsafe.' }
foreach ($pair in @(@('--proto', '=https'), @('--retry', '0'), @('--connect-timeout', '30'),
                    @('--max-time', '300'), @('--speed-limit', '16384'), @('--speed-time', '60'),
                    @('--max-redirs', '0'), @('--output', $output))) {
    $index = [Array]::IndexOf($called, $pair[0])
    if ($index -lt 0 -or $called[$index + 1] -ne $pair[1]) { throw "Missing argument: $($pair[0])" }
}
if ($called -contains '--insecure' -or $called -contains '--location' -or $called -contains '--continue-at') { throw 'Unsafe curl option.' }
if ($called -notcontains '--tlsv1.2' -or $called -notcontains '--fail') { throw 'Missing TLS or HTTP guard.' }

Reset-Mock @(28, 0)
Receive-CloudSocArchive $uri $output
if ($Calls.Count -ne 2 -or $Sleeps.Count -ne 1 -or $Sleeps[0] -ne 3) { throw 'Retry must be bounded.' }
foreach ($code in @(6, 7, 18, 28, 52, 55, 56)) {
    Reset-Mock @($code, $code)
    Assert-Throws { Receive-CloudSocArchive $uri $output } "curl exit $code"
    if ($Calls.Count -ne 2) { throw 'Transient failure was not limited to two attempts.' }
}
foreach ($code in @(2, 22, 23, 60)) {
    Reset-Mock @($code)
    Assert-Throws { Receive-CloudSocArchive $uri $output } "curl exit $code"
    if ($Calls.Count -ne 1) { throw 'Permanent failure was retried.' }
}
foreach ($httpCase in @('301', '302', '206')) {
    Reset-Mock
    $script:Status = $httpCase
    Assert-Throws { Receive-CloudSocArchive $uri $output } 'HTTP 200'
}
Reset-Mock
$script:Existing = $true
Assert-Throws { Receive-CloudSocArchive $uri $output } 'already exists'
if ($Calls.Count) { throw 'Existing file reached download.' }
Reset-Mock
Assert-Throws { Receive-CloudSocArchive 'http://attacker.invalid/a.zip' $output } 'Only pinned'
if ($Calls.Count) { throw 'Untrusted URL reached download.' }
Write-Output 'Download argument, bounded retry, HTTP/TLS failure and existing-file tests passed. No network or files modified.'
