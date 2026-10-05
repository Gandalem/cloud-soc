$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# A pwsh CI parent can expose Core modules to Windows PowerShell 5.1.
# Load this shell's own Security module without changing host policy.
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Force
. (Join-Path $PSScriptRoot '../enrollment-windows.ps1')
$root = Join-Path ([IO.Path]::GetTempPath()) ('cloud-soc-enrollment-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$script:Calls = New-Object 'Collections.Generic.List[string]'
$script:Failure=$false
$script:Token=('1' * 32) + '.' + ('a' * 43)
function Read-Host { param($Prompt,[switch]$AsSecureString) $script:Calls.Add('prompt'); return ConvertTo-SecureString $script:Token -AsPlainText -Force }
function Invoke-SocEnrollmentRequest { param($Context,$Action,$Data)
    $script:Calls.Add($Action)
    if ($Action -eq 'enroll') {
        if ($Data.attempt -cnotmatch '^[A-Za-z0-9_-]{43}$') { throw 'Missing random attempt.' }
        return @{id=('1' * 32);endpoint='https://receiver.invalid:9200';organization='synthetic';probe=('b' * 64);receipt_verified=$false;
            keys=@(@{scope='host';key='synthetic:host'},@{scope='network';key='synthetic:network'})}
    }
    return @{}
}
function Confirm-SocEnrollmentReceipt { param($Context,$Members) $script:Calls.Add('receipt'); if ($script:Failure) { throw 'Injected missing receipt' }; $Context.Verified=$true }
function Invoke-SocWindowsBundle { param($Source,$Endpoint,$CaPath,$Organization,$InterfaceGuid,[switch]$AllowUnavailableRevocation,[switch]$DryRun,$EnrollmentStart,$EnrollmentReceipt,$EnrollmentAbort)
    if ($DryRun) { $script:Calls.Add('preview'); return }
    try {
        $keys = & $EnrollmentStart
        if ($keys.host -isnot [Security.SecureString] -or $keys.network -isnot [Security.SecureString]) { throw 'Keys were not secure in-process parameters.' }
        & $EnrollmentReceipt @(@{Kind='host'},@{Kind='network'})
    } catch { & $EnrollmentAbort; throw }
    finally { if ($keys) { $keys.host.Dispose(); $keys.network.Dispose() } }
}
try {
    @{os='windows';network=$true;enrollment_protocol=1;package_id=('2' * 32);portal_url='https://portal.invalid';endpoint='https://receiver.invalid:9200';organization='synthetic'} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'package.json')
    $args=@{Source=$root;Endpoint='https://receiver.invalid:9200';CaPath='C:\synthetic\ca.crt';Organization='synthetic';PackageSha256=('c' * 64)}
    Invoke-SocEnrollmentInstall @args -DryRun
    if (($script:Calls -join ',') -ne 'preview') { throw 'Preview prompted/networked.' }
    $script:Calls.Clear()
    Invoke-SocEnrollmentInstall @args
    if (($script:Calls -join ',') -ne 'prompt,enroll,receipt') { throw ('Unexpected enrollment order: ' + ($script:Calls -join ',')) }
    $script:Calls.Clear(); $script:Failure=$true
    try { Invoke-SocEnrollmentInstall @args; throw 'Missing rejection.' }
    catch { if ($_.Exception.Message -ne 'Injected missing receipt') { throw } }
    if (($script:Calls -join ',') -ne 'prompt,enroll,receipt,abort') { throw 'Failure did not revoke enrollment.' }
    Write-Host 'Enrollment hidden token, closure, secure keys, preview and failed-receipt abort: passed.'
} finally {
    if ((Split-Path -Leaf $root) -cnotmatch '^cloud-soc-enrollment-test-[a-f0-9]{32}$') { throw 'Unsafe test cleanup.' }
    Remove-Item -LiteralPath $root -Recurse -Force
}
