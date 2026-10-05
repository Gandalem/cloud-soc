$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Match install.ps1: helpers are dot-sourced in a launcher scope, not globally.
& {
. (Join-Path $PSScriptRoot '../enrollment-windows.ps1')
$realReceipt = (Get-Command Confirm-SocEnrollmentReceipt).ScriptBlock
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
        return @{id=('1' * 32);endpoint='https://receiver.invalid:9200';organization='synthetic';probe=('b' * 64);receipt_verified=$false;recovery_probe=$Context.RecoveryProbe;
            keys=@(@{scope='host';key='synthetic:host'}) + $(if ($Context.Network) { @(@{scope='network';key='synthetic:network'}) } else { @() })}
    }
    if ($Action -eq 'receipt') { return @{verified=$true;state='complete';id=$Context.SessionId} }
    return @{}
}
function Confirm-SocEnrollmentReceipt { param($Context,$Members) $script:Calls.Add('receipt'); if ($script:Failure) { throw 'Injected missing receipt' }; $Context.Verified=$true }
$script:Started=$false
function Get-SocReEnrollmentPlan { param($Context) $script:Calls.Add('plan'); return @{Started=$script:Started;Probe=('d' * 64)} }
function Test-SocServerTls { param($Endpoint,$CaPath,[switch]$AllowUnavailableRevocation) $script:Calls.Add('tls') }
function Move-SocFailedPreparation { param($Plan) $script:Calls.Add('archive') }
function Invoke-SocStartedReEnrollment { param($Plan,$Context,$Keys)
    if ($Keys.host -isnot [Security.SecureString]) { throw 'Re-enrollment replacement key was not secure.' }
    $script:Calls.Add('started-recovery'); Confirm-SocEnrollmentReceipt $Context @()
}
function Invoke-SocWindowsBundle { param($Source,$Endpoint,$CaPath,$Organization,$InterfaceGuid,[switch]$AllowUnavailableRevocation,[switch]$DryRun,$EnrollmentStart,$EnrollmentReceipt,$EnrollmentAbort,[switch]$HostOnly)
    if ($DryRun) { $script:Calls.Add('preview'); return }
    try {
        $keys = & $EnrollmentStart
        if ($keys.host -isnot [Security.SecureString] -or (-not $HostOnly -and $keys.network -isnot [Security.SecureString])) { throw 'Keys were not secure in-process parameters.' }
        if ($HostOnly -and $keys.ContainsKey('network')) { throw 'Host-only minted a network key.' }
        & $EnrollmentReceipt @(@{Kind='host'})
    } catch { & $EnrollmentAbort; throw }
    finally { if ($keys) { $keys.host.Dispose(); if ($keys.ContainsKey('network')) { $keys.network.Dispose() } } }
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
    $script:Calls.Clear(); $script:Failure=$false
    $spec=Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw | ConvertFrom-Json
    $spec.network=$false
    $spec | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'package.json')
    Invoke-SocEnrollmentInstall @args
    if (($script:Calls -join ',') -ne 'prompt,enroll,receipt') { throw 'Host-only enrollment failed.' }
    $script:Calls.Clear()
    Invoke-SocEnrollmentInstall @args -ReEnroll -DryRun
    if (($script:Calls -join ',') -ne 'plan') { throw 'Re-enrollment preview changed state/prompted/networked.' }
    $script:Calls.Clear()
    Invoke-SocEnrollmentInstall @args -ReEnroll
    if (($script:Calls -join ',') -ne 'plan,tls,prompt,enroll,archive,receipt') { throw 'Failed preparation reissued twice or skipped its archive.' }
    $script:Calls.Clear(); $script:Started=$true
    Invoke-SocEnrollmentInstall @args -ReEnroll
    if (($script:Calls -join ',') -ne 'plan,tls,prompt,enroll,started-recovery,receipt') { throw 'Started recovery entered fresh install.' }
    # Run the real probe writer twice through a loopback socket and mocked OS/API
    # boundaries. A new nonce must be inside Filebeat's first 1024 fingerprint bytes.
    function Assert-SocLocalPath { param($Path) }
    function Assert-SocBundleService { param($Member) }
    function Get-Service { param($Name) return [pscustomobject]@{Status='Running'} }
    $probeRoot=Join-Path $root 'probe'
    New-Item -ItemType Directory -Path (Join-Path $probeRoot 'inputs'),(Join-Path $probeRoot 'data') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $probeRoot 'data/meta.json'),'{"uuid":"00000000-0000-0000-0000-000000000001"}')
    $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
    $listener.Start()
    try {
        $probeContext=@{Endpoint=('https://127.0.0.1:'+$listener.LocalEndpoint.Port);Probe=('b'*64);PackageId=('2'*32);SessionId=('1'*32);Attempt=('a'*43);Verified=$false}
        & $realReceipt $probeContext @(@{Kind='host';Root=$probeRoot;Service='synthetic-no-service'})
        $accepted=$listener.AcceptTcpClient();$accepted.Dispose()
        $first=[IO.File]::ReadAllBytes((Join-Path $probeRoot 'installation-probe.ndjson'))
        [IO.File]::Move((Join-Path $probeRoot 'installation-probe.ndjson'),(Join-Path $probeRoot 'first-event.ndjson'))
        [IO.File]::Move((Join-Path $probeRoot 'inputs/installation-probe.yml'),(Join-Path $probeRoot 'first-input.yml'))
        $probeContext.Probe=('d'*64);$probeContext.Verified=$false
        & $realReceipt $probeContext @(@{Kind='host';Root=$probeRoot;Service='synthetic-no-service'})
        $accepted=$listener.AcceptTcpClient();$accepted.Dispose()
        $second=[IO.File]::ReadAllBytes((Join-Path $probeRoot 'installation-probe.ndjson'))
        $hash=[Security.Cryptography.SHA256]::Create()
        try {
            if ([Convert]::ToBase64String($hash.ComputeHash($first,0,1024)) -ceq [Convert]::ToBase64String($hash.ComputeHash($second,0,1024)) -or
                -not [Text.Encoding]::UTF8.GetString($second,0,1024).Contains(('d'*64)) -or -not $probeContext.Verified) { throw 'Re-enrollment probe fingerprint did not change.' }
        } finally {$hash.Dispose()}
    } finally {$listener.Stop()}
    Write-Host 'Enrollment hidden token, closure, secure keys, preview and failed-receipt abort: passed.'
} finally {
    if ((Split-Path -Leaf $root) -cnotmatch '^cloud-soc-enrollment-test-[a-f0-9]{32}$') { throw 'Unsafe test cleanup.' }
    Remove-Item -LiteralPath $root -Recurse -Force
}
}
