# Administrator opt-in; no collector settings, services, keys or policy changes.
#requires -Version 5.1
param(
    [string]$Root = (Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'),
    [switch]$ApproveRetention,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'transaction-windows.ps1')
Assert-SocAdministrator
Assert-SocLocalPath $Root
New-SocProtectedDirectory $Root -Reuse
Assert-SocNativeDiscovery $Root
foreach ($marker in @('recovery-pending.json','discovery-update-pending.json','probe-active.txt')) {
    if (Test-Path -LiteralPath (Join-Path $Root $marker)) { throw 'An installation/update/probe is pending; evidence activation refused.' }
}
$source = [IO.File]::ReadAllText((Join-Path $Root 'discovery-native.cs'))
if ($source -notmatch 'internal static class RejectionEvidence') { throw 'Update Discovery from a verified new package first; no files were changed.' }
$target = Join-Path $Root 'rejection-evidence'
Assert-SocLocalPath $target
if (Test-Path -LiteralPath $target) { throw 'Evidence store already exists; not replaced. Preserve its fingerprint key and manifest.' }
if ($DryRun) {
    Write-Output 'DRY RUN: verified native installation. Proposed admin-only reference/HMAC retention: 7 days, 16 MiB, 2000 records. No writes or activation.'
    return
}
if (-not $ApproveRetention) { throw 'Explicit -ApproveRetention is required for 7 days / 16 MiB / 2000 references. Raw event bodies are not stored.' }
$lockPath = Join-Path $Root 'discovery.lock'
Assert-SocLocalPath $lockPath
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw 'Existing Discovery lock is missing; no files were changed.' }
$held = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
$stage = Join-Path $Root ('.evidence-stage-' + [guid]::NewGuid().ToString('N'))
try {
    New-SocProtectedDirectory $stage
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        $keyStream = [IO.File]::Open((Join-Path $stage 'fingerprint.key'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $keyStream.Write($bytes,0,$bytes.Length); $keyStream.Flush($true) }
        finally { $keyStream.Dispose() }
    }
    finally { $rng.Dispose(); [Array]::Clear($bytes, 0, $bytes.Length) }
    $policy = '{"schema":1,"days":7,"max_bytes":16777216,"max_records":2000,"approved":true}'
    [IO.File]::WriteAllText((Join-Path $stage 'policy.json'), $policy, (New-Object Text.UTF8Encoding($false)))
    New-SocProtectedDirectory $stage -Reuse
    # Rename only our new directory; partial preparation is never enabled.
    [IO.Directory]::Move($stage, $target)
    Write-Output 'Evidence preservation enabled for the next Discovery run. Actual rejection capture and server reference comparison are NOT verified.'
} finally {
    $held.Dispose()
    # On failure retain the protected stage for inspection; never remove unknown files.
}
