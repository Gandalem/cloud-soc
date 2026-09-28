# Real compilation/integrity tests in workspace fixtures. No admin tasks or services.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Force
}
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
$root = Join-Path ((Resolve-Path (Join-Path $PSScriptRoot '../../../state')).ProviderPath) ('native-build-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
function New-SocProtectedDirectory { param($Path,[switch]$Reuse) New-Item -ItemType Directory -Path $Path | Out-Null }
try {
    Build-SocNativeDiscovery -Root $root -Source (Split-Path -Parent $PSScriptRoot)
    Assert-SocNativeDiscovery $root
    $manifest = Get-Content -LiteralPath (Join-Path $root 'discovery-native.json') -Raw | ConvertFrom-Json
    if ($manifest.worker -ne 'native-v1') { throw 'Wrong worker manifest' }
    if (@(Get-ChildItem -LiteralPath $root -Directory).Count) { throw 'Build scratch directory left behind' }
    [IO.File]::AppendAllText((Join-Path $root 'cloud-soc-discovery.exe'), 'tamper')
    $rejected = $false
    try { Assert-SocNativeDiscovery $root } catch { if ($_.Exception.Message -notmatch 'integrity') { throw }; $rejected=$true }
    if (-not $rejected) { throw 'Modified executable accepted' }
    function Get-AuthenticodeSignature { param($LiteralPath) [pscustomobject]@{ Status='NotSigned'; SignerCertificate=$null } }
    $rejected=$false
    try { Build-SocNativeDiscovery -Root $root -Source (Split-Path -Parent $PSScriptRoot) } catch { if ($_.Exception.Message -notmatch 'signature') { throw }; $rejected=$true }
    if (-not $rejected) { throw 'Untrusted compiler accepted' }
    Write-Output 'Native build, compiler trust, manifest, tamper rejection and exact scratch cleanup passed.'
} finally {
    $parent = (Resolve-Path (Join-Path $PSScriptRoot '../../../state')).ProviderPath
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($root)) -ine $parent -or [IO.Path]::GetFileName($root) -notmatch '^native-build-test-[a-f0-9]{32}$') { throw 'Unsafe test cleanup path' }
    Assert-SocLocalPath $root
    Remove-Item -LiteralPath $root -Recurse -Force
}
