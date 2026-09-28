# Build reviewed source using the Windows .NET Framework toolchain, not a script host.
function Build-SocNativeDiscovery([string]$Root, [string]$Source) {
    Assert-SocLocalPath $Root
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Windows .NET Framework 4.x compiler is unavailable. No runtime or policy was installed/changed.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $compiler
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(,|$)') { throw 'Windows compiler signature verification failed; no alternative compiler was downloaded.' }
    $sourceFile = Join-Path $Source 'discovery-native.cs'
    Assert-SocLocalPath $sourceFile
    $originalHash = (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash
    $build = Join-Path $Root ('.discovery-build-' + [guid]::NewGuid().ToString('N'))
    New-SocProtectedDirectory $build
    try {
        $copy = Join-Path $build 'discovery-native.cs'
        Copy-Item -LiteralPath $sourceFile -Destination $copy -ErrorAction Stop
        if ((Get-FileHash -LiteralPath $copy).Hash -cne $originalHash) { throw 'Discovery source copy verification failed.' }
        $binary = Join-Path $build 'cloud-soc-discovery.exe'
        $framework = Split-Path -Parent $compiler
        $PSNativeCommandUseErrorActionPreference = $false
        & $compiler /noconfig /nologo /target:exe /platform:x64 /optimize+ "/reference:$framework\System.dll" "/reference:$framework\System.Core.dll" "/reference:$framework\System.Web.Extensions.dll" "/out:$binary" $copy
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Native Discovery build failed. No execution-policy change or script fallback was attempted.' }
        foreach ($name in @('discovery-native.cs','cloud-soc-discovery.exe','discovery-native.json')) { Assert-SocLocalPath (Join-Path $Root $name) }
        Copy-Item -LiteralPath $copy -Destination (Join-Path $Root 'discovery-native.cs') -Force -ErrorAction Stop
        Copy-Item -LiteralPath $binary -Destination (Join-Path $Root 'cloud-soc-discovery.exe') -Force -ErrorAction Stop
        @{ schema=1; worker='native-v1'; source_sha256=$originalHash; exe_sha256=(Get-FileHash -LiteralPath $binary).Hash } |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'discovery-native.json') -Encoding UTF8
        Assert-SocNativeDiscovery $Root
    } finally {
        # Exact generated directory only; reject links before any recursive removal.
        Assert-SocLocalPath $build
        if ([IO.Path]::GetDirectoryName($build) -ine $Root -or [IO.Path]::GetFileName($build) -notmatch '^\.discovery-build-[a-f0-9]{32}$') { throw 'Unsafe native build cleanup path.' }
        foreach ($item in Get-ChildItem -LiteralPath $build -Force) {
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unexpected native build output; retained for review.' }
        }
        Remove-Item -LiteralPath $build -Recurse -Force -ErrorAction Stop
    }
}

function Assert-SocNativeDiscovery([string]$Root) {
    foreach ($name in @('discovery-native.json','discovery-native.cs','cloud-soc-discovery.exe')) { Assert-SocLocalPath (Join-Path $Root $name) }
    $manifest = Get-Content -LiteralPath (Join-Path $Root 'discovery-native.json') -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($manifest.schema -ne 1 -or $manifest.worker -ne 'native-v1' -or
        $manifest.source_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $Root 'discovery-native.cs')).Hash -or
        $manifest.exe_sha256 -cne (Get-FileHash -LiteralPath (Join-Path $Root 'cloud-soc-discovery.exe')).Hash) { throw 'Native Discovery integrity verification failed.' }
}

function New-SocNativeDiscoveryAction([string]$Root) {
    Assert-SocNativeDiscovery $Root
    New-ScheduledTaskAction -Execute (Join-Path $Root 'cloud-soc-discovery.exe') -Argument ('--root "{0}"' -f $Root) -WorkingDirectory $Root
}

function Invoke-SocNativeRefresh([string]$Root) {
    Assert-SocNativeDiscovery $Root
    & (Join-Path $Root 'cloud-soc-discovery.exe') --root $Root
    if ($LASTEXITCODE -ne 0) { throw 'Native Discovery refresh failed; inspect protected discovery-diagnostic.json. No script fallback was used.' }
}

function Write-SocDiscoveryFailureSummary([string]$Root, [datetime]$Since) {
    try {
        $path = Join-Path $Root 'discovery-diagnostic.json'
        Assert-SocLocalPath $path
        if (-not (Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).Length -gt 8192) { return }
        $value = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $timestamp = if ($value.generated_at -is [datetime]) { $value.generated_at.ToUniversalTime() } else { [DateTimeOffset]::Parse([string]$value.generated_at).UtcDateTime }
        if ($value.worker -ne 'native-v1' -or $value.status -ne 'error' -or $timestamp -lt $Since.ToUniversalTime() -or
            $value.stage -notin @('arguments','channels','lock','settings','files','publish') -or $value.error_type -notmatch '^[A-Za-z]{1,80}$') { return }
        Write-Warning ('Discovery diagnostic: stage={0}; error={1}; HRESULT={2}. No log contents or credentials are included.' -f $value.stage, $value.error_type, [int]$value.hresult)
    } catch { Write-Warning 'Discovery diagnostic unavailable; original installation error is unchanged.' }
}
