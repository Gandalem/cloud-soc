# Synthetic protected SYSTEM test only; never installs agents or contacts a server.
#requires -Version 5.1
#requires -RunAsAdministrator
param([switch]$RunIsolatedTest, [Parameter(Mandatory=$true)][string]$ResultPath)
$ErrorActionPreference = 'Stop'
if (-not $RunIsolatedTest) { throw 'Explicit isolated test approval is required.' }
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
Assert-SocLocalPath $ResultPath
if (Test-Path -LiteralPath $ResultPath) { throw 'Result exists; not overwritten.' }
$stage = New-SocStage
$result = [ordered]@{ passed=$false; cleaned=$false; system_capture=$false; protected_acl=$false; key_unchanged=$false; input_unchanged=$false; disabled_default=$false; error=$null }
try {
    $root = Join-Path $stage.Path 'agent'
    foreach ($path in @($root,(Join-Path $root 'inputs'),(Join-Path $root 'logs'))) { New-SocProtectedDirectory $path }
    $settings = @{ log_roots=@((Join-Path $stage.Path 'missing-fixture-logs')); required_channels=@('Application') }
    [IO.File]::WriteAllText((Join-Path $root 'discovery-settings.json'),($settings | ConvertTo-Json))
    Build-SocNativeDiscovery -Root $root -Source (Split-Path -Parent $PSScriptRoot)
    Invoke-SocDiscoveryProbe $root
    $health = Get-Content -LiteralPath (Join-Path $root 'health.ndjson') | Select-Object -Last 1 | ConvertFrom-Json
    if ($health.rejection_evidence.state -ne 'disabled') { throw 'Default was not disabled.' }
    $result.disabled_default = $true
    & (Join-Path $PSScriptRoot '../enable-rejection-evidence.ps1') -Root $root -DryRun
    & (Join-Path $PSScriptRoot '../enable-rejection-evidence.ps1') -Root $root -ApproveRetention
    $data = @{'@timestamp'=[DateTime]::UtcNow.AddSeconds(-30).ToString('o'); agent=@{id='11111111-1111-4111-8111-111111111111'};
        winlog=@{channel='Application';provider_name='Cloud-SOC-Synthetic';record_id=42;event_data=@{password='PRIVATE_CANARY';safe='synthetic'}};
        event=@{code='1000'};message='PRIVATE_CANARY';authorization='PRIVATE_CANARY'}
    $entry = @{'@timestamp'=[DateTime]::UtcNow.ToString('o');'log.logger'='elasticsearch';
        message=("Cannot index event '"+($data | ConvertTo-Json -Depth 12 -Compress)+"' (status=400): {`"type`":`"document_parsing_exception`"}")}
    $input = Join-Path $root 'logs/filebeat-events-data-synthetic.ndjson'
    [IO.File]::WriteAllText($input,(($entry | ConvertTo-Json -Compress)+"`n"))
    $before = (Get-FileHash -LiteralPath $input).Hash
    $key = Join-Path $root 'rejection-evidence/fingerprint.key'
    $keyHash = (Get-FileHash -LiteralPath $key).Hash
    Invoke-SocDiscoveryProbe $root
    $health = Get-Content -LiteralPath (Join-Path $root 'health.ndjson') | Select-Object -Last 1 | ConvertFrom-Json
    $manifestPath = Join-Path $root 'rejection-evidence/manifest.json'
    $text = [IO.File]::ReadAllText($manifestPath)
    $manifest = $text | ConvertFrom-Json
    if ($health.rejection_evidence.state -ne 'observed' -or $health.rejection_evidence.records -ne 1 -or $manifest.records.Count -ne 1 -or $text.Contains('PRIVATE_CANARY')) { throw 'SYSTEM capture/privacy failed.' }
    $result.system_capture = $true
    foreach ($path in @((Join-Path $root 'rejection-evidence'),$key,$manifestPath)) {
        $acl = Get-Acl -LiteralPath $path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Owner not protected.' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Evidence access exposed.' }
        }
    }
    $result.protected_acl = $true
    Invoke-SocDiscoveryProbe $root
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.records.Count -ne 1) { throw 'SYSTEM persistent dedup failed.' }
    $result.key_unchanged = (Get-FileHash -LiteralPath $key).Hash -ceq $keyHash
    $result.input_unchanged = (Get-FileHash -LiteralPath $input).Hash -ceq $before
    $originalManifest = (Get-FileHash -LiteralPath $manifestPath).Hash
    [IO.File]::WriteAllText((Join-Path $root 'rejection-evidence/unknown.txt'),'must preserve')
    Invoke-SocDiscoveryProbe $root
    $health = Get-Content -LiteralPath (Join-Path $root 'health.ndjson') | Select-Object -Last 1 | ConvertFrom-Json
    if ($health.rejection_evidence.state -ne 'error' -or (Get-FileHash -LiteralPath $manifestPath).Hash -cne $originalManifest) { throw 'Evidence error changed store or stopped Discovery.' }
    $result.passed = $result.key_unchanged -and $result.input_unchanged
} catch { $result.error = $_.Exception.GetType().Name }
finally {
    try {
        if (Test-Path -LiteralPath (Join-Path (Join-Path $stage.Path 'agent') 'probe-active.txt')) { throw 'SYSTEM probe remains active.' }
        Remove-SocOwnedDirectory -Path $stage.Path -ExpectedPath $stage.Path -Token $stage.Token
        $result.cleaned=$true
    } catch { $result.error='Protected fixture cleanup incomplete.' }
    $stream = [IO.File]::Open($ResultPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($result | ConvertTo-Json)); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}
if (-not $result.passed -or -not $result.cleaned) { exit 1 }
