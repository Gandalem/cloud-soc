# Explicit benign OS event + isolated rejection; existing collector remains unchanged.
#requires -Version 5.1
#requires -RunAsAdministrator
param([switch]$RunIsolatedTest, [Parameter(Mandatory=$true)][string]$Python,
      [Parameter(Mandatory=$true)][string]$ResultPath)
$ErrorActionPreference = 'Stop'
if (-not $RunIsolatedTest) { throw 'Explicit isolated reference test approval is required.' }
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
. (Join-Path $PSScriptRoot '../repair-windows.ps1')
. (Join-Path $PSScriptRoot '../update-discovery-windows.ps1')
Assert-SocAdministrator
Assert-SocLocalPath $ResultPath
if (Test-Path -LiteralPath $ResultPath) { throw 'Result exists.' }
$installed = Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'
$guard = Get-SocUpdateGuard $installed
$service = Get-CimInstance Win32_Service -Filter "Name='cloud-soc-filebeat'"
$policies = Get-ExecutionPolicy -List | ConvertTo-Json -Compress
$storeKey = (Get-FileHash -LiteralPath (Join-Path $installed 'rejection-evidence/fingerprint.key')).Hash
$stage = New-SocStage
$result = [ordered]@{ passed=$false; cleaned=$false; stage='prepare'; actual_os_reference=$false;
    actual_filebeat_diagnostic=$false; system_capture=$false; payload_hmac_match=$false;
    deduplicated=$false; guard_unchanged=$false; policy_unchanged=$false; error_type=$null }
try {
    $root = Join-Path $stage.Path 'agent'
    foreach ($path in @($root,(Join-Path $root 'inputs'),(Join-Path $root 'logs'))) { New-SocProtectedDirectory $path }
    [IO.File]::WriteAllText((Join-Path $root 'discovery-settings.json'),'{"log_roots":[],"required_channels":["Application"]}')
    Build-SocNativeDiscovery -Root $root -Source (Split-Path -Parent $PSScriptRoot)
    Invoke-SocDiscoveryProbe $root
    & (Join-Path $PSScriptRoot '../enable-rejection-evidence.ps1') -Root $root -ApproveRetention
    $result.stage = 'os_event'
    $marker = 'CLOUD_SOC_P0C18_' + [guid]::NewGuid().ToString('N')
    & "$env:WINDIR\System32\eventcreate.exe" /L APPLICATION /T INFORMATION /SO CloudSOCTest /ID 1000 /D $marker | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic event creation failed.' }
    $event = Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='CloudSOCTest';Id=1000;StartTime=(Get-Date).AddMinutes(-2)} -MaxEvents 30 |
        Where-Object { $_.Message -eq $marker } | Select-Object -First 1
    if (-not $event) { throw 'OS event not found.' }
    $agent = (Get-Content -LiteralPath (Join-Path $installed 'data/meta.json') -Raw | ConvertFrom-Json).uuid
    $reference = @{agent_id=$agent;channel='Application';provider=$event.ProviderName;record_id=[long]$event.RecordId;
        event_code=[string]$event.Id;occurred_at=$event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ');marker=$marker}
    [IO.File]::WriteAllText((Join-Path $root 'expected.json'),($reference | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    $result.actual_os_reference = $true
    $result.reference = $reference
    $result.stage = 'filebeat_400'
    $fixture = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../tests/p0c18_reference_fixture.py'))
    $beat = Join-Path $installed 'filebeat-9.5.2-windows-x86_64/filebeat.exe'
    & $Python $fixture --root $root --filebeat $beat
    if ($LASTEXITCODE -ne 0) { throw 'Actual Filebeat reference fixture failed.' }
    $result.actual_filebeat_diagnostic = $true
    $result.stage = 'system_capture'
    Invoke-SocDiscoveryProbe $root
    $health = Get-Content -LiteralPath (Join-Path $root 'health.ndjson') -Tail 1 | ConvertFrom-Json
    if ($health.rejection_evidence.state -ne 'observed' -or $health.rejection_evidence.records -ne 1) { throw 'SYSTEM evidence missing.' }
    $result.system_capture = $true
    $framework = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319'
    $check = Join-Path $stage.Path 'reference-check.exe'
    & (Join-Path $framework 'csc.exe') /noconfig /nologo /target:exe /platform:x64 /main:EvidenceReferenceCheck `
        "/reference:$framework\System.dll" "/reference:$framework\System.Core.dll" "/reference:$framework\System.Web.Extensions.dll" `
        "/out:$check" (Join-Path $root 'discovery-native.cs') (Join-Path $PSScriptRoot 'rejection-evidence-reference-check.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Reference checker compile failed.' }
    & $check $root
    if ($LASTEXITCODE -ne 0) { throw 'Reference/content HMAC verification failed.' }
    $result.payload_hmac_match = $true
    $manifest = Get-Content -LiteralPath (Join-Path $root 'rejection-evidence/manifest.json') -Raw | ConvertFrom-Json
    $result.os_occurred_at = $reference.occurred_at
    $result.reference.occurred_at = $manifest.records[0].occurred_at
    $identity = $manifest.records[0].id
    Invoke-SocDiscoveryProbe $root
    $manifest = Get-Content -LiteralPath (Join-Path $root 'rejection-evidence/manifest.json') -Raw | ConvertFrom-Json
    $result.deduplicated = @($manifest.records).Count -eq 1 -and $manifest.records[0].id -ceq $identity
    $readback = Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='CloudSOCTest';Id=1000} -MaxEvents 30 |
        Where-Object { $_.RecordId -eq $reference.record_id } | Select-Object -First 1
    if (-not $readback -or $readback.Message -cne $marker) { throw 'OS reference changed.' }
    Assert-SocUpdateGuard $installed $guard $service
    if ((Get-FileHash -LiteralPath (Join-Path $installed 'rejection-evidence/fingerprint.key')).Hash -cne $storeKey) { throw 'Operating evidence key changed.' }
    $result.guard_unchanged = $true
    $result.policy_unchanged = $policies -ceq (Get-ExecutionPolicy -List | ConvertTo-Json -Compress)
    $result.passed = $result.deduplicated -and $result.policy_unchanged
    $result.stage = 'await_readonly_central_comparison'
} catch {
    $result.error_type = $_.Exception.GetType().Name
    $result.failure_trace = $stage.Path
    $_.Exception.Message | Set-Content -LiteralPath (Join-Path $stage.Path 'failure.txt') -Encoding UTF8
} finally {
    if ($result.passed) {
        try { Remove-SocOwnedDirectory -Path $stage.Path -ExpectedPath $stage.Path -Token $stage.Token; $result.cleaned=$true }
        catch { $result.passed=$false; $result.error_type='ProtectedCleanupFailed' }
    }
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}
if (-not $result.passed -or -not $result.cleaned) { exit 1 }
