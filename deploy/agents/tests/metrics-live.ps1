# Explicit read-only check against the installed collector. Build stays in staging.
#requires -Version 5.1
#requires -RunAsAdministrator
param([Parameter(Mandatory=$true)][string]$ResultPath)
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Force
}
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
Assert-SocLocalPath $ResultPath
if (Test-Path -LiteralPath $ResultPath) { throw 'Result already exists.' }
$root=Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'
Assert-SocLocalPath $root
$stage=New-SocStage
$result=[ordered]@{passed=$false; cleaned=$false; policy_before=[string](Get-ExecutionPolicy); policy_after=$null; metrics=$null; service=$null; error_type=$null}
try {
    $build=Join-Path $stage.Path 'worker'
    New-SocProtectedDirectory $build
    Build-SocNativeDiscovery -Root $build -Source (Split-Path -Parent $PSScriptRoot)
    $value=& (Join-Path $build 'cloud-soc-discovery.exe') --metrics-root $root
    if ($LASTEXITCODE -ne 0) { throw 'Read-only metrics failed.' }
    $result.metrics=$value | ConvertFrom-Json
    if ($result.metrics.schema -ne 1 -or $result.metrics.state -ne 'observed') { throw 'No live metric sample available.' }
    $result.service=[string](Get-Service cloud-soc-filebeat).Status
    $result.policy_after=[string](Get-ExecutionPolicy)
    if ($result.policy_before -ne $result.policy_after) { throw 'Policy changed.' }
    $result.passed=$true
} catch { $result.error_type=$_.Exception.GetType().Name }
finally {
    $result.policy_after=[string](Get-ExecutionPolicy)
    $result.service=[string](Get-Service cloud-soc-filebeat).Status
    try { Remove-SocOwnedDirectory -Path $stage.Path -ExpectedPath $stage.Path -Token $stage.Token; $result.cleaned=$true }
    catch { $result.error_type='CleanupFailed' }
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}
if (-not $result.passed -or -not $result.cleaned) { exit 1 }
