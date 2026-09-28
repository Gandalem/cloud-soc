# Explicit admin-only integration test. Synthetic files; no agent services or network.
#requires -Version 5.1
#requires -RunAsAdministrator
param([switch]$RunIsolatedTest, [Parameter(Mandatory=$true)][string]$ResultPath)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Force
}
if (-not $RunIsolatedTest) { throw 'Specify -RunIsolatedTest to authorize temporary SYSTEM tasks and protected synthetic files.' }
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
Assert-SocLocalPath $ResultPath
if (Test-Path -LiteralPath $ResultPath) { throw 'Result path already exists.' }
$stage = New-SocStage
$policyName = 'Cloud-SOC-Native-Policy-Test-' + [guid]::NewGuid().ToString('N')
$policyCreated = $false
$result = [ordered]@{ passed=$false; cleaned=$false; policy_before=$null; policy_after=$null; error=$null }
try {
    $root = Join-Path $stage.Path 'agent'
    $logs = Join-Path $stage.Path 'fixtures'
    foreach ($path in @($root,$logs,(Join-Path $root 'inputs'))) { New-SocProtectedDirectory $path }
    New-SocProtectedDirectory (Join-Path $root 'logs')
    $metric=@{'@timestamp'=[DateTime]::UtcNow.ToString('o'); 'log.logger'='monitoring'; 'service.name'='filebeat';
        message='Non-zero metrics in the last 30s'; monitoring=@{metrics=@{libbeat=@{output=@{events=@{total=10;acked=9;dropped=1}}}}}}
    [IO.File]::WriteAllText((Join-Path $root 'logs/filebeat-20260928.ndjson'),(($metric | ConvertTo-Json -Depth 10 -Compress)+"`n"))
    [IO.File]::WriteAllText((Join-Path $logs 'synthetic.log'), "synthetic-data-only`n")
    @{ log_roots=@($logs); required_channels=@('Application') } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'discovery-settings.json') -Encoding UTF8
    $policyPath = Join-Path $stage.Path 'system-policy.txt'
    $command = "[string](Get-ExecutionPolicy) | Set-Content -LiteralPath '$policyPath'"
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -Command "{0}"' -f $command)
    $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $policyName -Action $action -Principal $principal | Out-Null
    $policyCreated = $true
    $started = (Get-Date).AddSeconds(-1)
    Start-ScheduledTask $policyName
    Wait-SocTask -Name $policyName -Started $started -TimeoutSeconds 30
    $result.policy_before = (Get-Content -LiteralPath $policyPath -Raw).Trim()
    Build-SocNativeDiscovery -Root $root -Source (Split-Path -Parent $PSScriptRoot)
    Invoke-SocDiscoveryProbe $root
    $report = Get-Content -LiteralPath (Join-Path $root 'discovery-report.json') -Raw | ConvertFrom-Json
    if ($report.worker -ne 'native-v1' -or $report.selected_channels -lt 1) { throw 'Native SYSTEM report missing' }
    $health=Get-Content -LiteralPath (Join-Path $root 'health.ndjson') | Select-Object -Last 1 | ConvertFrom-Json
    if ($health.collector_metrics.state -ne 'observed' -or $health.collector_metrics.output_dropped -ne 1) { throw 'SYSTEM metrics report missing' }
    $input = Join-Path $root 'inputs\discovered.yml'
    $beforeHash = (Get-FileHash -LiteralPath $input).Hash
    [IO.File]::WriteAllText((Join-Path $root 'collection-policy.txt'), 'invalid synthetic policy')
    $failed = $false
    try { Invoke-SocDiscoveryProbe $root } catch { if ($_.Exception.Message -notmatch 'SYSTEM Discovery failed') { throw }; $failed=$true }
    if (-not $failed) { throw 'Invalid policy unexpectedly succeeded' }
    $diagnostic = Get-Content -LiteralPath (Join-Path $root 'discovery-diagnostic.json') -Raw | ConvertFrom-Json
    if ($diagnostic.status -ne 'error' -or $diagnostic.stage -ne 'settings' -or (Get-FileHash -LiteralPath $input).Hash -cne $beforeHash) { throw 'Error evidence or input preservation failed' }
    $started = (Get-Date).AddSeconds(-1)
    Start-ScheduledTask $policyName
    Wait-SocTask -Name $policyName -Started $started -TimeoutSeconds 30
    $result.policy_after = (Get-Content -LiteralPath $policyPath -Raw).Trim()
    if ($result.policy_before -ne $result.policy_after) { throw 'SYSTEM policy changed' }
    $result.passed = $true
} catch { $result.error=$_.Exception.Message }
finally {
    try {
        if ($policyCreated) {
            Stop-ScheduledTask $policyName
            if ((Get-ScheduledTask $policyName).State -in @('Running','Queued')) { throw 'Policy test still running' }
            Unregister-ScheduledTask $policyName -Confirm:$false
        }
        if (Test-Path -LiteralPath (Join-Path (Join-Path $stage.Path 'agent') 'probe-active.txt')) { throw 'Native probe cleanup incomplete' }
        Remove-SocOwnedDirectory -Path $stage.Path -ExpectedPath $stage.Path -Token $stage.Token
        $result.cleaned=$true
    } catch { $result.error='Cleanup incomplete; protected fixture retained at ' + $stage.Path }
    $result | ConvertTo-Json | Set-Content -LiteralPath $ResultPath -Encoding UTF8
}
if (-not $result.passed -or -not $result.cleaned) { exit 1 }
