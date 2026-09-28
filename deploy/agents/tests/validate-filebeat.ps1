# Optional offline smoke test with the pinned official Windows Filebeat binary.
param([Parameter(Mandatory = $true)][string]$FilebeatPath, [string]$NativeFixturePath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../discover-windows.ps1')
$workspace = Join-Path ((Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath) ('state\beat-smoke-' + [Guid]::NewGuid().ToString('N'))
$root = Join-Path $workspace 'agent'
$fixtures = Join-Path $workspace 'fixtures'
$null = New-Item -ItemType Directory -Path (Join-Path $root 'inputs') -Force
$null = New-Item -ItemType Directory -Path $fixtures
$fixture = Join-Path $fixtures 'test.log'
$marker = 'CLOUD_SOC_SYNTHETIC_DISCOVERY_TEST'
[IO.File]::WriteAllText($fixture, ($marker + "`n"), (New-Object Text.UTF8Encoding($false)))
[IO.File]::WriteAllText((Join-Path $fixtures 'unicode.log'), ($marker + "_UTF16`n"), [Text.Encoding]::Unicode)
[IO.File]::WriteAllText((Join-Path $fixtures 'privacy.log'), "password=PRIVATE_SMOKE_CANARY`n", (New-Object Text.UTF8Encoding($false)))
function Get-WinEvent {
    param($ListLog, [switch]$Force, $ErrorAction, $ErrorVariable)
    [pscustomobject]@{ LogName = 'Cloud-SOC-Synthetic-Nonexistent-Channel'; IsEnabled = $true; LogType = 'Operational' }
}
@{ log_roots=@($fixtures); required_channels=@() } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'discovery-settings.json') -Encoding UTF8
if ($NativeFixturePath) {
    $null=New-Item -ItemType Directory -Path (Join-Path $root 'logs') -Force
    $metric=@{'@timestamp'='2026-09-28T00:00:00Z'; 'log.logger'='monitoring'; 'service.name'='filebeat';
        message='Non-zero metrics in the last 30s';
        monitoring=@{metrics=@{libbeat=@{output=@{events=@{total=10;acked=9;dropped=1}};pipeline=@{queue=@{filled=@{pct=0.8;events=2;bytes=40}}}}}}}
    [IO.File]::WriteAllText((Join-Path $root 'logs/filebeat-20260928.ndjson'),(($metric | ConvertTo-Json -Depth 12 -Compress)+"`n"))
}
function Refresh-Fixture {
    if ($NativeFixturePath) { & $NativeFixturePath --refresh-fixture $root; if ($LASTEXITCODE) { throw 'Native fixture discovery failed' } }
    else { Update-SourceDiscovery -Root $root -LogRoots @($fixtures) }
}
Refresh-Fixture
$configuration = @{
    'filebeat.config.inputs' = @{ enabled = $true; path = (Join-Path $root 'inputs\*.yml'); 'reload.enabled' = $true; 'reload.period' = '1s' }
    'output.console' = @{ pretty = $false }
    'logging.to_files' = $false
    'logging.to_stderr' = $true
    'logging.level' = 'info'
    'setup.ilm.enabled' = $false
    'setup.template.enabled' = $false
    'queue.disk' = @{ max_size = '1GB' }
    processors = @(
        @{ script = @{ lang = 'javascript'; file = (Join-Path $PSScriptRoot '../privacy.js'); timeout = '50ms'; tag_on_exception = '_privacy_error' } },
        @{ drop_event = @{ when = @{ contains = @{ tags = '_privacy_error' } } } }
    )
}
$configPath = Join-Path $root 'filebeat.yml'
Write-DiscoveryFile $configPath ($configuration | ConvertTo-Json -Depth 12)
& $FilebeatPath test config -c $configPath --path.data (Join-Path $root 'data') --path.logs (Join-Path $root 'logs')
if ($LASTEXITCODE) { throw 'Pinned Filebeat configuration validation failed' }
$process = New-Object Diagnostics.Process
$process.StartInfo.FileName = $FilebeatPath
$process.StartInfo.Arguments = '-c "{0}" --path.data "{1}" --path.logs "{2}"' -f $configPath, (Join-Path $root 'data'), (Join-Path $root 'logs')
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
$processStarted = $false
try {
    $null = $process.Start()
    $processStarted = $true
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    Start-Sleep -Seconds 4
    [IO.File]::WriteAllText((Join-Path $fixtures 'new.log'), ($marker + "_NEW`n"), (New-Object Text.UTF8Encoding($false)))
    Refresh-Fixture
    $null = $process.WaitForExit(14000)
    if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($stderr -match 'No such input type|unknown input type|Error creating input') { [Console]::Error.WriteLine($stderr); throw 'Native input construction failed' }
    $events = @($stdout -split '\r?\n' | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    $messages = @($events | Where-Object { $_.PSObject.Properties.Name -contains 'message' } | ForEach-Object { $_.message })
    foreach ($expected in @($marker, ($marker + '_NEW'), ($marker + '_UTF16'))) {
        if ($expected -notin $messages) { throw "Synthetic log was not collected: $expected" }
    }
    if ($stderr -notmatch 'winlog') { throw 'Winlog input was not attempted by the actual binary' }
    if ($stdout -match 'PRIVATE_SMOKE_CANARY' -or '[REDACTED]' -notin $messages) { throw 'Privacy processing failed in native Beat.' }
    $reports = @($events | Where-Object { $_.PSObject.Properties.Name -contains 'cloud_soc' })
    if (-not $reports.Count -or $reports[0].cloud_soc.discovery.schema -ne 1) { throw 'Health NDJSON was not parsed by native Beat.' }
    if ($NativeFixturePath) {
        $metric=$reports[0].cloud_soc.discovery.collector_metrics
        if ($metric.state -ne 'observed' -or $metric.output_dropped -ne 1 -or $metric.output_acked -ne 9 -or $metric.queue_pct -ne 0.8) { throw 'Metrics did not survive native Filebeat/privacy/queue processing.' }
    }
    Write-Output 'Native Filebeat smoke test passed: synthetic files and live reload; nonexistent event channel; no network output.'
} finally {
    if ($processStarted -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    $process.Dispose()
}
