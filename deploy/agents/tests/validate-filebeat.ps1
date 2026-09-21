# Optional offline smoke test with the pinned official Windows Filebeat binary.
param([Parameter(Mandatory = $true)][string]$FilebeatPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../discover-windows.ps1')
$root = Join-Path ((Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath) ('state\beat-smoke-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path (Join-Path $root 'inputs') -Force
$null = New-Item -ItemType Directory -Path (Join-Path $root 'fixtures')
$fixture = Join-Path $root 'fixtures\test.log'
$marker = 'CLOUD_SOC_SYNTHETIC_DISCOVERY_TEST'
[IO.File]::WriteAllText($fixture, ($marker + "`n"), (New-Object Text.UTF8Encoding($false)))
[IO.File]::WriteAllText((Join-Path $root 'fixtures\unicode.log'), ($marker + "_UTF16`n"), [Text.Encoding]::Unicode)
function Get-WinEvent {
    param($ListLog, [switch]$Force, $ErrorAction, $ErrorVariable)
    [pscustomobject]@{ LogName = 'Cloud-SOC-Synthetic-Nonexistent-Channel'; IsEnabled = $true; LogType = 'Operational' }
}
Update-SourceDiscovery -Root $root -LogRoots @((Join-Path $root 'fixtures'))
$configuration = @{
    'filebeat.config.inputs' = @{ enabled = $true; path = (Join-Path $root 'inputs\*.yml'); 'reload.enabled' = $true; 'reload.period' = '1s' }
    'output.console' = @{ pretty = $false }
    'logging.to_files' = $false
    'logging.to_stderr' = $true
    'logging.level' = 'info'
    'setup.ilm.enabled' = $false
    'setup.template.enabled' = $false
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
    [IO.File]::WriteAllText((Join-Path $root 'fixtures\new.log'), ($marker + "_NEW`n"), (New-Object Text.UTF8Encoding($false)))
    Update-SourceDiscovery -Root $root -LogRoots @((Join-Path $root 'fixtures'))
    $null = $process.WaitForExit(14000)
    if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($stderr -match 'No such input type|unknown input type|Error creating input') { [Console]::Error.WriteLine($stderr); throw 'Native input construction failed' }
    $messages = @($stdout -split '\r?\n' | Where-Object { $_ } | ForEach-Object { ($_ | ConvertFrom-Json).message })
    foreach ($expected in @($marker, ($marker + '_NEW'), ($marker + '_UTF16'))) {
        if ($expected -notin $messages) { throw "Synthetic log was not collected: $expected" }
    }
    if ($stderr -notmatch 'winlog') { throw 'Winlog input was not attempted by the actual binary' }
    Write-Output 'Native Filebeat smoke test passed: synthetic files and live reload; nonexistent event channel; no network output.'
} finally {
    if ($processStarted -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
    $process.Dispose()
}
