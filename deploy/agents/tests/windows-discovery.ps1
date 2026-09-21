$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../discover-windows.ps1')

function Assert-True($Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Get-WinEvent {
    param($ListLog, [switch]$Force, $ErrorAction, $ErrorVariable)
    @(
        [pscustomobject]@{ LogName = 'Security'; IsEnabled = $true; LogType = 'Admin' },
        [pscustomobject]@{ LogName = 'Custom/Operational'; IsEnabled = $true; LogType = 'Operational' },
        [pscustomobject]@{ LogName = 'Disabled'; IsEnabled = $false; LogType = 'Operational' },
        [pscustomobject]@{ LogName = 'Trace'; IsEnabled = $true; LogType = 'Analytical' },
        [pscustomobject]@{ LogName = 'Debug'; IsEnabled = $true; LogType = 'Debug' },
        [pscustomobject]@{ LogName = '${SECRET}'; IsEnabled = $true; LogType = 'Operational' }
    )
}
$testParent = Join-Path ((Resolve-Path (Join-Path $PSScriptRoot '../../..')).ProviderPath) 'state'
$null = New-Item -ItemType Directory -Path $testParent -Force
$temp = [IO.Path]::GetFullPath((Join-Path $testParent ('cloud-soc-discovery-' + [Guid]::NewGuid().ToString('N'))))
$null = New-Item -ItemType Directory -Path $temp
try {
    $logs = Join-Path $temp 'logs'
    $null = New-Item -ItemType Directory -Path $logs
    $deep = $logs
    foreach ($number in 1..12) { $deep = Join-Path $deep 'deep'; $null = New-Item -ItemType Directory -Path $deep }
    [IO.File]::WriteAllText((Join-Path $deep 'service.log'), "test record`n", (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText((Join-Path $logs 'utf16.log'), "unicode log`n", [Text.Encoding]::Unicode)
    [IO.File]::WriteAllText((Join-Path $logs 'empty.log'), '')
    [IO.File]::WriteAllText((Join-Path $logs 'secret.key'), 'private')
    [IO.File]::WriteAllText((Join-Path $logs 'server.CRT'), 'certificate')
    [IO.File]::WriteAllText((Join-Path $logs '.env'), 'credentials')
    [IO.File]::WriteAllBytes((Join-Path $logs 'binary.bin'), [byte[]]@(0, 2, 0, 255))
    $outside = Join-Path $temp 'not-logs'
    $null = New-Item -ItemType Directory -Path $outside
    [IO.File]::WriteAllText((Join-Path $outside 'private.txt'), 'not a log')
    $null = New-Item -ItemType Junction -Path (Join-Path $logs 'linked') -Target $outside
    $first = Get-SourceDiscovery -LogRoots @($logs, $logs) -RequiredChannels @('Security')
    Assert-True (@($first.inputs | Where-Object type -eq winlog).Count -eq 2) 'Wrong channel coverage'
    $files = @($first.inputs | Where-Object type -eq filestream)
    Assert-True ($files.Count -eq 2) 'Expected UTF8 and UTF16 inputs'
    Assert-True (@($files.paths).Count -eq 2) 'Duplicates or unsafe files were collected'
    Assert-True (@($first.report.entries | Where-Object status -eq unsupported_direct_channel).Count -eq 2) 'Direct channels not reported'
    Assert-True (@($first.report.entries | Where-Object status -eq disabled).Count -eq 1) 'Disabled channel not reported'
    Assert-True (@($first.report.entries | Where-Object status -eq binary).Count -eq 1) 'Binary file not rejected'
    Assert-True (@($first.report.entries | Where-Object status -eq reparse_point).Count -eq 1) 'Junction was followed'
    $oldIds = @($first.inputs.id)
    [IO.File]::WriteAllText((Join-Path $logs 'created-later.log'), "new record`n", (New-Object Text.UTF8Encoding($false)))
    $second = Get-SourceDiscovery -LogRoots @($logs) -RequiredChannels @('Security')
    Assert-True (@(Compare-Object $oldIds @($second.inputs.id)).Count -eq 0) 'Input IDs changed on discovery'
    Assert-True (@(($second.inputs | Where-Object type -eq filestream).paths).Count -eq 3) 'New log not discovered'
    $root = Join-Path $temp 'agent'
    $null = New-Item -ItemType Directory -Path (Join-Path $root 'inputs') -Force
    Update-SourceDiscovery -Root $root -LogRoots @($logs) -RequiredChannels @('Security')
    $config = Get-Content -LiteralPath (Join-Path $root 'inputs\discovered.yml') -Raw | ConvertFrom-Json
    Assert-True (@($config).Count -eq 4) 'Reloadable JSON input list incorrect'
    [IO.File]::WriteAllText((Join-Path $logs 'replace-test.log'), "refresh again`n", (New-Object Text.UTF8Encoding($false)))
    Update-SourceDiscovery -Root $root -LogRoots @($logs) -RequiredChannels @('Security')
    $updated = Get-Content -LiteralPath (Join-Path $root 'inputs\discovered.yml') -Raw | ConvertFrom-Json
    Assert-True (@(($updated | Where-Object type -eq filestream).paths).Count -eq 4) 'Atomic replacement did not publish the new file'
    $before = [IO.File]::ReadAllText((Join-Path $root 'inputs\discovered.yml'))
    function Get-WinEvent { param($ListLog, [switch]$Force, $ErrorAction, $ErrorVariable) @() }
    $failed = $false
    try { Update-SourceDiscovery -Root $root -LogRoots @($logs) } catch { $failed = $true }
    Assert-True $failed 'Empty discovery must fail closed'
    Assert-True ([IO.File]::ReadAllText((Join-Path $root 'inputs\discovered.yml')) -ceq $before) 'Failed discovery overwrote good input list'
    foreach ($path in @('C:\', $env:ProgramData, 'C:\Users\user', 'C:\logs\..\secret')) {
        $failed = $false
        try { $null = Assert-LogRoot $path } catch { $failed = $true }
        Assert-True $failed "Unsafe root accepted: $path"
    }
} finally {
    $resolved = (Resolve-Path -LiteralPath $temp).ProviderPath
    $expectedParent = [IO.Path]::GetFullPath($testParent).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($resolved) -ne $expectedParent -or [IO.Path]::GetFileName($resolved) -notlike 'cloud-soc-discovery-*') { throw 'Unsafe test cleanup target' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Output 'Windows channel/file/encoding/refresh/failure discovery tests passed'
