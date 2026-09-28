# Real files/hashes/locks; synthetic services and scheduled tasks only.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force
}
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
. (Join-Path $PSScriptRoot '../repair-windows.ps1')
. (Join-Path $PSScriptRoot '../update-discovery-windows.ps1')
function Check($Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; return }
    throw "Expected failure: $Pattern"
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('soc-update-test-' + [guid]::NewGuid().ToString('N'))
$oldProgramData = $env:ProgramData
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $env:ProgramData = Join-Path $temp 'program-data'
    $root = Join-Path $temp 'agent'
    $source = Join-Path $temp 'package'
    foreach ($dir in @($env:ProgramData,$root,$source,(Join-Path $root 'inputs'),(Join-Path $root 'data'))) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    foreach ($name in @('ca.crt','data\filebeat.keystore','data\registry','data\queue','privacy.js','discovery-settings.json','inputs\discovered.yml','inputs\health.yml')) {
        [IO.File]::WriteAllText((Join-Path $root $name), 'original-'+$name)
    }
    Copy-Item (Join-Path $root 'ca.crt') $source
    [IO.File]::WriteAllText((Join-Path $source 'discovery-native.cs'), 'new-source')
    $endpoint = 'https://soc.example.invalid:9200'
    $config = @{
        'output.elasticsearch'=@{hosts=@($endpoint); api_key='${CLOUD_SOC_API_KEY}'; 'ssl.verification_mode'='full'; 'ssl.certificate_authorities'=@((Join-Path $root 'ca.crt'))}
        processors=@(@{add_fields=@{target='organization';fields=@{id='school'}}})
        'filebeat.config.inputs'=@{path=(Join-Path $root 'inputs\*.yml')}
    }
    $config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'filebeat.yml')
    $beatHome = Join-Path $root 'filebeat-9.5.2-windows-x86_64'
    $command = '"{0}" --environment=windows_service --path.home "{1}" --path.config "{2}" --path.data "{3}" --path.logs "{4}" -c "{5}" -E logging.files.redirect_stderr=true' -f (Join-Path $beatHome 'filebeat.exe'), $beatHome, $root, (Join-Path $root 'data'), (Join-Path $root 'logs'), (Join-Path $root 'filebeat.yml')
    $script:service = [pscustomobject]@{State='Running'; ProcessId=123; StartMode='Auto'; StartName='LocalSystem'; PathName=$command}
    $script:task = [pscustomobject]@{TaskName='Cloud-SOC-Discovery'; TaskPath='\'; State='Ready';
        Actions=@([pscustomobject]@{Execute=(Join-Path $root 'cloud-soc-discovery.exe'); Arguments=('--root "{0}"' -f $root); WorkingDirectory=$root});
        Principal=[pscustomobject]@{UserId='SYSTEM'; LogonType=5; RunLevel=1}; Settings=[pscustomobject]@{Enabled=$true}}
    $script:fail = ''; $script:answer = 'yes'; $script:probes=0
    function Assert-SocAdministrator {}
    function Assert-SocRepairAcl { param($Path) }
    function Assert-SocRepairDistribution { param($Root,$Version,$Hash) }
    function New-SocProtectedDirectory { param($Path,[switch]$Reuse)
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
    }
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) return $script:service.PSObject.Copy() }
    function Get-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) return $script:task }
    function Export-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
        return '<Task><Actions>native</Actions><Settings><Enabled>{0}</Enabled></Settings><Triggers>every-minute</Triggers></Task>' -f ([string]$script:task.Settings.Enabled).ToLowerInvariant()
    }
    function Disable-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
        $script:task.Settings.Enabled=$false; $script:task.State='Disabled'
        if ($script:fail -eq 'disable') { throw 'synthetic disable failure' }
    }
    function Enable-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
        if ($script:fail -eq 'enable-once') { $script:fail=''; throw 'synthetic enable failure' }
        $script:task.Settings.Enabled=$true; $script:task.State='Ready'
    }
    function Read-Host { param($Prompt) return $script:answer }
    $script:copyVerified = ${function:Copy-SocUpdateVerified}
    $script:fixtureRoot = $root
    function Copy-SocUpdateVerified { param($Source,$Target,$Hash)
        if ($script:fail -eq 'copy' -and $Target -eq (Join-Path $script:fixtureRoot 'cloud-soc-discovery.exe')) {
            $script:fail='copy-consumed'
            [IO.File]::WriteAllText($Target, 'partial-write')
            throw 'synthetic partial copy failure'
        }
        & $script:copyVerified @PSBoundParameters
    }
    function Write-FixtureNative([string]$Root,[string]$Text) {
        foreach ($name in @('discovery-native.cs','cloud-soc-discovery.exe')) { [IO.File]::WriteAllText((Join-Path $Root $name), $Text) }
        @{schema=1;worker='native-v1';source_sha256=(Get-FileHash (Join-Path $Root 'discovery-native.cs')).Hash;exe_sha256=(Get-FileHash (Join-Path $Root 'cloud-soc-discovery.exe')).Hash} |
            ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'discovery-native.json')
    }
    function Build-SocNativeDiscovery { param($Root,$Source)
        if ($script:fail -eq 'build') { throw 'synthetic build failure' }
        Write-FixtureNative $Root ([IO.File]::ReadAllText((Join-Path $Source 'discovery-native.cs')))
    }
    function Invoke-SocDiscoveryProbe { param($Root)
        $script:probes++
        if ($script:fail -eq 'stage' -and $script:probes -eq 1) { throw 'synthetic stage failure' }
        if ($script:fail -eq 'stage-cleanup' -and $script:probes -eq 1) {
            [IO.File]::WriteAllText((Join-Path $Root 'probe-active.txt'),'left'); throw 'synthetic stage cleanup failure'
        }
        if ($script:probes -eq 2) {
            [IO.File]::WriteAllText((Join-Path $Root 'inputs\discovered.yml'), 'new-input')
            [IO.File]::WriteAllText((Join-Path $Root 'data\queue'), 'advanced-live-queue')
            if ($script:fail -eq 'live') { throw 'synthetic live failure' }
            if ($script:fail -eq 'cleanup') { [IO.File]::WriteAllText((Join-Path $Root 'probe-active.txt'),'left'); throw 'synthetic cleanup failure' }
            if ($script:fail -eq 'backup') {
                $pending = Get-Content (Join-Path $Root 'discovery-update-pending.json') -Raw | ConvertFrom-Json
                [IO.File]::WriteAllText((Join-Path $pending.backup 'cloud-soc-discovery.exe'), 'corrupted')
                throw 'synthetic backup corruption'
            }
            if ($script:fail -eq 'guard') { [IO.File]::WriteAllText((Join-Path $Root 'privacy.js'), 'external-change') }
        }
        $time = if ($script:fail -eq 'stale') { [DateTime]::UtcNow.AddDays(-1) } else { [DateTime]::UtcNow }
        @{generated_at=$time.ToString('o');collector_metrics=@{state='unavailable'}} | ConvertTo-Json -Depth 4 -Compress |
            Set-Content -LiteralPath (Join-Path $Root 'health.ndjson')
    }
    $params = @{Root=$root;Source=$source;Endpoint=$endpoint;CaPath=(Join-Path $source 'ca.crt');Organization='school';Version='9.5.2';Hash='unused-mocked-distribution'}
    Write-FixtureNative $root 'old-source'
    $initial = @{}
    foreach ($name in @('filebeat.yml','ca.crt','data\filebeat.keystore','data\registry')) { $initial[$name]=(Get-FileHash (Join-Path $root $name)).Hash }
    Invoke-SocDiscoveryUpdate @params -DryRun
    Check ($script:probes -eq 0 -and -not (Test-Path (Join-Path $env:ProgramData 'Cloud-SOC'))) 'DryRun wrote state'
    $script:answer='no'
    Throws { Invoke-SocDiscoveryUpdate @params } 'cancelled'
    $script:answer='yes'
    $params.Organization='wrong'
    Throws { Invoke-SocDiscoveryUpdate @params -DryRun } 'organization'
    $params.Organization='school'
    [IO.File]::WriteAllText((Join-Path $source 'ca.crt'), 'wrong-ca')
    Throws { Invoke-SocDiscoveryUpdate @params -DryRun } 'CA differs'
    Copy-Item -LiteralPath (Join-Path $root 'ca.crt') -Destination (Join-Path $source 'ca.crt') -Force
    [IO.File]::AppendAllText((Join-Path $root 'cloud-soc-discovery.exe'), 'tamper')
    Throws { Invoke-SocDiscoveryUpdate @params -DryRun } 'integrity'
    Write-FixtureNative $root 'old-source'
    $script:task.Settings.Enabled=$false; $script:task.State='Running'
    Throws { Wait-SocUpdateIdle $root '' -TimeoutSeconds 0 } 'still running'
    $script:task.Settings.Enabled=$true; $script:task.State='Ready'
    Throws { Assert-SocUpdateTask $root '<Task><Actions>changed</Actions></Task>' } 'definition changed'
    $script:service.State='Stopped'
    Throws { Invoke-SocDiscoveryUpdate @params } 'running automatic'
    $script:service.State='Running'
    [IO.File]::WriteAllText((Join-Path $root 'discovery-update-pending.json'),'pending')
    Throws { Invoke-SocDiscoveryUpdate @params } 'Incomplete operation'
    Remove-Item -LiteralPath (Join-Path $root 'discovery-update-pending.json')
    foreach ($failure in @('build','stage','stage-cleanup','stale','disable','copy','live','enable-once','guard','')) {
        Write-FixtureNative $root 'old-source'
        [IO.File]::WriteAllText((Join-Path $root 'inputs\discovered.yml'),'original-input')
        [IO.File]::WriteAllText((Join-Path $root 'privacy.js'),'original-privacy.js')
        $script:fail=$failure; $script:probes=0
        if ($failure) { Throws { Invoke-SocDiscoveryUpdate @params } 'synthetic|fresh metrics|Protected configuration' }
        else { Invoke-SocDiscoveryUpdate @params }
        $expected = if ($failure) {'old-source'} else {'new-source'}
        Check ([IO.File]::ReadAllText((Join-Path $root 'cloud-soc-discovery.exe')) -eq $expected) "Bad code restore: $failure"
        if ($failure) { Check ([IO.File]::ReadAllText((Join-Path $root 'inputs\discovered.yml')) -eq 'original-input') "Bad input restore: $failure" }
        if ($script:probes -ge 2) { Check ([IO.File]::ReadAllText((Join-Path $root 'data\queue')) -eq 'advanced-live-queue') 'Queue was rewound' }
        Check $script:task.Settings.Enabled "Schedule not restored: $failure"
        Check (-not (Test-Path (Join-Path $root 'discovery-update-pending.json'))) "Unexpected pending marker: $failure"
        foreach ($name in $initial.Keys) { Check ((Get-FileHash (Join-Path $root $name)).Hash -ceq $initial[$name]) "Protected state changed: $name" }
    }
    # An external policy lock prevents replacement; the original schedule resumes.
    Write-FixtureNative $root 'old-source'
    $script:fail=''; $script:probes=0
    $held=Open-SocUpdateLock $root
    try { Throws { Invoke-SocDiscoveryUpdate @params } 'lock is busy' } finally { $held.Dispose() }
    Check $script:task.Settings.Enabled 'Lock failure left schedule disabled'
    Check ([IO.File]::ReadAllText((Join-Path $root 'cloud-soc-discovery.exe')) -eq 'old-source') 'Lock failure replaced executable'
    foreach ($failure in @('backup','cleanup')) {
        Write-FixtureNative $root 'old-source'; $script:fail=$failure; $script:probes=0
        Throws { Invoke-SocDiscoveryUpdate @params } 'rollback incomplete'
        Check (Test-Path (Join-Path $root 'discovery-update-pending.json')) 'Missing interrupted-update marker'
        Check (-not $script:task.Settings.Enabled) 'Unsafe rollback re-enabled task'
        Throws { Invoke-SocDiscoveryUpdate @params } 'Incomplete operation'
        Remove-Item -LiteralPath (Join-Path $root 'discovery-update-pending.json')
        if (Test-Path (Join-Path $root 'probe-active.txt')) { Remove-Item -LiteralPath (Join-Path $root 'probe-active.txt') }
        $script:task.Settings.Enabled=$true; $script:task.State='Ready'
    }
    $link = Join-Path $root 'linked-file'
    New-Item -ItemType HardLink -Path $link -Target (Join-Path $root 'privacy.js') | Out-Null
    Throws { Assert-SocUpdatePath $link } 'linked file'
    Remove-Item -LiteralPath $link
    Write-Host 'PASS: dry-run/cancel/identity/backup/hash/rollback/guard/queue/lock/pending/link tests'
} finally {
    $env:ProgramData=$oldProgramData
    Assert-SocLocalPath $temp
    if ([IO.Path]::GetDirectoryName($temp) -ine [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($temp) -notmatch '^soc-update-test-[a-f0-9]{32}$') { throw 'Unsafe fixture cleanup path' }
    $null = @(Get-SocRepairTree $temp)
    Remove-Item -LiteralPath $temp -Recurse -Force
}
