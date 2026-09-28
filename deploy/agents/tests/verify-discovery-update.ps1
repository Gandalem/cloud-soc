$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../verify-discovery-update-windows.ps1')

function Check($Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Check-Status($Result, [string]$Id, [string]$Status) {
    $item = @($Result.checks | Where-Object id -eq $Id)
    Check ($item.Count -eq 1 -and $item[0].status -eq $Status) "Unexpected $Id status"
}
function Write-Text([string]$Path, [string]$Text) { [IO.File]::WriteAllText($Path, $Text) }
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

$temp = Join-Path ([IO.Path]::GetTempPath()) ('soc-p2c07-verify-' + [guid]::NewGuid().ToString('N'))
$oldProgramData = $env:ProgramData
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $env:ProgramData = Join-Path $temp 'program-data'
    $root = Join-Path $temp 'agent'
    $backupId = 'b8875768910447038c913428b9ab9c65'
    $backup = Join-Path $env:ProgramData ('Cloud-SOC\updates\' + $backupId)
    foreach ($dir in @($env:ProgramData,$root,(Join-Path $root 'data'),(Join-Path $root 'inputs'),$backup,(Join-Path $backup 'inputs'),(Join-Path $env:ProgramData 'Cloud-SOC\staging'))) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    foreach ($name in @('filebeat.yml','ca.crt','data\filebeat.keystore','discovery-settings.json','privacy.js','collection-policy.txt')) {
        $path = Join-Path $root $name
        $parent = Split-Path -Parent $path
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Write-Text $path ('secret-sentinel-' + $name)
    }
    Write-Text (Join-Path $root 'data\registry') 'live-registry'
    Write-Text (Join-Path $root 'data\queue') 'live-queue'
    Write-Text (Join-Path $root 'discovery-native.cs') 'new-source'
    Write-Text (Join-Path $root 'cloud-soc-discovery.exe') 'new-exe'
    @{schema=1;worker='native-v1';source_sha256=(Hash (Join-Path $root 'discovery-native.cs'));exe_sha256=(Hash (Join-Path $root 'cloud-soc-discovery.exe'))} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'discovery-native.json') -Encoding UTF8

    $oldFiles = @{
        'discovery-native.cs'='old-source'; 'cloud-soc-discovery.exe'='old-exe'; 'discovery-native.json'='old-manifest';
        'inputs\discovered.yml'='old-discovered'; 'inputs\health.yml'='old-health'
    }
    $manifestFiles = @()
    foreach ($name in $oldFiles.Keys) {
        $target = Join-Path $backup $name
        $parent = Split-Path -Parent $target
        if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Write-Text $target $oldFiles[$name]
        $manifestFiles += @{path=$name;sha256=(Hash $target)}
    }
    $taskXml = '<Task><Principals><Principal><UserId>SYSTEM</UserId></Principal></Principals><Settings><Enabled>true</Enabled></Settings><Actions><Exec><Command>native.exe</Command></Exec></Actions><Triggers><TimeTrigger /></Triggers></Task>'
    Write-Text (Join-Path $backup 'task.xml') $taskXml
    $guard = @{}
    foreach ($name in @('filebeat.yml','ca.crt','data\filebeat.keystore','discovery-settings.json','privacy.js','collection-policy.txt')) { $guard[$name] = Hash (Join-Path $root $name) }
    @{schema=1;files=$manifestFiles;task_sha256=(Hash (Join-Path $backup 'task.xml'));guard=$guard;queue_restore=$false} |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $backup 'manifest.json') -Encoding UTF8

    $script:policyCall = 0
    $script:policyChanged = $false
    $script:serviceState = 'Running'
    $script:taskExecute = Join-Path $root 'cloud-soc-discovery.exe'
    function Test-SocVerificationAdmin { return $true }
    function Test-SocVerificationProtectedAcl { param($Path) return $true }
    function Get-ExecutionPolicy { param($Scope,$ErrorAction) $script:policyCall++; if ($script:policyChanged -and $script:policyCall -gt 5) { return 'AllSigned' }; return 'RemoteSigned' }
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) [pscustomobject]@{State=$script:serviceState;StartMode='Auto';ProcessId=123;StartName='LocalSystem'} }
    function Get-ScheduledTask {
        param($TaskName,$TaskPath,$ErrorAction)
        if ($TaskName -and $TaskName -ne 'Cloud-SOC-Discovery') { return @() }
        [pscustomobject]@{
            TaskName='Cloud-SOC-Discovery'; TaskPath='\'; State='Ready';
            Actions=@([pscustomobject]@{Execute=$script:taskExecute;Arguments=('--root "{0}"' -f $root);WorkingDirectory=$root});
            Principal=[pscustomobject]@{UserId='SYSTEM';LogonType='ServiceAccount';RunLevel='Highest'};
            Settings=[pscustomobject]@{Enabled=$true}
        }
    }
    function Get-ScheduledTaskInfo { param($TaskName,$TaskPath,$ErrorAction) [pscustomobject]@{LastTaskResult=0} }
    function Export-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) return $taskXml }

    $script:policyCall=0
    $pass = Invoke-SocDiscoveryUpdateVerification -Root $root -BackupId $backupId
    Check ($pass.overall.status -eq 'pass') 'Baseline verifier did not pass'
    Check-Status $pass 'pre_update_guard_matches_current' 'pass'
    Check-Status $pass 'backup_task_matches_current' 'pass'
    $json = $pass | ConvertTo-Json -Depth 12
    Check ($json -notmatch 'secret-sentinel') 'Secret/config contents leaked into JSON'
    Check ($json -notmatch 'live-queue|live-registry') 'Queue/registry contents leaked into JSON'

    Write-Text (Join-Path $backup 'cloud-soc-discovery.exe') 'tampered-old-exe'
    $script:policyCall=0
    $badBackup = Invoke-SocDiscoveryUpdateVerification -Root $root -BackupId $backupId
    Check-Status $badBackup 'backup_files_integrity' 'fail'
    Write-Text (Join-Path $backup 'cloud-soc-discovery.exe') $oldFiles['cloud-soc-discovery.exe']

    Write-Text (Join-Path $root 'data\filebeat.keystore') 'changed-key-by-fixture'
    $script:policyCall=0
    $badGuard = Invoke-SocDiscoveryUpdateVerification -Root $root -BackupId $backupId
    Check-Status $badGuard 'pre_update_guard_matches_current' 'fail'
    Write-Text (Join-Path $root 'data\filebeat.keystore') 'secret-sentinel-data\filebeat.keystore'

    Write-Text (Join-Path $root 'probe-active.txt') 'synthetic'
    $script:policyCall=0
    $badTrace = Invoke-SocDiscoveryUpdateVerification -Root $root -BackupId $backupId
    Check-Status $badTrace 'no_pending_or_probe_traces' 'fail'
    Remove-Item -LiteralPath (Join-Path $root 'probe-active.txt')

    $script:taskExecute = Join-Path $root 'wrong.exe'
    $script:policyCall=0
    $badTask = Invoke-SocDiscoveryUpdateVerification -Root $root -BackupId $backupId
    Check-Status $badTask 'discovery_task_native_enabled' 'fail'
    $script:taskExecute = Join-Path $root 'cloud-soc-discovery.exe'

    $script:serviceState='Stopped'
    $script:policyCall=0
    $badService = Invoke-SocDiscoveryUpdateVerification -Root $root -BackupId $backupId
    Check-Status $badService 'filebeat_running_auto' 'fail'
    $script:serviceState='Running'

    Write-Text (Join-Path $root 'cloud-soc-discovery.exe') 'tampered-new-exe'
    $script:policyCall=0
    $badNative = Invoke-SocDiscoveryUpdateVerification -Root $root -BackupId $backupId
    Check-Status $badNative 'native_integrity' 'fail'
    Write-Text (Join-Path $root 'cloud-soc-discovery.exe') 'new-exe'

    $script:policyChanged=$true; $script:policyCall=0
    $badPolicy = Invoke-SocDiscoveryUpdateVerification -Root $root -BackupId $backupId
    Check-Status $badPolicy 'execution_policy_unchanged' 'fail'
    $script:policyChanged=$false
} finally {
    $env:ProgramData = $oldProgramData
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
