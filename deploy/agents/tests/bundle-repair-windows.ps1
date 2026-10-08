# Real files, archives, hashes and backups; OS boundaries are mocked. No capture/network/elevation.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force
}
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
. (Join-Path $PSScriptRoot '../repair-windows.ps1')
. (Join-Path $PSScriptRoot '../bundle-windows.ps1')
$baseMembers = (Get-Command Get-SocBundleMembers).ScriptBlock
$temp=Join-Path ([IO.Path]::GetTempPath()) ('cloud-soc-bundle-repair-' + [guid]::NewGuid().ToString('N'))
$oldData=$env:ProgramData; $oldFiles=$env:ProgramFiles
New-Item -ItemType Directory -Path $temp | Out-Null
$env:ProgramData=Join-Path $temp 'program-data'; $env:ProgramFiles=Join-Path $temp 'program-files'
$source=Join-Path $temp 'source'
New-Item -ItemType Directory -Path $source | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot '../packetbeat.base.json') -Destination $source
[IO.File]::WriteAllText((Join-Path $source 'ca.crt'),'synthetic-ca')
[IO.File]::WriteAllText((Join-Path $source 'privacy.js'),'synthetic-reviewed-privacy')
$endpoint='https://soc.example.invalid:9200'; $nic='11111111-1111-1111-1111-111111111111'
$calls=New-Object 'Collections.Generic.List[string]'
function Step([string]$Name) { $script:calls.Add($Name); if ($script:failure -ceq $Name) { throw "Injected $Name" } }
function Assert-Throws([scriptblock]$Action,[string]$Pattern) {
    try { & $Action | Out-Null } catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; return }
    throw "Expected failure: $Pattern"
}
function Assert-SocAdministrator { Step 'admin' }
function Assert-SocRepairAcl { param($Path) }
function New-SocProtectedDirectory { param($Path,[switch]$Reuse)
    Assert-SocLocalPath $Path
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
}
function Get-SocBundleMembers {
    $members = & $script:baseMembers
    foreach ($m in $members) { $m.Hash=(Get-FileHash -LiteralPath (Join-Path $m.Root ($m.Beat+'-9.5.2-windows-x86_64.zip')) -Algorithm SHA512).Hash }
    return $members
}
function Get-CimInstance { param($ClassName,$Filter,$ErrorAction)
    $name=($Filter -replace "^Name='|'$",'')
    if ($script:services.ContainsKey($name)) { return $script:services[$name].PSObject.Copy() }
}
function Get-Service { param($Name,$ErrorAction)
    $service=$script:services[$Name]
    $value=[pscustomobject]@{Status=$service.State;ServicesDependedOn=@([pscustomobject]@{Name='npcap'})}
    $value | Add-Member ScriptMethod WaitForStatus { param($State,$Timeout) if ($this.Status -ne $State) { throw 'Synthetic status mismatch' } }
    return $value
}
function Get-Process { param($ErrorAction) return @() }
function New-Service { param($Name,$DisplayName,$BinaryPathName,$StartupType,$DependsOn)
    Step ($Name+'-create')
    $script:services[$Name]=[pscustomobject]@{State='Stopped';ProcessId=0;StartMode=$StartupType;DelayedAutoStart=$false;StartName='LocalSystem';PathName=$BinaryPathName}
    Step ($Name+'-create-after')
}
function Remove-SocBundleService { param($Member)
    Assert-SocBundleService $Member
    Step ($Member.Service+'-delete'); $script:services.Remove($Member.Service)
}
function Assert-SocNativeDiscovery { param($Root) Step 'native-integrity' }
function Get-SocRepairDiscovery { param($Root,[switch]$AllowEnabled)
    if (-not $AllowEnabled -and $script:task -and $script:task.Settings.Enabled) { throw 'Expected disabled task' }
    return $script:task
}
function Export-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
    return '<Task><Actions><Exec><Command>synthetic-native</Command></Exec></Actions><Settings><Enabled>{0}</Enabled></Settings></Task>' -f ([string]$script:task.Settings.Enabled).ToLowerInvariant()
}
function Get-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) return $script:task }
function Disable-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
    Step 'task-disable'; $script:task.Settings.Enabled=$false; $script:task.State='Disabled'
}
function Enable-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
    Step 'task-enable'; $script:task.Settings.Enabled=$true; $script:task.State='Ready'
}
function New-FixtureTask([bool]$Enabled) {
    $hostRoot=Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'
    return [pscustomobject]@{State=$(if ($Enabled) {'Ready'} else {'Disabled'});Settings=[pscustomobject]@{Enabled=$Enabled};
        Actions=@([pscustomobject]@{Execute=(Join-Path $hostRoot 'cloud-soc-discovery.exe')})}
}
function Register-SocRepairDiscovery { param($Root) Step 'task-register'; $script:task=New-FixtureTask $true; Step 'task-register-after' }
function Start-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) Step 'task-start' }
function Stop-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) Step 'task-stop' }
function Unregister-ScheduledTask { param($TaskName,$TaskPath,$Confirm,$ErrorAction) Step 'task-delete'; $script:task=$null }
function Get-ScheduledTaskInfo { param($TaskName,$TaskPath) return @{LastRunTime=[datetime]'2000-01-01'} }
function Wait-SocTask { param($Name,$Started,$PreviousRun) Step 'task-wait' }
function Assert-SocBundleFreshReport { param($Root,$Started)
    Step 'task-report'
    if ($script:failure -ceq 'external-task-start') { Start-ExternalCollector }
}
function Assert-SocBundleRepairNetwork { param($InterfaceGuid) Step 'network'; if ($InterfaceGuid -cne $nic) { throw 'Wrong existing NIC' } }
function Test-SocServerTls { param($Endpoint,$CaPath,[switch]$AllowUnavailableRevocation) Step 'tls' }
function Invoke-SocDiscoveryProbe { param($Root)
    [IO.File]::WriteAllText((Join-Path $Root 'discovery-report.json'),'probe-report')
    Step 'probe'
}
function Test-SocBundleMember { param($Root,$Beat)
    Step ($Beat+'-config-auth')
    if ($script:failure -ceq 'change-config' -and $Beat -eq 'packetbeat') { [IO.File]::AppendAllText((Join-Path $Root 'packetbeat.yml'),' ') }
    if ($script:failure -ceq 'external-auth-start' -and $Beat -eq 'packetbeat') { Start-ExternalCollector }
    if ($script:failure -ceq 'external-start-mode' -and $Beat -eq 'packetbeat') { $script:services['cloud-soc-packetbeat'].StartMode='Auto' }
    if ($script:failure -ceq 'external-delayed-mode' -and $Beat -eq 'packetbeat') { $script:services['cloud-soc-packetbeat'].DelayedAutoStart=$true }
}
function Start-ExternalCollector {
    $script:services['cloud-soc-packetbeat'].State='Running'; $script:services['cloud-soc-packetbeat'].ProcessId=456
    $root=Join-Path $env:ProgramFiles 'Cloud-SOC-Network'
    [IO.File]::WriteAllText((Join-Path $root 'data\queue.canary'),'external-new-queue')
}
function Set-Service { param($Name,$StartupType,$ErrorAction)
    Step ($Name+'-'+$StartupType)
    $script:services[$Name].StartMode=@{Manual='Manual';Disabled='Disabled';Automatic='Auto'}[$StartupType]
    $script:services[$Name].DelayedAutoStart=$false
}
function Invoke-SocServiceConfig { param($Name,$Start)
    $mode=@{'delayed-auto'='Automatic';auto='Automatic';demand='Manual';disabled='Disabled'}[$Start]
    if ($script:failure -ceq ($Name+'-Automatic-once') -and $mode -eq 'Automatic') {
        $script:failure=''
        throw ('Injected '+$Name+'-Automatic-once')
    }
    Step ($Name+'-'+$mode)
    $script:services[$Name].StartMode=@{Automatic='Auto';Manual='Manual';Disabled='Disabled'}[$mode]
    $script:services[$Name].DelayedAutoStart=($Start -ceq 'delayed-auto')
}
function Start-Service { param($Name,$ErrorAction)
    $script:services[$Name].State='Running'; $script:services[$Name].ProcessId=123
    $member=@(Get-SocBundleMembers | Where-Object Service -eq $Name)[0]
    [IO.File]::WriteAllText((Join-Path $member.Root 'data\queue.canary'),'newer-queue')
    Step ($Name+'-start')
    if ($script:failure -ceq 'external-between-starts' -and $Name -eq 'cloud-soc-filebeat') { Start-ExternalCollector }
}
function Stop-Service { param($Name,$ErrorAction)
    Step ($Name+'-stop'); if ($script:cleanupFailure) { throw 'Injected cleanup failure' }
    $script:services[$Name].State='Stopped'; $script:services[$Name].ProcessId=0
}
function Start-Sleep { param($Seconds) }
function Reset-Fixture {
    foreach ($path in @($env:ProgramFiles,$env:ProgramData)) {
        if (Test-Path -LiteralPath $path) {
            Assert-SocLocalPath $path
            if ([IO.Path]::GetDirectoryName($path) -ine $temp) { throw 'Unsafe fixture reset' }
            Remove-Item -LiteralPath $path -Recurse -Force
        }
        New-Item -ItemType Directory -Path $path | Out-Null
    }
    $script:failure=''; $script:cleanupFailure=$false; $script:calls.Clear(); $script:services=@{}
    foreach ($m in (& $script:baseMembers)) {
        foreach ($dir in @($m.Root,(Join-Path $m.Root 'data'),(Join-Path $m.Root 'inputs'),(Join-Path $m.Root ($m.Beat+'-9.5.2-windows-x86_64')))) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        foreach ($name in Get-SocBundleStableNames $m.Beat) { [IO.File]::WriteAllText((Join-Path $m.Root $name),'synthetic-stable') }
        [IO.File]::WriteAllText((Join-Path $m.Root 'data\queue.canary'),'original-queue')
        [IO.File]::WriteAllText((Join-Path $m.Root 'discovery-report.json'),'original-report')
        [IO.File]::WriteAllText((Join-Path $m.Root 'install-owner.txt'),[guid]::NewGuid().ToString('N'))
        foreach ($name in @('ca.crt','privacy.js')) { Copy-Item -LiteralPath (Join-Path $source $name) -Destination $m.Root -Force }
        if ($m.Kind -eq 'network') {
            $config=Get-Content -LiteralPath (Join-Path $source 'packetbeat.base.json') -Raw | ConvertFrom-Json
            $config.'packetbeat.interfaces'.device='\Device\NPF_{'+$nic+'}'
            $config.processors[1].add_fields.fields.id='school'; $config.processors[2].add_fields.fields.sensor_platform='windows'
            $config.'output.elasticsearch'.hosts=@($endpoint)
            $config.'output.elasticsearch'.'ssl.certificate_authorities'=@((Join-Path $m.Root 'ca.crt'))
            $config.'output.elasticsearch'.index='soc-network-windows-9.5.2-%{+yyyy.MM.dd}'
        } else {
            $config=[pscustomobject]@{'output.elasticsearch'=[pscustomobject]@{hosts=@($endpoint);api_key='${CLOUD_SOC_API_KEY}';'ssl.verification_mode'='full';'ssl.certificate_authorities'=@((Join-Path $m.Root 'ca.crt'))};
                processors=@([pscustomobject]@{add_host_metadata=[pscustomobject]@{}},
                    [pscustomobject]@{add_fields=[pscustomobject]@{target='organization';fields=[pscustomobject]@{id='school'}}},
                    [pscustomobject]@{script=[pscustomobject]@{lang='javascript';file='privacy.js';timeout='50ms';tag_on_exception='_privacy_error'}},
                    [pscustomobject]@{drop_event=[pscustomobject]@{when=[pscustomobject]@{contains=[pscustomobject]@{tags='_privacy_error'}}}});
                'filebeat.config.inputs'=[pscustomobject]@{path=(Join-Path $m.Root 'inputs\*.yml')}}
        }
        $config | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath (Join-Path $m.Root ($m.Beat+'.yml')) -Encoding UTF8
        $exe=Join-Path $m.Root ($m.Beat+'-9.5.2-windows-x86_64\'+$m.Beat+'.exe')
        [IO.File]::WriteAllText($exe,'synthetic-not-executable')
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip=[IO.Compression.ZipFile]::Open((Join-Path $m.Root ($m.Beat+'-9.5.2-windows-x86_64.zip')),'Create')
        try { [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$exe,($m.Beat+'-9.5.2-windows-x86_64/'+$m.Beat+'.exe')) | Out-Null } finally { $zip.Dispose() }
        $script:services[$m.Service]=[pscustomobject]@{State='Stopped';ProcessId=0;StartMode='Disabled';DelayedAutoStart=$false;StartName='LocalSystem';PathName=(Get-SocBundleCommand $m.Root $m.Beat)}
    }
    $script:task=New-FixtureTask $false
}
function Add-PendingFixture {
    $tx=New-SocStage
    $members=Get-SocBundleMembers
    foreach ($m in $members) { $m.Prepared=@{token=[IO.File]::ReadAllText((Join-Path $m.Root 'install-owner.txt'))} }
    Save-SocBundleRecoveryIdentity $tx $members
    Save-SocBundleJournal $tx 'retained_recovery_required' $true
    [IO.File]::WriteAllText((Join-Path $env:ProgramData 'Cloud-SOC\bundle-pending.json'),$tx.Token)
    return $tx
}
$params=@{Source=$source;Endpoint=$endpoint;CaPath=(Join-Path $source 'ca.crt');Organization='school'}
try {
    Reset-Fixture
    Invoke-SocBundleRepairCore @params -DryRun
    if (($calls -join ',') -cne 'admin,native-integrity' -or (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Cloud-SOC'))) { throw 'Preview caused host side effects' }
    Assert-Throws { Invoke-SocBundleRepairCore @params -InterfaceGuid '22222222-2222-2222-2222-222222222222' -DryRun } 'NIC differs'
    foreach ($fail in @('network','tls','probe','filebeat-config-auth','packetbeat-config-auth','task-start','task-wait','task-report',
        'cloud-soc-filebeat-Manual','cloud-soc-filebeat-start','cloud-soc-packetbeat-Manual','cloud-soc-packetbeat-start','cloud-soc-packetbeat-Automatic')) {
        Reset-Fixture; $script:failure=$fail
        $members=Get-SocBundleMembers; $before=@{}
        foreach ($m in $members) { foreach ($name in Get-SocBundleStableNames $m.Beat) { $before[(Join-Path $m.Root $name)]=(Get-FileHash -LiteralPath (Join-Path $m.Root $name)).Hash } }
        Assert-Throws { Invoke-SocBundleRepairCore @params } ('Injected '+[regex]::Escape($fail))
        foreach ($m in $members) {
            if ($services[$m.Service].State -ne 'Stopped' -or $services[$m.Service].StartMode -ne 'Disabled') { throw "Wrong rollback service state: $fail" }
            $expected=if ($calls -contains ($m.Service+'-start')) {'newer-queue'} else {'original-queue'}
            if ([IO.File]::ReadAllText((Join-Path $m.Root 'data\queue.canary')) -cne $expected) { throw 'Queue was rewound' }
        }
        foreach ($path in $before.Keys) { if ((Get-FileHash -LiteralPath $path).Hash -cne $before[$path]) { throw 'Key/config/stable file changed' } }
        if (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Cloud-SOC\bundle-repair-pending.json')) { throw "Clean rollback left pending: $fail" }
        if ($calls -contains 'cloud-soc-filebeat-start') {
            foreach ($check in @('probe','filebeat-config-auth','packetbeat-config-auth','task-report')) { if ($calls.IndexOf($check) -gt $calls.IndexOf('cloud-soc-filebeat-start')) { throw 'Early collector start' } }
        }
    }
    foreach ($enabled in @($false,$true)) {
        Reset-Fixture; $script:task=New-FixtureTask $enabled; $tx=Add-PendingFixture
        Invoke-SocBundleRepairCore @params
        foreach ($s in $services.Values) { if ($s.State -ne 'Running' -or $s.StartMode -ne 'Auto' -or -not $s.DelayedAutoStart) { throw 'Pair not recovered with delayed start' } }
        if (-not $task.Settings.Enabled -or (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Cloud-SOC\bundle-pending.json'))) { throw 'Recovery not finalized' }
        if ((Read-SocBundleRepairJson (Join-Path $tx.Path 'bundle-state.json')).phase -cne 'committed_receipt_unverified') { throw 'False receipt status' }
    }
    # A post-start failure must restore delayed auto as well as ordinary modes, without rewinding queues.
    Reset-Fixture
    foreach ($s in $services.Values) { $s.StartMode='Auto'; $s.DelayedAutoStart=$true }
    $script:failure='cloud-soc-packetbeat-Automatic-once'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'Injected cloud-soc-packetbeat-Automatic-once'
    foreach ($s in $services.Values) {
        if ($s.State -ne 'Stopped' -or $s.StartMode -ne 'Auto' -or -not $s.DelayedAutoStart) { throw 'Delayed auto rollback lost original mode.' }
    }
    Reset-Fixture; $script:failure='external-delayed-mode'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'delayed start changed'
    if (-not $services['cloud-soc-packetbeat'].DelayedAutoStart -or ($calls -contains 'cloud-soc-filebeat-start')) { throw 'External delayed flag adopted or overwritten.' }
    Reset-Fixture; $script:task=$null
    Invoke-SocBundleRepairCore @params
    if (-not $task -or -not $task.Settings.Enabled) { throw 'Missing Discovery not recovered' }
    Reset-Fixture; $script:task=New-FixtureTask $true; $script:failure='probe'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'Injected probe'
    if (-not $task.Settings.Enabled) { throw 'Original enabled task not restored' }
    Reset-Fixture; $script:task=$null; $script:failure='task-wait'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'Injected task-wait'
    if ($task -or -not ($calls -contains 'task-delete')) { throw 'Owned new task not rolled back' }
    Reset-Fixture; $script:task=$null; $script:failure='task-register-after'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'Injected task-register-after'
    if (-not $task -or -not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Cloud-SOC\bundle-repair-pending.json'))) { throw 'Ambiguous new task was adopted/deleted' }
    Reset-Fixture; $script:failure='change-config'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'changed during recovery'
    if (($calls -join ',') -match 'filebeat-start|packetbeat-start' -or -not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Cloud-SOC\bundle-repair-pending.json'))) { throw 'Changed configuration started/overwritten' }
    foreach ($phase in @('external-auth-start','external-task-start','external-between-starts')) {
        Reset-Fixture; $script:failure=$phase
        Assert-Throws { Invoke-SocBundleRepairCore @params } 'started outside recovery'
        if ($services['cloud-soc-packetbeat'].State -ne 'Running' -or $services['cloud-soc-packetbeat'].ProcessId -ne 456 -or
            ($calls -contains 'cloud-soc-packetbeat-stop') -or ($calls -contains 'cloud-soc-packetbeat-start')) {
            throw 'Externally started collector was stopped/adopted'
        }
        $networkRoot=Join-Path $env:ProgramFiles 'Cloud-SOC-Network'
        if ([IO.File]::ReadAllText((Join-Path $networkRoot 'data\queue.canary')) -cne 'external-new-queue' -or
            -not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Cloud-SOC\bundle-repair-pending.json'))) { throw 'External activity lost its queue/guard' }
        if ($phase -ne 'external-between-starts' -and ($calls -contains 'cloud-soc-filebeat-start')) { throw 'Pair started before quiescent check' }
        if ($phase -eq 'external-between-starts' -and $services['cloud-soc-filebeat'].State -ne 'Stopped') { throw 'Owned Filebeat start not rolled back' }
    }
    Reset-Fixture; $script:failure='external-start-mode'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'start mode changed'
    if ($services['cloud-soc-packetbeat'].StartMode -cne 'Auto' -or ($calls -contains 'cloud-soc-filebeat-start')) { throw 'External start mode adopted/overwritten' }
    Reset-Fixture; $tx=Add-PendingFixture; $members=Get-SocBundleMembers
    $identity=Join-Path $tx.Path 'bundle-recovery.json'
    $original=[IO.File]::ReadAllText($identity)
    foreach ($change in @('transaction','root','hash','duplicate','pre-start')) {
        $value=$original | ConvertFrom-Json
        switch ($change) {
            transaction { $value.transaction='0'*32 }
            root { $value.members[0].root=$source }
            hash { $value.members[0].files.'ca.crt'='0'*64 }
            duplicate { $value.members[1].kind='host' }
            pre-start { Save-SocBundleJournal $tx 'preparing' $false }
        }
        $value | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $identity -Encoding UTF8
        Assert-Throws { Get-SocBundlePendingRecovery $members } 'identity|file changed|final-ready'
        Save-SocBundleJournal $tx 'retained_recovery_required' $true
    }
    Reset-Fixture; $services['cloud-soc-packetbeat'].State='Running'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'recognized service stopped'
    if ($calls -contains 'tls') { throw 'Credentials could be sent before pair identity passed' }
    Reset-Fixture; $members=Get-SocBundleMembers
    $network=Join-Path $members[1].Root 'packetbeat.yml'
    $value=Get-Content -LiteralPath $network -Raw | ConvertFrom-Json
    $value.'packetbeat.npcap.never_install'=$false
    $value | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $network
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'metadata-only'
    Reset-Fixture; $members=Get-SocBundleMembers
    $hostConfig=Join-Path $members[0].Root 'filebeat.yml'
    $value=Get-Content -LiteralPath $hostConfig -Raw | ConvertFrom-Json
    $value.processors=$value.processors[0..2]
    $value | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $hostConfig
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'privacy pipeline'
    Reset-Fixture; $script:failure='cloud-soc-packetbeat-start'; $script:cleanupFailure=$true
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'Injected'
    if (-not (Test-Path -LiteralPath (Join-Path $env:ProgramData 'Cloud-SOC\bundle-repair-pending.json'))) { throw 'Unsafe cleanup lost recovery record' }
    $calls.Clear(); $script:failure=''; $script:cleanupFailure=$false
    $services['cloud-soc-filebeat'].State='Stopped'; $services['cloud-soc-filebeat'].ProcessId=0
    $services['cloud-soc-packetbeat'].State='Stopped'; $services['cloud-soc-packetbeat'].ProcessId=0
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'Interrupted Repair'
    if ($calls -contains 'tls') { throw 'Interrupted repair adopted automatically' }
    $pending=Join-Path $env:ProgramData 'Cloud-SOC\bundle-repair-pending.json'
    $reservation=Read-SocBundleRepairJson $pending
    $recordPath=Join-Path (Join-Path $env:ProgramData ('Cloud-SOC\staging\'+$reservation.transaction)) 'repair-state.json'
    $record=Read-SocBundleRepairJson $recordPath
    $originalRecord=[IO.File]::ReadAllText($recordPath)
    foreach ($change in @('organization','transaction','duplicate','path')) {
        $value=$originalRecord | ConvertFrom-Json
        switch ($change) {
            organization { $value.organization='other' }
            transaction { $value.transaction='0'*32 }
            duplicate { $value.members[1].kind='host' }
            path { $value.backups.host=$source }
        }
        Write-SocBundleJsonAtomic $recordPath $value
        Assert-Throws { Invoke-SocBundleRepairCore @params -ResumeRepair -DryRun } 'identity|backup path'
    }
    [IO.File]::WriteAllText($recordPath,$originalRecord)
    $backupFile=Join-Path $record.backups.host 'snapshot\data\queue.canary'
    [IO.File]::AppendAllText($backupFile,'tampered')
    Assert-Throws { Invoke-SocBundleRepairCore @params -ResumeRepair -DryRun } 'backup file changed'
    [IO.File]::WriteAllText($backupFile,'original-queue')
    $beforePending=[IO.File]::ReadAllText($pending); $beforeRecord=[IO.File]::ReadAllText($recordPath)
    $calls.Clear()
    Invoke-SocBundleRepairCore @params -ResumeRepair -DryRun
    if ([IO.File]::ReadAllText($pending) -cne $beforePending -or [IO.File]::ReadAllText($recordPath) -cne $beforeRecord -or
        ($calls -join ',') -match 'tls|task-disable|start') { throw 'Resume preview modified state' }
    $script:task.State='Queued'
    Assert-Throws { Invoke-SocBundleRepairCore @params -ResumeRepair -DryRun } 'active task'
    $script:task.State='Disabled'
    Invoke-SocBundleRepairCore @params -ResumeRepair
    if (Test-Path -LiteralPath $pending) { throw 'Successful resume left pending' }
    foreach ($member in Get-SocBundleMembers) {
        if ($services[$member.Service].State -ne 'Running' -or [IO.File]::ReadAllText((Join-Path $member.Root 'data\queue.canary')) -cne 'newer-queue') { throw 'Resume lost latest queue or service' }
    }
    foreach ($missing in @('cloud-soc-packetbeat','both')) {
        Reset-Fixture; $tx=Add-PendingFixture; Save-SocBundleJournal $tx 'prepared' $false
        $script:services.Remove('cloud-soc-packetbeat')
        if ($missing -eq 'both') { $script:services.Remove('cloud-soc-filebeat') }
        Invoke-SocBundleRepairCore @params
        foreach ($service in $services.Values) { if ($service.State -ne 'Running') { throw 'Missing service was not recovered' } }
        if ($calls.IndexOf('cloud-soc-packetbeat-create') -lt $calls.IndexOf('packetbeat-config-auth')) { throw 'Service created before full preflight' }
    }
    Reset-Fixture; $script:services.Remove('cloud-soc-packetbeat')
    Assert-Throws { Invoke-SocBundleRepairCore @params -DryRun } 'Missing service requires'
    Reset-Fixture
    $members=Get-SocBundleMembers
    foreach ($member in $members) { Assert-SocBundleRepairMember $member $source $endpoint $params.CaPath 'school' }
    $tx=New-SocStage; $xml=Export-ScheduledTask
    Save-SocRepairResumeRecord $tx $members $endpoint 'school' @{} $xml $xml 'reserved'
    Write-SocBundleJsonAtomic $pending @{schema=2;transaction=$tx.Token;auto_restore_queue=$false}
    $calls.Clear()
    Invoke-SocBundleRepairCore @params -ResumeRepair -DryRun
    if (($calls -join ',') -cne 'admin,native-integrity') { throw 'Reserved preview changed host state' }
    Reset-Fixture; $tx=Add-PendingFixture; $script:services.Remove('cloud-soc-packetbeat'); $script:failure='cloud-soc-packetbeat-create-after'
    Assert-Throws { Invoke-SocBundleRepairCore @params } 'Injected'
    if (-not (Test-Path -LiteralPath $pending)) { throw 'Ambiguous service creation lost journal' }
    $script:failure=''
    Assert-Throws { Invoke-SocBundleRepairCore @params -ResumeRepair -DryRun } 'Ambiguous/missing service'
    Write-Host 'Stopped pair recovery/preview, real distribution/backup hashes, phase failures, queue preservation and interruption guards passed (OS/ACL mocked).'
} finally {
    $env:ProgramData=$oldData; $env:ProgramFiles=$oldFiles
    Assert-SocLocalPath $temp
    if ((Split-Path -Leaf $temp) -cnotmatch '^cloud-soc-bundle-repair-[a-f0-9]{32}$') { throw 'Unsafe test cleanup' }
    Remove-Item -LiteralPath $temp -Recurse -Force
}
