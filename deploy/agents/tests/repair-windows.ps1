# Real temporary files with synthetic services/tasks. No installation or network.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force
}
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
. (Join-Path $PSScriptRoot '../repair-windows.ps1')
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; return }
    throw "Expected failure: $Pattern"
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('cloud-soc-repair-' + [guid]::NewGuid().ToString('N'))
$originalProgramData = $env:ProgramData
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $root = Join-Path $temp 'agent'
    $source = Join-Path $temp 'package'
    $env:ProgramData = Join-Path $temp 'program-data'
    foreach ($dir in @($root,$source,$env:ProgramData,(Join-Path $root 'inputs'),(Join-Path $root 'data'))) { New-Item -ItemType Directory $dir | Out-Null }
    foreach ($name in @('ca.crt','data\filebeat.keystore','privacy.js','discovery-settings.json','discover-windows.ps1','inputs\discovered.yml','data\registry-state')) {
        [IO.File]::WriteAllText((Join-Path $root $name), 'synthetic-original')
    }
    [IO.File]::WriteAllText((Join-Path $source 'ca.crt'), 'synthetic-original')
    [IO.File]::WriteAllText((Join-Path $source 'discover-windows.ps1'), 'synthetic-new-discovery')
    $link = Join-Path $root 'linked-source'
    New-Item -ItemType Junction -Path $link -Target $source | Out-Null
    Assert-Throws { Get-SocRepairTree $root | Out-Null } 'linked path'
    [IO.Directory]::Delete($link)
    $link = Join-Path $root 'linked-file'
    New-Item -ItemType HardLink -Path $link -Target (Join-Path $root 'privacy.js') | Out-Null
    Assert-Throws { Get-SocRepairTree $root | Out-Null } 'linked file'
    Remove-Item -LiteralPath $link -Force
    $endpoint = 'https://soc.example.invalid:9200'
    $config = [pscustomobject]@{
        'output.elasticsearch' = [pscustomobject]@{ hosts = @($endpoint); api_key = '${CLOUD_SOC_API_KEY}'; 'ssl.verification_mode' = 'full'; 'ssl.certificate_authorities' = @((Join-Path $root 'ca.crt')) }
        processors = @([pscustomobject]@{ add_fields = [pscustomobject]@{ target = 'organization'; fields = [pscustomobject]@{ id = 'school' } } })
        'filebeat.config.inputs' = [pscustomobject]@{ path = (Join-Path $root 'inputs\*.yml') }
    }
    $config | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $root 'filebeat.yml')
    $beatDirectory = Join-Path $root 'filebeat-9.5.2-windows-x86_64'
    $command = '"{0}" --environment=windows_service --path.home "{1}" --path.config "{2}" --path.data "{3}" --path.logs "{4}" -c "{5}" -E logging.files.redirect_stderr=true' -f (Join-Path $beatDirectory 'filebeat.exe'), $beatDirectory, $root, (Join-Path $root 'data'), (Join-Path $root 'logs'), (Join-Path $root 'filebeat.yml')
    $script:service = [pscustomobject]@{ State = 'Stopped'; ProcessId = 0; StartMode = 'Disabled'; StartName = 'LocalSystem'; PathName = $command }
    Assert-SocRepairIdentity $service $config $command $endpoint 'school' $root
    Assert-Throws { Assert-SocRepairIdentity $service $config $command $endpoint 'other' $root } 'organization'
    Assert-Throws { Assert-SocRepairIdentity $service $config ($command+' extra') $endpoint 'school' $root } 'identity/path'
    Assert-Throws { Assert-SocRepairIdentity $service $config $command 'https://other.invalid' 'school' $root } 'endpoint'
    $service.State = 'Running'
    Assert-Throws { Assert-SocRepairIdentity $service $config $command $endpoint 'school' $root } 'stopped'
    $service.State = 'Stopped'

    # Verify pinned archive contents, not just a plausible service command.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    New-Item -ItemType Directory $beatDirectory | Out-Null
    [IO.File]::WriteAllText((Join-Path $beatDirectory 'filebeat.exe'), 'synthetic-not-executable')
    $zipPath = Join-Path $root 'filebeat-9.5.2-windows-x86_64.zip'
    $zip = [IO.Compression.ZipFile]::Open($zipPath, 'Create')
    try { [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $beatDirectory 'filebeat.exe'), 'filebeat-9.5.2-windows-x86_64/filebeat.exe') | Out-Null } finally { $zip.Dispose() }
    $hash = (Get-FileHash $zipPath -Algorithm SHA512).Hash
    Assert-SocRepairDistribution $root '9.5.2' $hash
    Assert-Throws { Assert-SocRepairDistribution $root '9.5.2' ('0'*128) } 'checksum'
    [IO.File]::WriteAllText((Join-Path $beatDirectory 'extra.dll'), 'unexpected')
    Assert-Throws { Assert-SocRepairDistribution $root '9.5.2' $hash } 'Unexpected'
    Remove-Item -LiteralPath (Join-Path $beatDirectory 'extra.dll')
    [IO.File]::WriteAllText((Join-Path $beatDirectory 'filebeat.exe'), 'modified')
    Assert-Throws { Assert-SocRepairDistribution $root '9.5.2' $hash } 'modified'
    [IO.File]::WriteAllText((Join-Path $beatDirectory 'filebeat.exe'), 'synthetic-not-executable')

    # Only these OS boundaries are mocked. Backup/hash/identity/restore use real files.
    function Assert-SocAdministrator {}
    function Assert-SocRepairAcl { param($Path) }
    function New-SocProtectedDirectory { param($Path,[switch]$Reuse)
        if (-not (Test-Path $Path)) { New-Item -ItemType Directory $Path | Out-Null }
    }
    function Get-CimInstance { param($ClassName,$Filter,$ErrorAction) return $script:service }
    function Get-Process { param($ErrorAction) return @() }
    $legacyAction = [pscustomobject]@{ Execute=(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'); Arguments=('-NoProfile -NonInteractive -File "{0}" -Refresh' -f (Join-Path $root 'discover-windows.ps1')); WorkingDirectory='' }
    function New-FixtureTask {
        [pscustomobject]@{ TaskName='Cloud-SOC-Discovery'; TaskPath='\'; State='Disabled'; Actions=@($legacyAction.PSObject.Copy()); Principal=[pscustomobject]@{ UserId='SYSTEM'; LogonType=5; RunLevel=1 }; Settings=[pscustomobject]@{ Enabled=$false } }
    }
    $script:task = $null; $script:fail = ''; $script:answer = 'yes'
    $script:calls = New-Object 'Collections.Generic.List[string]'
    function Get-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
        if ($script:task) { return $script:task }; return @()
    }
    function Export-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
        $a = $script:task.Actions[0]
        '<Task><Principal>SYSTEM</Principal><Actions><Exec><Command>{0}</Command><Arguments>{1}</Arguments><WorkingDirectory>{2}</WorkingDirectory></Exec></Actions><Settings><Enabled>{3}</Enabled></Settings><Triggers>original-schedule</Triggers></Task>' -f $a.Execute,[Security.SecurityElement]::Escape($a.Arguments),$a.WorkingDirectory,([string]$script:task.Settings.Enabled).ToLowerInvariant()
    }
    function New-ScheduledTaskAction { param($Execute,$Argument,$WorkingDirectory)
        [pscustomobject]@{ Execute=$Execute; Arguments=$Argument; WorkingDirectory=$WorkingDirectory }
    }
    function Set-ScheduledTask { param($TaskName,$TaskPath,$Action,$ErrorAction)
        $script:calls.Add('task-set')
        $copy = $script:task.PSObject.Copy(); $copy.Actions=@($Action); $script:task=$copy
        if ($script:fail -eq 'task-set' -and $Action.Arguments -match 'DiscoveryRoot') { throw 'synthetic task-set failure' }
    }
    function Enable-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
        $script:calls.Add('task-enable'); $script:task.Settings.Enabled=$true; $script:task.State='Ready'
        if ($script:fail -eq 'task-enable') { throw 'synthetic task-enable failure' }
    }
    function Disable-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction)
        $script:calls.Add('task-disable'); $script:task.Settings.Enabled=$false; $script:task.State='Disabled'
    }
    function Read-Host { param($Prompt) return $script:answer }
    function Test-SocServerTls { param($Endpoint,$CaPath,[switch]$AllowUnavailableRevocation)
        $script:calls.Add('tls'); if ($script:fail -eq 'tls') { throw 'synthetic TLS failure' }
    }
    function Invoke-SocDiscoveryProbe { param($Root)
        $script:calls.Add('probe')
        [IO.File]::WriteAllText((Join-Path $Root 'inputs\discovered.yml'), 'synthetic-refresh')
        if ($script:fail -eq 'probe') { throw 'synthetic SYSTEM failure' }
        if ($script:fail -eq 'probe-cleanup') {
            [IO.File]::WriteAllText((Join-Path $Root 'probe-active.txt'), 'synthetic')
            throw 'synthetic cleanup failure'
        }
    }
    function Invoke-SocRepairBeat { param($Root,$Version,$Check)
        $script:calls.Add($Check)
        if ($script:fail -eq $Check) { throw "synthetic $Check failure" }
    }
    function Register-SocRepairDiscovery { param($Root) $script:task=New-FixtureTask; $script:task.Settings.Enabled=$true; $script:task.State='Ready'; $script:calls.Add('register') }
    function Start-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) $script:calls.Add('task-start') }
    function Wait-SocTask { param($Name,$Started) if ($script:fail -eq 'task') { throw 'synthetic task failure' } }
    function Stop-ScheduledTask { param($TaskName,$TaskPath,$ErrorAction) $script:calls.Add('task-stop') }
    function Unregister-ScheduledTask { param($TaskName,$TaskPath,$Confirm,$ErrorAction) $script:task=$false; $script:calls.Add('unregister') }
    function Set-Service { param($Name,$StartupType,$ErrorAction)
        $script:calls.Add('mode:'+ $StartupType)
        $script:service.StartMode = @{ Disabled='Disabled'; Manual='Manual'; Automatic='Auto' }[$StartupType]
    }
    function Start-Service { param($Name,$ErrorAction)
        $script:calls.Add('service-start')
        if ($script:fail -eq 'start') { throw 'synthetic start failure' }
        $script:service.State='Running'
    }
    function Stop-Service { param($Name,$ErrorAction) $script:calls.Add('service-stop'); $script:service.State='Stopped' }
    function Get-Service { param($Name)
        $value = [pscustomobject]@{ Status=$script:service.State }
        $value | Add-Member ScriptMethod WaitForStatus { param($state,$timeout) }
        return $value
    }
    function Start-Sleep { param($Seconds) }
    $params = @{ Root=$root; Source=$source; Endpoint=$endpoint; CaPath=(Join-Path $source 'ca.crt'); Organization='school'; Version='9.5.2'; Hash=$hash }
    $script:answer=''
    Assert-Throws { Invoke-SocFilebeatRepairCore @params } 'cancelled'
    if (Test-Path (Join-Path $env:ProgramData 'Cloud-SOC')) { throw 'Cancellation created backup/state' }
    $script:answer='yes'
    foreach ($change in @('path','execute','arguments','directory','principal','logon','level','extra-action')) {
        $script:task=New-FixtureTask
        switch ($change) {
            'path' { $script:task.TaskPath='\Other\' }
            'execute' { $script:task.Actions[0].Execute='cmd.exe' }
            'arguments' { $script:task.Actions[0].Arguments+=' -Unexpected' }
            'directory' { $script:task.Actions[0].WorkingDirectory=$source }
            'principal' { $script:task.Principal.UserId='other' }
            'logon' { $script:task.Principal.LogonType=3 }
            'level' { $script:task.Principal.RunLevel=0 }
            'extra-action' { $script:task.Actions+= $legacyAction }
        }
        Assert-Throws { Get-SocRepairDiscovery $root } 'identity differs'
    }
    $script:task=New-FixtureTask
    $originalXml=Export-ScheduledTask
    Assert-SocRepairTaskUnchanged $root $originalXml
    Assert-Throws { Assert-SocRepairTaskUnchanged $root ($originalXml.Replace('original-schedule','other-schedule')) } 'definition changed'
    $script:task=$null
    Assert-Throws { Assert-SocRepairTaskUnchanged $root $originalXml } 'disappeared'
    $script:task=New-FixtureTask
    $script:task.Principal.UserId='other'
    Assert-Throws { Invoke-SocFilebeatRepairCore @params } 'identity differs'
    $script:task=New-FixtureTask
    $script:task.Settings.Enabled=$true; $script:task.State='Ready'
    Assert-Throws { Invoke-SocFilebeatRepairCore @params } 'disabled and idle'
    $script:task=$null
    foreach ($failure in @('tls','probe','config','output','task','start')) {
        $script:fail=$failure; $script:calls.Clear()
        Assert-Throws { Invoke-SocFilebeatRepairCore @params -Repair } 'synthetic'
        if ($service.State -ne 'Stopped' -or $service.StartMode -ne 'Disabled' -or $script:task) { throw "State not restored: $failure" }
        foreach ($name in @('data\filebeat.keystore','data\registry-state','discover-windows.ps1','inputs\discovered.yml')) {
            if ([IO.File]::ReadAllText((Join-Path $root $name)) -cne 'synthetic-original') { throw "File not preserved: $name / $failure" }
        }
        if ($failure -in @('tls','probe','config','output','task') -and 'service-start' -in $script:calls) { throw 'Service started before prerequisites passed' }
    }
    $script:fail='probe-cleanup'
    Assert-Throws { Invoke-SocFilebeatRepairCore @params -Repair } 'synthetic cleanup'
    if (-not (Test-Path (Join-Path $root 'recovery-pending.json'))) { throw 'Incomplete cleanup marker lost' }
    Assert-Throws { Invoke-SocFilebeatRepairCore @params -Repair } 'Interrupted/incomplete'
    # Only this test's simulated, non-running resources are reset for the success case.
    $pending = Get-Content (Join-Path $root 'recovery-pending.json') -Raw | ConvertFrom-Json
    Remove-Item -LiteralPath (Join-Path $root 'probe-active.txt')
    Restore-SocRepairFiles $root $pending.backup
    Remove-Item -LiteralPath (Join-Path $root 'recovery-pending.json')
    $script:fail=''; $script:calls.Clear()
    Invoke-SocFilebeatRepairCore @params
    if ($service.State -ne 'Running' -or $service.StartMode -ne 'Auto' -or -not $script:task) { throw 'Recovery did not activate verified resources' }
    if (($script:calls -join ',') -ne 'tls,probe,config,output,register,task-start,mode:Manual,service-start,mode:Automatic') { throw 'Wrong recovery order' }
    $manifests = @(Get-ChildItem (Join-Path $env:ProgramData 'Cloud-SOC\recovery') -Filter manifest.json -Recurse)
    if ($manifests.Count -ne 7) { throw 'Missing verified backups' }
    foreach ($manifest in $manifests) {
        $snapshot = Join-Path $manifest.DirectoryName 'snapshot'
        foreach ($file in (Get-Content $manifest.FullName -Raw | ConvertFrom-Json).files) {
            if ((Get-FileHash (Join-Path $snapshot $file.path)).Hash -cne $file.sha256) { throw 'Backup changed' }
        }
    }
    # A disabled legacy SYSTEM task is preserved, not deleted/re-registered.
    $script:service.State='Stopped'; $script:service.StartMode='Disabled'
    foreach ($failure in @('probe','config','output','task-set','task-enable','task','start','')) {
        $script:task=New-FixtureTask
        $originalXml = Export-ScheduledTask
        $script:fail=$failure; $script:calls.Clear()
        if ($failure) {
            Assert-Throws { Invoke-SocFilebeatRepairCore @params -Repair } 'synthetic'
            if ((Export-ScheduledTask) -cne $originalXml -or $script:task.State -ne 'Disabled') { throw "Existing task not restored: $failure" }
            if ($service.State -ne 'Stopped' -or $service.StartMode -ne 'Disabled') { throw "Existing service not restored: $failure" }
            if (Test-Path (Join-Path $root 'recovery-pending.json')) { throw "Rollback unexpectedly incomplete: $failure" }
        } else {
            Invoke-SocFilebeatRepairCore @params -Repair
            if ($script:task.Actions[0].WorkingDirectory -ne $root -or $script:task.Actions[0].Arguments -notmatch 'DiscoveryRoot' -or -not $script:task.Settings.Enabled) { throw 'Legacy task action not repaired/enabled' }
        }
        if ('unregister' -in $script:calls -or 'register' -in $script:calls) { throw 'Existing task was deleted/replaced' }
        $backups = @(Get-ChildItem (Join-Path $env:ProgramData 'Cloud-SOC\recovery') -Filter discovery-task.xml -Recurse)
        foreach ($file in $backups) {
            if ([IO.File]::ReadAllText($file.FullName) -cne $originalXml -or (Get-FileHash $file.FullName).Hash -ne (Get-Content (Join-Path $file.DirectoryName 'discovery-task.sha256'))) { throw 'Task backup differs' }
        }
    }
    Write-Output 'Recovery identity/distribution, cancellation, six failure paths, backup integrity and success order passed.'
} finally {
    $env:ProgramData = $originalProgramData
    $resolved = [IO.Path]::GetFullPath($temp)
    if ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -ne [IO.Path]::GetTempPath().TrimEnd('\') -or [IO.Path]::GetFileName($resolved) -notmatch '^cloud-soc-repair-[a-f0-9]{32}$') { throw 'Unsafe fixture cleanup' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
