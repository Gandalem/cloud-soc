# Mocked SCM boundary. Never changes a real service or the registry.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../repair-windows.ps1')
$script:state=@{StartMode='Auto';DelayedAutoStart=$false}
$script:calls=0
$script:fail=''
function Get-CimInstance {
    param($ClassName,$Filter,$ErrorAction)
    if ($script:fail -eq 'missing') { return $null }
    return [pscustomobject]$script:state
}
function Invoke-SocServiceConfig {
    param($Name,$Start)
    $script:calls++
    if ($script:fail -eq 'command') { throw 'injected SCM failure' }
    if ($script:fail -eq 'unchanged') { return }
    $script:state.StartMode=@{'delayed-auto'='Auto';auto='Auto';demand='Manual';disabled='Disabled'}[$Start]
    $script:state.DelayedAutoStart=($Start -ceq 'delayed-auto')
}
function Assert-Throws([scriptblock]$Action) {
    $failed=$false
    try { & $Action } catch { $failed=$true }
    if (-not $failed) { throw 'Expected fail-closed result.' }
}
foreach ($name in @('cloud-soc-filebeat','cloud-soc-packetbeat')) {
    $script:state=@{StartMode='Auto';DelayedAutoStart=$false}
    $before=Get-SocServiceStartup $name
    Set-SocServiceStartup $name
    if (-not $state.DelayedAutoStart -or $before.DelayedAutoStart) { throw 'Delayed startup not applied or snapshot mutated.' }
    Set-SocServiceStartup -Name $name @before
    if ($state.DelayedAutoStart) { throw 'Original ordinary auto mode not restored.' }
    foreach ($mode in @('Manual','Disabled')) {
        Set-SocServiceStartup -Name $name -StartMode $mode -DelayedAutoStart $false
        if ($state.StartMode -ne $mode -or $state.DelayedAutoStart) { throw 'Original mode not restored.' }
    }
    $script:state=@{StartMode='Auto';DelayedAutoStart=$true}
    $before=Get-SocServiceStartup $name
    Set-SocServiceStartup -Name $name -StartMode Manual -DelayedAutoStart $false
    Set-SocServiceStartup -Name $name @before
    if (-not $state.DelayedAutoStart) { throw 'Delayed rollback mode lost.' }
}
$beforeCalls=$calls
Assert-Throws { Set-SocServiceStartup 'sshd' }
Assert-Throws { Get-SocServiceStartup 'sshd' }
Assert-Throws { Set-SocServiceStartup 'cloud-soc-filebeat' -StartMode Manual }
if ($calls -ne $beforeCalls) { throw 'Invalid request reached SCM.' }
foreach ($failure in @('command','unchanged','missing')) {
    $script:fail=$failure; $script:state=@{StartMode='Manual';DelayedAutoStart=$false}
    Assert-Throws { Set-SocServiceStartup 'cloud-soc-filebeat' }
}
$script:fail=''
$script:state=@{StartMode='Auto'}
Assert-Throws { Get-SocServiceStartup 'cloud-soc-filebeat' }
Write-Host 'Service startup tests passed.'
