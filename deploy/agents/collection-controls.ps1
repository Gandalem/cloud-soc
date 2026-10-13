#requires -Version 5.1
# Local explicit switches. No reinstallation, key change or registry reset.
param([Parameter(Mandatory=$true)][ValidateSet('system','web','network')][string]$Kind,
      [Parameter(Mandatory=$true)][ValidateSet('on','off')][string]$Enabled,
      [string]$Site)
$ErrorActionPreference='Stop'
$root=Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'
$path=Join-Path $root 'collection-profile.json'
$switchPath=Join-Path $root 'collection-switches.json'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as administrator.' }
$profile=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
if ($profile.schema -ne 1) { throw 'Unknown collection profile.' }
foreach ($item in @($root,$path,$switchPath)) { if ((Test-Path -LiteralPath $item) -and ((Get-Item -LiteralPath $item).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked configuration refused.' } }
$switches=@{}; $web=@{}
if (Test-Path -LiteralPath $switchPath) {
    $old=Get-Content -LiteralPath $switchPath -Raw | ConvertFrom-Json
    foreach ($property in $old.PSObject.Properties) {
        if ($property.Name -notin @('system','web','network')) { throw 'Unknown local switch.' }
        if ($property.Name -eq 'web') { foreach ($siteProperty in $property.Value.PSObject.Properties) { if ($siteProperty.Value -isnot [bool]) { throw 'Invalid web switch.' }; $web[$siteProperty.Name]=$siteProperty.Value } }
        else { if ($property.Value -isnot [bool]) { throw 'Invalid switch.' }; $switches[$property.Name]=$property.Value }
    }
}
$active=$Enabled -eq 'on'
if ($Kind -eq 'web') {
    $selected=@($profile.web_inputs | Where-Object { $_.id -ceq ('cloud-soc-site-'+$Site) })
    if ($selected.Count -ne 1) { throw 'Select one configured site ID.' }
    $web[$Site]=$active
} elseif ($Kind -eq 'network') {
    if ($profile.network -ne $true) { throw 'Network was not selected in this installation; unrelated collectors are not adopted.' }
    $service=Get-Service -Name cloud-soc-packetbeat -ErrorAction Stop
    $native=Get-CimInstance Win32_Service -Filter "Name='cloud-soc-packetbeat'"
    $expected=Join-Path $env:ProgramFiles 'Cloud-SOC-Network\packetbeat-9.5.2-windows-x86_64\packetbeat.exe'
    if ($native.PathName -notmatch ('^\s*"?'+[regex]::Escape($expected)+'(?:"|\s|$)')) { throw 'Unknown network service executable.' }
    if ($active) { Set-Service -Name $service.Name -StartupType Automatic; Start-Service -Name $service.Name }
    else { Stop-Service -Name $service.Name; Set-Service -Name $service.Name -StartupType Disabled }
    $switches['network']=$active
} else { $switches['system']=$active }
$switches['web']=$web
$temp=Join-Path $root ('.collection-'+[Guid]::NewGuid().ToString('N')+'.tmp')
try {
    [IO.File]::WriteAllText($temp,($switches | ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $switchPath) { [IO.File]::Replace($temp,$switchPath,$null) }
    else { [IO.File]::Move($temp,$switchPath) }
} finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp } }
Start-ScheduledTask -TaskName Cloud-SOC-Discovery
Write-Output 'Collection switch applied; verify fresh central receipt separately.'
