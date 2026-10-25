#requires -Version 5.1
param([ValidateSet('install','status','stop','start','uninstall','help')][string]$Action)
$ErrorActionPreference='Stop'
if($Action -eq 'help'){Write-Host 'Start.cmd [install|status|stop|start|uninstall|help]';return}
. (Join-Path $PSScriptRoot 'transaction-windows.ps1')
. (Join-Path $PSScriptRoot 'repair-windows.ps1')
. (Join-Path $PSScriptRoot 'enrollment-windows.ps1')
Assert-SocAdministrator
Assert-SocRepairAcl $PSScriptRoot
if(-not $Action){Write-Host '1. 설치  2. 상태  3. 중지  4. 재개  5. 삭제  0. 종료';$Action=@{'1'='install';'2'='status';'3'='stop';'4'='start';'5'='uninstall'}[(Read-Host '선택')];if(-not $Action){return}}
$spec=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'package.json') -Raw | ConvertFrom-Json
$recordPath=Join-Path $PSScriptRoot 'managed-install.json'
function Read-OwnedInstall {
    Assert-SocRepairAcl $recordPath
    $record=Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    if($record.device_id -cne $spec.managed_device_id -or $record.package_id -cne $spec.package_id -or $record.state -cne 'installed'){throw 'Installation ownership differs.'}
    foreach($entry in $record.services){$service=Get-CimInstance Win32_Service -Filter ("Name='"+$entry.name+"'");if(-not $service -or $service.PathName -cne $entry.command){throw 'Owned service differs.'}}
    foreach($file in $record.files.PSObject.Properties){Assert-SocLocalPath $file.Name;Assert-SocRepairAcl $file.Name;if((Get-FileHash -LiteralPath $file.Name -Algorithm SHA256).Hash -cne $file.Value){throw 'Owned installation file differs.'}}
    return $record
}
if(Test-Path -LiteralPath $recordPath){
    Assert-SocRepairAcl $recordPath
    $local=Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if($local.device_id -cne $spec.managed_device_id -or $local.package_id -cne $spec.package_id){throw 'Managed device identity differs.'}
    if($local.state -eq 'removed'){
        if($Action -in @('status','uninstall')){Write-Host '로컬 프로그램 삭제됨. 서버 접근 차단 결과는 포털에서 확인하세요.';return}
        throw 'Removed installation; no automatic queue restore or reinstallation.'
    }
    if($Action -eq 'install'){$null=Read-OwnedInstall;Write-Host '이미 등록된 설치입니다. 상태·중지·재개·삭제 메뉴를 사용하세요.';return}
}
if($Action -eq 'install'){
    Assert-SocRepairAcl (Join-Path $PSScriptRoot 'registration.json')
    $registration=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'registration.json') -Raw | ConvertFrom-Json
    if($registration.device_id -cne $spec.managed_device_id -or $registration.enrollment_id -cnotmatch '^[a-f0-9]{32}$' -or $registration.token -cnotmatch '^[a-f0-9]{32}\.[A-Za-z0-9_-]{43}$' -or $registration.enrollment_id -cne $registration.token.Split('.')[0] -or [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -ge $registration.expires){throw 'Registration binding differs or expired.'}
    foreach($line in Get-Content -LiteralPath (Join-Path $PSScriptRoot 'SHA256SUMS')){
        if($line -cnotmatch '^([a-f0-9]{64})  ([A-Za-z0-9_.-]+)$'){throw 'Invalid integrity manifest.'}
        $path=Join-Path $PSScriptRoot $Matches[2];Assert-SocLocalPath $path
        if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Matches[1]){throw 'Installation integrity differs.'}
    }
    $attemptPath=Join-Path $PSScriptRoot ('attempt-'+$registration.enrollment_id+'.txt')
    if(-not(Test-Path -LiteralPath $attemptPath)){$fresh=ConvertTo-SecureString (New-SocEnrollmentAttempt) -AsPlainText -Force;try{$fresh | ConvertFrom-SecureString | Set-Content -LiteralPath $attemptPath -Encoding ASCII}finally{$fresh.Dispose()}}
    Assert-SocRepairAcl $attemptPath
    $attemptSecure=Get-Content -LiteralPath $attemptPath -Raw | ConvertTo-SecureString
    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($attemptSecure)
    try{$attempt=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);$attemptSecure.Dispose()}
    $token=ConvertTo-SecureString $registration.token -AsPlainText -Force
    try{Invoke-SocEnrollmentInstall -Source $PSScriptRoot -Endpoint $spec.endpoint -CaPath (Join-Path $PSScriptRoot 'ca.crt') -Organization $spec.organization -PackageSha256 $registration.package_sha256 -RegistrationToken $token -RegistrationAttempt $attempt}finally{$token.Dispose();$attempt=$null;$registration=$null}
    $members=@(Get-SocBundleMembers -HostOnly:(-not $spec.network));$services=@();$files=@{}
    foreach($member in $members){
        $service=Get-CimInstance Win32_Service -Filter ("Name='"+$member.Service+"'")
        $services+=@{name=$member.Service;command=$service.PathName;root=$member.Root}
        foreach($file in Get-ChildItem -LiteralPath $member.Root -File -Recurse){
            $relative=$file.FullName.Substring($member.Root.Length+1)
            if($relative -match '^(logs|inputs)\\' -or ($relative -match '^data\\' -and $relative -notmatch '\.keystore$')){continue}
            Assert-SocLocalPath $file.FullName;Assert-SocRepairAcl $file.FullName
            $files[$file.FullName]=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        }
    }
    @{device_id=$spec.managed_device_id;package_id=$spec.package_id;state='installed';services=$services;files=$files} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $recordPath -Encoding UTF8
    $uninstall='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cloud-SOC-'+$spec.managed_device_id
    if(Test-Path -LiteralPath $uninstall){throw 'Existing uninstall registration differs.'}
    New-Item -Path $uninstall | Out-Null
    New-ItemProperty -LiteralPath $uninstall -Name DisplayName -Value 'Cloud SOC Agent' -PropertyType String | Out-Null
    New-ItemProperty -LiteralPath $uninstall -Name UninstallString -Value ('"'+(Join-Path $PSHOME 'powershell.exe')+'" -NoProfile -File "'+$PSCommandPath+'" uninstall') -PropertyType String | Out-Null
    Remove-Item -LiteralPath (Join-Path $PSScriptRoot 'registration.json')
    Write-Host '장치 등록과 최초 시험 로그 수신을 완료했습니다. 다운로드 원본도 안전하게 삭제하세요.'
    return
}
$managementLocks=@()
try {
foreach($lockName in @('Global\Cloud-SOC-Bundle-Install','Global\Cloud-SOC-Filebeat-Recovery')){
    $managementLock=New-Object Threading.Mutex($false,$lockName)
    try{$held=$managementLock.WaitOne(0)}catch [Threading.AbandonedMutexException]{$managementLock.ReleaseMutex();$managementLock.Dispose();throw 'Previous management was interrupted; inspect owned state first.'}
    if(-not $held){$managementLock.Dispose();throw 'Another installation or management action is active.'}
    $managementLocks+=$managementLock
}
$record=Read-OwnedInstall
if($Action -eq 'status'){foreach($entry in $record.services){Get-Service -Name $entry.name | Select-Object Name,Status};Write-Host '최신 일반 로그와 분석 상태는 포털에서 조회하세요.';return}
if($Action -in @('stop','start')){
    foreach($entry in $record.services){if($Action -eq 'stop'){Stop-Service -Name $entry.name;Set-Service -Name $entry.name -StartupType Disabled}else{Set-Service -Name $entry.name -StartupType Automatic;Start-Service -Name $entry.name}}
    if($Action -eq 'stop'){Disable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' | Out-Null;Stop-ScheduledTask -TaskName 'Cloud-SOC-Discovery'}else{Enable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' | Out-Null;Start-ScheduledTask -TaskName 'Cloud-SOC-Discovery'}
    Write-Host '로컬 수집 서비스에 적용했습니다. 서버 접근 권한은 별개입니다.';return
}
Write-Host '1. 미전송 자료·설정 보존 후 삭제  2. 수집기 자료까지 삭제  그 외: 취소'
$choice=Read-Host '선택';if($choice -notin @('1','2')){return}
if($choice -eq '2' -and (Read-Host '수집기 큐·설정·키를 삭제하려면 DELETE 입력') -cne 'DELETE'){return}
$record=Read-OwnedInstall
$allowed=@((Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'),(Join-Path $env:ProgramFiles 'Cloud-SOC-Network'))
foreach($entry in $record.services){if($entry.root -cnotin $allowed -or $entry.name -cnotin @('cloud-soc-filebeat','cloud-soc-packetbeat')){throw 'Unowned removal target.'};Assert-SocLocalPath $entry.root;foreach($file in Get-SocRepairTree $entry.root){Assert-SocLocalPath $file.FullName}}
$archive=Join-Path (Split-Path -Parent $PSScriptRoot) ('retired-'+[guid]::NewGuid().ToString('N'));New-SocProtectedDirectory $archive
@{state='removing';device_id=$spec.managed_device_id;remote_revocation='not_confirmed';data_preserved=($choice -eq '1')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $archive 'operation.json') -Encoding UTF8
foreach($entry in $record.services){Stop-Service -Name $entry.name;Set-Service -Name $entry.name -StartupType Disabled}
$task=Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery'
$hostRoot=Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'
if(@($task.Actions).Count -ne 1 -or -not $task.Actions[0].Execute.StartsWith($hostRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Discovery task ownership differs.'}
Stop-ScheduledTask -TaskName 'Cloud-SOC-Discovery';Unregister-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -Confirm:$false
foreach($entry in $record.services){& (Join-Path $env:WINDIR 'System32\sc.exe') delete $entry.name | Out-Null;if($LASTEXITCODE -ne 0){throw 'Service removal failed.'};if($choice -eq '1'){Move-Item -LiteralPath $entry.root -Destination (Join-Path $archive (Split-Path -Leaf $entry.root))}else{Remove-Item -LiteralPath $entry.root -Recurse -Force}}
$record.state='removed';$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $recordPath -Encoding UTF8
$uninstall='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cloud-SOC-'+$spec.managed_device_id
if(Test-Path -LiteralPath $uninstall){Remove-Item -LiteralPath $uninstall}
@{state='removed';device_id=$spec.managed_device_id;remote_revocation='not_confirmed';data_preserved=($choice -eq '1')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $archive 'operation.json') -Encoding UTF8
Write-Host '로컬 프로그램 제거 완료. 서버 접근 차단은 포털의 같은 장치에서 완료하세요.'
}finally{for($i=$managementLocks.Count-1;$i -ge 0;$i--){$managementLocks[$i].ReleaseMutex();$managementLocks[$i].Dispose()}}
