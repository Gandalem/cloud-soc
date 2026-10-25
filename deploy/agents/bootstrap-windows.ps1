#requires -Version 5.1
param([ValidateSet('install','status','stop','start','uninstall','help')][string]$Action,
    [string]$BundleDirectory=$PSScriptRoot)
$ErrorActionPreference='Stop'
if ($Action -eq 'help') { Write-Host 'Start.cmd [install|status|stop|start|uninstall|help]'; return }
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments=@('-NoProfile','-File',('"'+$PSCommandPath+'"'),'-BundleDirectory',('"'+$BundleDirectory+'"'))
    if($Action){$arguments+=$Action}
    $process=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList $arguments -PassThru -Wait
    exit $process.ExitCode
}
function Assert-BootstrapPath([string]$Path) {
    $cursor=[IO.Path]::GetFullPath($Path)
    while($cursor){if((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked installation path refused.'};$cursor=[IO.Path]::GetDirectoryName($cursor)}
}
function ProtectedDirectory([string]$Path){
    Assert-BootstrapPath $Path
    if(Test-Path -LiteralPath $Path){
        $acl=Get-Acl -LiteralPath $Path
        if(-not $acl.AreAccessRulesProtected){throw 'Existing installation storage is not protected.'}
        if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Unexpected installation owner.'}
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw 'Unexpected installation access.'}}
        return
    }
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')){$identity=New-Object Security.Principal.SecurityIdentifier($sid);$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $directory=New-Object IO.DirectoryInfo($Path)
    if($PSVersionTable.PSEdition -eq 'Core'){[IO.FileSystemAclExtensions]::Create($directory,$acl)}else{$directory.Create($acl)}
}
try {
    $base=Join-Path $env:ProgramData 'Cloud-SOC-Bundles'
    $existing=$null
    if(Test-Path -LiteralPath (Join-Path $BundleDirectory 'package.json')){
        $hint=Get-Content -LiteralPath (Join-Path $BundleDirectory 'package.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if($hint.managed_device_id -cmatch '^[a-f0-9]{32}$'){
            $candidate=Join-Path $base $hint.managed_device_id
            if(Test-Path -LiteralPath (Join-Path $candidate 'managed-install.json')){$existing=$candidate}
        }
    }elseif(Test-Path -LiteralPath $base){
        $candidates=@(Get-ChildItem -LiteralPath $base -Directory | Where-Object {$_.Name -cmatch '^[a-f0-9]{32}$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'managed-install.json'))})
        if($candidates.Count -eq 1){$existing=$candidates[0].FullName}
        elseif($candidates.Count -gt 1){throw 'Select the installed device configuration directory.'}
    }
    if($existing){
        ProtectedDirectory $base;ProtectedDirectory $existing
        if($Action){& (Join-Path $existing 'agent-manager.ps1') $Action}else{& (Join-Path $existing 'agent-manager.ps1')}
        exit 0
    }
    Assert-BootstrapPath $BundleDirectory
    $spec=Get-Content -LiteralPath (Join-Path $BundleDirectory 'package.json') -Raw | ConvertFrom-Json
    $registration=Get-Content -LiteralPath (Join-Path $BundleDirectory 'registration.json') -Raw | ConvertFrom-Json
    if($spec.managed_device_id -cnotmatch '^[a-f0-9]{32}$' -or $registration.device_id -cne $spec.managed_device_id){throw 'Device binding differs.'}
    $runtime=Join-Path $BundleDirectory 'runtime.zip'
    if((Get-Item -LiteralPath $runtime).Length -gt 8MB -or (Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -cne $registration.runtime_sha256){throw 'Runtime integrity differs.'}
    ProtectedDirectory $base
    $target=Join-Path $base $spec.managed_device_id;ProtectedDirectory $target
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive=[IO.Compression.ZipFile]::OpenRead($runtime)
    try{
        $seen=@{};$total=0
        foreach($entry in $archive.Entries){
            $total+=$entry.Length
            if($archive.Entries.Count -gt 100 -or $total -gt 16MB -or $entry.FullName -cnotmatch '^[a-zA-Z0-9_.-]+$' -or $entry.FullName -in @('.','..') -or $seen.ContainsKey($entry.FullName) -or $entry.FullName -in @('package.json','ca.crt','collection-profile.json','SHA256SUMS','README.txt','registration.json')){throw 'Unexpected runtime member.'}
            $seen[$entry.FullName]=$true;$path=Join-Path $target $entry.FullName;Assert-BootstrapPath $path
            $inputStream=$entry.Open();$memory=New-Object IO.MemoryStream
            try{$inputStream.CopyTo($memory);$bytes=$memory.ToArray()}finally{$inputStream.Dispose();$memory.Dispose()}
            if(Test-Path -LiteralPath $path){
                $hash=[Security.Cryptography.SHA256]::Create()
                try{$expected=([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','')}finally{$hash.Dispose()}
                if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $expected){throw 'Existing runtime version differs; no replacement.'}
            }else{$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}}
        }
    }finally{$archive.Dispose()}
    foreach($name in @('package.json','ca.crt','collection-profile.json','SHA256SUMS','README.txt','registration.json')){
        $source=Join-Path $BundleDirectory $name;$path=Join-Path $target $name;Assert-BootstrapPath $source;Assert-BootstrapPath $path
        if(-not(Test-Path -LiteralPath $source)){if($name -eq 'collection-profile.json'){continue};throw 'Missing device settings.'}
        if((Get-Item -LiteralPath $source).Length -gt 256KB){throw 'Oversized device settings.'}
        if((Test-Path -LiteralPath $path) -and $name -ne 'registration.json' -and (Get-FileHash -LiteralPath $source).Hash -ne (Get-FileHash -LiteralPath $path).Hash){throw 'Existing device settings differ.'}
        if($name -eq 'registration.json' -or -not(Test-Path -LiteralPath $path)){Copy-Item -LiteralPath $source -Destination $path -Force}
    }
    if($Action){& (Join-Path $target 'agent-manager.ps1') $Action}else{& (Join-Path $target 'agent-manager.ps1')}
    exit 0
}catch{[Console]::Error.WriteLine('장치 설치 도구를 완료하지 못했습니다. 권한·설정·등록 만료 상태를 확인하세요. 기존 자료는 초기화하지 않았습니다.');exit 1}
