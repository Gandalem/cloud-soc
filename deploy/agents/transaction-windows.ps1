# Shared installation scratch space and SYSTEM probe. No top-level host changes.
function Assert-SocAdministrator {
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Use 64-bit PowerShell on Windows x86_64.' }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as Administrator.' }
}

function Get-SocDirectoryAcl {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    return $acl
}

function Assert-SocLocalPath([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '["\x00-\x1f${}]|(^|\\)\.\.?($|\\)') { throw 'Unsafe local installation path.' }
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse-point installation path is not allowed.' }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}

function New-SocProtectedDirectory([string]$Path, [switch]$Reuse) {
    Assert-SocLocalPath $Path
    if (Test-Path -LiteralPath $Path) {
        if (-not $Reuse -or -not (Test-Path -LiteralPath $Path -PathType Container)) { throw 'Installation directory already exists.' }
        $acl = Get-Acl -LiteralPath $Path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544') -or -not $acl.AreAccessRulesProtected) { throw 'Existing staging parent is not protected; no permissions were changed.' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'Existing staging parent has unexpected access.' }
        }
        return
    }
    $directory = New-Object IO.DirectoryInfo($Path)
    $acl = Get-SocDirectoryAcl
    if ($PSVersionTable.PSEdition -eq 'Core') { [IO.FileSystemAclExtensions]::Create($directory, $acl) }
    else { $directory.Create($acl) }
    New-SocProtectedDirectory $Path -Reuse
}

function Test-SocServerTls([string]$Endpoint, [string]$CaPath) {
    $curl = Get-SystemCurl
    $PSNativeCommandUseErrorActionPreference = $false
    $status = & $curl --disable --silent --show-error --proto '=https' --tlsv1.2 --retry 0 --max-redirs 0 `
        --connect-timeout 10 --max-time 20 --cacert $CaPath --output NUL --write-out '%{http_code}' -- ($Endpoint.TrimEnd('/') + '/')
    if ($LASTEXITCODE -ne 0 -or $status -notin @('200', '401')) { throw 'Central TLS/connectivity preflight failed. Check server address, CA and connectivity; no credentials were sent.' }
    Write-Host '[OK] Central server TLS (API authentication still pending).'
}

function New-SocStage {
    $base = Join-Path $env:ProgramData 'Cloud-SOC'
    New-SocProtectedDirectory $base -Reuse
    $parent = Join-Path $base 'staging'
    New-SocProtectedDirectory $parent -Reuse
    $token = [guid]::NewGuid().ToString('N')
    $path = Join-Path $parent $token
    New-SocProtectedDirectory $path
    [IO.File]::WriteAllText((Join-Path $path 'install-owner.txt'), $token)
    return @{ Path = $path; Token = $token }
}

function Remove-SocOwnedDirectory([string]$Path, [string]$ExpectedPath, [string]$Token) {
    Assert-SocLocalPath $Path
    if ([IO.Path]::GetFullPath($Path).TrimEnd('\') -ine [IO.Path]::GetFullPath($ExpectedPath).TrimEnd('\') -or $Token -cnotmatch '^[a-f0-9]{32}$') { throw 'Cleanup target mismatch.' }
    $marker = Join-Path $Path 'install-owner.txt'
    if (Test-Path -LiteralPath (Join-Path $Path 'probe-active.txt')) { throw 'Probe cleanup is incomplete; directory retained.' }
    Assert-SocLocalPath $marker
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf) -or [IO.File]::ReadAllText($marker) -cne $Token) { throw 'Cleanup ownership mismatch; directory retained.' }
    # Enumerate one level at a time; never descend through a junction during checks.
    $pending = New-Object 'Collections.Generic.Stack[string]'
    $pending.Push($Path)
    while ($pending.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Cleanup refused a linked child; directory retained.' }
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
}

function Wait-SocTask([string]$Name, [datetime]$Started, [int]$TimeoutSeconds = 300) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 1
        $info = Get-ScheduledTaskInfo -TaskName $Name
        $task = Get-ScheduledTask -TaskName $Name
        if ($info.LastRunTime -ge $Started -and $task.State -notin @('Running', 'Queued')) {
            if ($info.LastTaskResult -ne 0) { throw "SYSTEM Discovery failed (exit $($info.LastTaskResult)). Check execution policy and source access; policy was not bypassed." }
            return
        }
    } while ((Get-Date) -lt $deadline)
    throw 'SYSTEM Discovery timed out.'
}

function Invoke-SocDiscoveryProbe([string]$Root) {
    $name = 'Cloud-SOC-Preflight-' + [guid]::NewGuid().ToString('N')
    $created = $false
    try {
        $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments = '-NoProfile -NonInteractive -File "{0}" -Refresh -DiscoveryRoot "{1}"' -f (Join-Path $Root 'discover-windows.ps1'), $Root
        $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $Root
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
        [IO.File]::WriteAllText((Join-Path $Root 'probe-active.txt'), $name)
        Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings | Out-Null
        $created = $true
        $started = (Get-Date).AddSeconds(-1)
        Start-ScheduledTask -TaskName $name
        Wait-SocTask -Name $name -Started $started
        $report = Get-Content -LiteralPath (Join-Path $Root 'discovery-report.json') -Raw | ConvertFrom-Json
        # PowerShell 7 may deserialize ISO timestamps as DateTime rather than string.
        $generated = if ($report.generated_at -is [datetime]) { $report.generated_at.ToUniversalTime() }
                     else { [DateTimeOffset]::Parse([string]$report.generated_at, [Globalization.CultureInfo]::InvariantCulture).UtcDateTime }
        if ($generated -lt $started.ToUniversalTime() -or $generated -gt [DateTime]::UtcNow.AddSeconds(30)) { throw 'SYSTEM Discovery did not publish a fresh report.' }
    } finally {
        if ($created) {
            Stop-ScheduledTask -TaskName $name -ErrorAction Stop
            $deadline = (Get-Date).AddSeconds(30)
            while ((Get-ScheduledTask -TaskName $name).State -in @('Running', 'Queued')) {
                if ((Get-Date) -ge $deadline) { throw 'Probe did not stop; scratch data must be retained.' }
                Start-Sleep -Seconds 1
            }
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            Remove-Item -LiteralPath (Join-Path $Root 'probe-active.txt') -ErrorAction Stop
        }
    }
}

function Select-SocInterface {
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop)
    if (-not $routes.Count) { throw 'No active physical default-route NIC found. Specify -InterfaceGuid explicitly for an approved adapter.' }
    $adapters = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.ifIndex -in @($routes.InterfaceIndex) })
    if (-not $adapters.Count) { throw 'No active physical default-route NIC found. Specify -InterfaceGuid explicitly for VPN/virtual adapters.' }
    for ($i = 0; $i -lt $adapters.Count; $i++) {
        $ips = @(Get-NetIPAddress -InterfaceIndex $adapters[$i].ifIndex -AddressFamily IPv4 -ErrorAction Stop | Select-Object -ExpandProperty IPAddress)
        Write-Host ('[{0}] {1} | {2}' -f ($i + 1), $adapters[$i].InterfaceDescription, ($ips -join ', '))
    }
    if ($adapters.Count -eq 1) {
        $answer = Read-Host 'Use this interface for metadata capture? [y/N]'
        if ($answer -notmatch '^(?i:y|yes)$') { throw 'Interface selection cancelled; capture was not started.' }
        return ([guid]$adapters[0].InterfaceGuid).ToString()
    }
    $answer = Read-Host 'Select the approved interface number (blank cancels)'
    $selection = 0
    if (-not [int]::TryParse($answer, [ref]$selection) -or $selection -lt 1 -or $selection -gt $adapters.Count) { throw 'Interface selection cancelled.' }
    return ([guid]$adapters[$selection - 1].InterfaceGuid).ToString()
}
