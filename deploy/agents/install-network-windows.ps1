#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Endpoint,
    [Parameter(Mandatory = $true)][string]$CaPath,
    [Parameter(Mandatory = $true)][string]$Organization,
    [string]$InterfaceGuid,
    [switch]$PreflightOnly,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'download-windows.ps1')
. (Join-Path $PSScriptRoot 'transaction-windows.ps1')
$Version = '9.5.2'
$ServiceName = 'cloud-soc-packetbeat'
$Root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Cloud-SOC-Network'
$FinalRoot = $Root
$Stage = $null
$ServiceStarted = $false
$BeatHome = Join-Path $Root "packetbeat-$Version-windows-x86_64"
$Exe = Join-Path $BeatHome 'packetbeat.exe'
$ConfigPath = Join-Path $Root 'packetbeat.yml'
$DataPath = Join-Path $Root 'data'
$LogsPath = Join-Path $Root 'logs'
$Hash = 'd85de062273901fef2a1fe00b5b1dc4da01d764a65be72ccd2ae0e6d473e6a8cc8525244cf1c64a5f568416041118cef5ee44a2cd927a16315b255bad130cbac'
$CommonArgs = @('--path.home', $BeatHome, '--path.config', $Root, '--path.data', $DataPath, '--path.logs', $LogsPath, '-c', $ConfigPath)
$ServiceCreated = $false
$RootCreated = $false

function Assert-Arguments {
    if ($Endpoint -cnotmatch '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:([0-9]{1,5}))?/?\z') { throw 'Use an HTTPS DNS/IPv4 endpoint without credentials, path, query or fragment.' }
    $portValue = $Matches[4]
    if ($portValue -and ([int]$portValue -lt 1 -or [int]$portValue -gt 65535)) { throw 'Invalid endpoint port.' }
    if ($Organization -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\z') { throw 'Invalid organization identifier.' }
    if ($CaPath -notmatch '^[a-zA-Z]:[\\/]' -or $CaPath -match '[\x00-\x1f${}]') { throw 'CA must be an absolute local Windows path without variable expansion.' }
    if ($InterfaceGuid -and ($InterfaceGuid -cnotmatch '^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\z' -or [guid]$InterfaceGuid -eq [guid]::Empty)) { throw 'Supply the non-empty InterfaceGuid from Get-NetAdapter, without braces.' }
    if ($Root -match '["\x00-\x1f${}]') { throw 'Unsupported Program Files path.' }
}

function Set-AgentPaths([string]$Path) {
    $script:Root = $Path
    $script:BeatHome = Join-Path $Path "packetbeat-$Version-windows-x86_64"
    $script:Exe = Join-Path $BeatHome 'packetbeat.exe'
    $script:ConfigPath = Join-Path $Path 'packetbeat.yml'
    $script:DataPath = Join-Path $Path 'data'
    $script:LogsPath = Join-Path $Path 'logs'
    $script:CommonArgs = @('--path.home', $BeatHome, '--path.config', $Root, '--path.data', $DataPath, '--path.logs', $LogsPath, '-c', $ConfigPath)
}

function Get-AgentConfig {
    $config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'packetbeat.base.json') -Raw | ConvertFrom-Json
    $config.'packetbeat.interfaces'.device = '\Device\NPF_{' + $InterfaceGuid.ToUpperInvariant() + '}'
    $config.processors[1].add_fields.fields.id = $Organization
    $config.processors[2].add_fields.fields.sensor_platform = 'windows'
    $config.'output.elasticsearch'.hosts = @($Endpoint.TrimEnd('/'))
    $config.'output.elasticsearch'.'ssl.certificate_authorities' = @((Join-Path $Root 'ca.crt'))
    $config.'output.elasticsearch'.index = "soc-network-windows-$Version-%{+yyyy.MM.dd}"
    return $config
}

function Assert-NoInstallation {
    # Filebeat is allowed: this is an independent add-on, not a replacement.
    foreach ($name in @($ServiceName, 'packetbeat', 'elastic-agent')) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "Existing service: $name. No automatic replacement." }
    }
    foreach ($path in @($Root, (Join-Path $env:ProgramFiles 'Packetbeat'), (Join-Path $env:ProgramFiles 'Packetbeat-Data'), (Join-Path $env:ProgramData 'packetbeat'), (Join-Path $env:ProgramFiles 'Elastic'))) {
        if (Test-Path -LiteralPath $path) { throw "Existing installation or partial state: $path" }
    }
    foreach ($name in @('packetbeat', 'elastic-agent')) {
        if (Get-Process -Name $name -ErrorAction SilentlyContinue) { throw "Collector already running: $name" }
    }
}

function Assert-Npcap {
    $driver = Get-Service -Name npcap -ErrorAction SilentlyContinue
    $dll = Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll'
    if (-not $driver -or $driver.Status -ne 'Running' -or -not (Test-Path -LiteralPath $dll -PathType Leaf)) {
        throw 'Install and start approved x64 Npcap first. This installer does not install or start its driver.'
    }
    # never_install alone is insufficient when Npcap is absent. Check the actual DLL
    # without opening any capture device before invoking the bundled executable.
    if (-not ('CloudSocNetworkPcap' -as [type])) {
        $source = 'using System; using System.Runtime.InteropServices; public static class CloudSocNetworkPcap { [DllImport(@"__DLL__", CallingConvention=CallingConvention.Cdecl)] public static extern IntPtr pcap_lib_version(); }'.Replace('__DLL__', $dll.Replace('"', '""'))
        Add-Type -TypeDefinition $source
    }
    $npcapVersion = [Runtime.InteropServices.Marshal]::PtrToStringAnsi([CloudSocNetworkPcap]::pcap_lib_version())
    if (-not $npcapVersion.StartsWith('Npcap version', [StringComparison]::Ordinal)) { throw 'An Npcap-compatible DLL could not be verified; refusing to run Packetbeat.' }
}

function Assert-Interface {
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object { [guid]$_.InterfaceGuid -eq [guid]$InterfaceGuid })
    if ($adapters.Count -ne 1 -or $adapters[0].Status -ne 'Up') { throw 'Selected interface is missing or not Up. Check Get-NetAdapter -IncludeHidden.' }
}

function Assert-ArchiveHash([string]$Path, [string]$Expected) {
    if ($Expected -cnotmatch '^[a-f0-9]{128}$' -or (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash -ine $Expected) { throw 'SHA-512 mismatch; download will not be executed.' }
}

function Invoke-Beat([string[]]$BeatArguments) {
    Assert-Npcap
    & $Exe @CommonArgs @BeatArguments
    if ($LASTEXITCODE -ne 0) { throw "Packetbeat $($BeatArguments -join ' ') failed (exit $LASTEXITCODE)." }
}

function Set-ProtectedDirectory([string]$Path) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

try {
    if ($DryRun -and -not $InterfaceGuid) { $InterfaceGuid = '11111111-1111-1111-1111-111111111111' }
    Assert-Arguments
    $config = Get-AgentConfig | ConvertTo-Json -Depth 16
    if ($DryRun) {
        $config
        [Console]::Error.WriteLine('DRY RUN: no writes, download, network, Npcap loading, interface access, capture, keystore or service changes.')
        exit 0
    }
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Use 64-bit PowerShell on Windows x86_64.' }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as Administrator (not required for -DryRun).' }
    Assert-NoInstallation
    Assert-SocLocalPath $FinalRoot
    $null = Get-SystemCurl
    Assert-Npcap
    if (-not $InterfaceGuid) { $InterfaceGuid = Select-SocInterface }
    Assert-Interface
    if (-not (Test-Path -LiteralPath $CaPath -PathType Leaf)) { throw 'CA certificate file does not exist.' }
    Test-SocServerTls -Endpoint $Endpoint -CaPath $CaPath
    if ($PreflightOnly) {
        Write-Host 'Network OS/admin/Npcap/NIC/TLS preflight passed. Key/config/ingestion are not verified yet.'
        exit 0
    }
    $Stage = New-SocStage
    Set-AgentPaths $Stage.Path
    $RootCreated = $true
    foreach ($path in @($DataPath, $LogsPath)) { New-Item -ItemType Directory -Path $path | Out-Null }
    $package = "packetbeat-$Version-windows-x86_64.zip"
    $archive = Join-Path $Root $package
    Receive-CloudSocArchive -Uri "https://artifacts.elastic.co/downloads/beats/packetbeat/$package" -OutFile $archive
    Assert-ArchiveHash $archive $Hash
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $prefix = "packetbeat-$Version-windows-x86_64/"
        foreach ($entry in $zip.Entries) {
            if (-not $entry.FullName.StartsWith($prefix, [StringComparison]::Ordinal) -or $entry.FullName -match '(^|/)\.\.(/|$)|[\\:]') { throw 'Unexpected archive path.' }
        }
    } finally { $zip.Dispose() }
    Expand-Archive -LiteralPath $archive -DestinationPath $Root
    Copy-Item -LiteralPath $CaPath -Destination (Join-Path $Root 'ca.crt')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'privacy.js') -Destination $Root
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    # Even preflight commands receive never_install, never an empty default config.
    [IO.File]::WriteAllText($ConfigPath, '{"packetbeat.npcap.never_install":true}', $utf8)
    Invoke-Beat -BeatArguments @('keystore', 'create')
    Write-Host 'Enter the network-only publisher API key as id:api_key (not encoded).'
    Invoke-Beat -BeatArguments @('keystore', 'add', 'CLOUD_SOC_NETWORK_API_KEY')
    [IO.File]::WriteAllText($ConfigPath, (Get-AgentConfig | ConvertTo-Json -Depth 16), $utf8)
    Invoke-Beat -BeatArguments @('test', 'config')
    Invoke-Beat -BeatArguments @('test', 'output')
    if (Test-Path -LiteralPath $FinalRoot) { throw 'Final destination appeared during preparation; installation stopped.' }
    Assert-SocLocalPath $FinalRoot
    [IO.Directory]::Move($Root, $FinalRoot)
    Set-AgentPaths $FinalRoot
    [IO.File]::WriteAllText($ConfigPath, (Get-AgentConfig | ConvertTo-Json -Depth 16), $utf8)
    Invoke-Beat -BeatArguments @('test', 'config')
    Invoke-Beat -BeatArguments @('test', 'output')
    $command = '"{0}" --environment=windows_service --path.home "{1}" --path.config "{2}" --path.data "{3}" --path.logs "{4}" -c "{5}" -E logging.files.redirect_stderr=true' -f $Exe, $BeatHome, $Root, $DataPath, $LogsPath, $ConfigPath
    New-Service -Name $ServiceName -DisplayName 'Cloud SOC Packetbeat' -BinaryPathName $command -StartupType Manual -DependsOn npcap | Out-Null
    $ServiceCreated = $true
    $ServiceStarted = $true
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 3
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') { throw 'Packetbeat did not remain running.' }
    Set-Service -Name $ServiceName -StartupType Automatic
    Write-Host 'Packetbeat is active. Metadata only; no PCAP storage. Verify soc-network-windows-* documents; startup/TLS checks do not prove ingestion.'
    exit 0
} catch {
    if ($ServiceCreated) {
        Stop-Service -Name $ServiceName -ErrorAction Continue
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Continue
    }
    [Console]::Error.WriteLine("Installation failed: $($_.Exception.Message)")
    if ($RootCreated -and $Stage -and -not $ServiceStarted -and -not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        try {
            $expected = if ($Root -eq $FinalRoot) { $FinalRoot } else { $Stage.Path }
            Remove-SocOwnedDirectory -Path $Root -ExpectedPath $expected -Token $Stage.Token
            [Console]::Error.WriteLine('Preparation rolled back. No Packetbeat service was started; correct the error and retry.')
        } catch { [Console]::Error.WriteLine('Safe cleanup could not finish; protected scratch state retained.') }
    } elseif ($RootCreated) { [Console]::Error.WriteLine("Post-start failure: state retained at $Root to preserve queues/keys. Repair is not yet supported; do not delete data.") }
    exit 1
}
