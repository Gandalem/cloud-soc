#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Endpoint,
    [Parameter(Mandatory = $true)][string]$CaPath,
    [Parameter(Mandatory = $true)][string]$Organization,
    [string[]]$AdditionalChannel = @(),
    [string[]]$AdditionalLogRoot = @(),
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Version = '9.5.2'
$ServiceName = 'cloud-soc-filebeat'
$DiscoveryTask = 'Cloud-SOC-Discovery'
. (Join-Path $PSScriptRoot 'discover-windows.ps1')
$Root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Cloud-SOC-Agent'
$BeatHome = Join-Path $Root "filebeat-$Version-windows-x86_64"
$Exe = Join-Path $BeatHome 'filebeat.exe'
$ConfigPath = Join-Path $Root 'filebeat.yml'
$DataPath = Join-Path $Root 'data'
$LogsPath = Join-Path $Root 'logs'
$Hash = 'cdb07ad1e39e7c65cefcd7c71e1dfcfa4f92b00daafc132c78490e3e04f664f67403cdb925c5873a8441058d6de08d29790bf6776748edc63582f50174c508c8'
$Channels = @('Application', 'Security', 'System') + $AdditionalChannel
$LogRoots = @(Get-DefaultLogRoots) + $AdditionalLogRoot
$CommonArgs = @('--path.home', $BeatHome, '--path.config', $Root, '--path.data', $DataPath, '--path.logs', $LogsPath, '-c', $ConfigPath)
$ServiceCreated = $false
$RootCreated = $false
$TaskCreated = $false

function Assert-Arguments {
    if ($Endpoint -cnotmatch '^https://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:([0-9]{1,5}))?/?\z') {
        throw 'Use an HTTPS DNS/IPv4 endpoint without credentials, path, query or fragment.'
    }
    $portValue = $Matches[4]
    if ($portValue -and ([int]$portValue -lt 1 -or [int]$portValue -gt 65535)) { throw 'Invalid endpoint port.' }
    if ($Organization -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\z') { throw 'Invalid organization identifier (1-64 letters, digits, underscore, hyphen).' }
    if ($CaPath -notmatch '^[a-zA-Z]:[\\/]' -or $CaPath -match '[\x00-\x1f${}]') { throw 'CA must be an absolute local Windows path without control characters or variable expansion.' }
    $seen = @{}
    foreach ($channel in $Channels) {
        if ($channel -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9 /_.-]{0,199}\z') { throw 'Invalid channel name. Supply explicit event channels, not wildcards.' }
        if ($seen.ContainsKey($channel)) { throw "Duplicate channel: $channel" }
        $seen[$channel] = $true
    }
    if ($Root -match '["\r\n${}]') { throw 'Unsupported Program Files path.' }
    foreach ($path in $LogRoots) { $null = Assert-LogRoot $path }
}

function Get-AgentConfig {
    return @{
        'filebeat.config.inputs' = @{ enabled = $true; path = (Join-Path $Root 'inputs\*.yml'); 'reload.enabled' = $true; 'reload.period' = '10s' }
        processors = @(
            @{ add_host_metadata = @{} },
            @{ add_fields = @{ target = 'organization'; fields = @{ id = $Organization } } }
        )
        'output.elasticsearch' = @{
            hosts = @($Endpoint.TrimEnd('/'))
            api_key = '${CLOUD_SOC_API_KEY}'
            'ssl.certificate_authorities' = @((Join-Path $Root 'ca.crt'))
            'ssl.verification_mode' = 'full'
            index = "soc-host-raw-windows-$Version-%{+yyyy.MM.dd}"
            timeout = 30
        }
        'setup.ilm.enabled' = $false
        'setup.template.enabled' = $false
        'logging.level' = 'info'
        'logging.to_files' = $true
        'logging.to_eventlog' = $false
        'queue.disk' = @{ max_size = '1GB' }
    }
}

function Assert-NoInstallation {
    foreach ($name in @($ServiceName, 'cloud-soc-winlogbeat', 'winlogbeat', 'filebeat', 'elastic-agent')) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "Existing service: $name. No automatic replacement is allowed." }
    }
    if (Get-ScheduledTask -TaskName $DiscoveryTask -ErrorAction SilentlyContinue) { throw 'Existing discovery task; no automatic replacement.' }
    foreach ($path in @($Root, (Join-Path $env:ProgramFiles 'Filebeat'), (Join-Path $env:ProgramFiles 'Filebeat-Data'), (Join-Path $env:ProgramData 'filebeat'), (Join-Path $env:ProgramFiles 'Winlogbeat'), (Join-Path $env:ProgramFiles 'Winlogbeat-Data'), (Join-Path $env:ProgramFiles 'Elastic'), (Join-Path $env:ProgramData 'winlogbeat'))) {
        if (Test-Path -LiteralPath $path) { throw "Existing installation or partial state: $path. Review it manually." }
    }
    foreach ($name in @('winlogbeat', 'filebeat', 'elastic-agent')) {
        if (Get-Process -Name $name -ErrorAction SilentlyContinue) { throw "Collector already running: $name" }
    }
}

function Assert-ArchiveHash([string]$Path, [string]$Expected) {
    if ($Expected -cnotmatch '^[a-f0-9]{128}$' -or (Get-FileHash -LiteralPath $Path -Algorithm SHA512).Hash -ine $Expected) {
        throw 'SHA-512 mismatch; refusing to extract or execute the download.'
    }
}

function Invoke-Beat([string[]]$BeatArguments) {
    & $Exe @CommonArgs @BeatArguments
    if ($LASTEXITCODE -ne 0) { throw "Filebeat $($BeatArguments -join ' ') failed (exit $LASTEXITCODE)." }
}

function Set-ProtectedDirectory([string]$Path) {
    # Keystore obfuscation is not an access-control boundary; restrict the entire tree.
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

function Test-DiscoveryTask {
    $started = (Get-Date).AddSeconds(-1)
    $deadline = (Get-Date).AddMinutes(5)
    Start-ScheduledTask -TaskName $DiscoveryTask
    do {
        Start-Sleep -Seconds 1
        $info = Get-ScheduledTaskInfo -TaskName $DiscoveryTask
        $task = Get-ScheduledTask -TaskName $DiscoveryTask
        if ($info.LastRunTime -ge $started -and $task.State -ne 'Running') {
            if ($info.LastTaskResult -ne 0) { throw "Discovery task failed (exit $($info.LastTaskResult)); inspect execution policy and source access." }
            return
        }
    } while ((Get-Date) -lt $deadline)
    throw 'Discovery task did not finish successfully within five minutes.'
}

try {
    Assert-Arguments
    $config = Get-AgentConfig | ConvertTo-Json -Depth 12
    if ($DryRun) {
        $config
        [Console]::Error.WriteLine('DRY RUN: automatic active event channels + recursive text log discovery every minute. No source inventory in this preview; generated on the server.')
        [Console]::Error.WriteLine('No download, writes, key prompt, OS/source checks, network or service changes.')
        exit 0
    }
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Use 64-bit PowerShell on Windows x86_64.' }
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as Administrator (not required for -DryRun).' }
    Assert-NoInstallation
    if (-not (Test-Path -LiteralPath $CaPath -PathType Leaf)) { throw 'CA certificate file does not exist.' }
    $null = Get-SourceDiscovery -LogRoots $LogRoots -RequiredChannels $Channels

    # New-Item without -Force fails if another installer created the directory first.
    New-Item -ItemType Directory -Path $Root | Out-Null
    $RootCreated = $true
    Set-ProtectedDirectory $Root
    foreach ($path in @($DataPath, $LogsPath, (Join-Path $Root 'inputs'))) { New-Item -ItemType Directory -Path $path | Out-Null }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'discover-windows.ps1') -Destination $Root
    $settings = @{ log_roots = @($LogRoots); required_channels = @($Channels) } | ConvertTo-Json -Depth 8
    Write-DiscoveryFile (Join-Path $Root 'discovery-settings.json') $settings
    Update-SourceDiscovery -Root $Root -LogRoots $LogRoots -RequiredChannels $Channels
    $package = "filebeat-$Version-windows-x86_64.zip"
    $archive = Join-Path $Root $package
    $oldTls = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri "https://artifacts.elastic.co/downloads/beats/filebeat/$package" -OutFile $archive -TimeoutSec 600 -MaximumRedirection 0
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $oldTls
    }
    Assert-ArchiveHash $archive $Hash
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $prefix = "filebeat-$Version-windows-x86_64/"
        foreach ($entry in $zip.Entries) {
            if (-not $entry.FullName.StartsWith($prefix, [StringComparison]::Ordinal) -or $entry.FullName -match '(^|/)\.\.(/|$)|[\\:]') { throw 'Unexpected archive path.' }
        }
    } finally { $zip.Dispose() }
    Expand-Archive -LiteralPath $archive -DestinationPath $Root
    Copy-Item -LiteralPath $CaPath -Destination (Join-Path $Root 'ca.crt')
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($ConfigPath, '{}', $utf8)
    Invoke-Beat -BeatArguments @('keystore', 'create')
    Write-Host 'Enter the restricted Elasticsearch API key as id:api_key (not the encoded value).'
    Invoke-Beat -BeatArguments @('keystore', 'add', 'CLOUD_SOC_API_KEY')
    [IO.File]::WriteAllText($ConfigPath, $config, $utf8)
    Invoke-Beat -BeatArguments @('test', 'config')
    Invoke-Beat -BeatArguments @('test', 'output')

    # Quote every path and use the same data/keystore path for preflight and service.
    $command = '"{0}" --environment=windows_service --path.home "{1}" --path.config "{2}" --path.data "{3}" --path.logs "{4}" -c "{5}" -E logging.files.redirect_stderr=true' -f $Exe, $BeatHome, $Root, $DataPath, $LogsPath, $ConfigPath
    New-Service -Name $ServiceName -DisplayName 'Cloud SOC Filebeat' -BinaryPathName $command -StartupType Manual | Out-Null
    $ServiceCreated = $true
    Start-Service -Name $ServiceName
    (Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 3
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') { throw 'Service did not remain running.' }
    Set-Service -Name $ServiceName -StartupType Automatic
    # Respect the machine's existing PowerShell execution policy; never bypass it.
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -File "{0}" -Refresh' -f (Join-Path $Root 'discover-windows.ps1'))
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -StartWhenAvailable
    Register-ScheduledTask -TaskName $DiscoveryTask -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings | Out-Null
    $TaskCreated = $true
    Test-DiscoveryTask
    Write-Host 'Service active; TLS/auth connection test passed. Document ingestion is NOT yet verified. Check soc-host-raw-windows-* in Kibana.'
    exit 0
} catch {
    if ($TaskCreated) { Disable-ScheduledTask -TaskName $DiscoveryTask -ErrorAction Continue | Out-Null }
    if ($ServiceCreated) {
        Stop-Service -Name $ServiceName -ErrorAction Continue
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Continue
    }
    [Console]::Error.WriteLine("Installation failed: $($_.Exception.Message)")
    if ($RootCreated) { [Console]::Error.WriteLine("Protected partial state retained at $Root. Review before reinstalling; no automatic cleanup.") }
    exit 1
}
