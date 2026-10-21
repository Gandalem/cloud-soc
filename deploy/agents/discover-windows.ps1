#requires -Version 5.1
# cloud-soc-policy-format: 1
param([switch]$Refresh, [string]$DiscoveryRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# BEGIN SECURITY CHANNELS
$script:SecurityChannels = @{
    'Security' = '1100,1102,4616,4624,4625,4634,4647,4648,4672,4688,4697,4698,4699,4700,4701,4702,4719,4720,4722,4723,4724,4725,4726,4728,4729,4732,4733,4738,4740,4756,4757,4767,4768,4769,4771,4776,4946,4947,4948,4950,5025'
    'System' = '104,6005,6006,6008,7040,7045'
    'Microsoft-Windows-Windows Defender/Operational' = '1006,1007,1008,1009,1010,1011,1116,1117,1118,1119,1121,1122,5001,5004,5007,5010,5012'
    'Microsoft-Windows-CodeIntegrity/Operational' = '3004,3033,3034,3076,3077,3089,3099'
    'Microsoft-Windows-AppLocker/EXE and DLL' = '8003,8004'
    'Microsoft-Windows-AppLocker/MSI and Script' = '8006,8007,8028,8029,8038'
    'Microsoft-Windows-AppLocker/Packaged app-Execution' = '8021,8022'
    'Microsoft-Windows-Sysmon/Operational' = '1,4,6,8,19,20,21,25'
    'Microsoft-Windows-PowerShell/Operational' = '4103,4104'
    'PowerShellCore/Operational' = '4103,4104'
    'Microsoft-Windows-TaskScheduler/Operational' = '106,140,141,142'
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' = '1149'
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' = '21,22,23,24,25,39,40'
}
$script:SecurityNoise = @{
    'Security' = '5156,5158'
    'Microsoft-Windows-Windows Defender/Operational' = '1000,1001,1150'
    'Microsoft-Windows-Sysmon/Operational' = '3,5,7,11,22,23,26'
    'Microsoft-Windows-AppLocker/EXE and DLL' = '8002'
    'Microsoft-Windows-AppLocker/MSI and Script' = '8005'
    'Microsoft-Windows-AppLocker/Packaged app-Execution' = '8020,8023'
    'Microsoft-Windows-PowerShell/Operational' = '4105,4106'
    'PowerShellCore/Operational' = '4105,4106'
    'Microsoft-Windows-TaskScheduler/Operational' = '100,102,200,201'
}
# END SECURITY CHANNELS

function Get-SecurityRoles([string]$Root) {
    $path = Join-Path $Root 'security-roles.json'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    if ((Test-ReparseAncestor $path) -or (Get-Item -LiteralPath $path).Length -gt 8192) { throw 'Invalid security role policy.' }
    $p = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($p.schema -ne 1 -or $p.roles -isnot [array] -or @($p.PSObject.Properties.Name | Where-Object { $_ -notin @('schema','roles') }).Count -or
        @($p.roles | Select-Object -Unique).Count -ne @($p.roles).Count -or @($p.roles | Where-Object { $_ -notin @('packages','sysmon_network','directory_service','application') }).Count) { throw 'Unknown security role.' }
    return @($p.roles)
}

function Get-DiscoveryId([string]$Value) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Get-DefaultLogRoots {
    return @((Join-Path $env:SystemRoot 'System32\LogFiles\Firewall'))
}

function Assert-LogRoot([string]$Path) {
    if ($Path -notmatch '^[a-zA-Z]:[\\/]' -or $Path -match '[\x00-\x1f$*?\[\]{}]' -or $Path -match '(^|[\\/])\.\.?([\\/]|$)') { throw "Unsafe log root: $Path" }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    $forbidden = @([IO.Path]::GetPathRoot($full).TrimEnd('\'), $env:SystemRoot, $env:ProgramData, $env:ProgramFiles, [Environment]::GetFolderPath('ProgramFilesX86'),
        (Join-Path ($env:SystemDrive + '\') 'Users'), (Join-Path $env:SystemRoot 'System32'))
    if ($full -in $forbidden -or $full -match '^[a-zA-Z]:\\Users(\\|$)') { throw "Select a log directory, not a drive, user-profile or system root: $Path" }
    $agent = Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'
    if ($full -ieq $agent -or $full.StartsWith($agent + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Collector files cannot be collected recursively.' }
    return $full
}

function Test-ReparseAncestor([string]$Path) {
    $cursor = $Path
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $true }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor.TrimEnd('\'))
    }
    return $false
}

function Get-LogEncoding([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $buffer = New-Object byte[] 8192
        $length = $stream.Read($buffer, 0, $buffer.Length)
        if (-not $length) { return 'empty_pending' }
        if ($length -ge 4 -and $buffer[0] -eq 255 -and $buffer[1] -eq 254 -and $buffer[2] -eq 0 -and $buffer[3] -eq 0) { return 'unsupported_encoding' }
        if ($length -ge 2 -and $buffer[0] -eq 255 -and $buffer[1] -eq 254) { return 'utf-16le-bom' }
        if ($length -ge 2 -and $buffer[0] -eq 254 -and $buffer[1] -eq 255) { return 'utf-16be-bom' }
        for ($i = 0; $i -lt $length; $i++) {
            if ($buffer[$i] -lt 32 -and $buffer[$i] -notin @(9, 10, 12, 13)) { return 'binary' }
        }
        $decoder = (New-Object Text.UTF8Encoding($false, $true)).GetDecoder()
        $chars = New-Object char[] 8192
        # A sample may end midway through a UTF-8 character; only flush at EOF.
        try { $null = $decoder.GetChars($buffer, 0, $length, $chars, 0, ($stream.Position -eq $stream.Length)) }
        catch [Text.DecoderFallbackException] { return 'unsupported_encoding' }
        return 'utf-8'
    } finally { $stream.Dispose() }
}

function Get-SourceDiscovery([string[]]$LogRoots, [string[]]$RequiredChannels = @(), [string[]]$Exclusions = @(), [string[]]$SecurityRoles = @()) {
    $entries = New-Object 'Collections.Generic.List[object]'
    $inputs = New-Object 'Collections.Generic.List[object]'
    $errors = @()
    $logs = @(Get-WinEvent -ListLog * -Force -ErrorAction SilentlyContinue -ErrorVariable errors)
    foreach ($errorRecord in $errors) {
        $entries.Add(@{ kind = 'channel'; name = [string]$errorRecord.TargetObject; status = 'enumeration_error' })
    }
    $selected = @{}
    foreach ($log in ($logs | Sort-Object LogName -Unique)) {
        $name = [string]$log.LogName
        $status = 'selected'
        if (-not $log.IsEnabled) { $status = 'disabled' }
        elseif ([string]$log.LogType -in @('Analytical', 'Analytic', 'Debug')) { $status = 'unsupported_direct_channel' }
        elseif ($name -match '[\x00-\x1f${}]') { $status = 'unsafe_name' }
        elseif (-not $script:SecurityChannels.ContainsKey($name) -and $name -notin $RequiredChannels -and
            -not ($SecurityRoles -contains 'application' -and $name -eq 'Application') -and
            -not ($SecurityRoles -contains 'directory_service' -and $name -in @('Directory Service','DNS Server','DFS Replication'))) { $status = 'policy_excluded' }
        $entries.Add(@{ kind = 'channel'; name = $name; status = $status })
        if ($status -ne 'selected') { continue }
        $selected[$name] = $true
        $inputs.Add([ordered]@{
            type = 'winlog'; id = ('cloud-soc-event-' + (Get-DiscoveryId $name)); name = $name
            include_xml = $false; ignore_missing_channel = $true
            fields_under_root = $true
            fields = [ordered]@{ labels = [ordered]@{ log_source = 'windows_event'; collection_mode = 'auto_discovery' } }
        })
        $channelInput = $inputs[$inputs.Count - 1]
        $channelInput.fields.labels.collection_policy = 'security-focused-v1'
        if ($script:SecurityChannels.ContainsKey($name)) {
            $ids = $script:SecurityChannels[$name]
            if ($name -eq 'Microsoft-Windows-Sysmon/Operational' -and $SecurityRoles -contains 'sysmon_network') { $ids += ',3,11,22,26' }
            if ($name -eq 'Security' -and $SecurityRoles -contains 'sysmon_network') { $ids += ',5156,5158' }
            # Native Event Log queries have a limited condition budget. Filter
            # inside Beats rather than split the stable input/bookmark identity.
            $filter = "var allowed=[],noise=[]; function register(p){allowed=p.ids.split(',');noise=(p.noise||'').split(',');} function process(event){var id=event.Get('winlog.event_id');if(id===null||id===undefined)id=event.Get('event.code');if(/^(error|critical|warning|warn|alert|emerg)$/i.test(String(event.Get('log.level')))||event.Get('event.outcome')==='failure')return event;if(/^[0-9]{1,5}$/.test(String(id))&&noise.indexOf(String(id))>=0&&allowed.indexOf(String(id))<0)event.Cancel();return event;}"
            $channelInput.processors = @(@{script=@{lang='javascript';source=$filter;params=@{ids=$ids;noise=$script:SecurityNoise[$name]};tag_on_exception='_security_selection_error'}})
        }
    }
    if (-not $selected.Count) { throw 'No supported active event channels were discovered; previous configuration retained.' }
    foreach ($name in $RequiredChannels) {
        if (-not $selected.ContainsKey($name)) { throw "Required channel is absent, disabled or unsupported: $name" }
    }
    $pathsByEncoding = @{}
    $seen = @{}
    foreach ($root in ($LogRoots | Sort-Object -Unique)) {
        $root = Assert-LogRoot $root
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            $entries.Add(@{ kind = 'directory'; name = $root; status = 'missing' }); continue
        }
        if (Test-ReparseAncestor $root) {
            $entries.Add(@{ kind = 'directory'; name = $root; status = 'reparse_point' }); continue
        }
        $pending = New-Object 'Collections.Generic.Stack[string]'
        $pending.Push($root)
        while ($pending.Count) {
            $directory = $pending.Pop()
            try { $children = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) }
            catch { $entries.Add(@{ kind = 'directory'; name = $directory; status = 'unreadable' }); continue }
            foreach ($item in $children) {
                $path = $item.FullName
                if ($seen.ContainsKey($path)) { continue }; $seen[$path] = $true
                $status = 'selected'
                $excluded = @($Exclusions | Where-Object { $path -ieq $_ -or $path.StartsWith($_.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
                if ($excluded) { $status = 'policy_excluded' }
                elseif ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $status = 'reparse_point' }
                elseif ($path -match '[\x00-\x1f$*?\[\]{}]') { $status = 'unsafe_path' }
                elseif ($item.PSIsContainer) { $pending.Push($path); continue }
                elseif ($path -notmatch '[\\/]System32[\\/]LogFiles[\\/]Firewall[\\/]pfirewall(?:_(?:Domain|Private|Public))?\.log(?:\.[0-9]+)?$') { $status = 'policy_excluded' }
                elseif ($path -match '\.(evtx|etl|gz|zip|7z|cab|dmp|db|sqlite|pem|key|crt|cer|der|pfx|p12|docx?|xlsx?|pdf|kdbx)$' -or $path -match '[\\/](\.env|id_rsa|id_ed25519|id_ecdsa|credentials|secrets?)(\.|[\\/]|$)') { $status = 'binary_archive_or_secret' }
                else {
                    try { $encoding = Get-LogEncoding $path }
                    catch { $encoding = 'unreadable' }
                    if ($encoding -notin @('utf-8', 'utf-16le-bom', 'utf-16be-bom')) { $status = $encoding }
                    else {
                        if (-not $pathsByEncoding.ContainsKey($encoding)) { $pathsByEncoding[$encoding] = New-Object 'Collections.Generic.List[string]' }
                        $pathsByEncoding[$encoding].Add($path.Replace('\', '/'))
                    }
                }
                $entries.Add(@{ kind = 'file'; name = $path; status = $status })
            }
        }
    }
    foreach ($encoding in ($pathsByEncoding.Keys | Sort-Object)) {
        $inputs.Add([ordered]@{
            type = 'filestream'; id = "cloud-soc-windows-files-$encoding-v2"
            paths = @($pathsByEncoding[$encoding] | Sort-Object -Unique); encoding = $encoding
            'prospector.scanner.symlinks' = $false
            'file_identity.fingerprint' = [ordered]@{ growing = $true }
            fields_under_root = $true
            fields = [ordered]@{ labels = [ordered]@{ log_source = 'windows_file'; collection_mode = 'auto_discovery'; collection_policy = 'security-focused-v1' } }
        })
    }
    return @{
        inputs = @($inputs.ToArray())
        report = @{ generated_at = [DateTime]::UtcNow.ToString('o'); entries = @($entries.ToArray()); selected_channels = $selected.Count }
    }
}

function Write-DiscoveryFile([string]$Path, [string]$Content) {
    if (Test-Path -LiteralPath $Path) {
        if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing reparse-point output.' }
        if ([IO.File]::ReadAllText($Path) -ceq $Content) { return }
    }
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($Path)) ([Guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($temporary, $Content, (New-Object Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $Path) }
}

function Update-SourceDiscovery([string]$Root, [string[]]$LogRoots, [string[]]$RequiredChannels = @()) {
    $lock = [IO.File]::Open((Join-Path $Root 'discovery.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        if ($null -eq $LogRoots) {
            $settings = Get-Content -LiteralPath (Join-Path $Root 'discovery-settings.json') -Raw | ConvertFrom-Json
            $LogRoots = $settings.log_roots; $RequiredChannels = $settings.required_channels
        }
        $version = 0; $exclusions = @()
        $policyPath = Join-Path $Root 'collection-policy.txt'
        if (Test-Path -LiteralPath $policyPath) {
            if (Test-ReparseAncestor $policyPath) { throw 'Unsafe policy file.' }
            $lines = [IO.File]::ReadAllLines($policyPath)
            if (-not $lines.Count -or $lines[0] -notmatch '^version=([0-9]{1,9})$') { throw 'Invalid policy version.' }
            $version = [int]$Matches[1]; $LogRoots = @()
            foreach ($line in ($lines | Select-Object -Skip 1)) {
                if ($line.StartsWith('root=')) { $LogRoots += (Assert-LogRoot $line.Substring(5)) }
                elseif ($line.StartsWith('exclude=')) { $exclusions += (Assert-LogRoot $line.Substring(8)) }
                else { throw 'Invalid policy record.' }
            }
            if (-not $LogRoots.Count) { throw 'No policy roots.' }
        }
        $discovery = Get-SourceDiscovery -LogRoots $LogRoots -RequiredChannels $RequiredChannels -Exclusions $exclusions -SecurityRoles @(Get-SecurityRoles $Root)
        Write-DiscoveryFile (Join-Path $Root 'inputs\discovered.yml') (ConvertTo-Json -InputObject @($discovery.inputs) -Depth 16)
        Write-DiscoveryFile (Join-Path $Root 'discovery-report.json') ($discovery.report | ConvertTo-Json -Depth 8)
        Write-HealthReport -Root $Root -Report $discovery.report -Version $version
    } finally { $lock.Dispose() }
}

function Write-HealthReport([string]$Root, $Report, [int]$Version = 0) {
    $entries = @($Report.entries)
    $selected = @($entries | Where-Object { $_.status -eq 'selected' }).Count
    $errors = @($entries | Where-Object { $_.status -in @('unreadable', 'enumeration_error') }).Count
    $summary = [ordered]@{ schema = 1; generated_at = $Report.generated_at; policy_version = $version
        selected = $selected; excluded = ($entries.Count - $selected - $errors); errors = $errors; total = $entries.Count
        sources = @($entries | Select-Object -First 200 | ForEach-Object { @{ id = (Get-DiscoveryId ([string]$_.name)); status = $_.status } })
        queue_state = 'unknown'; transport_state = 'unknown' }
    $spool = Join-Path $Root 'health.ndjson'
    $previous = Join-Path $Root 'health-previous.ndjson'
    foreach ($path in @($spool, $previous)) {
        if (Test-ReparseAncestor $path) { throw 'Unsafe health spool.' }
    }
    if ((Test-Path -LiteralPath $spool) -and (Get-Item -LiteralPath $spool).Length -gt 5242880) {
        Move-Item -LiteralPath $spool -Destination $previous -Force
    }
    [IO.File]::AppendAllText($spool, ($summary | ConvertTo-Json -Depth 8 -Compress) + "`n", (New-Object Text.UTF8Encoding($false)))
    $input = @(@{ type = 'filestream'; id = 'cloud-soc-health-v1'; paths = @((Join-Path $Root 'health*.ndjson'))
        'prospector.scanner.fingerprint.length' = 64
        parsers = @(@{ ndjson = @{ target = 'cloud_soc.discovery' } }); fields_under_root = $true
        fields = @{ labels = @{ log_source = 'agent_health' } }
        processors = @(@{ drop_fields = @{ fields = @('message'); ignore_missing = $true } }) })
    Write-DiscoveryFile (Join-Path $Root 'inputs\health.yml') (ConvertTo-Json -InputObject $input -Depth 12)
}

if ($Refresh) {
    try {
        $root = if ($DiscoveryRoot) { $DiscoveryRoot } else { Join-Path $env:ProgramFiles 'Cloud-SOC-Agent' }
        if ($root -notmatch '^[A-Za-z]:[\\/]' -or (Test-ReparseAncestor $root)) { throw 'Unsafe discovery root.' }
        Update-SourceDiscovery -Root $root
    } catch { [Console]::Error.WriteLine("Discovery failed; inspect discovery-report.json and task history: $($_.Exception.Message)"); exit 1 }
}
