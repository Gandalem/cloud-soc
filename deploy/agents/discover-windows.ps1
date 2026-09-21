#requires -Version 5.1
param([switch]$Refresh)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-DiscoveryId([string]$Value) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value.ToLowerInvariant())))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Get-DefaultLogRoots {
    return @((Join-Path $env:SystemRoot 'Logs'), (Join-Path $env:SystemRoot 'System32\LogFiles'),
        (Join-Path ($env:SystemDrive + '\') 'inetpub\logs'), (Join-Path $env:ProgramData 'logs'))
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

function Get-SourceDiscovery([string[]]$LogRoots, [string[]]$RequiredChannels = @()) {
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
        $entries.Add(@{ kind = 'channel'; name = $name; status = $status })
        if ($status -ne 'selected') { continue }
        $selected[$name] = $true
        $inputs.Add([ordered]@{
            type = 'winlog'; id = ('cloud-soc-event-' + (Get-DiscoveryId $name)); name = $name
            include_xml = $true; ignore_missing_channel = $true
            fields_under_root = $true
            fields = [ordered]@{ labels = [ordered]@{ log_source = 'windows_event'; collection_mode = 'auto_discovery' } }
        })
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
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $status = 'reparse_point' }
                elseif ($path -match '[\x00-\x1f$*?\[\]{}]') { $status = 'unsafe_path' }
                elseif ($item.PSIsContainer) { $pending.Push($path); continue }
                elseif ($path -match '\.(evtx|etl|gz|zip|7z|cab|dmp|db|sqlite|pem|key|crt|cer|der|pfx|p12)$' -or $path -match '[\\/](\.env|id_rsa|id_ed25519|id_ecdsa)(\.|$)') { $status = 'binary_archive_or_secret' }
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
            fields = [ordered]@{ labels = [ordered]@{ log_source = 'windows_file'; collection_mode = 'auto_discovery' } }
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
        $discovery = Get-SourceDiscovery -LogRoots $LogRoots -RequiredChannels $RequiredChannels
        Write-DiscoveryFile (Join-Path $Root 'inputs\discovered.yml') (ConvertTo-Json -InputObject @($discovery.inputs) -Depth 16)
        Write-DiscoveryFile (Join-Path $Root 'discovery-report.json') ($discovery.report | ConvertTo-Json -Depth 8)
    } finally { $lock.Dispose() }
}

if ($Refresh) {
    try {
        $root = Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'
        $settings = Get-Content -LiteralPath (Join-Path $root 'discovery-settings.json') -Raw | ConvertFrom-Json
        Update-SourceDiscovery -Root $root -LogRoots $settings.log_roots -RequiredChannels $settings.required_channels
    } catch { [Console]::Error.WriteLine("Discovery failed; inspect discovery-report.json and task history: $($_.Exception.Message)"); exit 1 }
}
