# Read-only audit of retained rejection diagnostics and OS record availability.
# No raw events, paths, channel names, keys, or event bodies are returned.
#requires -Version 5.1
param(
    [string]$Root = (Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'),
    [string]$ResultPath,
    [string]$Since,
    [string]$Until,
    [string]$BaselinePath,
    [ValidateRange(1,120)][int]$Seconds = 60
)
$ErrorActionPreference = 'Stop'
function Assert-AuditPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':')) { throw 'Only local filesystem paths are allowed.' }
    for ($part = $full; $part; $part = [IO.Path]::GetDirectoryName($part)) {
        if ((Test-Path -LiteralPath $part) -and ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked audit path is not allowed.' }
    }
    return $full
}
$rootPath = Assert-AuditPath $Root
$logPath = Assert-AuditPath (Join-Path $rootPath 'logs')
$destination=$null
if ($ResultPath) {
    $destination=Assert-AuditPath $ResultPath
    if (Test-Path -LiteralPath $destination) { throw 'Audit output already exists; not overwritten.' }
    if ($destination.StartsWith($logPath.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Audit output cannot be inside diagnostic inputs.' }
}
function Get-AuditTime([string]$Value) {
    if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$') { throw 'Use an explicit ISO-8601 timestamp with timezone.' }
    return [DateTimeOffset]::Parse($Value,[Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
}
$from=$null; $to=$null
if ([bool]$Since -ne [bool]$Until) { throw 'Since and Until must both be supplied.' }
if ($Since) {
    $from=Get-AuditTime $Since; $to=Get-AuditTime $Until
    if ($from -ge $to -or ($to-$from).TotalDays -gt 31) { throw 'Invalid audit time window (maximum 31 days).' }
}
$prior=$null
if ($BaselinePath) {
    $baselineFile=Get-Item -LiteralPath (Assert-AuditPath $BaselinePath)
    if ($baselineFile.PSIsContainer -or $baselineFile.Length -gt 16384) { throw 'Invalid baseline report size.' }
    $baseline=[IO.File]::ReadAllText($baselineFile.FullName) | ConvertFrom-Json
    if ($baseline.schema -notin @(1,2) -or $baseline.scope -ne 'retained_diagnostics_only' -or
        $baseline.complete_loss_count -ne $false -or $baseline.replay_performed -ne $false -or
        $baseline.field_limit_entries -isnot [ValueType] -or $baseline.field_limit_entries -is [bool] -or
        [double]$baseline.field_limit_entries -lt 0 -or [double]$baseline.field_limit_entries -gt 2147483647 -or
        [double]$baseline.field_limit_entries -ne [Math]::Floor([double]$baseline.field_limit_entries)) { throw 'Invalid baseline report.' }
    $prior=[int]$baseline.field_limit_entries
}
$clock = [Diagnostics.Stopwatch]::StartNew()
$report = [ordered]@{schema=2; checked_at=[DateTime]::UtcNow.ToString('o'); scope='retained_diagnostics_only';
    files=0; bytes_read=0L; lines=0; malformed=0; oversized=0; field_limit_entries=0;
    references_found=0; references_checked=0; os_record_present=0; os_record_absent=0; os_check_failed=0;
    truncated=$false; references_limited=$false; first_rejection_at=$null; last_rejection_at=$null;
    complete_loss_count=$false; replay_performed=$false;
    requested_since=if ($from) {$from.ToString('o')} else {$null}; requested_until=if ($to) {$to.ToString('o')} else {$null};
    prior_field_limit_entries=$prior; diagnostic_files=0; rejection_files=0; oldest_entry_at=$null; newest_entry_at=$null;
    entries_in_window=0; field_limit_entries_in_window=0; invalid_timestamps=0;
    evidence_state='not_checked'; historical_loss_count=$null; recovery_ready=$false; identity_verified=$false}
$refs = @{}
$first = $null; $last = $null
$oldest=$null; $newest=$null
# Rejection evidence must not be starved by high-volume metrics files.
$files = @(Get-ChildItem -LiteralPath $logPath -File | Where-Object { $_.Name -match '^filebeat(?:-events-data)?-.*\.ndjson$' } |
    Sort-Object @{Expression={if ($_.Name -like 'filebeat-events-data-*') {0} else {1}}}, @{Expression='LastWriteTimeUtc';Descending=$true} | Select-Object -First 33)
$report.diagnostic_files=$files.Count
$report.rejection_files=@($files | Where-Object {$_.Name -like 'filebeat-events-data-*'}).Count
if ($files.Count -gt 32) { $report.truncated=$true; $files=$files[0..31] }
foreach ($file in $files) {
    if ($clock.Elapsed.TotalSeconds -ge $Seconds -or $report.bytes_read -ge 67108864) { $report.truncated=$true; break }
    $path = Assert-AuditPath $file.FullName
    $stream = [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        # Bound memory/read volume even for malformed files without line endings.
        $limit = [int][Math]::Min([Math]::Min($stream.Length,8388608),67108864-$report.bytes_read)
        $bytes = New-Object byte[] $limit
        $used=0
        while ($used -lt $limit) { $n=$stream.Read($bytes,$used,$limit-$used); if ($n -eq 0) { break }; $used+=$n }
        $report.files++; $report.bytes_read+=$used
        if ($stream.Length -gt $used) { $report.truncated=$true }
        $text=[Text.Encoding]::UTF8.GetString($bytes,0,$used)
        $lines=$text.Split([char]10)
        # Do not parse a partial final record from an active or capped file.
        for ($i=0; $i -lt $lines.Length-1; $i++) {
            if ($clock.Elapsed.TotalSeconds -ge $Seconds) { $report.truncated=$true; break }
            $line=$lines[$i]; $report.lines++
            if ($line.Length -gt 524288) { $report.oversized++; continue }
            try { $entry=$line | ConvertFrom-Json } catch { $report.malformed++; continue }
            $date=[DateTimeOffset]::MinValue
            $hasTime=$false
            # Use the literal offset: JSON DateTime conversion differs in PS5/7.
            $timestamp=[regex]::Match($line,'(?<!\\)"@timestamp"\s*:\s*"(?<v>[^"\\\r\n]{20,40})"')
            if ($timestamp.Success -and $timestamp.Groups['v'].Value -match '(?:Z|[+-]\d{2}:?\d{2})$') {
                $hasTime=[DateTimeOffset]::TryParse($timestamp.Groups['v'].Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$date)
            }
            if ($hasTime) {
                if ($null -eq $oldest -or $date -lt $oldest) {$oldest=$date}
                if ($null -eq $newest -or $date -gt $newest) {$newest=$date}
            } else {$report.invalid_timestamps++}
            $inWindow=$hasTime -and ($null -eq $from -or ($date -ge $from -and $date -lt $to))
            if ($inWindow) {$report.entries_in_window++}
            $message=[string]$entry.message
            if ($entry.'log.logger' -ne 'elasticsearch' -or $message -notmatch 'Cannot index event' -or $message -notmatch 'Limit of total fields \[[0-9]+\]') { continue }
            $report.field_limit_entries++
            if ($inWindow) {$report.field_limit_entries_in_window++}
            if ($hasTime) {
                if ($null -eq $first -or $date -lt $first) { $first=$date }
                if ($null -eq $last -or $date -gt $last) { $last=$date }
            }
            if (-not $inWindow) {continue}
            # These are diagnostic hints, not a replay manifest or proof of loss.
            $channel=[regex]::Match($message,'"channel"\s*:\s*"(?<v>[^"\r\n]{1,256})"')
            $record=[regex]::Match($message,'"record_id"\s*:\s*(?<v>0x[0-9a-fA-F]+|[0-9]+)')
            if ($channel.Success -and $record.Success) {
                try {
                    $id=if ($record.Groups['v'].Value.StartsWith('0x')) { [Convert]::ToInt64($record.Groups['v'].Value.Substring(2),16) } else { [long]$record.Groups['v'].Value }
                    if ($id -gt 0) {
                        $name=$channel.Groups['v'].Value; $key=$name+'|'+$id
                        if (-not $refs.ContainsKey($key)) {
                            if ($refs.Count -ge 200) {$report.references_limited=$true}
                            else {$refs[$key]=@{channel=$name; id=$id}}
                        }
                    }
                } catch { }
            }
        }
    } finally { $stream.Dispose() }
}
$report.references_found=$refs.Count
foreach ($reference in $refs.Values) {
    if ($clock.Elapsed.TotalSeconds -ge $Seconds) { $report.truncated=$true; break }
    $reader=$null; $event=$null
    try {
        $query=New-Object Diagnostics.Eventing.Reader.EventLogQuery($reference.channel,[Diagnostics.Eventing.Reader.PathType]::LogName,('*[System[EventRecordID='+$reference.id+']]'))
        $reader=New-Object Diagnostics.Eventing.Reader.EventLogReader($query)
        $event=$reader.ReadEvent([TimeSpan]::FromSeconds(1))
        $report.references_checked++
        if ($null -ne $event) { $report.os_record_present++ } else { $report.os_record_absent++ }
    } catch { $report.os_check_failed++ }
    finally { if ($event) { $event.Dispose() }; if ($reader) { $reader.Dispose() } }
}
if ($null -ne $first) { $report.first_rejection_at=$first.UtcDateTime.ToString('o') }
if ($null -ne $last) { $report.last_rejection_at=$last.UtcDateTime.ToString('o') }
if ($null -ne $oldest) {$report.oldest_entry_at=$oldest.UtcDateTime.ToString('o')}
if ($null -ne $newest) {$report.newest_entry_at=$newest.UtcDateTime.ToString('o')}
if ($report.field_limit_entries_in_window -gt 0) {$report.evidence_state='rejections_observed_identity_unverified'}
elseif ($report.entries_in_window -gt 0) {$report.evidence_state='no_rejections_observed_in_read_subset'}
elseif ($from) {$report.evidence_state='requested_window_not_observed'}
else {$report.evidence_state='no_dated_entries_observed'}
$json=$report | ConvertTo-Json -Depth 4
if ($destination) {
    # CreateNew also protects against an output appearing after preflight.
    $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$bytes=(New-Object Text.UTF8Encoding($false)).GetBytes($json); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true)}
    finally {$stream.Dispose()}
} else { $json }
