# Read-only audit of retained rejection diagnostics and OS record availability.
# No raw events, paths, channel names, keys, or event bodies are returned.
#requires -Version 5.1
param(
    [string]$Root = (Join-Path $env:ProgramFiles 'Cloud-SOC-Agent'),
    [string]$ResultPath,
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
$clock = [Diagnostics.Stopwatch]::StartNew()
$report = [ordered]@{schema=1; checked_at=[DateTime]::UtcNow.ToString('o'); scope='retained_diagnostics_only';
    files=0; bytes_read=0L; lines=0; malformed=0; oversized=0; field_limit_entries=0;
    references_found=0; references_checked=0; os_record_present=0; os_record_absent=0; os_check_failed=0;
    truncated=$false; references_limited=$false; first_rejection_at=$null; last_rejection_at=$null;
    complete_loss_count=$false; replay_performed=$false}
$refs = @{}
$first = $null; $last = $null
$files = @(Get-ChildItem -LiteralPath $logPath -File | Where-Object { $_.Name -match '^filebeat(?:-events-data)?-.*\.ndjson$' } | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 33)
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
            if ($line -notmatch 'Limit of total fields') { continue }
            try { $entry=$line | ConvertFrom-Json } catch { $report.malformed++; continue }
            $message=[string]$entry.message
            if ($entry.'log.logger' -ne 'elasticsearch' -or $message -notmatch 'Cannot index event' -or $message -notmatch 'Limit of total fields \[[0-9]+\]') { continue }
            $report.field_limit_entries++
            $date=[DateTimeOffset]::MinValue
            if ([DateTimeOffset]::TryParse([string]$entry.'@timestamp',[ref]$date)) {
                if ($null -eq $first -or $date -lt $first) { $first=$date }
                if ($null -eq $last -or $date -gt $last) { $last=$date }
            }
            # These are diagnostic hints, not a replay manifest or proof of loss.
            $channel=[regex]::Match($message,'"channel"\s*:\s*"(?<v>[^"\r\n]{1,256})"')
            $record=[regex]::Match($message,'"record_id"\s*:\s*(?<v>0x[0-9a-fA-F]+|[0-9]+)')
            if ($channel.Success -and $record.Success -and $refs.Count -ge 200) { $report.references_limited=$true }
            if ($channel.Success -and $record.Success -and $refs.Count -lt 200) {
                try {
                    $id=if ($record.Groups['v'].Value.StartsWith('0x')) { [Convert]::ToInt64($record.Groups['v'].Value.Substring(2),16) } else { [long]$record.Groups['v'].Value }
                    if ($id -gt 0) { $name=$channel.Groups['v'].Value; $refs[($name+'|'+$id)]=@{channel=$name; id=$id} }
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
$json=$report | ConvertTo-Json -Depth 4
if ($ResultPath) {
    $destination=Assert-AuditPath $ResultPath
    if (Test-Path -LiteralPath $destination) { throw 'Audit output already exists; not overwritten.' }
    [IO.File]::WriteAllText($destination,$json,(New-Object Text.UTF8Encoding($false)))
} else { $json }
