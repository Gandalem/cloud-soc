$ErrorActionPreference='Stop'
$parent=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../state'))
$root=Join-Path $parent ('audit-loss-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $root 'logs') -Force | Out-Null
try {
    $path=Join-Path $root 'logs/filebeat-20260928.ndjson'
    $entry=@{'@timestamp'='2026-09-28T00:00:00Z'; 'log.logger'='elasticsearch'; message='Cannot index event SECRET_CANARY Limit of total fields [1000]'} | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($path,($entry+"`n"+'{"broken":'+"`n"+$entry))
    $audit=Join-Path $PSScriptRoot '../audit-windows-loss.ps1'
    $result=(& $audit -Root $root | ConvertFrom-Json)
    if ($result.field_limit_entries -ne 1 -or $result.files -ne 1 -or $result.references_found -ne 0) { throw 'Incorrect bounded audit counts.' }
    if (($result | ConvertTo-Json -Depth 5) -match 'SECRET_CANARY' -or $result.complete_loss_count -or $result.replay_performed) { throw 'Unsafe audit report.' }
    $output=Join-Path $root 'result.json'
    & $audit -Root $root -ResultPath $output
    $rejected=$false
    try { & $audit -Root $root -ResultPath $output } catch { $rejected=$true }
    if (-not $rejected) { throw 'Audit overwrote previous evidence.' }
    if ([IO.File]::ReadAllText($path) -cne ($entry+"`n"+'{"broken":'+"`n"+$entry)) { throw 'Read-only audit modified input.' }
    $baseline=Join-Path $root 'baseline.json'
    [IO.File]::WriteAllText($baseline,'{"schema":1,"scope":"retained_diagnostics_only","field_limit_entries":1798,"complete_loss_count":false,"replay_performed":false}')
    $window=@{Since='2026-09-27T00:00:00Z';Until='2026-09-28T00:00:00Z';BaselinePath=$baseline}
    $missing=(& $audit -Root $root @window | ConvertFrom-Json)
    if ($missing.evidence_state -ne 'requested_window_not_observed' -or $missing.prior_field_limit_entries -ne 1798 -or
        $missing.field_limit_entries_in_window -ne 0 -or $missing.historical_loss_count -ne $null -or $missing.recovery_ready) { throw 'Missing history was misrepresented as no loss.' }
    $observed=(& $audit -Root $root -Since '2026-09-28T00:00:00Z' -Until '2026-09-29T00:00:00Z' | ConvertFrom-Json)
    if ($observed.evidence_state -ne 'rejections_observed_identity_unverified' -or $observed.identity_verified -or $observed.schema -ne 2) {throw 'Reference observation overclaimed identity.'}
    $offset=Join-Path $root 'logs/filebeat-offset.ndjson'
    [IO.File]::WriteAllText($offset,'{"@timestamp":"2026-09-28T09:00:00.000+0900","log.logger":"elasticsearch","message":"Cannot index event Limit of total fields [1000]"}'+"`n")
    $offsetResult=(& $audit -Root $root -Since '2026-09-28T00:00:00Z' -Until '2026-09-28T00:00:01Z' | ConvertFrom-Json)
    if ($offsetResult.field_limit_entries_in_window -ne 2 -or [DateTimeOffset]$offsetResult.oldest_entry_at -ne [DateTimeOffset]'2026-09-28T00:00:00Z') {throw 'Elastic numeric timezone offset was lost.'}
    foreach ($args in @(@{Since='2026-09-28'},@{Since='2026-09-28T00:00:00Z';Until='2026-09-27T00:00:00Z'},@{ResultPath=$path})) {
        $rejected=$false
        try {& $audit -Root $root @args | Out-Null} catch {$rejected=$true}
        if (-not $rejected) {throw 'Invalid window/input output was accepted.'}
    }
    [IO.File]::WriteAllText($baseline,'{"schema":1,"scope":"retained_diagnostics_only","field_limit_entries":true,"complete_loss_count":false,"replay_performed":false}')
    $rejected=$false
    try {& $audit -Root $root -BaselinePath $baseline | Out-Null} catch {$rejected=$true}
    if (-not $rejected) {throw 'Invalid baseline count accepted.'}
    # A metrics backlog must not displace the retained rejection file.
    $rejection=Join-Path $root 'logs/filebeat-events-data-20260927.ndjson'
    [IO.File]::WriteAllText($rejection,$entry+"`n")
    (Get-Item -LiteralPath $rejection).LastWriteTimeUtc=[DateTime]'2026-09-27'
    for ($n=1;$n -le 33;$n++) {[IO.File]::WriteAllText((Join-Path $root ('logs/filebeat-extra-'+$n+'.ndjson')),'{}'+"`n")}
    $priority=(& $audit -Root $root | ConvertFrom-Json)
    if (-not $priority.truncated -or $priority.rejection_files -ne 1 -or $priority.field_limit_entries -lt 1) {throw 'Metrics starved rejection evidence.'}
    Write-Output 'Loss audit: bounded input, partial line, privacy, no overwrite, no replay passed.'
} finally {
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($root)) -ine $parent -or [IO.Path]::GetFileName($root) -notmatch '^audit-loss-test-[a-f0-9]{32}$') { throw 'Unsafe fixture cleanup' }
    Remove-Item -LiteralPath $root -Recurse -Force
}
