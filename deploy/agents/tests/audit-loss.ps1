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
    Write-Output 'Loss audit: bounded input, partial line, privacy, no overwrite, no replay passed.'
} finally {
    if ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($root)) -ine $parent -or [IO.Path]::GetFileName($root) -notmatch '^audit-loss-test-[a-f0-9]{32}$') { throw 'Unsafe fixture cleanup' }
    Remove-Item -LiteralPath $root -Recurse -Force
}
