# Explicit stopped-state resume: revalidate first, never rewind queues or force-stop collectors.
function Write-SocBundleJsonAtomic([string]$Path, $Value) {
    Assert-SocLocalPath $Path
    $parent=Split-Path -Parent $Path
    Assert-SocRepairAcl $parent
    if (Test-Path -LiteralPath $Path) {
        Assert-SocRepairAcl $Path
        $item=Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.PSObject.Properties['LinkType'] -and $item.LinkType)) { throw 'Atomic record refused a linked/non-file target.' }
    }
    $temporary=Join-Path $parent ('.bundle-json-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $created=$false
    try {
        $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $created=$true
        try {
            $bytes=[Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 10 -Compress))
            $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true)
        } finally { $stream.Dispose() }
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary,$Path,[NullString]::Value) }
        else { [IO.File]::Move($temporary,$Path) }
    } finally {
        if ($created -and (Test-Path -LiteralPath $temporary)) {
            Assert-SocLocalPath $temporary
            Remove-Item -LiteralPath $temporary -ErrorAction Stop
        }
    }
}

function Save-SocRepairResumeRecord($Transaction, $Members, [string]$Endpoint, [string]$Organization,
    $Backups, [string]$OriginalXml, [string]$TaskXml, [string]$Phase) {
    $entries=@()
    foreach ($member in $Members) {
        $entries += @{kind=$member.Kind;root=$member.Root;files=$member.Stable;original_start_mode=$member.OriginalService.StartMode;
            initially_missing=$member.InitiallyMissing;create_attempted=$member.RepairCreateAttempted;created=$member.RepairCreated}
    }
    Write-SocBundleJsonAtomic (Join-Path $Transaction.Path 'repair-state.json') @{
        schema=2;transaction=$Transaction.Token;endpoint=$Endpoint.TrimEnd('/');organization=$Organization;phase=$Phase;
        members=$entries;backups=$Backups;original_task_xml=$OriginalXml;task_xml=$TaskXml;auto_restore_queue=$false
    }
}

function Assert-SocRepairBackup([string]$Path, $Member) {
    $base=Join-Path $env:ProgramData 'Cloud-SOC\recovery'
    if ((Split-Path -Parent $Path) -ine $base -or (Split-Path -Leaf $Path) -cnotmatch '^[a-f0-9]{32}$') { throw 'Unexpected protected backup path; no restore attempted.' }
    Assert-SocLocalPath $Path
    Assert-SocRepairAcl $Path
    foreach ($item in Get-SocRepairTree $Path) { Assert-SocRepairAcl $item.FullName }
    $manifest=Read-SocBundleRepairJson (Join-Path $Path 'manifest.json') 2097152
    if ($manifest.status -cne 'verified' -or $manifest.queues_restore_automatically -isnot [bool] -or
        $manifest.queues_restore_automatically -or @($manifest.files).Count -gt 10000) { throw 'Backup manifest is not verified.' }
    $seen=@{}
    foreach ($file in $manifest.files) {
        if ($file.path -isnot [string] -or -not $file.path -or $file.path.Length -gt 1024 -or $file.path -match '^[/\\]|[:"\x00-\x1f]|(^|[/\\])\.\.?($|[/\\])' -or
            $file.sha256 -cnotmatch '^[A-Fa-f0-9]{64}$' -or $seen.ContainsKey($file.path)) { throw 'Invalid/duplicate backup file identity.' }
        $target=Join-Path (Join-Path $Path 'snapshot') $file.path
        Assert-SocLocalPath $target
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash -cne $file.sha256) { throw 'Protected backup file changed.' }
        $seen[$file.path]=$file.sha256
    }
    foreach ($name in Get-SocBundleStableNames $Member.Beat) {
        if (-not $seen.ContainsKey($name) -or $seen[$name] -cne $Member.Stable[$name]) { throw 'Backup does not belong to the current collector identity.' }
    }
}

function Get-SocTaskEnabledInvariant([string]$Xml) {
    $document=[xml]$Xml
    foreach ($node in @($document.SelectNodes('/*[local-name()="Task"]/*[local-name()="Settings"]/*[local-name()="Enabled"]'))) {
        $null=$node.ParentNode.RemoveChild($node)
    }
    return $document.OuterXml
}

function Resume-SocBundleRepair([string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
    [string]$InterfaceGuid, [switch]$DryRun) {
    $pending=Join-Path $env:ProgramData 'Cloud-SOC\bundle-repair-pending.json'
    if (-not (Test-Path -LiteralPath $pending)) { throw 'No interrupted Repair record exists; use ordinary -Repair for a recognized stopped pair.' }
    $reservation=Read-SocBundleRepairJson $pending
    if ($reservation.schema -ne 2 -or $reservation.transaction -cnotmatch '^[a-f0-9]{32}$' -or
        $reservation.auto_restore_queue -isnot [bool] -or $reservation.auto_restore_queue) { throw 'Legacy/invalid Repair record cannot resume automatically; state retained.' }
    $root=Join-Path (Join-Path $env:ProgramData 'Cloud-SOC\staging') $reservation.transaction
    Assert-SocLocalPath $root
    Assert-SocRepairAcl $root
    foreach ($item in Get-SocRepairTree $root) { Assert-SocRepairAcl $item.FullName }
    if ([IO.File]::ReadAllText((Join-Path $root 'install-owner.txt')) -cne $reservation.transaction) { throw 'Repair transaction ownership differs.' }
    $record=Read-SocBundleRepairJson (Join-Path $root 'repair-state.json')
    if ($record.schema -ne 2 -or $record.transaction -cne $reservation.transaction -or
        $record.endpoint -cne $Endpoint.TrimEnd('/') -or $record.organization -cne $Organization -or
        @($record.members).Count -ne 2 -or $record.auto_restore_queue -isnot [bool] -or $record.auto_restore_queue -or
        $record.phase -notin @('reserved','quiesced','backing_up','validated','creating_services','task_ready','starting','committed_receipt_unverified','resumed_stopped')) {
        throw 'Interrupted Repair identity/phase differs; no changes made.'
    }
    $backupKinds=@($record.backups.PSObject.Properties | ForEach-Object Name)
    if (@($backupKinds | Where-Object { $_ -notin @('host','network') }).Count -or
        ($record.phase -in @('validated','creating_services','task_ready','starting','committed_receipt_unverified') -and $backupKinds.Count -ne 2)) {
        throw 'Interrupted Repair backup set differs; state retained.'
    }
    $members=Get-SocBundleMembers
    $bundle=Get-SocBundlePendingRecovery $members
    foreach ($member in $members) {
        Assert-SocBundleRepairMember $member $Source $Endpoint $CaPath $Organization -AllowMissingService:([bool]$bundle)
        $entries=@($record.members | Where-Object kind -CEQ $member.Kind)
        if ($entries.Count -ne 1 -or $entries[0].root -ine $member.Root -or
            $entries[0].initially_missing -isnot [bool] -or $entries[0].original_start_mode -notin @('Disabled','Manual','Auto')) {
            throw 'Interrupted collector identity differs.'
        }
        $entry=$entries[0]
        if ($entry.create_attempted -isnot [bool] -or $entry.created -isnot [bool] -or
            ($entry.created -and -not $entry.create_attempted) -or
            (-not $entry.initially_missing -and ($member.InitiallyMissing -or $entry.create_attempted)) -or
            ($entry.initially_missing -and -not $member.InitiallyMissing -and -not $entry.created)) {
            throw 'Ambiguous/missing service registration cannot be adopted by resume.'
        }
        if (@($entry.files.PSObject.Properties).Count -ne $member.Stable.Count) { throw 'Interrupted collector file set differs.' }
        foreach ($name in $member.Stable.Keys) {
            $digest=$entry.files.PSObject.Properties[$name]
            if (-not $digest -or $digest.Value -cne $member.Stable[$name]) { throw 'Interrupted collector configuration/key/code changed.' }
        }
        if ($record.backups.PSObject.Properties[$member.Kind]) { Assert-SocRepairBackup $record.backups.($member.Kind) $member }
    }
    if ($InterfaceGuid -and ([guid]$InterfaceGuid).ToString() -cne $members[1].InterfaceGuid) { throw 'Requested NIC differs; resume is not migration.' }
    if (@(Get-Process -ErrorAction Stop | Where-Object ProcessName -In @('filebeat','packetbeat','elastic-agent')).Count) { throw 'An active collector process prevents stopped-state resume.' }
    Assert-SocNativeDiscovery $members[0].Root
    $task=Get-SocRepairDiscovery $members[0].Root -AllowEnabled
    $currentXml=$null
    if ($task) {
        if ([string]$task.State -in @('Running','Queued') -or $task.Actions[0].Execute -ine (Join-Path $members[0].Root 'cloud-soc-discovery.exe') -or
            -not $record.task_xml) { throw 'Unrecorded/active task prevents resume; definition retained.' }
        $currentXml=Export-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop
        if ((Get-SocTaskEnabledInvariant $currentXml) -cne (Get-SocTaskEnabledInvariant $record.task_xml)) { throw 'Discovery definition changed; resume refused.' }
    } elseif ($record.original_task_xml) { throw 'Original Discovery task disappeared; resume did not replace it.' }
    if ($DryRun) {
        Write-Host 'DRY RUN: interrupted Repair identity, current stopped state and recorded backups verified. No writes, network or task/service changes. SYSTEM/authentication/central receipt remain pending.'
        return
    }
    # Recheck immediately before changing only the known enabled flag; never restore old data.
    foreach ($member in $members) {
        Assert-SocBundleRepairMember $member $Source $Endpoint $CaPath $Organization -AllowMissingService:([bool]$bundle)
    }
    if (@(Get-Process -ErrorAction Stop | Where-Object ProcessName -In @('filebeat','packetbeat','elastic-agent')).Count) { throw 'Collector started before resume; no changes made.' }
    $currentReservation=Read-SocBundleRepairJson $pending
    if ($currentReservation.transaction -cne $reservation.transaction -or $currentReservation.schema -ne 2) { throw 'Repair reservation changed; retained.' }
    if ($task) {
        Assert-SocBundleTask $currentXml
        Disable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -TaskPath '\' -ErrorAction Stop | Out-Null
        $null=Get-SocRepairDiscovery $members[0].Root
    }
    $record.phase='resumed_stopped'
    Write-SocBundleJsonAtomic (Join-Path $root 'repair-state.json') $record
    Remove-Item -LiteralPath $pending -ErrorAction Stop
    Write-Host 'Verified interrupted Repair released for a fresh backup and full revalidation. Keys and queued data were not restored or deleted.'
}
