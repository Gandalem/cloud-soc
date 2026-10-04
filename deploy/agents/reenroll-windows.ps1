# Explicit failed-enrollment recovery. Public receipts only; no token/attempt on disk.
function Get-SocReEnrollmentPlan($Context) {
    Assert-SocAdministrator
    $members = @(Get-SocBundleMembers -HostOnly:(-not $Context.Network))
    $pending = Join-Path $env:ProgramData 'Cloud-SOC\bundle-pending.json'
    Assert-SocLocalPath $pending
    Assert-SocRepairAcl $pending
    if ((Get-Item -LiteralPath $pending).Length -ne 32) { throw 'Invalid pending enrollment.' }
    $token = [IO.File]::ReadAllText($pending)
    if ($token -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid pending enrollment.' }
    $root = Join-Path (Join-Path $env:ProgramData 'Cloud-SOC\staging') $token
    Assert-SocRepairAcl $root
    Assert-SocLocalPath $root
    foreach ($item in Get-SocRepairTree $root) { Assert-SocRepairAcl $item.FullName }
    if ([IO.File]::ReadAllText((Join-Path $root 'install-owner.txt')) -cne $token) { throw 'Pending ownership changed.' }
    $state = Read-SocBundleRepairJson (Join-Path $root 'bundle-state.json')
    if ($state.schema -ne 1 -or $state.transaction -cne $token -or $state.start_attempted -isnot [bool] -or
        $state.phase -notin @('retained_recovery_required','prepared')) { throw 'Unrecognized failure; preserved without changes.' }
    if (@(Get-Process -ErrorAction Stop | Where-Object ProcessName -In @('filebeat','packetbeat','elastic-agent')).Count) {
        throw 'Collectors must be stopped before explicit re-enrollment.'
    }
    $prepared = @()
    if ($state.start_attempted) {
        $null = Get-SocBundlePendingRecovery $members
        foreach ($member in $members) {
            Assert-SocBundleRepairMember $member $Context.Source $Context.Endpoint $Context.Ca $Context.Organization -AllowMissingService
            $prepared += @{Kind=$member.Kind;Path=$member.Root;Member=$member}
        }
    } else {
        foreach ($member in $members) {
            if ((Test-Path -LiteralPath $member.Root) -or (Get-Service -Name $member.Service -ErrorAction SilentlyContinue)) {
                throw 'Preparation failure mixed with final installation; no automatic adoption.'
            }
            $receipt = Join-Path $root ($member.Kind + '-prepared.json')
            if (Test-Path -LiteralPath $receipt) {
                $verified = Read-SocPreparedReceipt $receipt $member.Kind
                Assert-SocRepairDistribution $verified.path '9.5.2' $member.Hash $member.Beat
                $prepared += @{Kind=$member.Kind;Path=$verified.path;Member=$member;Receipt=$receipt;Token=$verified.token}
            }
        }
        if (-not $prepared.Count) { throw 'No verified prepared collector; state retained for review.' }
        if (Get-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -ErrorAction SilentlyContinue) { throw 'Unexpected permanent Discovery task.' }
    }
    $probe = $null
    foreach ($entry in $prepared) {
        $config = Read-SocBundleRepairJson (Join-Path $entry.Path ($entry.Member.Beat + '.yml'))
        if (@($config.'output.elasticsearch'.hosts).Count -ne 1 -or $config.'output.elasticsearch'.hosts[0] -cne $Context.Endpoint -or
            $config.processors[1].add_fields.fields.id -cne $Context.Organization -or
            (Get-FileHash -LiteralPath (Join-Path $entry.Path 'ca.crt') -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $Context.Ca -Algorithm SHA256).Hash) { throw 'Server/organization/CA migration refused.' }
        $marker = if ($entry.Kind -eq 'host') { $config.processors[-1].add_fields.fields.installation_probe }
                  else { $config.processors[2].add_fields.fields.installation_probe }
        if ($marker -cnotmatch '^[a-f0-9]{64}$' -or ($probe -and $probe -cne $marker)) { throw 'Failed enrollment identity differs.' }
        $probe = $marker
    }
    return @{Path=$root;Token=$token;Pending=$pending;Started=$state.start_attempted;Prepared=$prepared;Members=$members;Probe=$probe}
}

function Move-SocFailedPreparation($Plan) {
    $parent = Join-Path $env:ProgramData 'Cloud-SOC\reenrollment-backups'
    New-SocProtectedDirectory $parent -Reuse
    $backup = Join-Path $parent ([guid]::NewGuid().ToString('N'))
    New-SocProtectedDirectory $backup
    # Revalidate hashes/ownership after token exchange, before any move.
    foreach ($entry in $Plan.Prepared) { $null = Read-SocPreparedReceipt $entry.Receipt $entry.Kind }
    if ([IO.File]::ReadAllText($Plan.Pending) -cne $Plan.Token) { throw 'Pending reservation changed.' }
    [IO.File]::WriteAllText((Join-Path $backup 'archive-plan.json'), ($Plan | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    foreach ($entry in $Plan.Prepared) { [IO.Directory]::Move($entry.Path, (Join-Path $backup $entry.Kind)) }
    [IO.Directory]::Move($Plan.Path, (Join-Path $backup 'transaction'))
    [IO.File]::Move($Plan.Pending, (Join-Path $backup 'bundle-pending.json'))
    Write-Host ('Verified failed preparation archived without deleting keys/queues: ' + $backup)
}

function Set-SocReEnrollmentKey($Member, [Security.SecureString]$Key) {
    $beatHome = Join-Path $Member.Root ($Member.Beat + '-9.5.2-windows-x86_64')
    $name = if ($Member.Kind -eq 'host') { 'CLOUD_SOC_API_KEY' } else { 'CLOUD_SOC_NETWORK_API_KEY' }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        $plain | & (Join-Path $beatHome ($Member.Beat + '.exe')) --path.home $beatHome --path.config $Member.Root --path.data (Join-Path $Member.Root 'data') --path.logs (Join-Path $Member.Root 'logs') -c (Join-Path $Member.Root ($Member.Beat + '.yml')) keystore add $name --stdin --force
        if ($LASTEXITCODE -ne 0) { throw 'Re-enrollment keystore update failed.' }
    } finally { $plain=$null; [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Invoke-SocStartedReEnrollment($Plan, $Context, $Keys) {
    $backups = @{}
    foreach ($entry in $Plan.Prepared) {
        $member = $entry.Member
        Assert-SocBundleRepairMember $member $Context.Source $Context.Endpoint $Context.Ca $Context.Organization -AllowMissingService
        $backups[$member.Kind] = Backup-SocRepair $member.Root $member.OriginalService
    }
    $oldIdentity = Join-Path $Plan.Path 'bundle-recovery.json'
    $savedIdentity = Join-Path $Plan.Path ('bundle-recovery-before-reenroll-' + [guid]::NewGuid().ToString('N') + '.json')
    # No queue/registry restore on any failure; backups remain protected evidence.
    try {
        foreach ($member in $Plan.Members) {
            $configPath = Join-Path $member.Root ($member.Beat + '.yml')
            $config = Read-SocBundleRepairJson $configPath
            if ($member.Kind -eq 'host') { $config.processors[-1].add_fields.fields.installation_probe = $Context.Probe }
            else { $config.processors[2].add_fields.fields.installation_probe = $Context.Probe }
            [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 16), (New-Object Text.UTF8Encoding($false)))
            $member.Prepared = @{token=[IO.File]::ReadAllText((Join-Path $member.Root 'install-owner.txt'))}
        }
        # Keep the public probe consistent across collectors before changing keys.
        # A controlled key-update failure is retained for another explicit token.
        foreach ($member in $Plan.Members) {
            Set-SocReEnrollmentKey $member $Keys[$member.Kind]
            foreach ($path in @('inputs\installation-probe.yml','installation-probe.ndjson')) {
                $old = Join-Path $member.Root $path
                if ($member.Kind -eq 'host' -and (Test-Path -LiteralPath $old)) {
                    Assert-SocLocalPath $old; Assert-SocRepairAcl $old
                    [IO.File]::Move($old, (Join-Path $backups.host ('previous-' + (Split-Path -Leaf $old))))
                }
            }
        }
        [IO.File]::Move($oldIdentity, $savedIdentity)
        Save-SocBundleRecoveryIdentity $Plan $Plan.Members
        Invoke-SocBundleRepair -Source $Context.Source -Endpoint $Context.Endpoint -CaPath $Context.Ca -Organization $Context.Organization -AllowUnavailableRevocation:$Context.AllowUnavailable -HostOnly:(-not $Context.Network)
        Confirm-SocEnrollmentReceipt $Context $Plan.Members
        Save-SocBundleJournal $Plan 'committed_receipt_verified' $true
    } catch {
        foreach ($member in $Plan.Members) {
            if (Get-Service -Name $member.Service -ErrorAction SilentlyContinue) {
                Assert-SocBundleService $member
                Stop-Service -Name $member.Service -ErrorAction Stop
                Set-Service -Name $member.Service -StartupType Disabled
            }
        }
        $task = Get-SocRepairDiscovery $Plan.Members[0].Root -AllowEnabled
        if ($task) { Disable-ScheduledTask -TaskName 'Cloud-SOC-Discovery' -ErrorAction Stop | Out-Null }
        if (Test-Path -LiteralPath $oldIdentity) {
            [IO.File]::Move($oldIdentity, (Join-Path $Plan.Path ('bundle-recovery-failed-reenroll-' + [guid]::NewGuid().ToString('N') + '.json')))
        }
        Save-SocBundleRecoveryIdentity $Plan $Plan.Members
        Save-SocBundleJournal $Plan 'retained_recovery_required' $true
        if (-not (Test-Path -LiteralPath $Plan.Pending)) {
            $stream=[IO.File]::Open($Plan.Pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $bytes=[Text.Encoding]::UTF8.GetBytes($Plan.Token); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        }
        throw
    }
}
