# Single-token fresh Windows pair only. Repair and Discovery updates keep their keys.
. (Join-Path $PSScriptRoot 'transaction-windows.ps1')
. (Join-Path $PSScriptRoot 'bundle-windows.ps1')

function New-SocEnrollmentAttempt {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes); return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
    finally { $rng.Dispose() }
}

function Invoke-SocEnrollmentRequest($Context, [string]$Action, $Data) {
    if ($Action -notin @('enroll','receipt','abort')) { throw 'Invalid installer action.' }
    if (-not ('CloudSocEnrollmentHttp' -as [type])) {
        $compile=@{Path=(Join-Path $Context.Source 'enrollment-http.cs');ErrorAction='Stop'}
        if ($PSVersionTable.PSEdition -eq 'Core') { $compile.CompilerOptions=@('/nowarn:SYSLIB0014,SYSLIB0057') }
        Add-Type @compile
    }
    $json = $Data | ConvertTo-Json -Depth 8 -Compress
    for ($retry=0; $retry -lt 3; $retry++) {
        try {
            $response = [CloudSocEnrollmentHttp]::Post($Context.Portal, ('/api/installer/' + $Action), $Context.Ca,
                $Context.AllowUnavailable, $Context.Token, $json)
        } catch {
            if ($retry -eq 2) { throw 'Enrollment TLS/network request failed; no insecure retry was attempted.' }
            Start-Sleep -Seconds 2
            continue
        }
        if ($response.Status -eq 200) {
            try { return $response.Body | ConvertFrom-Json -ErrorAction Stop }
            catch { throw 'Invalid enrollment response; no success was assumed.' }
        }
        if ($response.Status -in @(409,503) -and $retry -lt 2) { Start-Sleep -Seconds 2; continue }
        # Never print an upstream body: it could contain a key or proxy diagnostics.
        throw ('Enrollment request refused (HTTP ' + $response.Status + '). Check token expiry, package, server preparation and enrollment history.')
    }
}

function Get-SocInstalledEnrollmentAgents($Members) {
    $agents = @{}
    foreach ($member in $Members) {
        Assert-SocLocalPath $member.Root
        $path = Join-Path $member.Root 'data\meta.json'
        Assert-SocLocalPath $path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -gt 4096) { throw 'Installed collector identity is unavailable.' }
        try { $identity = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -ErrorAction Stop }
        catch { throw 'Installed collector identity cannot be read; no metadata body is printed.' }
        if ($identity.uuid -cnotmatch '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$') { throw 'Invalid installed collector identity.' }
        $agents[$member.Kind] = $identity.uuid
    }
    return $agents
}

function Confirm-SocEnrollmentReceipt($Context, $Members) {
    $agents = Get-SocInstalledEnrollmentAgents $Members
    $hostRoot = ($Members | Where-Object Kind -eq 'host').Root
    $inputPath = Join-Path $hostRoot 'inputs\installation-probe.yml'
    $eventPath = Join-Path $hostRoot 'installation-probe.ndjson'
    Assert-SocLocalPath $inputPath
    Assert-SocLocalPath $eventPath
    if ((Test-Path -LiteralPath $inputPath) -or (Test-Path -LiteralPath $eventPath)) { throw 'Installation probe already exists; no file was replaced.' }
    $utf8 = New-Object Text.UTF8Encoding($false)
    # Filebeat's default fingerprint waits for 1024 bytes. This single harmless
    # event exceeds that threshold without reducing production fingerprint sizes.
    $event = @{ '@timestamp'=[datetime]::UtcNow.ToString('o'); event=@{action='installation_probe';kind='event'};
        labels=@{installation_probe=$Context.Probe}; message=('Cloud SOC installation verification. ' + ('x' * 1100)) }
    [IO.File]::WriteAllText($eventPath, (($event | ConvertTo-Json -Depth 6 -Compress) + "`n"), $utf8)
    $probeInput = @(@{type='filestream';id=('installation-' + $Context.PackageId);paths=@($eventPath);parsers=@(@{ndjson=@{target='';add_error_key=$true}})})
    [IO.File]::WriteAllText($inputPath, (ConvertTo-Json -InputObject $probeInput -Depth 8), $utf8)
    # Generate an approved TCP flow to the already configured receiver. No data or credentials.
    $uri = [uri]$Context.Endpoint
    $tcp = New-Object Net.Sockets.TcpClient
    try {
        $connecting = $tcp.ConnectAsync($uri.Host, $uri.Port)
        if (-not $connecting.Wait(10000)) { throw 'Verification flow timed out.' }
        $connecting.GetAwaiter().GetResult()
    } finally { $tcp.Dispose() }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt 180) {
        foreach ($member in $Members) {
            Assert-SocBundleService $member
            if ((Get-Service -Name $member.Service).Status -ne 'Running') { throw 'A collector stopped before central receipt verification.' }
        }
        $result = Invoke-SocEnrollmentRequest $Context 'receipt' @{attempt=$Context.Attempt;agents=$agents}
        if ($result.verified -is [bool] -and $result.verified -eq $true -and $result.state -ceq 'complete' -and $result.id -ceq $Context.SessionId) {
            $Context.Verified = $true
            Write-Host '[OK] Actual central documents verified for Filebeat and Packetbeat.'
            return
        }
        Write-Host 'Waiting for actual central log/network documents...'
        Start-Sleep -Seconds 5
    }
    throw 'Central receipt NOT verified within three minutes. Installation is not SUCCESS; owned services will be stopped and queues preserved.'
}

function Invoke-SocEnrollmentInstall([string]$Source, [string]$Endpoint, [string]$CaPath, [string]$Organization,
    [string]$InterfaceGuid, [string]$PackageSha256, [switch]$AllowUnavailableRevocation, [switch]$DryRun) {
    try { $spec = Get-Content -LiteralPath (Join-Path $Source 'package.json') -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'Package metadata cannot be read; verify and unpack the complete ZIP.' }
    if ($spec.PSObject.Properties.Name -notcontains 'enrollment_protocol' -or $spec.os -cne 'windows' -or -not $spec.network -or $spec.enrollment_protocol -ne 1 -or
        $spec.package_id -cnotmatch '^[a-f0-9]{32}$' -or $spec.portal_url -cnotmatch '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$' -or
        $spec.endpoint -cne $Endpoint -or $spec.organization -cne $Organization) { throw 'A fresh compatible Windows log+network package is required.' }
    if ($PackageSha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Supply the public package SHA-256 from the verified portal download command. Never pass a token as an argument.' }
    $context = @{ Source=$Source;Portal=$spec.portal_url;Ca=$CaPath;AllowUnavailable=[bool]$AllowUnavailableRevocation;
        PackageId=$spec.package_id;PackageHash=$PackageSha256;Endpoint=$Endpoint;Organization=$Organization;
        Token=$null;Attempt=$null;Probe=$null;SessionId=$null;Verified=$false }
    $begin = {
        $secure = Read-Host 'Paste ONE installation token (hidden input)' -AsSecureString
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $context.Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secure.Dispose() }
        $context.Attempt = New-SocEnrollmentAttempt
        $reply = Invoke-SocEnrollmentRequest $context 'enroll' @{attempt=$context.Attempt;package_id=$context.PackageId;package_sha256=$context.PackageHash}
        if ($reply.id -cne $context.Token.Split('.')[0] -or $reply.endpoint -cne $Endpoint -or $reply.organization -cne $Organization -or
            $reply.probe -cnotmatch '^[a-f0-9]{64}$' -or @($reply.keys).Count -ne 2 -or $reply.receipt_verified -isnot [bool] -or $reply.receipt_verified -ne $false) { throw 'Invalid enrollment binding; no collector started.' }
        $result = @{Probe=$reply.probe}
        foreach ($key in $reply.keys) {
            if ($key.scope -isnot [string] -or $key.key -isnot [string] -or $key.scope -notin @('host','network') -or $result.ContainsKey($key.scope) -or $key.key -cnotmatch '^[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$') { throw 'Invalid enrollment keys; no collector started.' }
            $result[$key.scope] = ConvertTo-SecureString $key.key -AsPlainText -Force
        }
        if (-not $result.ContainsKey('host') -or -not $result.ContainsKey('network')) { throw 'Missing enrollment role.' }
        $context.Probe=$reply.probe; $context.SessionId=$reply.id
        $reply=$null
        return $result
    }.GetNewClosure()
    $verify = { param($Members) Confirm-SocEnrollmentReceipt $context $Members }.GetNewClosure()
    $abort = {
        if ($context.Token -and $context.Attempt -and -not $context.Verified) {
            try { $null = Invoke-SocEnrollmentRequest $context 'abort' @{attempt=$context.Attempt}; Write-Warning 'Failed installation keys revoked.' }
            catch { Write-Warning 'Failed installation key revocation is NOT confirmed. Cancel this enrollment in the portal; do not report success.' }
        }
    }.GetNewClosure()
    try {
        Invoke-SocWindowsBundle -Source $Source -Endpoint $Endpoint -CaPath $CaPath -Organization $Organization -InterfaceGuid $InterfaceGuid `
            -AllowUnavailableRevocation:$AllowUnavailableRevocation -DryRun:$DryRun -EnrollmentStart $begin -EnrollmentReceipt $verify -EnrollmentAbort $abort
    } finally { $context.Token=$null; $context.Attempt=$null }
}
