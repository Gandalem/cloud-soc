# Shared download transport only. Callers must verify the pinned SHA-512 before use.
function Get-SystemCurl {
    $path = Join-Path ([Environment]::GetFolderPath('System')) 'curl.exe'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Windows system curl.exe is required. Update Windows before installation; no fallback to slow Invoke-WebRequest.'
    }
    return $path
}

function Receive-CloudSocArchive([string]$Uri, [string]$OutFile) {
    if ($Uri -cnotmatch '^https://artifacts\.elastic\.co/downloads/beats/(filebeat|packetbeat)/(filebeat|packetbeat)-[0-9]+\.[0-9]+\.[0-9]+-windows-x86_64\.zip\z') {
        throw 'Only pinned Elastic Windows archive URLs are supported.'
    }
    if (Test-Path -LiteralPath $OutFile) { throw 'Download destination already exists; no automatic replacement.' }
    $curl = Get-SystemCurl
    # PS 7 may turn native nonzero exits into exceptions; handle curl codes explicitly.
    $PSNativeCommandUseErrorActionPreference = $false
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        Write-Host "Downloading with system curl.exe (attempt $attempt/2; up to 300 seconds)."
        # Disable curlrc first so user defaults cannot disable TLS verification or add retries.
        $httpStatus = & $curl --disable --fail --show-error --proto '=https' --tlsv1.2 --retry 0 `
            --connect-timeout 30 --max-time 300 --speed-limit 16384 --speed-time 60 `
            --max-redirs 0 --write-out '%{http_code}' --output $OutFile -- $Uri
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            if ($httpStatus -ne '200') { throw 'Archive server did not return HTTP 200; redirects and partial responses are not accepted.' }
            return
        }
        if ($attempt -eq 2 -or $code -notin @(6, 7, 18, 28, 52, 55, 56)) {
            throw "Archive download failed (curl exit $code). Check network/proxy connectivity to artifacts.elastic.co. Partial state retained; do not reinstall over it."
        }
        Write-Host "Transfer failed (curl exit $code). Retrying from the beginning in 3 seconds."
        Start-Sleep -Seconds 3
    }
}
