# Real file/hash/path tests in an owned temp root; ACL boundary mocked, no elevation.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force
}
. (Join-Path $PSScriptRoot '../transaction-windows.ps1')
. (Join-Path $PSScriptRoot '../bundle-windows.ps1')
function Assert-SocRepairAcl { param($Path) }
function New-SocProtectedDirectory { param($Path,[switch]$Reuse) }
function Assert-Failure([scriptblock]$Action,[string]$Pattern) {
    try { & $Action | Out-Null } catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; return }
    throw "Expected failure: $Pattern"
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('cloud-soc-receipt-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$oldProgramData=$env:ProgramData
$env:ProgramData=$root
try {
    $parent = Join-Path $root 'Cloud-SOC\staging'
    $coordinator = Join-Path $parent ([guid]::NewGuid().ToString('N'))
    $token = [guid]::NewGuid().ToString('N')
    $staging = Join-Path $parent $token
    foreach ($dir in @($coordinator,$staging)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText((Join-Path $staging 'install-owner.txt'), $token)
    $configPath = Join-Path $staging 'packetbeat.yml'
    $config = @{'output.elasticsearch'=@{'ssl.certificate_authorities'=@((Join-Path $staging 'ca.crt'))};'packetbeat.npcap.never_install'=$true}
    [IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5))
    [IO.File]::WriteAllText((Join-Path $staging 'ca.crt'),'synthetic-public-ca')
    $receipt = Join-Path $coordinator 'network-prepared.json'
    Assert-Failure { Write-SocPreparedReceipt -Path (Join-Path $root 'arbitrary.json') -Stage @{Path=$staging;Token=$token} -Kind network } 'destination'
    Write-SocPreparedReceipt -Path $receipt -Stage @{Path=$staging;Token=$token} -Kind network
    $null = Read-SocPreparedReceipt $receipt network
    Assert-Failure { Read-SocPreparedReceipt $receipt host } 'identity'
    $original = [IO.File]::ReadAllText($configPath)
    [IO.File]::WriteAllText($configPath,'changed')
    Assert-Failure { Read-SocPreparedReceipt $receipt network } 'file changed'
    [IO.File]::WriteAllText($configPath,$original)
    [IO.File]::WriteAllText((Join-Path $staging 'extra'),'unexpected')
    Assert-Failure { Read-SocPreparedReceipt $receipt network } 'tree changed'
    Remove-Item -LiteralPath (Join-Path $staging 'extra')
    [IO.File]::WriteAllText((Join-Path $staging 'probe-active.txt'),'pending')
    Assert-Failure { Read-SocPreparedReceipt $receipt network } 'probe mismatch'
    Remove-Item -LiteralPath (Join-Path $staging 'probe-active.txt')
    $destination = Join-Path $root 'promoted'
    $member = @{Receipt=$receipt;Kind='network';Root=$destination;Beat='packetbeat';Promoted=$false}
    Move-SocBundleMember $member
    if (-not $member.Promoted -or (Test-Path -LiteralPath $staging)) { throw 'Not promoted' }
    $actual = Get-Content -LiteralPath (Join-Path $destination 'packetbeat.yml') -Raw | ConvertFrom-Json
    if ($actual.'output.elasticsearch'.'ssl.certificate_authorities'[0] -cne (Join-Path $destination 'ca.crt')) { throw 'Final path not rewritten' }
    if (-not $actual.'packetbeat.npcap.never_install') { throw 'Npcap protection changed' }
    Write-Host 'Prepared receipt identity, hashes, probe guard and final config rewrite: passed (ACL mocked).'
} finally {
    $env:ProgramData=$oldProgramData
    if ((Split-Path -Leaf $root) -cnotmatch '^cloud-soc-receipt-test-[a-f0-9]{32}$') { throw 'Unsafe test cleanup' }
    Remove-Item -LiteralPath $root -Recurse -Force
}
