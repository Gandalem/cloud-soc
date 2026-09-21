param([switch]$VerifyInstalledNpcap)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '../install-network-windows.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
# Never execute top-level installer code.
foreach ($definition in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([ScriptBlock]::Create($definition.Extent.Text))
}
if ($VerifyInstalledNpcap) {
    Assert-Npcap
    Write-Output 'Existing Npcap DLL verified without opening a capture device.'
    exit 0
}
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch { if ($_.Exception.Message -notmatch $Pattern) { throw }; return }
    throw "Expected error: $Pattern"
}
$Endpoint = 'https://soc.example.invalid:9200'
$Organization = 'school'
$CaPath = 'C:\certs\ca.crt'
$InterfaceGuid = '11111111-2222-3333-4444-555555555555'
$Root = 'C:\Program Files\Cloud-SOC-Network'
$ServiceName = 'cloud-soc-packetbeat'
Assert-Arguments
$InterfaceGuid = '00000000-0000-0000-0000-000000000000'
Assert-Throws { Assert-Arguments } 'InterfaceGuid'
$InterfaceGuid = '11111111-2222-3333-4444-555555555555'

function Get-Service { param($Name, $ErrorAction) }
function Test-Path { param($LiteralPath, $PathType) return $false }
function Get-Process { param($Name, $ErrorAction) }
Assert-Throws { Assert-Npcap } 'Npcap first'
Assert-NoInstallation
function Get-Service { param($Name, $ErrorAction) if ($Name -eq 'packetbeat') { @{ Name = $Name } } }
Assert-Throws { Assert-NoInstallation } 'Existing service'
# Existing Filebeat must be allowed.
function Get-Service { param($Name, $ErrorAction) if ($Name -eq 'cloud-soc-filebeat') { @{ Name = $Name } } }
Assert-NoInstallation
function Test-Path { param($LiteralPath, $PathType) return $LiteralPath -eq $Root }
Assert-Throws { Assert-NoInstallation } 'partial state'
function Test-Path { param($LiteralPath, $PathType) return $false }
function Get-Process { param($Name, $ErrorAction) if ($Name -eq 'packetbeat') { @{ Name = $Name } } }
Assert-Throws { Assert-NoInstallation } 'already running'

function Get-NetAdapter { param([switch]$IncludeHidden) @{ InterfaceGuid = $InterfaceGuid; Status = 'Down' } }
Assert-Throws { Assert-Interface } 'not Up'
function Get-NetAdapter { param([switch]$IncludeHidden) @{ InterfaceGuid = $InterfaceGuid; Status = 'Up' } }
Assert-Interface
function Get-NetAdapter { param([switch]$IncludeHidden) }
Assert-Throws { Assert-Interface } 'missing'

$actualHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA512).Hash.ToLowerInvariant()
Assert-ArchiveHash $PSCommandPath $actualHash
Assert-Throws { Assert-ArchiveHash $PSCommandPath ('0' * 128) } 'SHA-512 mismatch'
$Exe = 'Mock-Beat'
$CommonArgs = @('--path.data', 'C:\Program Files\Cloud-SOC-Network\data')
function Assert-Npcap { $script:NpcapChecked = $true }
function Mock-Beat { $script:CalledArgs = @($args); $global:LASTEXITCODE = 17 }
Assert-Throws { Invoke-Beat -BeatArguments @('test', 'config') } 'exit 17'
if (-not $NpcapChecked -or ($CalledArgs -join '|') -ne '--path.data|C:\Program Files\Cloud-SOC-Network\data|test|config') { throw 'Native argument or Npcap guard mismatch.' }
function Set-Acl { param($LiteralPath, $AclObject) $script:CapturedAcl = $AclObject }
Set-ProtectedDirectory 'C:\unused-mock-directory'
$rules = @($CapturedAcl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
if (-not $CapturedAcl.AreAccessRulesProtected -or $rules.Count -ne 2) { throw 'ACL not protected.' }
foreach ($rule in $rules) {
    if ($rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') -or $rule.InheritanceFlags -ne 'ContainerInherit,ObjectInherit') { throw 'Unsafe inherited access.' }
}
Write-Output 'Network Windows helper tests passed.'
