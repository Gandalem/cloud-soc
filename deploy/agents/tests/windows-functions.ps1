$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installer = Join-Path $PSScriptRoot '../install-windows.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }

# Load only function definitions, never the top-level installer or service actions.
$functions = $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($definition in $functions) { . ([ScriptBlock]::Create($definition.Extent.Text)) }

function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        return
    }
    throw "Expected error: $Pattern"
}

$Endpoint = 'https://soc.example.invalid:9200'
$Organization = 'school'
$CaPath = 'C:\certs\ca.crt'
$Root = 'C:\Program Files\Cloud-SOC-Agent'
$Channels = @('Application', 'Security', 'System')
Assert-Arguments
$Endpoint = "https://soc.example.invalid`n"
Assert-Throws { Assert-Arguments } 'HTTPS'
$Endpoint = 'https://soc.example.invalid:9200'
$Channels = @('Security', 'security')
Assert-Throws { Assert-Arguments } 'Duplicate'
$Channels = @('Security', 'Microsoft-Windows-PowerShell/Operational')
Assert-Arguments
$Channels = @("Security`n")
Assert-Throws { Assert-Arguments } 'Invalid channel'

$actualHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA512).Hash.ToLowerInvariant()
Assert-ArchiveHash $PSCommandPath $actualHash
Assert-Throws { Assert-ArchiveHash $PSCommandPath ('0' * 128) } 'SHA-512 mismatch'

# Native failures must not become an exit-0 installation success.
$Exe = 'Mock-Beat'
$CommonArgs = @('--path.data', 'C:\Program Files\Cloud-SOC-Agent\data')
function Mock-Beat { $script:CalledArgs = @($args); $global:LASTEXITCODE = 17 }
Assert-Throws { Invoke-Beat -BeatArguments @('test', 'output') } 'exit 17'
if (($CalledArgs -join '|') -ne '--path.data|C:\Program Files\Cloud-SOC-Agent\data|test|output') { throw 'Beat command arguments were lost or split.' }
function Mock-Beat { $global:LASTEXITCODE = 0 }
Invoke-Beat -BeatArguments @('test', 'config')

$ServiceName = 'cloud-soc-winlogbeat'
function Get-Service { param($Name, $ErrorAction) if ($Name -eq 'winlogbeat') { @{ Name = $Name } } }
Assert-Throws { Assert-NoInstallation } 'Existing service'
function Get-Service { param($Name, $ErrorAction) }
function Test-Path { param($LiteralPath) return $LiteralPath -eq $Root }
Assert-Throws { Assert-NoInstallation } 'partial state'
function Test-Path { param($LiteralPath) return $false }
function Get-Process { param($Name, $ErrorAction) if ($Name -eq 'filebeat') { @{ Name = $Name } } }
Assert-Throws { Assert-NoInstallation } 'already running'
function Get-Process { param($Name, $ErrorAction) }
Assert-NoInstallation

# Inspect constructed ACLs in memory; never call the real Set-Acl cmdlet.
function Set-Acl { param($LiteralPath, $AclObject) $script:CapturedAcl = $AclObject }
Set-ProtectedDirectory 'C:\unused-mock-path'
if (-not $CapturedAcl.AreAccessRulesProtected) { throw 'ACL inheritance was not disabled.' }
$rules = @($CapturedAcl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
if ($rules.Count -ne 2) { throw 'Unexpected ACL entries.' }
foreach ($rule in $rules) {
    if ($rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) { throw 'Unexpected principal in protected directory ACL.' }
    if ($rule.FileSystemRights -ne 'FullControl' -or $rule.AccessControlType -ne 'Allow') { throw 'Incorrect ACL rights.' }
    if ($rule.InheritanceFlags -ne 'ContainerInherit,ObjectInherit') { throw 'Child files would not inherit the protected ACL.' }
}
Write-Output 'PowerShell parser and isolated validation/checksum/native-error/existing-install/ACL tests passed.'
