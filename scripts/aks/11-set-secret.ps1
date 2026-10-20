<#
.SYNOPSIS
  Store a secret in the Key Vault from a hidden prompt. The value never appears in a process list, shell
  history or chat.

.DESCRIPTION
  The value is read as a SecureString, written to an owner-only temporary file, handed to
  `az keyvault secret set --file`, and the file is overwritten and deleted. Run it again with the same name to
  rotate (Key Vault keeps the old versions).
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Name, [string]$Description)
. "$PSScriptRoot/common.ps1"
Assert-Tool az 'Install the Azure CLI.'
$vault = Get-StateValue 'keyVault'
if (-not $vault) { throw 'No Key Vault recorded. Run 10-create-key-vault.ps1 first.' }
if ($Name -notmatch '^[a-zA-Z0-9-]{1,127}$') { throw 'Secret names use letters, digits and hyphens.' }

$secure = Read-Host -Prompt "Value for '$Name' (input is hidden)" -AsSecureString
if ($secure.Length -eq 0) { throw 'Empty value, nothing stored.' }
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("kv-" + [guid]::NewGuid().ToString('N'))
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    [IO.File]::WriteAllText($tmp, $plain, (New-Object Text.UTF8Encoding($false)))
    if (Test-Unix) { & chmod 600 $tmp }
    $plain = $null
    $args = @('keyvault', 'secret', 'set', '--vault-name', $vault, '--name', $Name, '--file', $tmp, '--encoding', 'utf-8', '--query', 'id', '-o', 'tsv', '--only-show-errors')
    if ($Description) { $args += @('--description', $Description) }
    $id = Invoke-Native az $args -Retries 3
    Write-Host "Stored $Name in $vault ($($id | Select-Object -First 1))" -ForegroundColor Green
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    if (Test-Path $tmp) {
        [IO.File]::WriteAllBytes($tmp, (New-Object byte[] 256))
        Remove-Item -Force $tmp
    }
}
