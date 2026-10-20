<#
.SYNOPSIS
  Create an Azure Key Vault that holds agent credentials, locked to your address and to RBAC.

.DESCRIPTION
  Key Vault is the system of record for secrets such as an NVIDIA API key or an Entra application's client
  secret: access control, audit log, versions and rotation live here. OpenShell cannot use Key Vault as a
  credential backend (it supports its own store, Kubernetes Secrets and HashiCorp Vault's API), so
  12-sync-credentials.ps1 copies a secret from here into an OpenShell provider.

  The vault uses RBAC (no access policies), soft delete with purge protection, and a firewall that allows only
  -AllowedIp. You are granted "Key Vault Secrets Officer" so you can set secrets. Cost is a few cents a month.
#>
[CmdletBinding()]
param(
    [string]$VaultName,
    [string[]]$AllowedIp
)
. "$PSScriptRoot/common.ps1"
Assert-Tool az 'Install the Azure CLI.'
$state = Get-ClusterContext

$vault = if ($VaultName) { $VaultName } else { Get-StateValue 'keyVault' ("kv-osrg-" + (Get-Random -Minimum 10000 -Maximum 99999)) }
if ($vault -notmatch '^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$') { throw "Vault names are 3-24 letters, digits or hyphens: $vault" }
if (-not $AllowedIp) { $AllowedIp = @((Invoke-RestMethod 'https://api.ipify.org').Trim()); Write-Note "allowing $($AllowedIp -join ', ') (pass -AllowedIp to change)" }

Save-State @{ keyVault = $vault }   # remember the name before creating it, so a re-run after a failure reuses it
Write-Step "Key Vault $vault"
$have = Invoke-Native az @('keyvault', 'show', '-n', $vault, '--query', 'name', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $have) {
    Invoke-Native az @('keyvault', 'create', '-g', $state.resourceGroup, '-n', $vault, '-l', $state.location,
        '--enable-rbac-authorization', 'true', '--enable-purge-protection', 'true', '--retention-days', '7',
        '--default-action', 'Deny', '--bypass', 'AzureServices', '--tags', 'purpose=openshell-risk-guard-trial', '--only-show-errors', '-o', 'none') -Retries 2 | Out-Null
}
foreach ($ip in $AllowedIp) {
    $range = if ($ip -match '/') { $ip } else { "$ip/32" }
    Invoke-Native az @('keyvault', 'network-rule', 'add', '-n', $vault, '--ip-address', $range, '--only-show-errors', '-o', 'none') -AllowFailure | Out-Null
}

Write-Step 'Granting you Key Vault Secrets Officer on this vault'
$vaultId = (Invoke-Native az @('keyvault', 'show', '-n', $vault, '--query', 'id', '-o', 'tsv', '--only-show-errors') | Select-Object -First 1)
# Assign by object ID, taken from the access token: guest and Microsoft accounts cannot always be looked up by
# user name in Graph, and the token's `oid` claim needs no Graph permission.
$token = (Invoke-Native az @('account', 'get-access-token', '--query', 'accessToken', '-o', 'tsv') | Select-Object -First 1)
$payload = $token.Split('.')[1].Replace('-', '+').Replace('_', '/')
while ($payload.Length % 4) { $payload += '=' }
$myOid = (([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))) | ConvertFrom-Json).oid
if (-not $myOid) { throw 'Could not read your object ID from the access token.' }
$haveRole = Invoke-Native az @('role', 'assignment', 'list', '--assignee', $myOid, '--scope', $vaultId, '--role', 'Key Vault Secrets Officer', '--query', '[0].id', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $haveRole) {
    Invoke-Native az @('role', 'assignment', 'create', '--assignee-object-id', $myOid, '--assignee-principal-type', 'User', '--role', 'Key Vault Secrets Officer',
        '--scope', $vaultId, '--only-show-errors', '-o', 'none') -Retries 2 | Out-Null
    Write-Note 'Role assignments can take a minute to take effect.'
}
Save-State @{ keyVault = $vault }
Write-Host "`nVault: $vault`nNext: scripts/aks/11-set-secret.ps1 -Name nvidia-api-key" -ForegroundColor Green
