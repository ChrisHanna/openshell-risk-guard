<#
.SYNOPSIS
  Require Microsoft Entra sign-in for the Risk Guard console, and record who may use it.

.DESCRIPTION
  Creates (or updates) one single-tenant Entra app registration for the console and writes the settings the console
  needs to .aks/state.json:

    * The app exposes one delegated scope, api://<app id>/access, and issues v2 access tokens. The console page signs
      people in with the authorization-code flow and PKCE (no client secret exists), and the console verifies each token
      itself: signature, issuer, tenant, audience, expiry and scope.
    * Access follows the account's OBJECT ID, which Entra assigns and never reuses; an email address is only shown to
      people. -AdminObjectId may read and change settings, -ViewerObjectId may read. By default the administrator is the
      account you are signed in to Azure with. Anyone else sees only a sign-in screen and receives no data.
    * The redirect URI is the console's HTTPS address, so 09-expose-console.ps1 must have chosen it first (it records
      the name in state). Pass -LocalRedirectPort to also allow http://localhost:<port>/ for trying the page locally.

  Re-run to change the lists or the address; it never creates a second registration. Afterwards run
  04-deploy-risk-guard.ps1 (passes the settings to the console) and 09-expose-console.ps1 (drops the IP allowlist,
  because sign-in is now the protection).

  To find someone's object ID:  az ad user show --id <their sign-in name> --query id -o tsv
#>
[CmdletBinding()]
param(
    [string[]]$AdminObjectId,
    [string[]]$ViewerObjectId,
    [string]$AppName = 'openshell-risk-guard-console',
    [int]$LocalRedirectPort
)
. "$PSScriptRoot/common.ps1"
Assert-Tool az 'Install the Azure CLI: https://learn.microsoft.com/cli/azure/install-azure-cli'

function Invoke-Graph([string]$Method, [string]$Uri, $Body) {
    $file = Join-Path ([IO.Path]::GetTempPath()) ("rg-graph-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
    try {
        $arguments = @('rest', '--method', $Method, '--uri', $Uri, '--headers', 'Content-Type=application/json')
        if ($null -ne $Body) {
            Set-Content -Path $file -Encoding utf8 -Value (ConvertTo-Json -InputObject $Body -Depth 12)
            $arguments += @('--body', "@$file")
        }
        return Invoke-Native az $arguments
    } finally { Remove-Item -Force $file -ErrorAction SilentlyContinue }
}

$tenant = (Invoke-Native az @('account', 'show', '--query', 'tenantId', '-o', 'tsv') | Select-Object -First 1).Trim()
if (-not $AdminObjectId) {
    $AdminObjectId = @((Invoke-Native az @('ad', 'signed-in-user', 'show', '--query', 'id', '-o', 'tsv') | Select-Object -First 1).Trim())
    Write-Note "administrator: the account you are signed in with (object ID $($AdminObjectId[0]))"
}
foreach ($oid in @($AdminObjectId) + @($ViewerObjectId)) {
    if ($oid -and $oid -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { throw "Not an object ID (a GUID): $oid" }
}
$consoleHost = Get-StateValue 'consoleHost'
if (-not $consoleHost) { throw 'The console address is not recorded yet. Run 09-expose-console.ps1 once first, then re-run this script.' }

Write-Step "Registering the console app '$AppName' in tenant $tenant"
$found = Invoke-Native az @('ad', 'app', 'list', '--display-name', $AppName, '--query', '[0].{id:id,appId:appId}', '-o', 'json') | ConvertFrom-Json
if ($found -and $found.appId) {
    $objectId = $found.id; $appId = $found.appId
    Write-Note "found the existing registration ($appId)"
} else {
    $created = Invoke-Native az @('ad', 'app', 'create', '--display-name', $AppName, '--sign-in-audience', 'AzureADMyOrg', '--query', '{id:id,appId:appId}', '-o', 'json') | ConvertFrom-Json
    $objectId = $created.id; $appId = $created.appId
    Write-Note "created ($appId)"
}

# Keep the scope's ID stable across runs so tokens and consent remain valid.
$existing = Invoke-Graph 'GET' "https://graph.microsoft.com/v1.0/applications/$objectId`?`$select=api" $null | ConvertFrom-Json
$scopeId = $null
foreach ($scope in @($existing.api.oauth2PermissionScopes)) { if ($scope.value -eq 'access') { $scopeId = $scope.id } }
if (-not $scopeId) { $scopeId = [guid]::NewGuid().ToString() }

$redirects = @("https://$consoleHost/")
if ($LocalRedirectPort) { $redirects += "http://localhost:$LocalRedirectPort/" }
$api = @{
    requestedAccessTokenVersion = 2
    oauth2PermissionScopes = @(@{
        id = $scopeId; value = 'access'; type = 'User'; isEnabled = $true
        adminConsentDisplayName = 'Use the Risk Guard console'
        adminConsentDescription = 'Allows the signed-in user to view the Risk Guard console and, if they are an administrator, change its settings.'
        userConsentDisplayName = 'Use the Risk Guard console'
        userConsentDescription = 'Sign in to the Risk Guard console.'
    })
}
Write-Step 'Configuring the scope, redirect address and token version'
Invoke-Graph 'PATCH' "https://graph.microsoft.com/v1.0/applications/$objectId" @{
    identifierUris = @("api://$appId")
    spa = @{ redirectUris = $redirects }
    api = $api
    optionalClaims = @{ accessToken = @(@{ name = 'email' }) }
} | Out-Null
# The console is its own client, so it is pre-authorized for its own scope (no consent screen for the scope itself).
# The Azure CLI is pre-authorized too, so `az account get-access-token --scope api://<app id>/access` works for scripts
# that read the console as the signed-in administrator, with no secret to store.
$azureCli = '04b07795-8ddb-4961-a3f5-6a4ee1a4e0d0'
$api.preAuthorizedApplications = @(
    @{ appId = $appId; delegatedPermissionIds = @($scopeId) },
    @{ appId = $azureCli; delegatedPermissionIds = @($scopeId) })
Invoke-Graph 'PATCH' "https://graph.microsoft.com/v1.0/applications/$objectId" @{ api = $api } | Out-Null

$sp = Invoke-Native az @('ad', 'sp', 'show', '--id', $appId, '--query', 'id', '-o', 'tsv') -AllowFailure
if (-not $sp) {
    Write-Step 'Creating the enterprise application (service principal) for the registration'
    Invoke-Native az @('ad', 'sp', 'create', '--id', $appId) | Out-Null
}

Save-State @{
    consoleEntraTenantId   = $tenant
    consoleEntraClientId   = $appId
    consoleEntraAdminOids  = @($AdminObjectId | ForEach-Object { $_.ToLowerInvariant() })
    consoleEntraViewerOids = @($ViewerObjectId | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
}
Write-Host ''
Write-Host "Sign-in configured for https://$consoleHost/" -ForegroundColor Green
Write-Host "  Administrators: $($AdminObjectId -join ', ')"
Write-Host "  Viewers:        $(if ($ViewerObjectId) { $ViewerObjectId -join ', ' } else { '(none)' })"
Write-Host 'Next: 04-deploy-risk-guard.ps1 (applies the settings), then 09-expose-console.ps1 (removes the IP allowlist).'
