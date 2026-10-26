<#
.SYNOPSIS
  Require Microsoft Entra sign-in for the Risk Guard console, and record who may use it.

.DESCRIPTION
  Creates (or updates) one single-tenant Entra app registration for the console and writes the settings the console
  needs to .aks/state.json:

    * The app exposes one delegated scope, api://<app id>/access, and issues v2 access tokens. The console page signs
      administrators in with the authorization-code flow and PKCE (no client secret exists), and the console verifies each
      token itself: signature, issuer, tenant, audience, expiry and scope.
    * Access follows the account's OBJECT ID, which Entra assigns and never reuses; an email address is only shown to
      people. -AdminObjectId may change settings (and is the only role that can); -ViewerObjectId is only meaningful with
      -RequireSignInToRead. By default the administrator is the account you are signed in to Azure with.
    * Everyone can read the console without signing in. Administrators sign in at https://<console>/admin, which is the
      only place that can change settings. Pass -RequireSignInToRead to make the whole console members-only instead.
    * The redirect URI is https://<console>/admin, so 09-expose-console.ps1 must have chosen the address first (it
      records the name in state). Pass -LocalRedirectPort to also allow http://localhost:<port>/admin for trying it locally.

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
    [int]$LocalRedirectPort,
    [switch]$RequireSignInToRead
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

function Resolve-EntraObjectId([string]$Identity) {
    $trimmed = $Identity.Trim()
    if ($trimmed -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        return $trimmed.ToLowerInvariant()
    }
    $candidates = @($trimmed)
    if ($trimmed -match '^([^@]+)\.christopherghannagmailcom@onmicrosoft\.com$') {
        $candidates += "$($Matches[1])@christopherghannagmail.onmicrosoft.com"
    }
    foreach ($candidate in $candidates) {
        $resolved = Invoke-Native az @('ad', 'user', 'show', '--id', $candidate, '--query', 'id', '-o', 'tsv') -AllowFailure
        if ($resolved) {
            $guid = ($resolved | Select-Object -First 1).Trim()
            if ($guid -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                Write-Note "resolved '$Identity' -> object ID $($guid.ToLowerInvariant())"
                return $guid.ToLowerInvariant()
            }
        }
    }
    throw "Not an object ID (a GUID) and could not resolve Entra user: $Identity"
}

$tenant = (Invoke-Native az @('account', 'show', '--query', 'tenantId', '-o', 'tsv') | Select-Object -First 1).Trim()
if (-not $AdminObjectId) {
    $signedIn = (Invoke-Native az @('ad', 'signed-in-user', 'show', '--query', 'id', '-o', 'tsv') | Select-Object -First 1).Trim()
    $AdminObjectId = @($signedIn)
    Write-Note "administrator: the account you are signed in with (object ID $($AdminObjectId[0]))"
    $secondApprover = Invoke-Native az @('ad', 'user', 'show', '--id', 'learningnemo-approver@christopherghannagmail.onmicrosoft.com', '--query', 'id', '-o', 'tsv') -AllowFailure
    if ($secondApprover) {
        $secondGuid = ($secondApprover | Select-Object -First 1).Trim()
        if ($secondGuid -and ($AdminObjectId -notcontains $secondGuid)) {
            $AdminObjectId += $secondGuid
            Write-Note "second approver administrator: learningnemo-approver@christopherghannagmail.onmicrosoft.com (object ID $secondGuid)"
        }
    }
}
$AdminObjectId = @($AdminObjectId | Where-Object { $_ } | ForEach-Object { Resolve-EntraObjectId $_ } | Select-Object -Unique)
$ViewerObjectId = @($ViewerObjectId | Where-Object { $_ } | ForEach-Object { Resolve-EntraObjectId $_ } | Select-Object -Unique)
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

# /admin receives the sign-in; / is where signing out returns.
$redirects = @("https://$consoleHost/admin", "https://$consoleHost/")
if ($LocalRedirectPort) { $redirects += @("http://localhost:$LocalRedirectPort/admin", "http://localhost:$LocalRedirectPort/") }
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
# Where the tenant allows it, the Azure CLI is pre-authorized too, so `az account get-access-token --scope api://<app id>/access`
# works for scripts that read a members-only console as the signed-in administrator, with no secret to store.
$azureCli = '04b07795-8ddb-4961-a3f5-6a4ee1a4e0d0'
$preAuthorized = @(@{ appId = $appId; delegatedPermissionIds = @($scopeId) })
# Entra only accepts a pre-authorized app that exists in this tenant. The Azure CLI's service principal is created on
# first use and some tenants cannot create it on demand, so this is best effort: only scripts that read a members-only
# console (-RequireSignInToRead) need it, and without it they can still be run from a signed-in browser.
$cliThere = Invoke-Native az @('ad', 'sp', 'show', '--id', $azureCli, '--query', 'id', '-o', 'tsv') -AllowFailure
if (-not $cliThere) { $cliThere = Invoke-Native az @('ad', 'sp', 'create', '--id', $azureCli, '--query', 'id', '-o', 'tsv') -AllowFailure -Retries 1 }
if ($cliThere) { $preAuthorized += @{ appId = $azureCli; delegatedPermissionIds = @($scopeId) } }
else { Write-Note 'the Azure CLI is not available as a client in this tenant; skipping its pre-authorization (not needed for the public console)' }
$api.preAuthorizedApplications = $preAuthorized
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
    consoleRequireSignInToRead = [bool]$RequireSignInToRead
}
Write-Host ''
Write-Host "Sign-in configured. Everyone: https://$consoleHost/   Administrators: https://$consoleHost/admin" -ForegroundColor Green
if ($RequireSignInToRead) { Write-Host '  The whole console is members-only (-RequireSignInToRead).' }
Write-Host "  Administrators: $($AdminObjectId -join ', ')"
Write-Host "  Viewers:        $(if ($ViewerObjectId) { $ViewerObjectId -join ', ' } else { '(none)' })"
Write-Host 'Next: 04-deploy-risk-guard.ps1 (applies the settings), then 09-expose-console.ps1 (removes the IP allowlist).'
