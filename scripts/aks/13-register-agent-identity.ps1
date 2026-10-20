<#
.SYNOPSIS
  Give an agent its own Microsoft Entra identity and map that identity to its Risk Guard workload.

.DESCRIPTION
  * Registers an Entra application (and service principal) for the agent, named openshell-agent-<AgentName>.
    Its application (client) ID is the agent's stable identity.
  * Creates a client secret and stores it ONLY in Key Vault (secret <AgentName>-client-secret); the value is never
    printed or written to the repository.
  * Lets sandboxes use the application ID as their Risk Guard workload: create the sandbox with
        --annotation openshell.nvidia.com/agent-id=<application id>
    Risk Guard binds the sandbox to that workload when the creating principal is on its binding allowlist. This
    script allows the chart's shared client-certificate identity (user:openshell-client) and turns on
    auto-registration, so the workload is created on first use and scoped to the sandbox's workspace.

  Reading the secret back for an OpenShell provider is 12-sync-credentials.ps1. An OpenShell provider that mints
  Entra tokens uses the profile in deploy/aks/entra-agent-provider.yaml.
#>
[CmdletBinding()]
param(
    [string]$AgentName = 'nat-agent',
    [string]$BindingPrincipal = 'user:openshell-client',
    [switch]$RotateSecret,
    [switch]$SkipRiskGuardUpdate
)
. "$PSScriptRoot/common.ps1"
Assert-Tool az 'Install the Azure CLI.'
$vault = Get-StateValue 'keyVault'
if (-not $vault) { throw 'No Key Vault recorded. Run 10-create-key-vault.ps1 first.' }
$display = "openshell-agent-$AgentName"
$secretName = "$AgentName-client-secret"

Write-Step "Entra application $display"
$appId = (Invoke-Native az @('ad', 'app', 'list', '--display-name', $display, '--query', '[0].appId', '-o', 'tsv', '--only-show-errors') -Retries 4 | Select-Object -First 1)
if (-not $appId) {
    $appId = (Invoke-Native az @('ad', 'app', 'create', '--display-name', $display, '--sign-in-audience', 'AzureADMyOrg', '--query', 'appId', '-o', 'tsv', '--only-show-errors') -Retries 3 | Select-Object -First 1)
}
$haveSp = Invoke-Native az @('ad', 'sp', 'show', '--id', $appId, '--query', 'id', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $haveSp) { Invoke-Native az @('ad', 'sp', 'create', '--id', $appId, '--only-show-errors', '-o', 'none') -Retries 3 | Out-Null }
$tenant = (Invoke-Native az @('account', 'show', '--query', 'tenantId', '-o', 'tsv') | Select-Object -First 1)

$haveSecret = Invoke-Native az @('keyvault', 'secret', 'show', '--vault-name', $vault, '--name', $secretName, '--query', 'id', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $haveSecret -or $RotateSecret) {
    Write-Step "Creating a client secret and storing it in Key Vault as $secretName"
    $secret = (Invoke-Native az @('ad', 'app', 'credential', 'reset', '--id', $appId, '--append', '--display-name', 'openshell-risk-guard', '--years', '1', '--query', 'password', '-o', 'tsv', '--only-show-errors') -Retries 3 | Select-Object -First 1)
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("kv-" + [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($tmp, $secret, (New-Object Text.UTF8Encoding($false)))
        if (Test-Unix) { & chmod 600 $tmp }
        $secret = $null
        Invoke-Native az @('keyvault', 'secret', 'set', '--vault-name', $vault, '--name', $secretName, '--file', $tmp, '--encoding', 'utf-8',
            '--description', "Client secret of Entra app $appId", '--query', 'id', '-o', 'tsv', '--only-show-errors') -Retries 4 | Out-Null
    } finally {
        if (Test-Path $tmp) { [IO.File]::WriteAllBytes($tmp, (New-Object byte[] 256)); Remove-Item -Force $tmp }
    }
}
Save-State @{ ("agentAppId-$AgentName") = $appId; agentTenantId = $tenant }

if (-not $SkipRiskGuardUpdate) {
    Use-Cluster
    $ns = Get-StateValue 'namespace' 'openshell'
    Write-Step "Letting $BindingPrincipal bind sandboxes to a workload by label (and auto-register the workload)"
    $deploy = (Invoke-Native kubectl @('get', 'deploy/risk-guard', '-n', $ns, '-o', 'json') | Out-String) | ConvertFrom-Json
    $container = $deploy.spec.template.spec.containers | Where-Object { $_.name -eq 'risk-guard' }
    $args = @($container.args)
    if ($args -notcontains '--auto-register-agents') { $args += '--auto-register-agents' }
    $current = if ($container.PSObject.Properties.Name -contains 'env') { @($container.env) } else { @() }
    $env_ = @($current | Where-Object { $_ -and $_.name -ne 'RISK_GUARD_AGENT_BINDING_PRINCIPALS' })
    $env_ += [pscustomobject]@{ name = 'RISK_GUARD_AGENT_BINDING_PRINCIPALS'; value = $BindingPrincipal }
    $patch = @{ spec = @{ template = @{ spec = @{ containers = @(@{ name = 'risk-guard'; args = $args; env = $env_ }) } } } } | ConvertTo-Json -Depth 12
    $patchFile = Join-Path ([IO.Path]::GetTempPath()) 'rg-identity-patch.json'
    Set-Content -Path $patchFile -Encoding utf8 -Value $patch
    try { Invoke-Native kubectl @('patch', 'deploy/risk-guard', '-n', $ns, '--patch-file', $patchFile) | Out-Null } finally { Remove-Item -Force $patchFile -ErrorAction SilentlyContinue }
    Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard', '-n', $ns, '--timeout=300s') | Out-Null
}

Write-Host ""
Write-Host "Agent identity" -ForegroundColor Green
Write-Host "  application (client) ID : $appId"
Write-Host "  tenant                  : $tenant"
Write-Host "  client secret           : Key Vault $vault / $secretName"
Write-Host "Use it as the workload:  openshell sandbox create ... --annotation openshell.nvidia.com/agent-id=$appId"
