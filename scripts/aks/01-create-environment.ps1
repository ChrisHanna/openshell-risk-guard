<#
.SYNOPSIS
  Create the resource group, container registry and AKS cluster used to run OpenShell with Risk Guard.

.DESCRIPTION
  Idempotent: existing resources are reused. The cluster uses Azure Linux nodes, the Azure CNI overlay
  with the Cilium dataplane (OpenShell needs a CNI that enforces NetworkPolicy), the OIDC issuer and
  workload identity, and is attached to the registry so nodes can pull from it.

  Cost: roughly 10 USD per day with the defaults (two D2s_v5 nodes, Basic registry). Run
  99-teardown.ps1 when finished.
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup,
    [string]$Location,
    [string]$ClusterName,
    [string]$AcrName,
    [string]$NodeVmSize = 'Standard_D2s_v5',
    [int]$NodeCount = 2
)
. "$PSScriptRoot/common.ps1"
Assert-Tools

$rg = Resolve-Setting $ResourceGroup 'resourceGroup' 'rg-openshell-risk-guard'
$loc = Resolve-Setting $Location 'location' 'eastus2'
$cluster = Resolve-Setting $ClusterName 'cluster' 'aks-openshell-risk-guard'
$acr = Resolve-Setting $AcrName 'acr' ("acrosrg" + (Get-Random -Minimum 10000 -Maximum 99999))
Save-State @{ resourceGroup = $rg; location = $loc; cluster = $cluster; acr = $acr }

$account = Invoke-Native az @('account', 'show', '--query', '{name:name,id:id}', '-o', 'json') | ConvertFrom-Json
Write-Step "Subscription: $($account.name)"
Write-Note 'Resources are created here and cost money until 99-teardown.ps1 removes them.'

$tags = 'purpose=openshell-risk-guard-trial'
Write-Step "Resource group $rg ($loc)"
Invoke-Native az @('group', 'create', '-n', $rg, '-l', $loc, '--tags', $tags, '--only-show-errors', '-o', 'none') | Out-Null

Write-Step "Container registry $acr"
$haveAcr = Invoke-Native az @('acr', 'show', '-g', $rg, '-n', $acr, '--query', 'name', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $haveAcr) {
    Invoke-Native az @('acr', 'create', '-g', $rg, '-n', $acr, '--sku', 'Basic', '--tags', $tags, '--only-show-errors', '-o', 'none') | Out-Null
}

Write-Step "AKS cluster $cluster (several minutes)"
$haveCluster = Invoke-Native az @('aks', 'show', '-g', $rg, '-n', $cluster, '--query', 'name', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $haveCluster) {
    Invoke-Native az @('aks', 'create', '-g', $rg, '-n', $cluster, '-l', $loc, '--tier', 'free',
        '--node-count', "$NodeCount", '--node-vm-size', $NodeVmSize, '--os-sku', 'AzureLinux',
        '--network-plugin', 'azure', '--network-plugin-mode', 'overlay', '--network-dataplane', 'cilium',
        '--enable-oidc-issuer', '--enable-workload-identity', '--attach-acr', $acr,
        '--generate-ssh-keys', '--tags', $tags, '--only-show-errors', '-o', 'none') -Retries 1 | Out-Null
}

Use-Cluster
Write-Step 'Nodes'
kubectl get nodes -o wide
Write-Step 'Runtime classes (kata-vm-isolation appears once a Kata node pool exists)'
kubectl get runtimeclass
Write-Host "`nDone. Next: scripts/aks/02-build-image.ps1" -ForegroundColor Green
