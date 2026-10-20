<#
.SYNOPSIS
  Add an AKS node pool that runs pods in Kata VM isolation (AKS Pod Sandboxing).

.DESCRIPTION
  Kata pods need Azure Linux nodes and a VM size that supports nested virtualization (Gen2, for example
  Dsv5). AKS registers the `kata-vm-isolation` runtime class when such a pool exists. To run every OpenShell
  sandbox in a Kata VM, re-run 03-install-openshell.ps1 with -RuntimeClass kata-vm-isolation.

  OpenShell requires Landlock ABI 3 (Linux 6.2+) inside the sandbox and fails closed without it. Whether the
  Kata guest kernel provides it is what this experiment tests: see docs/aks.md.
#>
[CmdletBinding()]
param(
    [string]$PoolName = 'kata',
    [string]$VmSize = 'Standard_D4s_v5',
    [int]$NodeCount = 1
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
$state = Get-ClusterContext

Write-Step "Node pool $PoolName ($VmSize x $NodeCount)"
$have = Invoke-Native az @('aks', 'nodepool', 'show', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $PoolName, '--query', 'name', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $have) {
    Invoke-Native az @('aks', 'nodepool', 'add', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $PoolName,
        '--node-vm-size', $VmSize, '--node-count', "$NodeCount", '--os-sku', 'AzureLinux', '--workload-runtime', 'KataVmIsolation',
        '--labels', 'pool=kata', '--tags', 'purpose=openshell-risk-guard-trial', '--only-show-errors', '-o', 'none') -Retries 1 | Out-Null
}
Use-Cluster
kubectl get nodes -L pool
kubectl get runtimeclass
Write-Host "`nDone. Sandboxes use Kata when OpenShell is installed with -RuntimeClass kata-vm-isolation." -ForegroundColor Green
