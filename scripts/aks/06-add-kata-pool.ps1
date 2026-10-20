<#
.SYNOPSIS
  Add a node pool that runs OpenShell sandboxes in Kata VMs.

.DESCRIPTION
  Two modes:

  UpstreamKata (default, works)
    A normal Ubuntu node pool on a VM size with nested virtualization, plus upstream Kata Containers installed by
    the kata-deploy Helm chart (QEMU runtime, RuntimeClass `kata-qemu`). Upstream's guest kernel enables Landlock,
    which OpenShell requires. kata-deploy is a privileged installer that changes the selected nodes (it writes
    the Kata runtime into their containerd configuration), so it is limited to nodes labeled openshell.ai/kata=true.

  AksPodSandboxing (does NOT work with OpenShell)
    AKS's managed Pod Sandboxing (`--workload-runtime KataVmIsolation`, RuntimeClass `kata-vm-isolation`). Its guest
    kernel lacks CONFIG_SECURITY_LANDLOCK, so OpenShell fails closed with "Landlock is not implemented". Kept only
    to reproduce that finding.

  Either way, the RuntimeClass is approved for OpenShell with the label openshell.ai/sandbox-attachable=true
  (OpenShell resource admission), and you then run 03-install-openshell.ps1 -RuntimeClass <name>.
#>
[CmdletBinding()]
param(
    [ValidateSet('UpstreamKata', 'AksPodSandboxing')][string]$Mode = 'UpstreamKata',
    [string]$PoolName = 'kata',
    [string]$VmSize = 'Standard_D4s_v5',
    [int]$NodeCount = 1,
    [string]$KataDeployVersion = '4.2.0'
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
$state = Get-ClusterContext

Write-Step "Node pool $PoolName ($VmSize x $NodeCount, mode $Mode)"
$have = Invoke-Native az @('aks', 'nodepool', 'show', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $PoolName, '--query', 'name', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $have) {
    $add = @('aks', 'nodepool', 'add', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $PoolName,
        '--node-vm-size', $VmSize, '--node-count', "$NodeCount", '--tags', 'purpose=openshell-risk-guard-trial', '--only-show-errors', '-o', 'none')
    if ($Mode -eq 'AksPodSandboxing') {
        $add += @('--os-sku', 'AzureLinux', '--workload-runtime', 'KataVmIsolation', '--labels', 'pool=kata')
    } else {
        $add += @('--os-sku', 'Ubuntu', '--labels', 'pool=kata', 'openshell.ai/kata=true')
    }
    Invoke-Native az $add -Retries 1 | Out-Null
}
Use-Cluster

if ($Mode -eq 'UpstreamKata') {
    Write-Step 'Locating the Kata node'
    $node = (Invoke-Native kubectl @('get', 'nodes', '-l', 'openshell.ai/kata=true', '-o', 'jsonpath={.items[0].metadata.name}') | Select-Object -First 1)
    if (-not $node) { throw 'No node carries the label openshell.ai/kata=true.' }
    Write-Note "node: $node (kata-deploy refuses a node without /dev/kvm or /dev/mshv)"

    Write-Step "Installing kata-deploy $KataDeployVersion (limited to openshell.ai/kata=true nodes)"
    Invoke-Native helm @('upgrade', '--install', 'kata-deploy', 'oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy',
        '--version', $KataDeployVersion, '-n', 'kube-system', '-f', (Join-Path $script:RepoRoot 'deploy/aks/kata-deploy-values.yaml'),
        '--wait', '--timeout', '20m') -Retries 1 | Out-Null
    $runtimeClass = 'kata-qemu'
} else {
    Write-Note 'WARNING: OpenShell cannot run in this guest (no Landlock). Use UpstreamKata for a working setup.'
    $runtimeClass = 'kata-vm-isolation'
}

# OpenShell only schedules sandboxes onto operator-approved resources. A RuntimeClass is approved by the fixed
# required label below; without it CreateSandbox fails with FAILED_PRECONDITION. This is the operator's explicit
# approval to run sandboxes in Kata VMs.
Write-Step "Approving RuntimeClass $runtimeClass for OpenShell"
Invoke-Native kubectl @('label', 'runtimeclass', $runtimeClass, 'openshell.ai/sandbox-attachable=true', '--overwrite') | Out-Null
Save-State @{ kataRuntimeClass = $runtimeClass; kataMode = $Mode }

kubectl get nodes -L pool
kubectl get runtimeclass --show-labels
Write-Host "`nDone. Next: scripts/aks/03-install-openshell.ps1 -RuntimeClass $runtimeClass" -ForegroundColor Green
