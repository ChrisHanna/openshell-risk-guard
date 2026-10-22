<#
.SYNOPSIS
  Install the Kubernetes Agent Sandbox controller and the OpenShell gateway from its Helm chart.

.DESCRIPTION
  OpenShell's chart requires the Agent Sandbox CRDs and controller, so a pinned release is applied
  first. The chart and the gateway images come from NVIDIA's public registry (ghcr.io/nvidia/openshell) at the OpenShell
  commit pinned in this repository's Cargo.toml, so no OpenShell checkout is needed. Pass -OpenShellPath to use a local
  checkout's chart instead (for working on OpenShell itself); -ImageTag overrides the image tag.

  Pass -RuntimeClass kata-vm-isolation to schedule every sandbox pod in a Kata VM (see 06-add-kata-pool.ps1).
#>
[CmdletBinding()]
param(
    [string]$OpenShellPath,
    [string]$ImageTag,
    [string]$AgentSandboxVersion = 'v1.0.7',
    [string]$Namespace = 'openshell',
    [string]$RuntimeClass,
    [switch]$ClearRuntimeClass,
    [string]$ReleaseName = 'openshell'
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster

$chartInfo = Get-OpenShellChart $OpenShellPath
$chart = $chartInfo.Ref
if (-not $ImageTag) { $ImageTag = $chartInfo.ImageTag }

Write-Step "Agent Sandbox controller $AgentSandboxVersion (cluster-wide CRD and controller from kubernetes-sigs)"
Write-Note 'Pinned release, not "latest". Review the manifest if you need to: github.com/kubernetes-sigs/agent-sandbox/releases'
Invoke-Native kubectl @('apply', '--server-side', '-f', "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$AgentSandboxVersion/sandbox.yaml") | Out-Null
Invoke-Native kubectl @('-n', 'agent-sandbox-system', 'rollout', 'status', 'deploy', '--timeout=180s') | Out-Null

Write-Step "OpenShell chart ($ImageTag) into namespace $Namespace"
$helmArgs = @('upgrade', '--install', $ReleaseName, $chart, '-n', $Namespace, '--create-namespace',
    '--set', "global.image.tag=$ImageTag", '--wait', '--timeout', '10m')
if ($chartInfo.Version) { $helmArgs += @('--version', $chartInfo.Version) }
if ($RuntimeClass) { $helmArgs += @('--set', "server.defaultRuntimeClassName=$RuntimeClass") }
if ($ClearRuntimeClass) { $helmArgs += @('--set', 'server.defaultRuntimeClassName=') }
# Keep values from earlier steps (such as the extension registration from 05) when upgrading an existing release.
$exists = Invoke-Native helm @('status', $ReleaseName, '-n', $Namespace) -AllowFailure -Retries 1
if ($exists) { $helmArgs += '--reset-then-reuse-values' }
Invoke-Native helm $helmArgs -Retries 1 | Out-Null
Save-State @{ namespace = $Namespace; releaseName = $ReleaseName; openshellImageTag = $ImageTag; openshellChart = $chart; openshellChartVersion = $chartInfo.Version }

kubectl get pods -n $Namespace
Write-Host "`nDone. Next: scripts/aks/04-deploy-risk-guard.ps1" -ForegroundColor Green
