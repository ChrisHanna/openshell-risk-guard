<#
.SYNOPSIS
  Install the Kubernetes Agent Sandbox controller and the OpenShell gateway from its Helm chart.

.DESCRIPTION
  OpenShell's chart requires the Agent Sandbox CRDs and controller, so a pinned release is applied
  first. OpenShell images come from ghcr.io/nvidia/openshell at the tag you pass (default: the commit of
  your OpenShell checkout, which published images are tagged with).

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

$openshell = Get-OpenShellCheckout $OpenShellPath
$chart = Join-Path $openshell 'deploy/helm/openshell'
if (-not (Test-Path $chart)) { throw "Chart not found at $chart" }
if (-not $ImageTag) { $ImageTag = (Invoke-Native git @('-C', $openshell, 'rev-parse', 'HEAD') | Select-Object -First 1).Trim() }

Write-Step "Agent Sandbox controller $AgentSandboxVersion (cluster-wide CRD and controller from kubernetes-sigs)"
Write-Note 'Pinned release, not "latest". Review the manifest if you need to: github.com/kubernetes-sigs/agent-sandbox/releases'
Invoke-Native kubectl @('apply', '--server-side', '-f', "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$AgentSandboxVersion/sandbox.yaml") | Out-Null
Invoke-Native kubectl @('-n', 'agent-sandbox-system', 'rollout', 'status', 'deploy', '--timeout=180s') | Out-Null

Write-Step "OpenShell chart ($ImageTag) into namespace $Namespace"
$helmArgs = @('upgrade', '--install', $ReleaseName, $chart, '-n', $Namespace, '--create-namespace',
    '--set', "global.image.tag=$ImageTag", '--wait', '--timeout', '10m')
if ($RuntimeClass) { $helmArgs += @('--set', "server.defaultRuntimeClassName=$RuntimeClass") }
if ($ClearRuntimeClass) { $helmArgs += @('--set', 'server.defaultRuntimeClassName=') }
# Keep values from earlier steps (such as the extension registration from 05) when upgrading an existing release.
$exists = Invoke-Native helm @('status', $ReleaseName, '-n', $Namespace) -AllowFailure -Retries 1
if ($exists) { $helmArgs += '--reset-then-reuse-values' }
Invoke-Native helm $helmArgs -Retries 1 | Out-Null
Save-State @{ namespace = $Namespace; releaseName = $ReleaseName; openshellImageTag = $ImageTag; openshellChart = $chart }

kubectl get pods -n $Namespace
Write-Host "`nDone. Next: scripts/aks/04-deploy-risk-guard.ps1" -ForegroundColor Green
