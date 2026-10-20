<#
.SYNOPSIS
  Register Risk Guard with the OpenShell gateway as a gateway interceptor and supervisor middleware.

.DESCRIPTION
  Applies deploy/aks/gateway-extensions-values.yaml to the OpenShell release. The gateway validates each
  registered service (Describe) at startup, so Risk Guard must already be running (04-deploy-risk-guard.ps1).
  Registration is static: the gateway restarts to pick it up.
#>
[CmdletBinding()]
param([string]$OpenShellPath)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster

$state = Get-ClusterContext
$ns = Get-StateValue 'namespace' 'openshell'
$release = Get-StateValue 'releaseName' 'openshell'
$chart = Get-StateValue 'openshellChart' (Join-Path (Get-OpenShellCheckout $OpenShellPath) 'deploy/helm/openshell')

Write-Step 'Confirming Risk Guard is ready before the gateway depends on it'
Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard', '-n', $ns, '--timeout=120s') | Out-Null

Write-Step 'Registering the interceptor and middleware'
Invoke-Native helm @('upgrade', $release, $chart, '-n', $ns, '--reuse-values', '-f', (Join-Path $script:RepoRoot 'deploy/aks/gateway-extensions-values.yaml'),
    '--wait', '--timeout', '10m') -Retries 1 | Out-Null

Write-Step 'Gateway log lines about Risk Guard'
Start-Sleep -Seconds 5
kubectl logs -n $ns statefulset/$release --tail=300 2>$null | Select-String -Pattern 'risk-guard|interceptor|middleware' | Select-Object -First 8 | ForEach-Object { $_.Line.Substring(0, [Math]::Min(180, $_.Line.Length)) }
Write-Host "`nDone. Run scripts/aks/07-verify.ps1 once you have connected the CLI (connect-gateway.sh)." -ForegroundColor Green
