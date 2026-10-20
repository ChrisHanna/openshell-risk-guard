<#
.SYNOPSIS
  Deploy the harmless test fixture and build a small workload image that has curl, for trying Risk Guard.

.DESCRIPTION
  * Imports python:3.12-alpine into your registry (one pull from Docker Hub) and runs the fixture from a ConfigMap.
  * Builds the `workload` stage of scripts/rail-guard-demo-assets.Dockerfile (Ubuntu with curl) in your registry.
  Afterwards: openshell sandbox create --from <acr>/openshell-demo/workload:1 --policy deploy/aks/sandbox-policy.yaml ...
#>
[CmdletBinding()]
param([string]$PythonSource = 'docker.io/library/python:3.12-alpine')
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster

$state = Get-ClusterContext
$ns = if ($state.namespace) { $state.namespace } else { 'openshell' }
$acrServer = "$($state.acr).azurecr.io"

Write-Step 'Importing the Python base image into your registry'
Invoke-Native az @('acr', 'import', '-n', $state.acr, '--source', $PythonSource, '--image', 'python:3.12-alpine', '--force', '--only-show-errors') -Retries 2 | Out-Null

Write-Step 'Deploying the fixture'
$src = Invoke-Native kubectl @('create', 'configmap', 'risk-guard-fixture-src', '-n', $ns,
    "--from-file=fixture.py=$(Join-Path $script:RepoRoot 'scripts/rail-guard-demo-fixture.py')", '--dry-run=client', '-o', 'yaml')
Invoke-KubectlApply ($src -join "`n")
$manifest = (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/fixture.yaml') -Raw).Replace('__PYTHON_IMAGE__', "$acrServer/python:3.12-alpine")
Invoke-KubectlApply $manifest
Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard-fixture', '-n', $ns, '--timeout=180s') | Out-Null

Write-Step 'Building the workload image (Ubuntu + curl) in your registry'
$ctx = Join-Path ([IO.Path]::GetTempPath()) ("rg-workload-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $ctx | Out-Null
try {
    Copy-Item (Join-Path $script:RepoRoot 'scripts/rail-guard-demo-assets.Dockerfile') (Join-Path $ctx 'Dockerfile')
    Invoke-Native az @('acr', 'build', '-r', $state.acr, '-t', 'openshell-demo/workload:1', '--target', 'workload', $ctx, '--no-logs', '--only-show-errors') -Retries 1 | Out-Null
} finally { Remove-Item -Recurse -Force $ctx -ErrorAction SilentlyContinue }
Save-State @{ workloadImage = "$acrServer/openshell-demo/workload:1" }

Write-Host "`nWorkload image: $acrServer/openshell-demo/workload:1" -ForegroundColor Green
Write-Host "Policy to use: deploy/aks/sandbox-policy.yaml"
