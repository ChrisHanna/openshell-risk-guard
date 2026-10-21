<#
.SYNOPSIS
  Build the NVIDIA NeMo Agent Toolkit demo agent image in your registry.

.DESCRIPTION
  The image extends the workload image from 08-deploy-fixture.ps1 (Ubuntu with curl) with Python, the NeMo Agent
  Toolkit, NeMo Guardrails and the demo agent (deploy/rail-guard-demo/agent). It is about 1.8 GB, so the build takes
  several minutes in Azure. Afterwards:

    openshell sandbox create --from <acr>/openshell-demo/nat-agent:1 --provider nvidia-nat \
      --policy deploy/aks/agent-sandbox-policy.yaml \
      --annotation openshell.nvidia.com/agent-id=<the agent's Entra application ID> -- sleep infinity

  The NVIDIA API key reaches the agent only as an OpenShell provider credential: store it in Key Vault
  (11-set-secret.ps1) and copy it into the provider with 12-sync-credentials.ps1.
#>
[CmdletBinding()]
param(
    [string]$Tag = '2',
    # Build with the local Docker engine and push, instead of `az acr build` (see 02-build-image.ps1 -LocalDocker).
    [switch]$LocalDocker
)
. "$PSScriptRoot/common.ps1"
Assert-Tool az 'Install the Azure CLI.'
$state = Get-ClusterContext
$base = "$($state.acr).azurecr.io/openshell-demo/workload:1"
$agentDir = Join-Path $script:RepoRoot 'deploy/rail-guard-demo/agent'

if ($LocalDocker) {
    Assert-Tool docker 'Install and start Docker Desktop.'
    $server = "$($state.acr).azurecr.io"
    Write-Step "Signing in to $server"
    Connect-AcrDocker $server
    Write-Step "Building nat-agent:$Tag locally on $base"
    $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        & docker build --progress=plain --build-arg "BASE=$base" -t "$server/openshell-demo/nat-agent:$Tag" -f (Join-Path $agentDir 'Dockerfile') $agentDir 2>&1 | ForEach-Object { "$_" } | Select-Object -Last 15
        if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }
        & docker push "$server/openshell-demo/nat-agent:$Tag" 2>&1 | Select-Object -Last 3
        if ($LASTEXITCODE -ne 0) { throw 'docker push failed' }
    } finally { $ErrorActionPreference = $previous }
    Save-State @{ agentImage = "$server/openshell-demo/nat-agent:$Tag" }
    Write-Host "Image: $server/openshell-demo/nat-agent:$Tag" -ForegroundColor Green
    return
}

Write-Step "Building nat-agent:$Tag on $base (several minutes, runs in Azure)"
Invoke-Native az @('acr', 'build', '-r', $state.acr, '-t', "openshell-demo/nat-agent:$Tag", '--build-arg', "BASE=$base",
    '-f', (Join-Path $agentDir 'Dockerfile'), $agentDir, '--no-logs', '--no-wait', '--only-show-errors') -Retries 1 | Out-Null
$runId = (Invoke-Native az @('acr', 'task', 'list-runs', '-r', $state.acr, '--top', '1', '--query', '[0].runId', '-o', 'tsv', '--only-show-errors') -Retries 5 | Select-Object -First 1)
Write-Note "run $runId queued"
while ($true) {
    Start-Sleep -Seconds 20
    $status = (Invoke-Native az @('acr', 'task', 'show-run', '-r', $state.acr, '--run-id', $runId, '--query', 'status', '-o', 'tsv', '--only-show-errors') -Retries 5 | Select-Object -First 1)
    if ($status -in 'Succeeded', 'Failed', 'Canceled', 'Error', 'Timeout') { break }
}
if ($status -ne 'Succeeded') { throw "Build $runId finished with status $status. Logs: az acr task logs -r $($state.acr) --run-id $runId" }
Save-State @{ agentImage = "$($state.acr).azurecr.io/openshell-demo/nat-agent:$Tag" }
Write-Host "Image: $($state.acr).azurecr.io/openshell-demo/nat-agent:$Tag" -ForegroundColor Green
