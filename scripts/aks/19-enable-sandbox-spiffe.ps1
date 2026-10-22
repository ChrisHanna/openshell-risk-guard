<#
.SYNOPSIS
  Give every OpenShell sandbox its own SPIFFE identity, using OpenShell's own SPIFFE support and the SPIRE that 17-deploy-spire.ps1 installed.

.DESCRIPTION
  1. Registers each sandbox's supervisor pod with SPIRE (deploy/aks/sandbox-spiffe.yaml): spiffe://<trust domain>/openshell/sandbox/<sandbox id>.
  2. Turns on OpenShell's provider token grants (deploy/aks/gateway-spiffe-values.yaml), so the SPIFFE Workload API socket is mounted into
     the gateway and into each supervisor pod. The gateway restarts, and sandboxes created afterwards have the socket.

  What this gives: an identity SPIRE issued to each sandbox, which OpenShell can use to obtain short-lived credentials (token grants)
  with no stored secret. What it does not give: Risk Guard does not receive that certificate, so it records the identity but does not
  verify it. See docs/workload-identity.md. Needs 17-deploy-spire.ps1 first. -Remove undoes it.
#>
[CmdletBinding()]
param(
    [string]$OpenShellPath,
    [switch]$Remove
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster

$ns = Get-StateValue 'namespace' 'openshell'
$release = Get-StateValue 'releaseName' 'openshell'
$trustDomain = Get-StateValue 'svidTrustDomain'
if (-not $trustDomain -and -not $Remove) { throw 'Run 17-deploy-spire.ps1 first: this needs SPIRE.' }

$chart = Get-StateValue 'openshellChart'
$chartVersion = Get-StateValue 'openshellChartVersion'
if (-not $chart) { $chartInfo = Get-OpenShellChart $OpenShellPath; $chart = $chartInfo.Ref; $chartVersion = $chartInfo.Version }

function Set-GatewaySpiffe([bool]$Enabled) {
    $values = Join-Path ([IO.Path]::GetTempPath()) ("gateway-spiffe-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.yaml')
    try {
        if ($Enabled) { Copy-Item (Join-Path $script:RepoRoot 'deploy/aks/gateway-spiffe-values.yaml') $values }
        else { @{ server = @{ providerTokenGrants = @{ spiffe = @{ enabled = $false } } } } | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 $values }
        $helmArgs = @('upgrade', $release, $chart, '-n', $ns, '--reuse-values', '-f', $values, '--wait', '--timeout', '10m')
        if ($chartVersion) { $helmArgs += @('--version', $chartVersion) }
        Invoke-Native helm $helmArgs -Retries 1 | Out-Null
    }
    finally { Remove-Item -Force $values -ErrorAction SilentlyContinue }
}

if ($Remove) {
    Write-Step 'Turning off sandbox SPIFFE identities'
    Set-GatewaySpiffe $false
    Invoke-Native kubectl @('delete', 'clusterspiffeid', 'openshell-sandboxes', '--ignore-not-found') -AllowFailure | Out-Null
    return
}

Write-Step 'Registering sandbox supervisors with SPIRE'
Invoke-KubectlApply (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/sandbox-spiffe.yaml') -Raw)

Write-Step 'Mounting the SPIFFE Workload API socket into the gateway and supervisors'
Set-GatewaySpiffe $true
Invoke-Native kubectl @('rollout', 'status', "statefulset/$release", '-n', $ns, '--timeout=300s') | Out-Null

Write-Host ''
Write-Host 'Sandboxes created from now on have a SPIFFE identity.' -ForegroundColor Green
Write-Host '  Entries:   kubectl exec -n openshell spire-server-0 -c spire-server -- /opt/spire/bin/spire-server entry show | grep sandbox'
Write-Host '  Turn off:  scripts/aks/19-enable-sandbox-spiffe.ps1 -Remove'
