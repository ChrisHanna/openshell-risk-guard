<#
.SYNOPSIS
  Give workloads a SPIFFE identity (SPIRE) and let Risk Guard recognise them by it.

.DESCRIPTION
  1. Installs SPIRE from the SPIFFE project's hardened Helm charts (deploy/aks/spire-values.yaml): a server that issues short-lived
     X.509-SVIDs, an agent on every node, the SPIFFE CSI driver that hands the agent's socket to pods, and the controller that
     turns a ClusterSPIFFEID into registrations. SPIRE publishes its trust bundle as the ConfigMap `spire-bundle` in the
     openshell namespace and keeps it current as its keys rotate.
  2. Records the trust domain in the saved state and re-runs 04-deploy-risk-guard.ps1, which then also serves the middleware on a
     second mutual-TLS listener (:50062) that accepts only certificates chaining to that bundle, for that trust domain.
  3. Deploys `svid-demo` (deploy/aks/svid-demo.yaml): a pod whose identity SPIRE derives from its namespace and service account,
     and which asks Risk Guard to score a request every 30 seconds as that identity. It shows up in the console as a workload.

  The trust domain is a name for this deployment (default: risk-guard.demo); it is not looked up in DNS. Nothing here stores a
  secret: SVIDs are issued to the pod, kept in memory-backed storage, and replaced before they expire.

  -Remove uninstalls SPIRE and the demo workload and turns the SPIFFE listener off (re-run 04 to apply that).
#>
[CmdletBinding()]
param(
    [string]$TrustDomain = 'risk-guard.demo',
    [string]$ImageTag,
    [switch]$SkipRiskGuardRedeploy,
    [switch]$Remove
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Assert-Tool helm 'Install Helm (https://helm.sh).'
Use-Cluster

$ns = Get-StateValue 'namespace' 'openshell'
$spireNs = 'spire-system'
$state = Get-ClusterContext
$tag = if ($ImageTag) { $ImageTag } else { Get-StateValue 'imageTag' }
$image = "$($state.acr).azurecr.io/openshell-risk-guard:$tag"

if ($Remove) {
    Write-Step 'Removing the SPIFFE demo workload and SPIRE'
    Invoke-Native kubectl @('delete', 'deploy/svid-demo', 'sa/svid-demo', 'configmap/svid-demo-helper', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native kubectl @('delete', 'clusterspiffeid', 'risk-guard-svid-demo', '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native helm @('uninstall', 'spire', '-n', $spireNs) -AllowFailure | Out-Null
    Invoke-Native helm @('uninstall', 'spire-crds', '-n', $spireNs) -AllowFailure | Out-Null
    Save-State @{ svidTrustDomain = '' }
    Write-Note 'Re-run 04-deploy-risk-guard.ps1 to switch the SPIFFE listener off.'
    return
}

if ($TrustDomain -notmatch '^[a-z0-9._-]+$') { throw "TrustDomain '$TrustDomain' must be lowercase letters, digits, '.', '-' or '_'." }

Write-Step 'Adding the SPIFFE Helm repository'
Invoke-Native helm @('repo', 'add', 'spiffe', 'https://spiffe.github.io/helm-charts-hardened/', '--force-update') | Out-Null
Invoke-Native helm @('repo', 'update', 'spiffe') | Out-Null

Write-Step "Installing SPIRE for trust domain $TrustDomain"
$values = Join-Path ([IO.Path]::GetTempPath()) ("spire-values-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.yaml')
try {
    (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/spire-values.yaml') -Raw).Replace('__TRUST_DOMAIN__', $TrustDomain) | Set-Content -Encoding utf8 $values
    Invoke-Native helm @('upgrade', '--install', 'spire-crds', 'spiffe/spire-crds', '-n', $spireNs, '--create-namespace', '--wait', '--timeout', '5m') | Out-Null
    Invoke-Native helm @('upgrade', '--install', 'spire', 'spiffe/spire', '-n', $spireNs, '-f', $values, '--wait', '--timeout', '10m') | Out-Null
}
finally { Remove-Item -Force $values -ErrorAction SilentlyContinue }
Write-Note 'SPIRE is running'

Write-Step 'Waiting for SPIRE to publish its trust bundle'
$deadline = (Get-Date).AddMinutes(3)
$bundle = ''
while ((Get-Date) -lt $deadline) {
    $bundle = (Invoke-Native kubectl @('get', 'configmap', 'spire-bundle', '-n', $ns, '-o', 'jsonpath={.data.bundle\.crt}') -AllowFailure | Out-String).Trim()
    if ($bundle -like '*BEGIN CERTIFICATE*') { break }
    Start-Sleep -Seconds 5
}
if ($bundle -notlike '*BEGIN CERTIFICATE*') { throw "SPIRE did not publish the trust bundle to configmap/spire-bundle in $ns." }
Write-Note "trust bundle published to configmap/spire-bundle in $ns"

Save-State @{ svidTrustDomain = $TrustDomain }
if (-not $SkipRiskGuardRedeploy) {
    Write-Step 'Redeploying Risk Guard with the SPIFFE listener'
    & "$PSScriptRoot/04-deploy-risk-guard.ps1" @(if ($ImageTag) { '-ImageTag'; $ImageTag })
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { throw '04-deploy-risk-guard.ps1 failed.' }
}

Write-Step 'Deploying the SPIFFE demo workload'
Invoke-KubectlApply ((Get-Content (Join-Path $script:RepoRoot 'deploy/aks/svid-demo.yaml') -Raw).Replace('__IMAGE__', $image))
Invoke-Native kubectl @('rollout', 'status', 'deploy/svid-demo', '-n', $ns, '--timeout=300s') | Out-Null

Write-Host ''
Write-Host "SPIFFE identity is on. Trust domain: $TrustDomain" -ForegroundColor Green
Write-Host '  Identity of the demo pod:  kubectl exec -n openshell deploy/svid-demo -c caller -- cat /certs/svid.pem | openssl x509 -noout -ext subjectAltName'
Write-Host '  What Risk Guard decided:   kubectl logs -n openshell deploy/svid-demo -c caller --tail=3'
Write-Host '  In the console:            a workload named "spiffe / workload:spiffe://... (spiffe)"'
