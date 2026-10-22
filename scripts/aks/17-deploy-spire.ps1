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

  With -EgressProxy it also deploys an Envoy proxy (deploy/aks/egress-proxy.yaml) and a workload that reaches its backend only through
  it (deploy/aks/egress-demo.yaml). The workload connects with its SVID; Envoy verifies it and asks Risk Guard (external
  authorization) about every request, forwarding allowed ones and answering 403 itself for denied ones, so the enforcement
  point is on the network path, not inside the workload.

  -Remove uninstalls SPIRE and the demo workload and turns the SPIFFE listener off (re-run 04 to apply that).
#>
[CmdletBinding()]
param(
    [string]$TrustDomain = 'risk-guard.demo',
    [string]$ImageTag,
    [switch]$SkipRiskGuardRedeploy,
    # Also deploy an Envoy egress proxy that enforces Risk Guard's decisions on the network path, and a workload that uses it.
    [switch]$EgressProxy,
    [switch]$Remove
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Assert-Tool helm 'Install Helm (https://helm.sh).'
Use-Cluster

$ns = Get-StateValue 'namespace' 'openshell'
# SPIRE shares the openshell namespace so Risk Guard can mount the trust bundle SPIRE publishes (a ConfigMap cannot cross namespaces).
$spireNs = $ns
$state = Get-ClusterContext
$tag = if ($ImageTag) { $ImageTag } else { Get-StateValue 'imageTag' }
$image = "$($state.acr).azurecr.io/openshell-risk-guard:$tag"

if ($Remove) {
    Write-Step 'Removing the SPIFFE demo workload and SPIRE'
    Invoke-Native kubectl @('delete', 'deploy/svid-demo', 'sa/svid-demo', 'configmap/svid-demo-helper', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native kubectl @('delete', 'deploy/egress-proxy', 'deploy/egress-demo', 'svc/egress-proxy', 'sa/egress-proxy', 'sa/egress-demo', 'configmap/egress-proxy-config', 'configmap/egress-demo-script', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native kubectl @('delete', 'clusterspiffeid', 'risk-guard-svid-demo', 'risk-guard-egress-proxy', 'risk-guard-egress-demo', '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native helm @('uninstall', 'spire', '-n', $spireNs) -AllowFailure | Out-Null
    Invoke-Native helm @('uninstall', 'spire-crds', '-n', $spireNs) -AllowFailure | Out-Null
    Save-State @{ svidTrustDomain = ''; svidEgressProxy = $false }
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
    Invoke-Native helm @('upgrade', '--install', 'spire-crds', 'spiffe/spire-crds', '-n', $spireNs, '--wait', '--timeout', '5m') | Out-Null
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

Save-State @{ svidTrustDomain = $TrustDomain; svidEgressProxy = [bool]$EgressProxy }
if (-not $SkipRiskGuardRedeploy) {
    Write-Step 'Redeploying Risk Guard with the SPIFFE listener'
    $deployArgs = @{}
    if ($ImageTag) { $deployArgs.ImageTag = $ImageTag }
    & "$PSScriptRoot/04-deploy-risk-guard.ps1" @deployArgs
}

Write-Step 'Deploying the SPIFFE demo workload'
Invoke-KubectlApply ((Get-Content (Join-Path $script:RepoRoot 'deploy/aks/svid-demo.yaml') -Raw).Replace('__IMAGE__', $image))
Invoke-Native kubectl @('rollout', 'status', 'deploy/svid-demo', '-n', $ns, '--timeout=300s') | Out-Null

if ($EgressProxy) {
    Write-Step 'Deploying the egress proxy and its workload'
    foreach ($file in 'egress-proxy', 'egress-demo') {
        Invoke-KubectlApply ((Get-Content (Join-Path $script:RepoRoot "deploy/aks/$file.yaml") -Raw).Replace('__TRUST_DOMAIN__', $TrustDomain))
    }
    Invoke-Native kubectl @('rollout', 'status', 'deploy/egress-proxy', '-n', $ns, '--timeout=300s') | Out-Null
    Invoke-Native kubectl @('rollout', 'status', 'deploy/egress-demo', '-n', $ns, '--timeout=300s') | Out-Null
}

Write-Host ''
Write-Host "SPIFFE identity is on. Trust domain: $TrustDomain" -ForegroundColor Green
Write-Host '  Identity of the demo pod:  kubectl exec -n openshell deploy/svid-demo -c caller -- cat /certs/svid.pem | openssl x509 -noout -ext subjectAltName'
Write-Host '  What Risk Guard decided:   kubectl logs -n openshell deploy/svid-demo -c caller --tail=3'
Write-Host '  In the console:            a workload named "spiffe / workload:spiffe://... (spiffe)"'
if ($EgressProxy) {
    Write-Host '  Routine request via the proxy:    kubectl exec -n openshell deploy/egress-demo -c caller -- python /etc/demo/call.py GET /repos/org/docs-site/issues'
    Write-Host '  Destructive request (refused 403): kubectl exec -n openshell deploy/egress-demo -c caller -- python /etc/demo/call.py DELETE /repos/org/payments-prod'
}
