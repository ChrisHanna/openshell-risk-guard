<#
.SYNOPSIS
  Put an egress proxy in the network path of OpenShell's sandboxes, so a sandbox whose workload Risk Guard has locked loses its
  network, whatever its supervisor does.

.DESCRIPTION
  Needs 17-deploy-spire.ps1 first (SPIRE and Risk Guard's SPIFFE listener). Then:

  1. Deploys the Envoy `sandbox-egress` proxy (deploy/aks/sandbox-egress.yaml), which asks Risk Guard about every tunnel it is
     asked to open, and a read-only service account that lets Risk Guard turn a supervisor pod's address into its sandbox.
  2. Redeploys Risk Guard so it trusts that proxy and answers its checks (04-deploy-risk-guard.ps1).
  3. Points the OpenShell gateway at the proxy (the chart's `upstreamProxy`). OpenShell still applies its own policy and SSRF
     checks first; only policy-approved TLS egress is chained through the proxy, with HTTP CONNECT. Plain HTTP and the cluster's
     own addresses (`noProxy`) do not go through it. The gateway restarts, and sandboxes created afterwards use the proxy.

  What the proxy refuses: a sandbox Risk Guard has no record of, and a workload an operator has quarantined
  (scripts: openshell-risk-guard workload-quarantine). A latched restriction is only recorded unless -RestrictionMode enforce.
  Fails closed: if the proxy or Risk Guard is down, new TLS egress from sandboxes fails. -Remove turns it off again.
#>
[CmdletBinding()]
param(
    [string]$ImageTag,
    [string]$OpenShellPath,
    # Destinations that bypass the proxy (OpenShell policy still applies to them).
    # What a latched (strict-epoch) restriction does to a sandbox's tunnels. Shadow records it; enforce refuses the tunnels. A
    # quarantine set by an operator is always enforced. Restrictions are scoped to one kind of request and stay latched until an
    # operator clears them, so enforcing them would cut off the demo fleet's agents: start in shadow.
    [ValidateSet('shadow', 'enforce')][string]$RestrictionMode = 'shadow',
    [string]$NoProxy = '.svc,.svc.cluster.local,10.0.0.0/8',
    [switch]$Remove
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster

$ns = Get-StateValue 'namespace' 'openshell'
$release = Get-StateValue 'releaseName' 'openshell'
$trustDomain = Get-StateValue 'svidTrustDomain'
if (-not $trustDomain -and -not $Remove) { throw 'Run 17-deploy-spire.ps1 first: this needs SPIRE and Risk Guard''s SPIFFE listener.' }

$chart = Get-StateValue 'openshellChart'
$chartVersion = Get-StateValue 'openshellChartVersion'
if (-not $chart) { $chartInfo = Get-OpenShellChart $OpenShellPath; $chart = $chartInfo.Ref; $chartVersion = $chartInfo.Version }

function Set-GatewayUpstreamProxy([string]$Url, [string]$Bypass) {
    # A values file, not --set: the bypass list has commas, which --set would split.
    $values = Join-Path ([IO.Path]::GetTempPath()) ("upstream-proxy-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.yaml')
    try {
        @{ upstreamProxy = @{ url = $Url; noProxy = $Bypass } } | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 $values
        $helmArgs = @('upgrade', $release, $chart, '-n', $ns, '--reuse-values', '-f', $values, '--wait', '--timeout', '10m')
        if ($chartVersion) { $helmArgs += @('--version', $chartVersion) }
        Invoke-Native helm $helmArgs -Retries 1 | Out-Null
    }
    finally { Remove-Item -Force $values -ErrorAction SilentlyContinue }
}

if ($Remove) {
    Write-Step 'Sending sandbox egress straight out again'
    Set-GatewayUpstreamProxy '' ''
    Save-State @{ svidSandboxEgress = $false }
    Invoke-Native kubectl @('delete', 'deploy/sandbox-egress', 'svc/sandbox-egress', 'configmap/sandbox-egress-config', 'sa/sandbox-egress', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native kubectl @('delete', 'clusterspiffeid', 'risk-guard-sandbox-egress', '--ignore-not-found') -AllowFailure | Out-Null
    Write-Note 'Re-run 04-deploy-risk-guard.ps1 to drop the proxy trust and the pod-reading service account.'
    return
}

Write-Step 'Deploying the sandbox egress proxy'
Invoke-KubectlApply ((Get-Content (Join-Path $script:RepoRoot 'deploy/aks/sandbox-egress.yaml') -Raw).Replace('__TRUST_DOMAIN__', $trustDomain))
Invoke-Native kubectl @('rollout', 'status', 'deploy/sandbox-egress', '-n', $ns, '--timeout=300s') | Out-Null

Write-Step 'Redeploying Risk Guard to answer its checks'
Save-State @{ svidSandboxEgress = $true; svidTunnelRestrictionMode = $RestrictionMode }
$deployArgs = @{}
if ($ImageTag) { $deployArgs.ImageTag = $ImageTag }
try { & "$PSScriptRoot/04-deploy-risk-guard.ps1" @deployArgs }
catch {
    # 04 ends by checking the public certificate, which can time out while the pod is still being replaced. What matters is that
    # the new pod becomes ready, so wait for that instead.
    Write-Note "04 reported: $($_.Exception.Message.Split("`n")[0])"
}
Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard', '-n', $ns, '--timeout=300s') | Out-Null

Write-Step 'Pointing the gateway at the proxy'
Set-GatewayUpstreamProxy "http://sandbox-egress.$ns.svc:8444" $NoProxy

Write-Host ''
Write-Host 'Sandbox TLS egress now goes through the proxy.' -ForegroundColor Green
Write-Host '  The proxy''s decisions:  kubectl logs -n openshell deploy/risk-guard -c risk-guard | grep "sandbox tunnel checked"'
Write-Host '  Turn it off:            scripts/aks/18-enable-sandbox-egress.ps1 -Remove'
