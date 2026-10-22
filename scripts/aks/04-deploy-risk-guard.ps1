<#
.SYNOPSIS
  Deploy Risk Guard next to the OpenShell gateway: secrets, configuration and the Deployment.

.DESCRIPTION
  * TLS certificate, TLS key and the resource HMAC key are generated once, inside the cluster, by the
    sidecar image itself (`local-secrets-generate`). They are written straight to Kubernetes Secrets;
    nothing is stored in the repository or on disk. Re-running keeps them unless -RotateSecrets is set
    (rotating the HMAC key is refused by the database, so rotate only on a fresh volume).
  * The CA certificate is public and goes to a ConfigMap the gateway mounts to trust Risk Guard.
  * The baseline profile and API route map are ConfigMaps. Replace -BaselinePath and -ApiSemanticsPath
    to protect your own APIs.
  * Risk Guard runs with --workload-from-principal: each sandbox binds to a workload derived from its
    workspace and the principal the gateway authenticated.
#>
[CmdletBinding()]
param(
    [string]$ImageTag,
    [string]$BaselinePath,
    [string]$ApiSemanticsPath,
    [switch]$RotateSecrets
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster

$state = Get-ClusterContext
$ns = Get-StateValue 'namespace' 'openshell'
$tag = if ($ImageTag) { $ImageTag } else { Get-StateValue 'imageTag' }
if (-not $tag) { throw 'No image tag recorded. Run 02-build-image.ps1 or pass -ImageTag.' }
$image = "$($state.acr).azurecr.io/openshell-risk-guard:$tag"
if (-not $BaselinePath) { $BaselinePath = Join-Path $script:RepoRoot 'deploy/aks/baseline.json' }
if (-not $ApiSemanticsPath) { $ApiSemanticsPath = Join-Path $script:RepoRoot 'config/api_semantics.yaml' }

Write-Step 'Checking the gateway installed its extension-signing keys'
if (-not (Invoke-Native kubectl @('get', 'secret', 'openshell-jwt-keys', '-n', $ns, '-o', 'name') -AllowFailure)) {
    throw "Secret openshell-jwt-keys not found in $ns. Run 03-install-openshell.ps1 first."
}

$haveSecrets = Invoke-Native kubectl @('get', 'secret', 'risk-guard-tls', '-n', $ns, '-o', 'name') -AllowFailure
if (-not $haveSecrets -or $RotateSecrets) {
    Write-Step 'Generating TLS and HMAC secrets inside the cluster'
    $sans = @("risk-guard.$ns.svc.cluster.local", "risk-guard.$ns.svc", 'risk-guard') | ForEach-Object { "--san $_" }
    $remote = 'd=$(mktemp -d) && openshell-risk-guard local-secrets-generate --out-dir "$d" ' + ($sans -join ' ') +
        ' >/dev/null && for f in ca.crt tls.crt tls.key hmac.key; do printf "%s:%s\n" "$f" "$(base64 -w0 "$d/$f")"; done; rm -rf "$d"'
    $lines = Invoke-InCluster -Name 'rg-secgen' -Namespace $ns -Image $image -ShellCommand $remote
    $b64 = @{}
    foreach ($line in $lines) { if ($line -match '^(ca\.crt|tls\.crt|tls\.key|hmac\.key):([A-Za-z0-9+/=]+)$') { $b64[$Matches[1]] = $Matches[2] } }
    foreach ($name in 'ca.crt', 'tls.crt', 'tls.key', 'hmac.key') { if (-not $b64.ContainsKey($name)) { throw "The generator did not return $name" } }

    Invoke-KubectlApply (@{ apiVersion = 'v1'; kind = 'Secret'; type = 'kubernetes.io/tls'
            metadata = @{ name = 'risk-guard-tls'; namespace = $ns }
            data = @{ 'tls.crt' = $b64['tls.crt']; 'tls.key' = $b64['tls.key'] } } | ConvertTo-Json -Depth 6)
    Invoke-KubectlApply (@{ apiVersion = 'v1'; kind = 'Secret'; type = 'Opaque'
            metadata = @{ name = 'risk-guard-hmac'; namespace = $ns }
            data = @{ key = $b64['hmac.key'] } } | ConvertTo-Json -Depth 6)
    $ca = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64['ca.crt']))
    Invoke-KubectlApply (@{ apiVersion = 'v1'; kind = 'ConfigMap'
            metadata = @{ name = 'risk-guard-ca'; namespace = $ns }
            data = @{ 'ca.crt' = $ca } } | ConvertTo-Json -Depth 6)
    Write-Note 'Secrets created. The CA certificate (public) is in ConfigMap risk-guard-ca.'
} else {
    Write-Note 'Secrets already exist; keeping them (use -RotateSecrets on a fresh volume to replace).'
}

Write-Step 'Configuration'
# The default baseline plus one per agent task profile (support, release, cloud); each is imported by its own init container.
$agentBaselines = @('support', 'release', 'cloud', 'token') | ForEach-Object { "--from-file=$_.json=$(Join-Path $script:RepoRoot "deploy/aks/agents/$_/baseline.json")" }
$baselineYaml = Invoke-Native kubectl (@('create', 'configmap', 'risk-guard-baseline', '-n', $ns, "--from-file=baseline.json=$BaselinePath") + $agentBaselines + @('--dry-run=client', '-o', 'yaml'))
Invoke-KubectlApply ($baselineYaml -join "`n")
$apiYaml = Invoke-Native kubectl @('create', 'configmap', 'risk-guard-api', '-n', $ns, "--from-file=api_semantics.yaml=$ApiSemanticsPath", '--dry-run=client', '-o', 'yaml')
Invoke-KubectlApply ($apiYaml -join "`n")

# A probe edited by hand (for example switched to tcpSocket) would merge with the manifest's exec probe into two
# handlers, which Kubernetes rejects. Clear the live probes so the manifest's probes are the only ones.
$live = Invoke-Native kubectl @('get', 'deploy/risk-guard', '-n', $ns, '-o', 'json') -AllowFailure
if ($live) {
    $containers = ((($live | Out-String) | ConvertFrom-Json).spec.template.spec.containers)
    for ($i = 0; $i -lt @($containers).Count; $i++) {
        if (@($containers)[$i].name -ne 'risk-guard') { continue }
        $ops = @()
        foreach ($probe in 'readinessProbe', 'livenessProbe') {
            if (@($containers)[$i].PSObject.Properties.Name -contains $probe) { $ops += @{ op = 'remove'; path = "/spec/template/spec/containers/$i/$probe" } }
        }
        if ($ops.Count) {
            $f = Join-Path ([IO.Path]::GetTempPath()) 'rg-probe-clear.json'
            Set-Content -Path $f -Encoding utf8 -Value (ConvertTo-Json -InputObject $ops -Depth 5)
            try { Invoke-Native kubectl @('patch', 'deploy/risk-guard', '-n', $ns, '--type=json', '--patch-file', $f) | Out-Null } finally { Remove-Item -Force $f -ErrorAction SilentlyContinue }
        }
    }
}

Write-Step "Deploying $image"
# Console sign-in: set up once by 15-setup-console-signin.ps1. Without it the console is read-only and unauthenticated
# (when 09-expose-console.ps1 publishes it without sign-in, it keeps its source-IP allowlist).
$signIn = ''
$entraTenant = Get-StateValue 'consoleEntraTenantId'
$entraClient = Get-StateValue 'consoleEntraClientId'
$entraAdmins = @(Get-StateValue 'consoleEntraAdminOids' @())
if ($entraTenant -and $entraClient -and $entraAdmins.Count) {
    $lines = @("            - --entra-tenant-id=$entraTenant", "            - --entra-client-id=$entraClient")
    foreach ($oid in $entraAdmins) { $lines += "            - --entra-admin-oid=$oid" }
    foreach ($oid in @(Get-StateValue 'consoleEntraViewerOids' @())) { $lines += "            - --entra-viewer-oid=$oid" }
    if (Get-StateValue 'consoleRequireSignInToRead') { $lines += '            - --entra-require-sign-in-to-read' }
    $signIn = $lines -join "`n"
    Write-Note "console sign-in: tenant $entraTenant, $($entraAdmins.Count) administrator(s)"
} else {
    Write-Note 'console sign-in is not configured (run 15-setup-console-signin.ps1)'
}
# SPIFFE workload identity: set up once by 17-deploy-spire.ps1, which records the trust domain. Without it Risk Guard serves only
# the gateway and supervisors; with it, a second mutual-TLS listener identifies callers by the SPIFFE ID in their X.509-SVID.
$svid = @{ args = ''; servicePort = ''; containerPort = ''; mount = ''; volume = ''; podSpec = '' }
$svidDomain = Get-StateValue 'svidTrustDomain'
if ($svidDomain) {
    $svid.args = "            - --svid-listen=0.0.0.0:50062`n            - --svid-bundle=/etc/spire/bundle/bundle.crt`n            - --svid-trust-domain=$svidDomain"
    $svid.servicePort = "    - name: grpc-svid`n      port: 50062`n      targetPort: grpc-svid"
    if (Get-StateValue 'svidEgressProxy') {
        # The egress proxy (17-deploy-spire.ps1 -EgressProxy) may ask for decisions on behalf of the workloads it has verified.
        $svid.args += "`n            - --svid-proxy-id=spiffe://$svidDomain/ns/$ns/sa/egress-proxy"
    }
    if (Get-StateValue 'svidSandboxEgress') {
        # The sandbox egress proxy (18-enable-sandbox-egress.ps1) asks about OpenShell's sandbox tunnels. Risk Guard maps each
        # tunnel's source address to a sandbox by reading supervisor pods, with a service account that can do only that.
        $svid.args += "`n            - --svid-proxy-id=spiffe://$svidDomain/ns/$ns/sa/sandbox-egress`n            - --tunnel-pod-namespace=$ns`n            - --tunnel-restriction-mode=$(Get-StateValue 'svidTunnelRestrictionMode' 'shadow')"
        $svid.podSpec = '      serviceAccountName: risk-guard-tunnels'
    }
    $svid.containerPort = "            - name: grpc-svid`n              containerPort: 50062"
    $svid.mount = "            - name: spire-bundle`n              mountPath: /etc/spire/bundle`n              readOnly: true"
    $svid.volume = "        - name: spire-bundle`n          configMap:`n            name: spire-bundle`n            optional: true"
    Write-Note "SPIFFE listener on :50062 for trust domain $svidDomain"
}
$manifest = (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/risk-guard.yaml') -Raw).Replace('__IMAGE__', $image).Replace('__CONSOLE_SIGNIN_ARGS__', $signIn).Replace('__SVID_ARGS__', $svid.args).Replace('__SVID_SERVICE_PORT__', $svid.servicePort).Replace('__SVID_CONTAINER_PORT__', $svid.containerPort).Replace('__SVID_MOUNT__', $svid.mount).Replace('__SVID_VOLUME__', $svid.volume).Replace('__SVID_POD_SPEC__', $svid.podSpec)
Invoke-KubectlApply $manifest
Invoke-Native kubectl @('rollout', 'restart', 'deploy/risk-guard', '-n', $ns) | Out-Null
Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard', '-n', $ns, '--timeout=300s') | Out-Null
kubectl get pods -n $ns -l app.kubernetes.io/name=risk-guard
kubectl logs -n $ns deploy/risk-guard -c risk-guard --tail=6
Save-State @{ riskGuardImage = $image }
Test-ConsoleCertificate
Write-Host "`nDone. Next: scripts/aks/05-register-extension.ps1" -ForegroundColor Green
