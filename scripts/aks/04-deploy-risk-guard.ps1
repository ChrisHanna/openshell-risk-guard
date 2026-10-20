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
if (-not $BaselinePath) { $BaselinePath = Join-Path $script:RepoRoot 'deploy/rail-guard-demo/baseline.json' }
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
$baselineYaml = Invoke-Native kubectl @('create', 'configmap', 'risk-guard-baseline', '-n', $ns, "--from-file=baseline.json=$BaselinePath", '--dry-run=client', '-o', 'yaml')
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
$manifest = (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/risk-guard.yaml') -Raw).Replace('__IMAGE__', $image)
Invoke-KubectlApply $manifest
Invoke-Native kubectl @('rollout', 'restart', 'deploy/risk-guard', '-n', $ns) | Out-Null
Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard', '-n', $ns, '--timeout=300s') | Out-Null
kubectl get pods -n $ns -l app.kubernetes.io/name=risk-guard
kubectl logs -n $ns deploy/risk-guard -c risk-guard --tail=6
Save-State @{ riskGuardImage = $image }
Write-Host "`nDone. Next: scripts/aks/05-register-extension.ps1" -ForegroundColor Green
