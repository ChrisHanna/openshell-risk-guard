<#
.SYNOPSIS
  Show a sandbox's SPIFFE identity doing real work: calling a service with a short-lived token it obtained with that identity, holding no stored secret.

.DESCRIPTION
  Needs 17-deploy-spire.ps1 and 19-enable-sandbox-spiffe.ps1 first. This:

  1. Downloads OpenShell's demo scripts (token-issuer.js, protected-service.js) at the pinned OpenShell commit into a ConfigMap. They are not
     copied into this repository.
  2. Deploys the token issuer and two protected services, alpha and beta (deploy/aks/token-grant-demo.yaml).
  3. Imports the provider profile (deploy/aks/token-grant-profile.yaml) and creates a provider from it, using the fleet pod's gateway
     connection. The profile makes the supervisor exchange the sandbox's JWT-SVID for a token whenever the sandbox calls alpha or beta.
  4. Registers the workload `spiffe-token-agent` with Risk Guard, which the fleet's token agent runs as.

  The fleet starts running the token agent once FLEET_TOKEN_AGENT=1 is set on it (16-deploy-fleet.ps1 -TokenAgent). -Remove undoes this script.
#>
[CmdletBinding()]
param([switch]$Remove)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster

$ns = Get-StateValue 'namespace' 'openshell'
$trustDomain = Get-StateValue 'svidTrustDomain'
if (-not $trustDomain -and -not $Remove) { throw 'Run 17-deploy-spire.ps1 first.' }

$fleetCli = @('exec', '-n', $ns, 'deploy/agent-fleet', '--', 'env', 'HOME=/tmp/fleet', 'OPENSHELL_GATEWAY=aks')

if ($Remove) {
    Write-Step 'Removing the token-grant demo'
    Invoke-Native kubectl (@('delete', 'deploy/token-issuer', 'deploy/alpha', 'deploy/beta', 'svc/token-issuer', 'svc/alpha', 'svc/beta', 'configmap/spiffe-token-demo-scripts', 'secret/spiffe-token-demo', '-n', $ns, '--ignore-not-found')) -AllowFailure | Out-Null
    Invoke-Native kubectl ($fleetCli + @('openshell', 'provider', 'delete', 'spiffe-token-demo')) -AllowFailure | Out-Null
    return
}

$rev = Get-PinnedOpenShellRev
Write-Step "Fetching OpenShell's demo scripts at $($rev.Substring(0, 9))"
$scripts = Join-Path ([IO.Path]::GetTempPath()) ("token-demo-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $scripts | Out-Null
try {
    foreach ($file in 'token-issuer.js', 'protected-service.js') {
        $url = "https://raw.githubusercontent.com/NVIDIA/OpenShell/$rev/examples/spiffe-token-grant-demo/k8s/$file"
        & curl.exe -fsSL -m 60 -o (Join-Path $scripts $file) $url
        if ($LASTEXITCODE -ne 0) { throw "could not download $url" }
    }
    $cm = Invoke-Native kubectl @('create', 'configmap', 'spiffe-token-demo-scripts', '-n', $ns,
        "--from-file=token-issuer.js=$(Join-Path $scripts 'token-issuer.js')",
        "--from-file=protected-service.js=$(Join-Path $scripts 'protected-service.js')", '--dry-run=client', '-o', 'yaml')
    Invoke-KubectlApply ($cm -join "`n")
}
finally { Remove-Item -Recurse -Force $scripts -ErrorAction SilentlyContinue }

Write-Step 'Deploying the token issuer, alpha and beta'
# The signing secret is generated once and kept; it never leaves the cluster.
$have = Invoke-Native kubectl @('get', 'secret', 'spiffe-token-demo', '-n', $ns, '-o', 'name') -AllowFailure
if (-not $have) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $secret = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    Invoke-KubectlApply (@{ apiVersion = 'v1'; kind = 'Secret'; type = 'Opaque'; metadata = @{ name = 'spiffe-token-demo'; namespace = $ns }
            stringData = @{ 'access-token-secret' = $secret } } | ConvertTo-Json -Depth 5)
}
Invoke-KubectlApply ((Get-Content (Join-Path $script:RepoRoot 'deploy/aks/token-grant-demo.yaml') -Raw).Replace('__TRUST_DOMAIN__', $trustDomain))
foreach ($d in 'token-issuer', 'alpha', 'beta') { Invoke-Native kubectl @('rollout', 'status', "deploy/$d", '-n', $ns, '--timeout=240s') | Out-Null }

Write-Step 'Registering the provider profile with the gateway'
$profile = Get-Content (Join-Path $script:RepoRoot 'deploy/aks/token-grant-profile.yaml') -Raw
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($profile))
Invoke-Native kubectl ($fleetCli + @('sh', '-c', "echo $encoded | base64 -d > /tmp/token-grant-profile.yaml")) | Out-Null
Invoke-Native kubectl ($fleetCli + @('openshell', 'profile', 'import', '-f', '/tmp/token-grant-profile.yaml')) -AllowFailure | Out-Null
Invoke-Native kubectl ($fleetCli + @('openshell', 'provider', 'create', '--name', 'spiffe-token-demo', '--type', 'spiffe-token-demo', '--runtime-credentials')) -AllowFailure | Out-Null
$check = Invoke-Native kubectl ($fleetCli + @('openshell', 'provider', 'get', 'spiffe-token-demo')) -AllowFailure
if (-not $check) { throw 'The gateway did not accept the provider. Is the fleet running (16-deploy-fleet.ps1)?' }

Write-Step 'Registering the token agent as a workload'
Invoke-Native kubectl @('exec', '-n', $ns, 'deploy/risk-guard', '-c', 'risk-guard', '--', '/usr/local/bin/openshell-risk-guard', 'agent-register',
    '--db', '/var/lib/openshell-risk-guard/risk-guard.db', '--agent-id', 'spiffe-token-agent', '--display-name', 'spiffe-token-agent') -AllowFailure | Out-Null

Write-Host ''
Write-Host 'The token-grant demo is deployed.' -ForegroundColor Green
Write-Host '  Next: 16-deploy-fleet.ps1 -TokenAgent, so the fleet runs a sandbox that calls alpha and beta.'
