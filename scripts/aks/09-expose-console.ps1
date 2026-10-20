<#
.SYNOPSIS
  Publish Risk Guard's read-only console on the internet, protected by an IP allowlist, TLS and a password.

.DESCRIPTION
  The console has no login of its own and only listens on the pod's loopback, so it is never exposed directly.
  This script adds an nginx proxy to the Risk Guard pod and a LoadBalancer Service in front of it:

    * Source-IP allowlist: only -AllowedIp (default: this machine's public address) can connect at all.
    * TLS with a certificate for the Service's DNS name, signed by a CA created for this cluster. Your browser
      warns until you trust the CA, which is saved to .aks/console-ca.crt (public).
    * HTTP basic auth with a generated password, saved to .aks/console-credentials.txt (git-ignored).
    * GET and HEAD only.

  Re-run with a new -AllowedIp when your address changes. -Remove deletes the public Service.
  This is read-only evidence (workloads, routes, principals); keep the allowlist tight.
#>
[CmdletBinding()]
param(
    [string[]]$AllowedIp,
    [string]$DnsLabel,
    [string]$NginxImage = 'mcr.microsoft.com/azurelinux/base/nginx:1.30.6-1-azl3.0.20261015',
    [switch]$RotatePassword,
    [switch]$Remove
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster
$state = Get-ClusterContext
$ns = Get-StateValue 'namespace' 'openshell'

if ($Remove) {
    Write-Step 'Removing the public console Service'
    Invoke-Native kubectl @('delete', 'service', 'risk-guard-console', '-n', $ns, '--ignore-not-found') | Out-Null
    Write-Host 'Removed. The proxy container stays in the pod but is no longer reachable from outside.' -ForegroundColor Green
    return
}

if (-not $AllowedIp) {
    Write-Step 'Detecting this machine''s public address for the allowlist'
    $AllowedIp = @((Invoke-RestMethod 'https://api.ipify.org').Trim())
    Write-Note "using $($AllowedIp -join ', ')  (pass -AllowedIp to override)"
}
foreach ($ip in $AllowedIp) { if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "Not an IPv4 address: $ip" } }
$ranges = @($AllowedIp | ForEach-Object { if ($_ -match '/') { $_ } else { "$_/32" } })

if (-not $DnsLabel) { $DnsLabel = Get-StateValue 'consoleDnsLabel' ("rg-console-" + (Get-Random -Minimum 100000 -Maximum 999999)) }
$fqdn = "$DnsLabel.$($state.location).cloudapp.azure.com"
Save-State @{ consoleDnsLabel = $DnsLabel; consoleHost = $fqdn }
$image = Get-StateValue 'riskGuardImage'
if (-not $image) { throw 'Run 04-deploy-risk-guard.ps1 first.' }

# --- TLS: a CA and server certificate for the DNS name, generated in-cluster by the Risk Guard image
$haveTls = Invoke-Native kubectl @('get', 'secret', 'risk-guard-console-tls', '-n', $ns, '-o', 'name') -AllowFailure
if (-not $haveTls -or $RotatePassword) {
    Write-Step "Creating a TLS certificate for $fqdn"
    $remote = 'd=$(mktemp -d) && openshell-risk-guard local-secrets-generate --out-dir "$d" --san ' + $fqdn +
        ' >/dev/null && for f in ca.crt tls.crt tls.key; do printf "%s:%s\n" "$f" "$(base64 -w0 "$d/$f")"; done; rm -rf "$d"'
    $lines = Invoke-InCluster -Name 'rg-console-cert' -Namespace $ns -Image $image -ShellCommand $remote
    $b64 = @{}
    foreach ($line in $lines) { if ($line -match '^(ca\.crt|tls\.crt|tls\.key):([A-Za-z0-9+/=]+)$') { $b64[$Matches[1]] = $Matches[2] } }
    foreach ($name in 'ca.crt', 'tls.crt', 'tls.key') { if (-not $b64.ContainsKey($name)) { throw "The generator did not return $name" } }
    Invoke-KubectlApply (@{ apiVersion = 'v1'; kind = 'Secret'; type = 'kubernetes.io/tls'
            metadata = @{ name = 'risk-guard-console-tls'; namespace = $ns }
            data = @{ 'tls.crt' = $b64['tls.crt']; 'tls.key' = $b64['tls.key'] } } | ConvertTo-Json -Depth 6)
    New-Item -ItemType Directory -Force $script:StateDir | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $script:StateDir 'console-ca.crt'), [Convert]::FromBase64String($b64['ca.crt']))
}

# --- Password: random, stored only as a hash in the cluster; the plain value goes to a local git-ignored file
$haveAuth = Invoke-Native kubectl @('get', 'secret', 'risk-guard-console-auth', '-n', $ns, '-o', 'name') -AllowFailure
$credFile = Join-Path $script:StateDir 'console-credentials.txt'
if (-not $haveAuth -or $RotatePassword) {
    Write-Step 'Creating the console password'
    $bytes = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($bytes); $rng.Dispose()
    $password = ([Convert]::ToBase64String($bytes)).Replace('+', 'A').Replace('/', 'b').Replace('=', '')
    $sha1 = [Security.Cryptography.SHA1]::Create()
    $hash = [Convert]::ToBase64String($sha1.ComputeHash([Text.Encoding]::UTF8.GetBytes($password))); $sha1.Dispose()
    $htpasswd = "viewer:{SHA}$hash`n"
    Invoke-KubectlApply (@{ apiVersion = 'v1'; kind = 'Secret'; type = 'Opaque'
            metadata = @{ name = 'risk-guard-console-auth'; namespace = $ns }
            data = @{ htpasswd = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($htpasswd)) } } | ConvertTo-Json -Depth 6)
    Set-Content -Path $credFile -Encoding ascii -Value @("url:      https://$fqdn/", "username: viewer", "password: $password")
    if ($IsLinux -or $IsMacOS) { & chmod 600 $credFile }
}

# --- Proxy configuration, container and public Service
Write-Step 'Adding the proxy to the Risk Guard pod'
$conf = Invoke-Native kubectl @('create', 'configmap', 'risk-guard-console-proxy', '-n', $ns, "--from-file=nginx.conf=$(Join-Path $script:RepoRoot 'deploy/aks/console-nginx.conf')", '--dry-run=client', '-o', 'yaml')
Invoke-KubectlApply ($conf -join "`n")
$patch = (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/console-proxy-patch.yaml') -Raw).Replace('__NGINX_IMAGE__', $NginxImage)
$patchFile = Join-Path ([IO.Path]::GetTempPath()) 'rg-console-patch.yaml'
Set-Content -Path $patchFile -Encoding utf8 -Value $patch
try { Invoke-Native kubectl @('patch', 'deploy/risk-guard', '-n', $ns, '--patch-file', $patchFile) | Out-Null } finally { Remove-Item -Force $patchFile -ErrorAction SilentlyContinue }
Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard', '-n', $ns, '--timeout=300s') | Out-Null

Write-Step "Publishing https://$fqdn/ to $($ranges -join ', ')"
$svc = @{ apiVersion = 'v1'; kind = 'Service'
    metadata = @{ name = 'risk-guard-console'; namespace = $ns; annotations = @{ 'service.beta.kubernetes.io/azure-dns-label-name' = $DnsLabel } }
    spec = @{ type = 'LoadBalancer'; loadBalancerSourceRanges = $ranges
        selector = @{ 'app.kubernetes.io/name' = 'risk-guard' }
        ports = @(@{ name = 'https'; port = 443; targetPort = 'https' }) } }
Invoke-KubectlApply ($svc | ConvertTo-Json -Depth 8)

Write-Step 'Waiting for the public address'
$ip = $null
for ($i = 0; $i -lt 40 -and -not $ip; $i++) {
    $ip = (kubectl get svc risk-guard-console -n $ns -o 'jsonpath={.status.loadBalancer.ingress[0].ip}' 2>$null)
    if (-not $ip) { Start-Sleep -Seconds 6 }
}
if (-not $ip) { throw 'No public IP yet. Check: kubectl get svc risk-guard-console -n openshell' }
Write-Host ""
Write-Host "Console:     https://$fqdn/   (public IP $ip)" -ForegroundColor Green
Write-Host "Allowed:     $($ranges -join ', ')"
Write-Host "Credentials: $credFile   (username viewer; the password is in that file)"
Write-Host "Trust CA:    $(Join-Path $script:StateDir 'console-ca.crt')   (optional; avoids the browser warning)"
