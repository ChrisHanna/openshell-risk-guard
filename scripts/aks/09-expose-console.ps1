<#
.SYNOPSIS
  Publish Risk Guard's console on the internet behind TLS and Microsoft Entra sign-in (or, without sign-in, an IP allowlist).

.DESCRIPTION
  The console only listens on the pod's loopback, so it is never exposed directly.
  This script adds an nginx proxy and a Let's Encrypt client to the Risk Guard pod and a LoadBalancer Service in
  front of them:

    * Sign-in (recommended): after scripts/aks/15-setup-console-signin.ps1 the console requires a Microsoft Entra
      account that is on its list. Everyone else sees only a sign-in screen, and every data route answers 401/403, so
      the address needs no further allowlist unless -AllowedIp is passed.
    * Source-IP allowlist: without sign-in, only -AllowedIp (default: this machine's public address) can use the
      console. nginx enforces it on port 443 (the Service keeps the client address, externalTrafficPolicy: Local).
    * A browser-trusted Let's Encrypt certificate for the Service's DNS name, issued and renewed automatically by a
      lego sidecar. This needs port 80 open to the internet; port 80 serves only the validation challenge and
      redirects everything else to HTTPS. Until the first certificate arrives (usually under a minute) the console
      presents a certificate from a cluster CA (saved to .aks/console-ca.crt). The name appears in public
      certificate-transparency logs, as for any Let's Encrypt certificate.
    * Without sign-in the console is read-only and unauthenticated, so the allowlist is the protection. -RequirePassword
      adds HTTP basic auth (.aks/console-credentials.txt); it cannot be combined with sign-in, which also uses the
      Authorization header.
    * Pages are GET/HEAD only. Settings changes (PUT/POST) reach /api/ only, and the console accepts them only from a
      signed-in administrator.

  Re-run with a new -AllowedIp when your address changes. -AcmeStaging uses Let's Encrypt's staging service
  (untrusted certificates, generous limits) for testing. -Remove deletes the public Service.
  The console shows evidence (workloads, routes, principals, decisions): never publish it without sign-in or an allowlist.
#>
[CmdletBinding()]
param(
    [string[]]$AllowedIp,
    [string]$DnsLabel,
    # Contact address registered with Let's Encrypt (expiry notices). Defaults to the signed-in Azure user.
    [string]$AcmeEmail,
    [switch]$AcmeStaging,
    # Ask for a password (HTTP basic auth). Off by default: the console is read-only and the allowlist applies.
    [switch]$RequirePassword,
    [string]$NginxImage = 'mcr.microsoft.com/azurelinux/base/nginx:1.30.6-1-azl3.0.20261015',
    [string]$LegoImage,
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

$signIn = [bool]((Get-StateValue 'consoleEntraClientId') -and @(Get-StateValue 'consoleEntraAdminOids' @()).Count)
if ($signIn -and $RequirePassword) { throw 'Sign-in and -RequirePassword both use the Authorization header and cannot be combined. Drop -RequirePassword.' }
if ($signIn) {
    Write-Note 'Entra sign-in is configured: the console shows nothing without a listed account.'
    if (-not $AllowedIp) { $AllowedIp = @('0.0.0.0/0') }
} elseif (-not $AllowedIp) {
    Write-Step 'Detecting this machine''s public address for the allowlist'
    $AllowedIp = @((Invoke-RestMethod 'https://api.ipify.org').Trim())
    Write-Note "using $($AllowedIp -join ', ')  (pass -AllowedIp to override; or run 15-setup-console-signin.ps1)"
}
foreach ($ip in $AllowedIp) { if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') { throw "Not an IPv4 address or range: $ip" } }
$ranges = @($AllowedIp | ForEach-Object { if ($_ -match '/') { $_ } else { "$_/32" } })

if (-not $DnsLabel) { $DnsLabel = Get-StateValue 'consoleDnsLabel' ("rg-console-" + (Get-Random -Minimum 100000 -Maximum 999999)) }
$fqdn = "$DnsLabel.$($state.location).cloudapp.azure.com"
Save-State @{ consoleDnsLabel = $DnsLabel; consoleHost = $fqdn }
$image = (Invoke-Native kubectl @('get', 'deploy/risk-guard', '-n', $ns, '-o', 'jsonpath={.spec.template.spec.containers[0].image}') -AllowFailure | Select-Object -First 1)
if (-not $image) { throw 'Risk Guard is not deployed. Run 04-deploy-risk-guard.ps1 first.' }

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
if ($RequirePassword -and (-not $haveAuth -or $RotatePassword)) {
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
    if (Test-Unix) { & chmod 600 $credFile }
}

# --- Proxy configuration, container and public Service
Write-Step 'Adding the proxy and the certificate client to the Risk Guard pod'
if (-not $AcmeEmail) { $AcmeEmail = (Invoke-Native az @('account', 'show', '--query', 'user.name', '-o', 'tsv') | Select-Object -First 1).Trim() }
if ($AcmeEmail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "Pass -AcmeEmail with a real address (got '$AcmeEmail')." }
$acmeServer = if ($AcmeStaging) { 'https://acme-staging-v02.api.letsencrypt.org/directory' } else { 'https://acme-v02.api.letsencrypt.org/directory' }
if (-not $LegoImage) { $LegoImage = "$($state.acr).azurecr.io/openshell-demo/lego:4.25.2" }
Write-Note "certificates from $acmeServer (contact $AcmeEmail)"

$confDir = Join-Path ([IO.Path]::GetTempPath()) ("rg-console-conf-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $confDir | Out-Null
try {
    $allow = if ($ranges -contains '0.0.0.0/0') { '    allow all;' } else { ($ranges | ForEach-Object { "    allow $_;" }) -join "`n" }
    $auth = if ($RequirePassword) { "    auth_basic `"Risk Guard console`";`n    auth_basic_user_file /etc/console-auth/htpasswd;" } elseif ($signIn) { '    # Entra sign-in is enforced by the console itself.' } else { '    # No login: read-only, allowlisted.' }
    $nginx = (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/console-nginx.conf') -Raw).Replace('__ALLOW__', $allow).Replace('__FQDN__', $fqdn).Replace('__AUTH__', $auth)
    [IO.File]::WriteAllText((Join-Path $confDir 'nginx.conf'), ($nginx -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
    $acme = (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/console-acme.sh') -Raw) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $confDir 'console-acme.sh'), $acme, (New-Object Text.UTF8Encoding($false)))
    $conf = Invoke-Native kubectl @('create', 'configmap', 'risk-guard-console-proxy', '-n', $ns, "--from-file=nginx.conf=$(Join-Path $confDir 'nginx.conf')", '--dry-run=client', '-o', 'yaml')
    Invoke-KubectlApply ($conf -join "`n")
    $script_ = Invoke-Native kubectl @('create', 'configmap', 'risk-guard-console-acme', '-n', $ns, "--from-file=console-acme.sh=$(Join-Path $confDir 'console-acme.sh')", '--dry-run=client', '-o', 'yaml')
    Invoke-KubectlApply ($script_ -join "`n")
} finally { Remove-Item -Recurse -Force $confDir -ErrorAction SilentlyContinue }
# Issued certificates and the ACME account live on their own small volume so pod restarts do not re-issue.
Invoke-KubectlApply (@{ apiVersion = 'v1'; kind = 'PersistentVolumeClaim'
        metadata = @{ name = 'risk-guard-acme'; namespace = $ns }
        spec = @{ accessModes = @('ReadWriteOnce'); resources = @{ requests = @{ storage = '1Gi' } } } } | ConvertTo-Json -Depth 8)
$patch = (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/console-proxy-patch.yaml') -Raw).Replace('__NGINX_IMAGE__', $NginxImage).Replace('__LEGO_IMAGE__', $LegoImage).Replace('__FQDN__', $fqdn).Replace('__ACME_EMAIL__', $AcmeEmail).Replace('__ACME_SERVER__', $acmeServer)
$patchFile = Join-Path ([IO.Path]::GetTempPath()) 'rg-console-patch.yaml'
Set-Content -Path $patchFile -Encoding utf8 -Value $patch
try { Invoke-Native kubectl @('patch', 'deploy/risk-guard', '-n', $ns, '--patch-file', $patchFile) | Out-Null } finally { Remove-Item -Force $patchFile -ErrorAction SilentlyContinue }
Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard', '-n', $ns, '--timeout=300s') | Out-Null

Write-Step "Publishing https://$fqdn/ ($(if ($signIn) { 'Entra sign-in required' } else { 'to ' + ($ranges -join ', ') }))"
$svc = @{ apiVersion = 'v1'; kind = 'Service'
    metadata = @{ name = 'risk-guard-console'; namespace = $ns; annotations = @{ 'service.beta.kubernetes.io/azure-dns-label-name' = $DnsLabel } }
    # Local keeps the client's address so nginx can enforce the allowlist. Port 80 must be reachable by Let's Encrypt,
    # so the network layer is open and the allowlist is applied by nginx on 443.
    spec = @{ type = 'LoadBalancer'; externalTrafficPolicy = 'Local'
        selector = @{ 'app.kubernetes.io/name' = 'risk-guard' }
        ports = @(@{ name = 'http'; port = 80; targetPort = 'http' }, @{ name = 'https'; port = 443; targetPort = 'https' }) } }
Invoke-KubectlApply ($svc | ConvertTo-Json -Depth 8)

Write-Step 'Waiting for the public address'
$ip = $null
for ($i = 0; $i -lt 40 -and -not $ip; $i++) {
    $ip = (kubectl get svc risk-guard-console -n $ns -o 'jsonpath={.status.loadBalancer.ingress[0].ip}' 2>$null)
    if (-not $ip) { Start-Sleep -Seconds 6 }
}
if (-not $ip) { throw 'No public IP yet. Check: kubectl get svc risk-guard-console -n openshell' }
# Staging certificates are never browser-trusted, so only a real issuance is held to the trust check.
if (-not $AcmeStaging) { Test-ConsoleCertificate }
Write-Host ""
Write-Host "Console:     https://$fqdn/   (public IP $ip)" -ForegroundColor Green
Write-Host "Allowed:     $(if ($signIn -and $ranges -contains '0.0.0.0/0') { 'any address (access is by Entra account)' } else { $ranges -join ', ' })"
if ($signIn) { Write-Host "Login:       Microsoft Entra; only the accounts listed in the console's settings see anything." } elseif ($RequirePassword) { Write-Host "Credentials: $credFile   (username viewer; the password is in that file)" } else { Write-Host "Login:       none (read-only, allowlisted). Pass -RequirePassword to add one." }
Write-Host "Certificate: Let's Encrypt, issued by the console-acme container (kubectl logs deploy/risk-guard -n $ns -c console-acme)"
if ($AcmeStaging) { Write-Host "             STAGING certificates are not trusted by browsers; re-run without -AcmeStaging for a real one." -ForegroundColor Yellow }
