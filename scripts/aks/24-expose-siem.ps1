<#
.SYNOPSIS
  DEMO ONLY. Publish the demo SIEM's Dashboards on the internet over HTTPS, with an admin login for you and a read-only `viewer` login for others.

.DESCRIPTION
  Needs 22-deploy-siem.ps1. With -Apply it
    1. prepares the OCSF index (a template so `time` is a date and the single node shows green) and an index pattern for the viewer,
    2. creates a read-only role and a `viewer` user (limited to reading the ocsf-* indices; no admin, no edits); the viewer password is generated into the
       Secret `opensearch-viewer` and never printed,
    3. puts nginx (TLS, rate-limited sign-in) and a Let's Encrypt client in front of Dashboards and gives them a public address,
    4. waits for a browser-trusted certificate.

  Anyone on the internet can then reach the sign-in page; what they can do depends on the account. Your admin login (the `admin` account) reaches everything.
  The data includes sandbox names, URLs and resource names from the demo agents. Take it down when the demo is over: -Remove.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Remove,
    [string]$DnsLabel,
    [string]$AcmeEmail,
    [switch]$AcmeStaging,
    [string]$NginxImage = 'mcr.microsoft.com/azurelinux/base/nginx:1.30.6-1-azl3.0.20261015',
    [string]$LegoImage
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
$state = Get-ClusterContext
Use-Cluster
$ns = 'siem'
$dir = Join-Path $script:RepoRoot 'deploy/aks/siem'

if (-not $Apply -and -not $Remove) {
    Write-Step 'Dry run: this would'
    Write-Note 'create a read-only role and a viewer user, an index template and index pattern in OpenSearch'
    Write-Note 'start nginx and a Let''s Encrypt client in front of Dashboards and give them a public address (HTTPS, rate-limited sign-in)'
    Write-Note 'Anyone can reach the sign-in page. Remove it with -Remove when the demo is over.'
    return
}

if ($Remove) {
    Write-Step 'Taking the SIEM off the internet'
    Invoke-Native kubectl @('delete', 'deploy/siem-edge', 'svc/siem-edge', 'configmap/siem-edge-nginx', 'configmap/siem-edge-acme', 'pvc/siem-acme', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native kubectl @('delete', 'networkpolicy', 'edge-ingress', 'edge-egress', 'dashboards-ingress', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native kubectl @('delete', 'secret', 'opensearch-viewer', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Write-Note 'The viewer user stays inside OpenSearch (harmless without the public address; delete it in Dashboards under Security if you want it gone).'
    return
}

function Invoke-OpenSearch([string]$Method, [string]$Path, [string]$Json = '') {
    # Runs curl inside the Dashboards pod, which already holds the admin password in its environment. The body goes in on stdin from a file (piping a
    # string to a native command from Windows PowerShell 5.1 mangled it: OpenSearch answered "Could not parse content of request").
    $cmd = "curl -sk -X $Method -u admin:`$OPENSEARCH_PASSWORD -H 'Content-Type: application/json' --data-binary @- https://opensearch-cluster-master:9200$Path"
    $file = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($file, $Json, (New-Object Text.UTF8Encoding($false)))
        $out = cmd /c "kubectl exec -i -n $ns deploy/dashboards-opensearch-dashboards -- sh -c ""$cmd"" < ""$file"" 2>&1"
    } finally { Remove-Item -Force $file -ErrorAction SilentlyContinue }
    return ($out -join "`n")
}

Write-Step 'Preparing the OCSF index'
# A template, so the next index has a proper date for `time`, integer class and severity ids, and no replica a single node cannot hold. The current index is
# replaced (it holds only demo events, and fills again as soon as sandboxes run).
$template = '{"index_patterns":["ocsf-*"],"template":{"settings":{"number_of_replicas":0},"mappings":{"properties":{"time":{"type":"date","format":"epoch_millis"},"class_uid":{"type":"integer"},"severity_id":{"type":"integer"},"activity_id":{"type":"integer"}}}},"priority":100}'
Invoke-OpenSearch 'PUT' '/_index_template/ocsf' $template | Out-Null
Invoke-OpenSearch 'DELETE' '/ocsf-openshell' | Out-Null

Write-Step 'Read-only role and viewer user'
$role = '{"cluster_permissions":["cluster_composite_ops_ro"],"index_permissions":[{"index_patterns":["ocsf-*"],"allowed_actions":["read","indices:admin/mappings/get","indices:admin/resolve/index","indices:monitor/settings/get"]},{"index_patterns":[".kibana",".kibana_*"],"allowed_actions":["read"]}],"tenant_permissions":[{"tenant_patterns":["global_tenant"],"allowed_actions":["kibana_all_read"]}]}'
Invoke-OpenSearch 'PUT' '/_plugins/_security/api/roles/ocsf_reader' $role | Out-Null
$haveViewer = Invoke-Native kubectl @('get', 'secret', 'opensearch-viewer', '-n', $ns, '-o', 'name') -AllowFailure
if (-not $haveViewer) {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $bytes = New-Object byte[] 16; $rng.GetBytes($bytes)
    $viewerPassword = (-join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })) + 'aZ9!_'
    $file = [IO.Path]::GetTempFileName()
    try { [IO.File]::WriteAllText($file, $viewerPassword); Invoke-Native kubectl @('create', 'secret', 'generic', 'opensearch-viewer', '-n', $ns, "--from-file=password=$file") | Out-Null }
    finally { Remove-Item -Force $file -ErrorAction SilentlyContinue }
} else {
    $viewerPassword = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((kubectl get secret opensearch-viewer -n $ns -o 'jsonpath={.data.password}')))
}
$user = (@{ password = $viewerPassword; backend_roles = @(); attributes = @{} } | ConvertTo-Json -Compress)
Invoke-OpenSearch 'PUT' '/_plugins/_security/api/internalusers/viewer' $user | Out-Null
Invoke-OpenSearch 'PUT' '/_plugins/_security/api/rolesmapping/ocsf_reader' '{"users":["viewer"]}' | Out-Null
foreach ($check in '/_plugins/_security/api/internalusers/viewer', '/_plugins/_security/api/roles/ocsf_reader', '/_plugins/_security/api/rolesmapping/ocsf_reader') {
    if ((Invoke-OpenSearch 'GET' $check) -match 'NOT_FOUND|error') { throw "The read-only account was not created ($check). Stopping before anything is made public." }
}
$viewerPassword = $null

Write-Step 'Dashboards: secure cookies behind HTTPS'
Invoke-Native helm @('upgrade', '--install', 'dashboards', 'opensearch/opensearch-dashboards', '--version', '3.9.0', '-n', $ns, '-f', (Join-Path $dir 'dashboards-values.yaml'), '--wait', '--timeout', '10m') -Retries 1 | Out-Null

Write-Step 'The public front door'
if (-not $AcmeEmail) { $AcmeEmail = (Invoke-Native az @('account', 'show', '--query', 'user.name', '-o', 'tsv') | Select-Object -First 1).Trim() }
if ($AcmeEmail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "Pass -AcmeEmail with a real address (got '$AcmeEmail')." }
$acmeServer = if ($AcmeStaging) { 'https://acme-staging-v02.api.letsencrypt.org/directory' } else { 'https://acme-v02.api.letsencrypt.org/directory' }
if (-not $LegoImage) { $LegoImage = "$($state.acr).azurecr.io/openshell-demo/lego:4.25.2" }
if (-not $DnsLabel) { $DnsLabel = Get-StateValue 'siemDnsLabel' ("rg-siem-" + (Get-Random -Minimum 100000 -Maximum 999999)) }
$fqdn = "$DnsLabel.$($state.location).cloudapp.azure.com"
Save-State @{ siemDnsLabel = $DnsLabel; siemHost = $fqdn }
$acmeScript = Join-Path ([IO.Path]::GetTempPath()) ("siem-acme-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.sh')
try {
    [IO.File]::WriteAllText($acmeScript, ((Get-Content (Join-Path $script:RepoRoot 'deploy/aks/console-acme.sh') -Raw) -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding($false)))
    $cm = Invoke-Native kubectl @('create', 'configmap', 'siem-edge-acme', '-n', $ns, "--from-file=console-acme.sh=$acmeScript", '--dry-run=client', '-o', 'yaml')
    Invoke-KubectlApply ($cm -join "`n")
} finally { Remove-Item -Force $acmeScript -ErrorAction SilentlyContinue }
$edge = (Get-Content (Join-Path $dir 'edge.yaml') -Raw).Replace('__FQDN__', $fqdn).Replace('__DNS_LABEL__', $DnsLabel).Replace('__ACME_EMAIL__', $AcmeEmail).Replace('__ACME_SERVER__', $acmeServer).Replace('__NGINX_IMAGE__', $NginxImage).Replace('__LEGO_IMAGE__', $LegoImage)
Invoke-KubectlApply $edge
Invoke-Native kubectl @('rollout', 'restart', 'deploy/siem-edge', '-n', $ns) | Out-Null
Invoke-Native kubectl @('rollout', 'status', 'deploy/siem-edge', '-n', $ns, '--timeout=300s') | Out-Null

Write-Step 'Waiting for the public address and a trusted certificate'
$ip = $null
for ($i = 0; $i -lt 60 -and -not $ip; $i++) {
    $ip = (kubectl get svc siem-edge -n $ns -o 'jsonpath={.status.loadBalancer.ingress[0].ip}' 2>$null)
    if (-not $ip) { Start-Sleep -Seconds 6 }
}
if (-not $ip) { throw 'No public IP yet. Check: kubectl get svc siem-edge -n siem' }
$trusted = $false
if (-not $AcmeStaging) {
    for ($i = 0; $i -lt 60 -and -not $trusted; $i++) {
        $out = (& curl.exe -sS -m 15 -o NUL -w '%{http_code} %{ssl_verify_result}' "https://$fqdn/" 2>$null | Out-String).Trim()
        if ($out -match '^\d{3} 0$') { $trusted = $true } else { Start-Sleep -Seconds 10 }
    }
}
Write-Host ''
Write-Host "SIEM:      https://$fqdn/   (public IP $ip)" -ForegroundColor Green
Write-Host "Admin:     user admin; copy the password:  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((kubectl -n siem get secret opensearch-admin -o jsonpath=`"{.data.password}`"))) | Set-Clipboard"
Write-Host "Viewer:    user viewer (read-only); the same command with the secret named opensearch-viewer"
Write-Host "Certificate: $(if ($trusted) { "trusted (Let's Encrypt)" } elseif ($AcmeStaging) { 'staging (not browser-trusted)' } else { 'not yet trusted; check: kubectl -n siem logs deploy/siem-edge -c acme' })"
Write-Host 'Take it down after the demo:  scripts/aks/24-expose-siem.ps1 -Remove'
