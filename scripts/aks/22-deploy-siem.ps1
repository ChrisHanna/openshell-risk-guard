<#
.SYNOPSIS
  DEMO ONLY. Deploy a reference SIEM (OpenSearch, OpenSearch Dashboards and an OpenTelemetry Collector) on its own node pool and namespace.

.DESCRIPTION
  Reads deploy/aks/siem/. By default this only prints what it would do. With -Apply it
    1. adds a node pool `siem` (labelled and tainted workload-class=siem) so nothing else shares its nodes,
    2. creates the `siem` namespace with default-deny network policies,
    3. generates the OpenSearch admin password into a Secret (it is never printed or written to the repository),
    4. installs OpenSearch, Dashboards and the collector with Helm.

  It costs one VM while it exists (Standard_D4s_v5 is about $0.19 an hour at list price in East US 2). Nothing is changed in Risk Guard or OpenShell;
  23-enable-ocsf-export.ps1 points OpenShell at the collector (and restarts the gateway briefly). -Remove deletes all of it.

  This is a demonstration, not an audit store: a cluster administrator can delete it, so it is not tamper-resistant. See docs/siem-integration.md.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Remove,
    [string]$VmSize = 'Standard_D4s_v5'
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
$state = Get-ClusterContext
Use-Cluster
$dir = Join-Path $script:RepoRoot 'deploy/aks/siem'
$pool = 'siem'
$ns = 'siem'
$opensearchVersion = '3.9.0'
$collectorVersion = '0.177.0'

if (-not $Apply -and -not $Remove) {
    Write-Step 'Dry run: this would'
    Write-Note "add node pool '$pool' ($VmSize x 1, label and taint workload-class=siem)"
    Write-Note "create namespace '$ns' with default-deny network policies"
    Write-Note "generate the OpenSearch admin password into Secret 'opensearch-admin'"
    Write-Note "install OpenSearch $opensearchVersion, OpenSearch Dashboards $opensearchVersion and the OpenTelemetry Collector chart $collectorVersion"
    Write-Note 'cost while it exists: about $0.19 an hour for the node, plus a 20 GiB disk. -Remove deletes everything.'
    return
}

if ($Remove) {
    Write-Step 'Removing the demo SIEM'
    foreach ($release in 'otel-collector', 'dashboards', 'opensearch') { Invoke-Native helm @('uninstall', $release, '-n', $ns) -AllowFailure | Out-Null }
    Invoke-Native kubectl @('delete', 'namespace', $ns, '--ignore-not-found', '--wait=true') -AllowFailure | Out-Null
    Invoke-Native az @('aks', 'nodepool', 'delete', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $pool, '--only-show-errors') -AllowFailure | Out-Null
    Write-Note 'Re-run 23-enable-ocsf-export.ps1 -Remove if OpenShell was pointed at the collector.'
    return
}

Write-Step "Node pool $pool"
$have = Invoke-Native az @('aks', 'nodepool', 'show', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $pool, '--query', 'name', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $have) {
    # --no-wait: the CLI's long-held connection to the Azure API is sometimes reset by the network; the pool is created either way, and we wait for the node.
    Invoke-Native az @('aks', 'nodepool', 'add', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $pool,
        '--node-vm-size', $VmSize, '--node-count', '1', '--os-sku', 'AzureLinux', '--labels', 'workload-class=siem',
        '--node-taints', 'workload-class=siem:NoSchedule', '--tags', 'purpose=openshell-risk-guard-demo-siem', '--no-wait', '--only-show-errors', '-o', 'none') -Retries 3 | Out-Null
}
Use-Cluster
$ready = $false
for ($i = 0; $i -lt 90 -and -not $ready; $i++) {
    $nodes = Invoke-Native kubectl @('get', 'nodes', '-l', 'workload-class=siem', '--no-headers') -AllowFailure
    if ($nodes -match ' Ready') { $ready = $true } else { Start-Sleep -Seconds 10 }
}
if (-not $ready) { throw "The '$pool' node did not become ready in 15 minutes." }

Write-Step 'Namespace and network policies'
Invoke-KubectlApply (Get-Content (Join-Path $dir 'namespace-and-policies.yaml') -Raw)

Write-Step 'Admin password (generated into a Secret, never printed)'
$existing = Invoke-Native kubectl @('get', 'secret', 'opensearch-admin', '-n', $ns, '-o', 'name') -AllowFailure
if (-not $existing) {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $bytes = New-Object byte[] 24; $rng.GetBytes($bytes)
    $body = -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
    $password = $body + 'aZ9!_'   # OpenSearch requires upper, lower, digit and a special character
    $file = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($file, $password)
        Invoke-Native kubectl @('create', 'secret', 'generic', 'opensearch-admin', '-n', $ns, "--from-file=password=$file") | Out-Null
    } finally { Remove-Item -Force $file -ErrorAction SilentlyContinue }
}

Write-Step 'Helm charts'
Invoke-Native helm @('repo', 'add', 'opensearch', 'https://opensearch-project.github.io/helm-charts/', '--force-update') | Out-Null
Invoke-Native helm @('repo', 'add', 'open-telemetry', 'https://open-telemetry.github.io/opentelemetry-helm-charts', '--force-update') | Out-Null
Invoke-Native helm @('repo', 'update', 'opensearch', 'open-telemetry') | Out-Null
Invoke-Native helm @('upgrade', '--install', 'opensearch', 'opensearch/opensearch', '--version', $opensearchVersion, '-n', $ns, '-f', (Join-Path $dir 'opensearch-values.yaml'), '--wait', '--timeout', '15m') -Retries 1 | Out-Null
Invoke-Native helm @('upgrade', '--install', 'dashboards', 'opensearch/opensearch-dashboards', '--version', $opensearchVersion, '-n', $ns, '-f', (Join-Path $dir 'dashboards-values.yaml'), '--wait', '--timeout', '10m') -Retries 1 | Out-Null
Invoke-Native helm @('upgrade', '--install', 'otel-collector', 'open-telemetry/opentelemetry-collector', '--version', $collectorVersion, '-n', $ns, '-f', (Join-Path $dir 'collector-values.yaml'), '--wait', '--timeout', '5m') -Retries 1 | Out-Null

Save-State @{ siemDeployed = $true }
Write-Host ''
Write-Host 'The demo SIEM is up.' -ForegroundColor Green
Write-Host '  Open the dashboards:  kubectl -n siem port-forward svc/dashboards-opensearch-dashboards 5601:5601   then https://localhost:5601 (user: admin)'
Write-Host '  Read the password:    kubectl -n siem get secret opensearch-admin -o jsonpath="{.data.password}"   (base64; do not paste it into chat or commit it)'
Write-Host '  Next:                 scripts/aks/23-enable-ocsf-export.ps1 -Apply   (points OpenShell at the collector; restarts the gateway briefly)'
