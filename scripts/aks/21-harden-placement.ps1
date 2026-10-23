<#
.SYNOPSIS
  Move Risk Guard and the services it relies on to their own node pool, away from sandboxes and demo workloads.

.DESCRIPTION
  Reads deploy/aks/placement-profile.json. By default this only reports what it would do. With -Apply it
    1. adds a node pool (default `security`, one small node) labelled and tainted as the profile says,
    2. gives each security workload a nodeSelector and a toleration for that taint, which moves it,
    3. runs scripts/conformance/placement.py to confirm where everything actually runs.

  This costs one more VM and restarts the services it moves: Risk Guard is briefly down (fail closed) while its disk reattaches.
  A node pool shares the cluster's control plane, so this is separation of nodes, not a separate trust domain; see docs/adr/0001-security-placement.md.
  -Remove puts the workloads back and deletes the pool.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Remove,
    [string]$VmSize = 'Standard_D2s_v5'
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
$state = Get-ClusterContext
Use-Cluster
$ns = Get-StateValue 'namespace' 'openshell'
$profile = Get-Content (Join-Path $script:RepoRoot 'deploy/aks/placement-profile.json') -Raw | ConvertFrom-Json
$labelKey = ($profile.node_labels.PSObject.Properties | Select-Object -First 1).Name
$labelValue = ($profile.node_labels.PSObject.Properties | Select-Object -First 1).Value

Write-Step "Placement profile '$($profile.name)'"
foreach ($w in $profile.security_workloads) { Write-Note "$($w.kind)/$($w.name) -> nodes labelled $labelKey=$labelValue" }
if (-not $Apply -and -not $Remove) {
    Write-Note "Dry run. -Apply adds node pool '$($profile.node_pool)' ($VmSize x 1) and moves these workloads. It costs one more VM."
    Write-Note 'Current placement:'
    & python (Join-Path $script:RepoRoot 'scripts/conformance/placement.py') --placement-only
    return
}

if ($Remove) {
    foreach ($w in $profile.security_workloads) {
        $patch = '[{"op":"remove","path":"/spec/template/spec/nodeSelector"},{"op":"remove","path":"/spec/template/spec/tolerations"}]'
        Invoke-Native kubectl @('patch', "$($w.kind)/$($w.name)", '-n', $ns, '--type=json', '-p', $patch) -AllowFailure | Out-Null
    }
    Invoke-Native az @('aks', 'nodepool', 'delete', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $profile.node_pool, '--only-show-errors') -AllowFailure | Out-Null
    return
}

Write-Step "Node pool $($profile.node_pool)"
$have = Invoke-Native az @('aks', 'nodepool', 'show', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $profile.node_pool, '--query', 'name', '-o', 'tsv', '--only-show-errors') -AllowFailure
if (-not $have) {
    Invoke-Native az @('aks', 'nodepool', 'add', '-g', $state.resourceGroup, '--cluster-name', $state.cluster, '-n', $profile.node_pool,
        '--node-vm-size', $VmSize, '--node-count', '1', '--os-sku', 'AzureLinux', '--labels', "$labelKey=$labelValue",
        '--node-taints', $profile.node_taint, '--tags', 'purpose=openshell-risk-guard-trial', '--only-show-errors', '-o', 'none') -Retries 1 | Out-Null
}

Write-Step 'Letting the per-node SPIRE daemons run on the tainted node (the proxies need their socket)'
$taintKey, $taintRest = $profile.node_taint -split '=', 2
$taintValue, $effect = $taintRest -split ':', 2
foreach ($name in @($profile.per_node_daemons_allowed_on_security_nodes)) {
    $existing = Invoke-Native kubectl @('get', "daemonset/$name", '-n', $ns, '-o', 'jsonpath={.spec.template.spec.tolerations}') -AllowFailure
    $list = @(); if ($existing) { $list = @($existing | ConvertFrom-Json) }
    if (-not ($list | Where-Object { $_.key -eq $taintKey })) {
        $list += @{ key = $taintKey; operator = 'Equal'; value = $taintValue; effect = $effect }
        $daemonPatch = @{ spec = @{ template = @{ spec = @{ tolerations = $list } } } } | ConvertTo-Json -Depth 10 -Compress
        Invoke-Native kubectl @('patch', "daemonset/$name", '-n', $ns, '--type=merge', '-p', $daemonPatch) | Out-Null
    }
}

Write-Step 'Moving the security workloads'
$patch = @{ spec = @{ template = @{ spec = @{
    nodeSelector = @{ $labelKey = $labelValue }
    tolerations = @(@{ key = $taintKey; operator = 'Equal'; value = $taintValue; effect = $effect })
} } } } | ConvertTo-Json -Depth 10 -Compress
foreach ($w in $profile.security_workloads) {
    Invoke-Native kubectl @('patch', "$($w.kind)/$($w.name)", '-n', $ns, '--type=merge', '-p', $patch) | Out-Null
}
foreach ($w in $profile.security_workloads) {
    Invoke-Native kubectl @('rollout', 'status', "$($w.kind)/$($w.name)", '-n', $ns, '--timeout=600s') | Out-Null
}
Write-Step 'Where everything runs now'
& python (Join-Path $script:RepoRoot 'scripts/conformance/placement.py') --out (Join-Path $script:RepoRoot 'conformance/placement.json')
