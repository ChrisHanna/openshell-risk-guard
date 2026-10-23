<#
.SYNOPSIS
  Send OpenShell's OCSF security events to the demo collector (OTLP over gRPC).

.DESCRIPTION
  Needs 22-deploy-siem.ps1 first. Upgrades the OpenShell gateway release so that
    * the gateway exports its OCSF events as OTLP log records to the collector, and
    * the sandbox supervisors it starts afterwards export theirs to the same collector (OpenShell passes the setting down).

  The gateway restarts briefly (about a minute), as in 18-enable-sandbox-egress.ps1. Sandboxes that are already running keep their old settings;
  new ones pick this up. By default this only prints what it would do; use -Apply. -Remove turns the export off again.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Remove,
    [string]$Endpoint = 'http://otel-collector.siem.svc:4317',
    [string]$OpenShellPath
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster
$ns = Get-StateValue 'namespace' 'openshell'
$release = Get-StateValue 'releaseName' 'openshell'
$chart = Get-StateValue 'openshellChart'
$chartVersion = Get-StateValue 'openshellChartVersion'
if (-not $chart) { $chartInfo = Get-OpenShellChart $OpenShellPath; $chart = $chartInfo.Ref; $chartVersion = $chartInfo.Version }

if (-not $Apply -and -not $Remove) {
    Write-Step 'Dry run: this would'
    Write-Note "set the gateway's OTLP endpoint to $Endpoint and enable OCSF log export (server.otlp.endpoint, gatewayConfig openshell.gateway.otlp.ocsf.enabled)"
    Write-Note 'restart the gateway briefly; running sandboxes keep their old settings, new ones export to the collector'
    return
}

function Set-OcsfExport([string]$Url, [bool]$On) {
    $values = Join-Path ([IO.Path]::GetTempPath()) ("ocsf-export-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.yaml')
    try {
        # A values file, not --set: the keys contain dots.
        @{ server = @{ otlp = @{ endpoint = $Url } }; gatewayConfig = @{ 'openshell.gateway.otlp.ocsf' = @{ enabled = $On } } } |
            ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 $values
        $helmArgs = @('upgrade', $release, $chart, '-n', $ns, '--reuse-values', '-f', $values, '--wait', '--timeout', '10m')
        if ($chartVersion) { $helmArgs += @('--version', $chartVersion) }
        Invoke-Native helm $helmArgs -Retries 1 | Out-Null
    } finally { Remove-Item -Force $values -ErrorAction SilentlyContinue }
}

if ($Remove) {
    Write-Step 'Turning OCSF export off'
    Set-OcsfExport '' $false
    return
}

Write-Step 'Checking the collector is ready first'
$ready = Invoke-Native kubectl @('-n', 'siem', 'get', 'deploy/otel-collector', '-o', 'jsonpath={.status.readyReplicas}') -AllowFailure
if ($ready -ne '1') { throw 'The collector is not ready. Run 22-deploy-siem.ps1 -Apply first.' }

Write-Step 'Pointing OpenShell at the collector'
Set-OcsfExport $Endpoint $true
Save-State @{ ocsfExport = $true }
Write-Host ''
Write-Host 'OpenShell now exports OCSF events to the collector.' -ForegroundColor Green
Write-Host '  Create a new sandbox (or wait for the fleet to), refuse a call, and look for the index ocsf-openshell in OpenSearch Dashboards.'
