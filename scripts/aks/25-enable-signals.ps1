<#
.SYNOPSIS
  DEMO. Let the demo SIEM ask Risk Guard to quarantine a workload for a while: a signals port on Risk Guard, its own token, a network fence, and an
  OpenSearch alert that sends the request.

.DESCRIPTION
  Needs 22-deploy-siem.ps1 (and Risk Guard from 04). With -Apply it
    1. creates the Secret `siem-signals-token` in the openshell namespace (a random 64-hex token; never printed),
    2. records that signals are on (dry run unless -Enforce) and redeploys Risk Guard with the signals port (a short restart),
    3. applies the network policies in deploy/aks/siem/signals-egress.yaml,
    4. sends Risk Guard's own OCSF events (refusals with workload, score and reason; tunnel refusals; signals) to the collector,
    5. creates the webhook channel and the alert in OpenSearch (scripts/siem/install_content.py --signals).

  Start in dry run (the default): every signal is recorded and answered, nothing is quarantined. Re-run with -Enforce when you have watched it.
  -Remove turns it off. See docs/siem-signals.md.
#>
[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$Remove,
    [switch]$Enforce
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster
$ns = Get-StateValue 'namespace' 'openshell'
$dir = Join-Path $script:RepoRoot 'deploy/aks/siem'

if (-not $Apply -and -not $Remove) {
    Write-Step 'Dry run: this would'
    Write-Note "create Secret siem-signals-token in $ns, redeploy Risk Guard with a signals port (:50063), fence it to OpenSearch, and create the webhook and alert in OpenSearch"
    Write-Note 'signals start in dry-run mode (recorded, nothing quarantined); add -Enforce to act on them'
    return
}

$hardened = (Get-StateValue 'riskGuardImage') -match '@sha256:'
$deployArgs = @{}   # splatted below; an inline @(...) would be passed as a positional argument instead
if ($hardened) { $deployArgs['Hardened'] = $true }
if ($Remove) {
    Write-Step 'Turning signals off'
    Save-State @{ signalsEnabled = $false; signalsDryRun = $false; ocsfExport = $false }
    Invoke-Native kubectl @('delete', 'networkpolicy', 'risk-guard-signals-fence', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-Native kubectl @('delete', 'networkpolicy', 'opensearch-to-risk-guard-signals', '-n', 'siem', '--ignore-not-found') -AllowFailure | Out-Null
    & "$PSScriptRoot/04-deploy-risk-guard.ps1" @deployArgs
    Invoke-Native kubectl @('delete', 'secret', 'siem-signals-token', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Write-Note 'The webhook channel and alert stay in OpenSearch (disable them there, or remove the SIEM with 22-deploy-siem.ps1 -Remove).'
    return
}

Write-Step 'Signals token (generated into a Secret, never printed)'
if (-not (Invoke-Native kubectl @('get', 'secret', 'siem-signals-token', '-n', $ns, '-o', 'name') -AllowFailure)) {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $token = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    $file = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($file, $token)
        Invoke-Native kubectl @('create', 'secret', 'generic', 'siem-signals-token', '-n', $ns, "--from-file=token=$file") | Out-Null
    } finally { Remove-Item -Force $file -ErrorAction SilentlyContinue }
    $token = $null
}

Write-Step 'The collector accepts events from Risk Guard (OTLP over HTTP, port 4318)'
Invoke-KubectlApply (Get-Content (Join-Path $dir 'namespace-and-policies.yaml') -Raw)
Invoke-Native helm @('upgrade', '--install', 'otel-collector', 'open-telemetry/opentelemetry-collector', '--version', '0.177.0', '-n', 'siem', '-f', (Join-Path $dir 'collector-values.yaml'), '--wait', '--timeout', '5m') -Retries 1 | Out-Null

Write-Step 'Network fence'
Invoke-KubectlApply (Get-Content (Join-Path $dir 'signals-egress.yaml') -Raw)

Write-Step 'Risk Guard with the signals port'
Save-State @{ signalsEnabled = $true; signalsDryRun = (-not $Enforce); ocsfExport = $true }
& "$PSScriptRoot/04-deploy-risk-guard.ps1" @deployArgs

Write-Step 'Webhook channel and alert in OpenSearch'
Push-Location $script:RepoRoot
try { python scripts/siem/install_content.py --signals } finally { Pop-Location }

Write-Host ''
Write-Host "Signals are on ($(if ($Enforce) { 'ENFORCING' } else { 'dry run: recorded, nothing quarantined' }))." -ForegroundColor Green
Write-Host 'See what arrived:  python scripts/siem/signal_demo.py --list'
Write-Host 'Try one end to end: python scripts/siem/signal_demo.py'
