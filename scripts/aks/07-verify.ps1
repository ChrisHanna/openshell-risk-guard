<#
.SYNOPSIS
  Show what Risk Guard recorded on the cluster: workloads, who bound each sandbox, and decisions.

.DESCRIPTION
  Port-forwards to the read-only console container in the Risk Guard pod, reads /api/state and the
  detail of each workload, and prints the binding (workspace, principal, identity provider, source).
  Open the console yourself with:  kubectl port-forward -n openshell deploy/risk-guard 8791
  then browse http://127.0.0.1:8791/
#>
[CmdletBinding()]
param([int]$LocalPort = 18791)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster
$state = Get-ClusterContext
$ns = Get-StateValue 'namespace' 'openshell'

$pf = Start-Process -FilePath kubectl -ArgumentList @('port-forward', '-n', $ns, 'deploy/risk-guard', "${LocalPort}:8791") -PassThru -WindowStyle Hidden
try {
    $base = "http://127.0.0.1:$LocalPort"
    $ready = $false
    for ($i = 0; $i -lt 20 -and -not $ready; $i++) {
        try { Invoke-RestMethod "$base/api/state" -TimeoutSec 3 | Out-Null; $ready = $true } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw 'The console did not answer. Check: kubectl logs -n openshell deploy/risk-guard -c console' }

    $fleet = Invoke-RestMethod "$base/api/state"
    Write-Step "Workloads: $(@($fleet.agents).Count)   Sandboxes: $(@($fleet.sandboxes).Count)"
    foreach ($agent in @($fleet.agents)) {
        $id = if ($agent.agent_id) { $agent.agent_id } else { $agent.id }
        Write-Host ""; Write-Host "workload  $id" -ForegroundColor Yellow
        $detail = Invoke-RestMethod ("$base/api/agents/" + [uri]::EscapeDataString($id))
        foreach ($run in @($detail.runs)) {
            foreach ($sb in @($run.sandboxes)) {
                $b = $sb.binding
                if ($b) {
                    Write-Host ("  sandbox {0}  workspace={1}  bound by {2}:{3} ({4})  via {5}" -f $sb.sandbox_id, $b.workspace, $b.principal_kind, $b.principal_subject, $b.principal_provider, $b.source)
                } else {
                    Write-Host ("  sandbox {0}  bound explicitly (run-bind); no creating principal recorded" -f $sb.sandbox_id)
                }
            }
        }
        $decisions = @($detail.decisions)
        if ($decisions.Count) {
            $decisions | Select-Object -First 8 | ForEach-Object { Write-Host ("  {0,-5} score {1,3}  {2} {3}" -f $_.evaluation.outcome.ToUpper(), $_.evaluation.risk_score, $_.request.method, $_.request.route_template) }
        }
    }
} finally {
    if ($pf -and -not $pf.HasExited) { Stop-Process -Id $pf.Id -Force }
}
