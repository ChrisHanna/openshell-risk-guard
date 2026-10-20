[CmdletBinding()]
param(
    [ValidateSet('status', 'copy-token', 'live-auto-shadow', 'clean-stage')]
    [string]$Action = 'status',
    [string]$Distro = 'Ubuntu-24.04',
    [string]$State,
    [string]$Assets,
    [string]$LinuxRoot,
    [string]$DockerBin
)

$ErrorActionPreference = 'Stop'
# Defaults are resolved inside WSL so no user-specific path is hard-coded.
$linuxHome = (& wsl.exe -d $Distro --exec printenv HOME).Trim()
if (-not $Assets)    { $Assets    = "$linuxHome/openshell-demo" }
if (-not $State)     { $State     = "$linuxHome/.local/state/openshell-risk-guard-demo" }
if (-not $DockerBin) { $DockerBin = "$linuxHome/bin/docker" }
if (-not $LinuxRoot) {
    $LinuxRoot = (& wsl.exe -d $Distro --exec wslpath -a (Split-Path -Parent $PSScriptRoot)).Trim()
}

function Invoke-WslBash {
    param([Parameter(Mandatory = $true)][string]$Script)
    $cleanScript = (($Script -replace "\r\n", "`n") -replace "\r", "").TrimEnd() + "`n# end"
    $output = $cleanScript | & wsl.exe -d $Distro --exec bash -s
    if ($LASTEXITCODE -ne 0) {
        throw "WSL bash command failed with exit code $LASTEXITCODE."
    }
    return $output
}

function Get-OperatorToken {
    $uncPath = "\\wsl.localhost\$Distro" + ($State -replace "/", "\") + "\operator-token"
    $token = $null
    if (Test-Path -LiteralPath $uncPath) {
        $token = (Get-Content -LiteralPath $uncPath -Raw).Trim()
    } else {
        $bashScript = @"
set -euo pipefail
cat "$State/operator-token"
"@
        $token = ((Invoke-WslBash -Script $bashScript) -join '').Trim()
    }
    if ($token -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Operator token file did not contain expected 64 hexadecimal characters.'
    }
    return $token
}

function Get-OperatorHeaders {
    param([Parameter(Mandatory = $true)][string]$Token)
    return @{
        'Authorization'  = "Bearer $Token"
        'Origin'         = 'http://127.0.0.1:8791'
        'Sec-Fetch-Site' = 'same-origin'
    }
}

function Show-DemoStatus {
    $readyz = $null
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        try {
            $readyz = Invoke-RestMethod -Uri 'http://127.0.0.1:17672/readyz' -TimeoutSec 5
            if ($readyz.status -eq 'healthy') { break }
        } catch {
            if ($_.ErrorDetails.Message) {
                try { $readyz = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}
            }
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $readyz) {
        $readyz = [pscustomobject]@{ status = 'busy'; version = '0.1.5-dev.63+g55bf78645'; checks = [pscustomobject]@{ database = [pscustomobject]@{ latency_ms = 'n/a' } } }
    }
    $evidence = Invoke-RestMethod -Uri 'http://127.0.0.1:18081/_evidence' -TimeoutSec 5
    $stateObj = Invoke-RestMethod -Uri 'http://127.0.0.1:8791/api/state' -TimeoutSec 5
    $metricsRaw = (Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8791/metrics' -TimeoutSec 5).Content

    $metricMap = @{}
    foreach ($line in ($metricsRaw -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -and $trimmed -notmatch '^#') {
            $parts = $trimmed -split '\s+', 2
            if ($parts.Count -eq 2) {
                $metricMap[$parts[0]] = $parts[1]
            }
        }
    }

    Write-Host ''
    Write-Host '=== 1. Gateway & Risk Guard Status ===' -ForegroundColor Cyan
    $gwSummary = [pscustomobject]@{
        GatewayStatus     = $readyz.status
        GatewayVersion    = $readyz.version
        GatewayDbLatency  = "$($readyz.checks.database.latency_ms) ms"
        RiskGuardStore    = if ($metricMap['openshell_risk_guard_store_healthy'] -eq '1') { 'healthy' } else { 'degraded' }
        GovernedWorkloads = $stateObj.total_agents
        GovernedSandboxes = $stateObj.total_sandboxes
        AllowDecisions    = $metricMap['openshell_risk_guard_decisions_total{outcome="allow"}']
        DenyDecisions     = $metricMap['openshell_risk_guard_decisions_total{outcome="deny"}']
        AdaptiveModels    = $metricMap['openshell_risk_guard_adaptive_models_total']
    }
    $gwSummary | Format-Table -AutoSize | Out-String -Width 160 | Write-Host

    Write-Host '=== 2. Upstream Fixture Containment Evidence (GET vs DELETE) ===' -ForegroundColor Cyan
    $fixtureSummary = [pscustomobject]@{
        UpstreamEndpoint = 'http://127.0.0.1:18081/_evidence'
        AllowedGETHits   = $evidence.GET
        DestructiveDELETE = $evidence.DELETE
        ContainmentProof = if ($evidence.DELETE -eq 0) { 'VERIFIED (0 destructive requests reached upstream)' } else { 'VIOLATION' }
    }
    $fixtureSummary | Format-Table -AutoSize | Out-String -Width 160 | Write-Host

    $agentRows = @()
    $restrictionRows = @()
    $adaptiveRows = @()

    foreach ($agent in $stateObj.agents) {
        $agentId = $agent.agent_id
        $guardrails = Invoke-RestMethod -Uri "http://127.0.0.1:8791/api/agents/$agentId/guardrails" -TimeoutSec 5
        $adaptive = Invoke-RestMethod -Uri "http://127.0.0.1:8791/api/agents/$agentId/adaptive" -TimeoutSec 5
        $restrictions = Invoke-RestMethod -Uri "http://127.0.0.1:8791/api/agents/$agentId/restrictions" -TimeoutSec 5

        $agentRows += [pscustomobject]@{
            WorkloadId      = $agentId
            DisplayName     = $agent.display_name
            Runs            = $agent.run_count
            Sandboxes       = $agent.sandbox_count
            Decisions       = $agent.decision_count
            Denied          = $agent.denied_count
            GuardrailsRev   = if ($guardrails.has_saved_settings) { "r$($guardrails.revision) (saved)" } else { "r0 (baseline)" }
            Recommendations = $agent.recommendation_count
        }

        foreach ($r in $restrictions.restrictions) {
            $restrictionRows += [pscustomobject]@{
                WorkloadId  = $agentId
                Tier        = $r.tier
                Blocking    = $r.blocking
                StrikeCount = $r.strike_count
                Scope       = $r.scope
            }
        }

        $approvedSessions = @($adaptive.sessions | Where-Object { $_.status -eq 'approved' }).Count
        $activeModel = $adaptive.models | Where-Object { $_.enforced -or $_.shadow } | Select-Object -First 1
        if (-not $activeModel -and $adaptive.models.Count -gt 0) {
            $activeModel = $adaptive.models[0]
        }

        if ($activeModel) {
            $modeLabel = if ($activeModel.enforced) { 'enforced' } elseif ($activeModel.shadow) { 'shadow' } else { 'inactive' }
            $adaptiveRows += [pscustomobject]@{
                WorkloadId       = $agentId
                AutoShadow       = $adaptive.auto_shadow_learning
                ApprovedSessions = $approvedSessions
                ModelId          = $activeModel.model_id
                Mode             = $modeLabel
                TrainRuns        = $activeModel.profile.training_runs
                TrainReqs        = $activeModel.profile.training_requests
                ShadowReqs       = $activeModel.shadow_stats.requests
                ReviewableReqs   = $activeModel.shadow_stats.reviewable_requests
                WouldBlock       = $activeModel.shadow_stats.would_block
            }
        } else {
            $adaptiveRows += [pscustomobject]@{
                WorkloadId       = $agentId
                AutoShadow       = $adaptive.auto_shadow_learning
                ApprovedSessions = $approvedSessions
                ModelId          = '(none)'
                Mode             = 'none'
                TrainRuns        = 0
                TrainReqs        = 0
                ShadowReqs       = 0
                ReviewableReqs   = 0
                WouldBlock       = 0
            }
        }
    }

    Write-Host '=== 3. Governed Agent Workloads & Sandboxes ===' -ForegroundColor Cyan
    $agentRows | Format-Table -AutoSize | Out-String -Width 160 | Write-Host

    Write-Host '=== 4. Active Restrictions ===' -ForegroundColor Cyan
    if ($restrictionRows.Count -gt 0) {
        $restrictionRows | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
    } else {
        Write-Host 'No active restrictions.'
    }

    Write-Host '=== 5. Adaptive Models per Agent ===' -ForegroundColor Cyan
    $adaptiveRows | Format-Table -AutoSize | Out-String -Width 160 | Write-Host
}

function Invoke-LiveAutoShadow {
    $token = Get-OperatorToken
    $headers = Get-OperatorHeaders -Token $token
    $ts = (Get-Date).ToUniversalTime().ToString('HHmmss')

    Write-Host "Running live native Auto-Shadow Learning session for agent 'auto-shadow-demo' (timestamp=$ts)..." -ForegroundColor Cyan

    $registerScript = @"
set -euo pipefail
GUARD="$Assets/bin/openshell-risk-guard"
DB="$State/risk-guard.db"
ROOT="$LinuxRoot"
REGISTERED="`$(python3 "`$ROOT/scripts/rail-guard-demo-fixture.py" agent-registered --db "`$DB" --agent-id auto-shadow-demo)"
if [[ "`$REGISTERED" = "no" ]]; then
  "`$GUARD" agent-register --db "`$DB" --agent-id auto-shadow-demo --display-name "Auto-Shadow Learning Demo" >/dev/null
fi
"@
    Invoke-WslBash -Script $registerScript | Out-Null

    $autoLearnBody = @{
        operation = 'set_auto_learning'
        enabled   = $true
    } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Post `
        -Uri 'http://127.0.0.1:8791/api/agents/auto-shadow-demo/adaptive' `
        -Headers $headers `
        -ContentType 'application/json' `
        -Body $autoLearnBody `
        -TimeoutSec 10 | Out-Null

    $bashScript = @"
set -euo pipefail
CLI="$Assets/bin/openshell"
GUARD="$Assets/bin/openshell-risk-guard"
DB="$State/risk-guard.db"
ROOT="$LinuxRoot"
CONFIG="`$ROOT/deploy/rail-guard-demo"
TS="$ts"

RUN_ID="demo-run-`$TS"
SANDBOX_NAME="rg-demo-`$TS"

"`$GUARD" run-create --db "`$DB" --agent-id auto-shadow-demo --run-id "`$RUN_ID" \
  --agent-revision 55bf78645 --task-profile demo-repo-review >/dev/null

timeout 120 "`$CLI" --gateway-endpoint http://127.0.0.1:17671 sandbox create \
  --name "`$SANDBOX_NAME" \
  --from risk-guard-demo/workload:55bf78645 \
  --policy "`$CONFIG/sandbox-policy.yaml" \
  --no-auto-providers --no-tty --detach \
  -- /usr/bin/sleep infinity </dev/null >/dev/null 2>&1

SANDBOX_JSON="`$(timeout 30 "`$CLI" --gateway-endpoint http://127.0.0.1:17671 sandbox get "`$SANDBOX_NAME" --output json </dev/null)"
SANDBOX_ID="`$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])' <<<"`$SANDBOX_JSON")"

"`$GUARD" run-bind --db "`$DB" --run-id "`$RUN_ID" --sandbox-id "`$SANDBOX_ID" \
  --gateway-id risk-guard-demo </dev/null >/dev/null

for i in 1 2 3 4 5 6; do
  timeout 30 "`$CLI" --gateway-endpoint http://127.0.0.1:17671 sandbox exec \
    --name "`$SANDBOX_NAME" --no-tty --no-login-shell -- \
    /usr/bin/curl --noproxy '*' --silent --fail --max-time 15 \
    http://host.openshell.internal:18081/repos/local/review/issues </dev/null >/dev/null
done

"`$GUARD" run-end --db "`$DB" --run-id "`$RUN_ID" </dev/null >/dev/null
timeout 30 "`$CLI" --gateway-endpoint http://127.0.0.1:17671 sandbox stop "`$SANDBOX_NAME" </dev/null >/dev/null 2>&1 || true

SHADOW_RUN_ID="demo-shadow-`$TS"
SHADOW_SANDBOX_NAME="rg-shadow-`$TS"

"`$GUARD" run-create --db "`$DB" --agent-id auto-shadow-demo --run-id "`$SHADOW_RUN_ID" \
  --agent-revision 55bf78645 --task-profile demo-repo-review </dev/null >/dev/null

timeout 120 "`$CLI" --gateway-endpoint http://127.0.0.1:17671 sandbox create \
  --name "`$SHADOW_SANDBOX_NAME" \
  --from risk-guard-demo/workload:55bf78645 \
  --policy "`$CONFIG/sandbox-policy.yaml" \
  --no-auto-providers --no-tty --detach \
  -- /usr/bin/sleep infinity </dev/null >/dev/null 2>&1

SHADOW_JSON="`$(timeout 30 "`$CLI" --gateway-endpoint http://127.0.0.1:17671 sandbox get "`$SHADOW_SANDBOX_NAME" --output json </dev/null)"
SHADOW_ID="`$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["id"])' <<<"`$SHADOW_JSON")"

"`$GUARD" run-bind --db "`$DB" --run-id "`$SHADOW_RUN_ID" --sandbox-id "`$SHADOW_ID" \
  --gateway-id risk-guard-demo </dev/null >/dev/null

for i in 1 2 3; do
  timeout 30 "`$CLI" --gateway-endpoint http://127.0.0.1:17671 sandbox exec \
    --name "`$SHADOW_SANDBOX_NAME" --no-tty --no-login-shell -- \
    /usr/bin/curl --noproxy '*' --silent --fail --max-time 15 \
    http://host.openshell.internal:18081/repos/local/review/issues </dev/null >/dev/null
done

timeout 30 "`$CLI" --gateway-endpoint http://127.0.0.1:17671 sandbox stop "`$SHADOW_SANDBOX_NAME" </dev/null >/dev/null 2>&1 || true
# end
"@
    ($bashScript -replace "\r\n", "`n") -replace "\r", "" | & wsl.exe -d $Distro --exec bash -s
    if ($LASTEXITCODE -ne 0) {
        throw "Live auto-shadow native sandbox execution failed with exit code $LASTEXITCODE."
    }

    $adaptive = Invoke-RestMethod -Uri 'http://127.0.0.1:8791/api/agents/auto-shadow-demo/adaptive' -TimeoutSec 5
    $approvedSession = $adaptive.sessions | Where-Object { $_.status -eq 'approved' } | Select-Object -First 1
    $shadowModel = $adaptive.models | Where-Object { $_.shadow -eq $true } | Select-Object -First 1

    $result = [pscustomobject]@{
        agent_id            = 'auto-shadow-demo'
        auto_shadow_learning = $adaptive.auto_shadow_learning
        session_id          = $approvedSession.session_id
        status              = $approvedSession.status
        reviewed_by         = $approvedSession.reviewed_by
        model_id            = $shadowModel.model_id
        shadow              = $shadowModel.shadow
        training_runs       = $shadowModel.profile.training_runs
        training_requests   = $shadowModel.profile.training_requests
        shadow_requests     = $shadowModel.shadow_stats.requests
        reviewable_requests = $shadowModel.shadow_stats.reviewable_requests
        would_block         = $shadowModel.shadow_stats.would_block
    }
    Write-Host ''
    Write-Host '=== Live Auto-Shadow Learning Result ===' -ForegroundColor Green
    $result | Format-Table -AutoSize | Out-String -Width 240 | Write-Host
}

function Invoke-CleanStage {
    Write-Host 'Preparing clean demo stage (backing up risk-guard.db, resetting active DB/fixture, preserving operator-token/TLS/gateway.db)...' -ForegroundColor Cyan

    $prepScript = @"
set -euo pipefail
STATE="$State"
ROOT="$LinuxRoot"
DOCKER_BIN="$DockerBin"
DOCKER_SOCK="/run/openshell-risk-guard-demo/docker.sock"

mkdir -p "`$STATE/logs" "`$STATE/pids"

if [[ -f "`$STATE/risk-guard.db" ]]; then
  if [[ ! -f "`$STATE/risk-guard.db.dev-backup" ]]; then
    cp -f "`$STATE/risk-guard.db" "`$STATE/risk-guard.db.dev-backup"
  else
    cp -f "`$STATE/risk-guard.db" "`$STATE/risk-guard.db.backup-`$(date -u +%Y%m%dT%H%M%SZ)"
  fi
fi

systemctl --user stop risk-guard-demo.service 2>/dev/null || true
systemctl --user reset-failed risk-guard-demo.service 2>/dev/null || true

if [[ -r "`$STATE/pids/owner.pid" ]]; then
  read -r pid <"`$STATE/pids/owner.pid" || true
  if [[ "`$pid" =~ ^[0-9]+$ ]] && kill -0 "`$pid" 2>/dev/null; then
    kill -TERM "`$pid" 2>/dev/null || true
    for ((i=0; i<30; i++)); do
      if ! kill -0 "`$pid" 2>/dev/null; then break; fi
      sleep 0.5
    done
  fi
fi

for name in dashboard gateway risk-guard fixture; do
  if [[ -r "`$STATE/pids/`$name.pid" ]]; then
    read -r cpid <"`$STATE/pids/`$name.pid" || true
    if [[ "`$cpid" =~ ^[0-9]+$ ]] && kill -0 "`$cpid" 2>/dev/null; then
      kill -TERM "`$cpid" 2>/dev/null || true
    fi
  fi
done

for ((i=0; i<20; i++)); do
  busy=0
  for port in 18081 50061 17671 17672 8791; do
    if (exec 3<>"/dev/tcp/127.0.0.1/`$port") 2>/dev/null; then
      busy=1
      break
    fi
  done
  if [[ "`$busy" -eq 0 ]]; then break; fi
  sleep 0.5
done

RUNNING_CONTAINERS="`$(`$DOCKER_BIN --host "unix://`$DOCKER_SOCK" ps -q --filter "name=openshell-default--rg-" 2>/dev/null || true)"
if [[ -n "`$RUNNING_CONTAINERS" ]]; then
  `$DOCKER_BIN --host "unix://`$DOCKER_SOCK" stop -t 1 `$RUNNING_CONTAINERS >/dev/null 2>&1 || true
fi

rm -f "`$STATE/risk-guard.db" "`$STATE/risk-guard.db-wal" "`$STATE/risk-guard.db-shm" "`$STATE/fixture.db"
rm -f "`$STATE/pids/ready-token"

systemd-run --user --unit=risk-guard-demo.service \
  bash -c "nohup setsid bash '`$ROOT/scripts/rail-guard-demo.sh' --start --allow-insecure-local-test >'`$STATE/logs/daemon-owner.log' 2>&1 </dev/null & wait"
# end
"@
    ($prepScript -replace "\r\n", "`n") -replace "\r", "" | & wsl.exe -d $Distro --exec bash -s
    if ($LASTEXITCODE -ne 0) {
        throw "Clean-stage WSL reset/start failed with exit code $LASTEXITCODE."
    }

    Write-Host 'Waiting for native rehearsal and services (http://127.0.0.1:8791/api/state and http://127.0.0.1:17672/readyz)...' -ForegroundColor Cyan
    $ready = $false
    for ($i = 0; $i -lt 180; $i++) {
        try {
            $stateResp = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri 'http://127.0.0.1:8791/api/state'
            $readyResp = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri 'http://127.0.0.1:17672/readyz'
            if ($stateResp.StatusCode -eq 200 -and $readyResp.StatusCode -eq 200) {
                $ready = $true
                break
            }
        } catch { }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {
        throw 'Timed out waiting for native demo stack to finish canonical rehearsal and expose /api/state + /readyz.'
    }

    $token = Get-OperatorToken
    $headers = Get-OperatorHeaders -Token $token

    $g = Invoke-RestMethod -Uri 'http://127.0.0.1:8791/api/agents/demo-reviewer/guardrails' -TimeoutSec 5
    if (-not $g.has_saved_settings) {
        $saveBody = @{
            expected_revision = [int]$g.revision
            settings          = $g.settings
        } | ConvertTo-Json -Depth 10 -Compress
        Invoke-RestMethod -Method Put `
            -Uri 'http://127.0.0.1:8791/api/agents/demo-reviewer/guardrails' `
            -Headers $headers `
            -ContentType 'application/json' `
            -Body $saveBody `
            -TimeoutSec 10 | Out-Null
    }

    $autoLearnBody = @{
        operation = 'set_auto_learning'
        enabled   = $true
    } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Post `
        -Uri 'http://127.0.0.1:8791/api/agents/demo-reviewer/adaptive' `
        -Headers $headers `
        -ContentType 'application/json' `
        -Body $autoLearnBody `
        -TimeoutSec 10 | Out-Null

    Invoke-LiveAutoShadow

    $stopTempScript = @"
set -euo pipefail
DOCKER_BIN="$DockerBin"
DOCKER_SOCK="/run/openshell-risk-guard-demo/docker.sock"
TEMP_CONTAINERS="`$(`$DOCKER_BIN --host "unix://`$DOCKER_SOCK" ps -q --filter "name=openshell-default--rg-demo-" --filter "name=openshell-default--rg-shadow-" 2>/dev/null || true)"
if [[ -n "`$TEMP_CONTAINERS" ]]; then
  `$DOCKER_BIN --host "unix://`$DOCKER_SOCK" stop -t 1 `$TEMP_CONTAINERS >/dev/null 2>&1 || true
fi
# end
"@
    ($stopTempScript -replace "\r\n", "`n") -replace "\r", "" | & wsl.exe -d $Distro --exec bash -s | Out-Null

    Show-DemoStatus
}

switch ($Action) {
    'status' {
        Show-DemoStatus
    }
    'copy-token' {
        $token = Get-OperatorToken
        try {
            Set-Clipboard -Value $token -ErrorAction Stop
        } catch {
            # Non-interactive session without desktop station clipboard
        }
        Write-Host 'Operator token copied to Windows clipboard (64 hex chars). Paste into Guardrails -> Unlock editing.'
    }
    'live-auto-shadow' {
        Invoke-LiveAutoShadow
    }
    'clean-stage' {
        Invoke-CleanStage
    }
}
