<#
.SYNOPSIS
  Run the agent fleet inside the cluster, so it keeps going when no workstation is on.

.DESCRIPTION
  Builds a small image (the `openshell` CLI, scripts/aks/agent-fleet.sh and run-agent.sh, and each agent's policy and
  workflow), pushes it to your registry, and deploys it as the Deployment `agent-fleet` (deploy/aks/fleet.yaml). The pod:

    * holds the cluster's own gateway client certificate from the Secret `openshell-client-tls`, read-only, and nothing
      else: no Kubernetes API access, no registry credentials, no model key;
    * reaches the gateway by its Service name through a localhost relay (the gateway's certificate is valid for
      localhost), so there is no `kubectl port-forward` to drop;
    * reads the three agents' Entra application IDs from the ConfigMap `agent-fleet-state`, created here from
      .aks/state.json (13-register-agent-identity.ps1 -AgentName <name> records them).

  Prerequisites: the agent image (14-build-agent-image.ps1), the NVIDIA key in the provider (11-set-secret.ps1, then
  12-sync-credentials.ps1), and the agents registered (13-register-agent-identity.ps1 for nat-agent, release-bot and
  ops-cleaner). The `openshell` CLI binary is not part of this repository: pass -OpenShellBinary, or let the script find
  one ($OPENSHELL_BIN, ~/openshell-demo/bin/openshell, or `openshell` on PATH, in WSL if need be). It must be a Linux
  x86-64 build **from the same OpenShell commit as the cluster's gateway**: a different version fails with protobuf decode
  errors, so the script checks the version against the gateway image and refuses a mismatch (-SkipVersionCheck overrides).

  Stop any fleet running on a workstation before starting this one (two fleets double the load and fight over sandboxes).
  Re-run to pick up changed scripts, policies or agents. -Remove stops the fleet. Logs: kubectl logs -n openshell deploy/agent-fleet
#>
[CmdletBinding()]
param(
    [string]$OpenShellBinary,
    [string]$Tag,
    [string]$WslDistro,
    [switch]$SkipVersionCheck,
    # Also run the SPIFFE token-grant agent (needs 20-deploy-token-grant-demo.ps1).
    [switch]$TokenAgent,
    # Build in Azure (az acr build) instead of with the local Docker engine.
    [switch]$AcrBuild,
    [switch]$Remove
)
. "$PSScriptRoot/common.ps1"
Assert-Tools

# WSL occasionally drops a call ("connection attempt failed"), so each call is retried before giving up.
function Invoke-WslText([string[]]$Arguments) {
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $out = (& wsl.exe @Arguments 2>$null | Out-String).Replace("`0", '').Trim(); $code = $LASTEXITCODE } finally { $ErrorActionPreference = $previous }
        if ($code -eq 0) { return $out }
        Start-Sleep -Seconds (2 * $attempt)
    }
    return $null
}
Use-Cluster
$state = Get-ClusterContext
$ns = Get-StateValue 'namespace' 'openshell'

if ($Remove) {
    Write-Step 'Stopping the in-cluster fleet'
    Invoke-Native kubectl @('delete', 'deployment', 'agent-fleet', '-n', $ns, '--ignore-not-found') | Out-Null
    Write-Host 'Stopped. Sandboxes already created are removed by the next sweep or with: openshell sandbox delete <name>' -ForegroundColor Green
    return
}

$names = @('nat-agent', 'release-bot', 'ops-cleaner')
$ids = [ordered]@{}
foreach ($name in $names) {
    $id = Get-StateValue "agentAppId-$name"
    if (-not $id) { throw "No Entra application for '$name'. Run 13-register-agent-identity.ps1 -AgentName $name first." }
    $ids["agentAppId-$name"] = $id
}
if (-not $Tag) {
    # Unique per build: a node reuses a cached image for a tag it already has, so a rebuilt image under an unchanged
    # commit-only tag would never be picked up.
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $sha = (& git -C $script:RepoRoot rev-parse --short HEAD 2>$null)
    $Tag = if ($sha) { "$sha-$stamp" } else { $stamp }
}
$server = "$($state.acr).azurecr.io"
$image = "$server/openshell-demo/fleet:$Tag"

$stage = Join-Path ([IO.Path]::GetTempPath()) ("rg-fleet-ctx-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force (Join-Path $stage 'scripts/aks'), (Join-Path $stage 'deploy/aks/fleet') | Out-Null
try {
    Write-Step 'Staging the build context'
    foreach ($f in 'scripts/aks/agent-fleet.sh', 'scripts/aks/run-agent.sh', 'scripts/aks/run-token-agent.sh', 'deploy/aks/agent-sandbox-policy.yaml', 'deploy/aks/agent-workflow.yml',
                   'deploy/aks/fleet/Dockerfile', 'deploy/aks/fleet/entrypoint.sh') {
        $text = (Get-Content (Join-Path $script:RepoRoot $f) -Raw) -replace "`r`n", "`n"
        [IO.File]::WriteAllText((Join-Path $stage $f), $text, (New-Object Text.UTF8Encoding($false)))
    }
    Copy-Item -Recurse (Join-Path $script:RepoRoot 'deploy/aks/agents') (Join-Path $stage 'deploy/aks/agents')
    # The end-state demo's deliberately weakened policies, their exception files and its own profile are not part of the fleet: keep them out of the image so no fleet script can select them.
    Get-ChildItem (Join-Path $stage 'deploy/aks/agents') -Recurse -File -Include 'policy.enforce.demo.yaml', 'demo-exceptions.json' | Remove-Item -Force
    Remove-Item -Recurse -Force (Join-Path $stage 'deploy/aks/agents/demo-end-state') -ErrorAction SilentlyContinue
    foreach ($f in Get-ChildItem (Join-Path $stage 'deploy/aks/agents') -Recurse -File -Include *.yaml, *.yml, *.json) {
        $text = (Get-Content $f.FullName -Raw) -replace "`r`n", "`n"
        [IO.File]::WriteAllText($f.FullName, $text, (New-Object Text.UTF8Encoding($false)))
    }

    # The CLI: an explicit path, one on PATH, or the one in WSL.
    $cliDest = Join-Path $stage 'openshell'
    $cliVersion = ''
    if ($OpenShellBinary) {
        Copy-Item $OpenShellBinary $cliDest
    } elseif (Get-Command openshell -ErrorAction SilentlyContinue) {
        Copy-Item (Get-Command openshell).Source $cliDest
    } elseif (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
        $wsl = @(); if ($WslDistro) { $wsl = @('-d', $WslDistro) }
        # --exec runs the command without WSL's outer shell, which would expand $HOME and friends before sh sees them, and the
        # command has no double quotes because Windows PowerShell 5.1 strips them from native arguments.
        $found = Invoke-WslText ($wsl + @('--exec', 'sh', '-c', 'for b in $OPENSHELL_BIN $HOME/openshell-demo/bin/openshell $(command -v openshell); do if [ -x $b ]; then echo $b; break; fi; done'))
        if (-not $found) { throw 'The openshell CLI was not found. Pass -OpenShellBinary <path to a Linux x86-64 build>.' }
        $cliVersion = Invoke-WslText ($wsl + @('--exec', $found, '--version'))
        $drive = $cliDest.Substring(0, 1).ToLowerInvariant()
        $wslDest = "/mnt/$drive" + ($cliDest.Substring(2) -replace '\\', '/')
        if ($null -eq (Invoke-WslText ($wsl + @('--exec', 'cp', $found, $wslDest)))) { throw "Could not copy $found out of WSL." }
        Write-Note "using $found from WSL"
    } else { throw 'The openshell CLI was not found. Pass -OpenShellBinary <path to a Linux x86-64 build>.' }
    # The CLI and the gateway must come from the same commit. The gateway image is tagged with its commit; the CLI reports
    # it after a "g" in its version (0.1.5-dev.63+g55bf78645).
    if (-not $SkipVersionCheck -and $cliVersion) {
        $gwImage = (Invoke-Native kubectl @('get', 'statefulset/openshell', '-n', $ns, '-o', 'jsonpath={.spec.template.spec.containers[0].image}') -AllowFailure | Select-Object -First 1)
        if (-not $gwImage) { $gwImage = (Invoke-Native kubectl @('get', 'deploy/openshell', '-n', $ns, '-o', 'jsonpath={.spec.template.spec.containers[0].image}') -AllowFailure | Select-Object -First 1) }
        $gwSha = if ($gwImage -match ':([0-9a-f]{40})$') { $Matches[1] } else { '' }
        $cliSha = if ($cliVersion -match '\+g([0-9a-f]{7,40})') { $Matches[1] } else { '' }
        if ($gwSha -and $cliSha -and -not $gwSha.StartsWith($cliSha.Substring(0, [Math]::Min(7, $cliSha.Length)))) {
            throw "The CLI ($cliVersion) is not from the gateway's commit ($($gwSha.Substring(0, 9))). Build the CLI from that commit, pass its path with -OpenShellBinary, or use -SkipVersionCheck."
        }
        if ($gwSha -and $cliSha) { Write-Note "CLI $cliVersion matches the gateway ($($gwSha.Substring(0, 9)))" }
        else { Write-Warning 'Could not read the gateway version, so the CLI version was not checked against it.' }
    }
    $bytes = [IO.File]::ReadAllBytes($cliDest)
    if ($bytes.Length -lt 1MB -or $bytes[0] -ne 0x7F -or $bytes[1] -ne 0x45 -or $bytes[2] -ne 0x4C -or $bytes[3] -ne 0x46) {
        throw 'That file is not a Linux (ELF) executable. The fleet image needs a Linux x86-64 openshell build.'
    }
    Write-Note ("openshell CLI: {0:N1} MB" -f ($bytes.Length / 1MB))

    if ($AcrBuild) {
        Write-Step "Building $image in Azure"
        Invoke-Native az @('acr', 'build', '-r', $state.acr, '-t', "openshell-demo/fleet:$Tag", '-f', 'deploy/aks/fleet/Dockerfile', $stage, '--only-show-errors') -Retries 1 | Out-Null
    } else {
        Assert-Tool docker 'Install and start Docker Desktop, or pass -AcrBuild.'
        Write-Step "Signing in to $server"
        Connect-AcrDocker $server
        Write-Step "Building $image locally"
        $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try {
            & docker build --progress=plain -t $image -f (Join-Path $stage 'deploy/aks/fleet/Dockerfile') $stage 2>&1 | ForEach-Object { "$_" } | Select-Object -Last 8
            if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }
            & docker push $image 2>&1 | Select-Object -Last 3
            if ($LASTEXITCODE -ne 0) { throw 'docker push failed' }
        } finally { $ErrorActionPreference = $previous }
    }
} finally { Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue }

Write-Step 'Deploying the fleet'
$stateFile = Join-Path ([IO.Path]::GetTempPath()) ("rg-fleet-state-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
try {
    [IO.File]::WriteAllText($stateFile, ($ids | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
    $cm = Invoke-Native kubectl @('create', 'configmap', 'agent-fleet-state', '-n', $ns, "--from-file=state.json=$stateFile", '--dry-run=client', '-o', 'yaml')
    Invoke-KubectlApply ($cm -join "`n")
} finally { Remove-Item -Force $stateFile -ErrorAction SilentlyContinue }
$manifest = (Get-Content (Join-Path $script:RepoRoot 'deploy/aks/fleet.yaml') -Raw).Replace('__IMAGE__', $image).Replace('__ACR__', $server).Replace('__NAMESPACE__', $ns).Replace('__TOKEN_AGENT__', $(if ($TokenAgent) { '1' } else { '0' }))
Invoke-KubectlApply $manifest
Invoke-Native kubectl @('rollout', 'restart', 'deploy/agent-fleet', '-n', $ns) | Out-Null
Invoke-Native kubectl @('rollout', 'status', 'deploy/agent-fleet', '-n', $ns, '--timeout=300s') | Out-Null
Save-State @{ fleetImage = $image }
Write-Host ''
Write-Host "Fleet running in the cluster: $image" -ForegroundColor Green
Write-Host "Logs: kubectl logs -n $ns deploy/agent-fleet -f"
