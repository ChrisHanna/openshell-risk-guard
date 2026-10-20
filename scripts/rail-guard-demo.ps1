[CmdletBinding()]
param(
    [ValidateSet('check', 'start')][string]$Action = 'start',
    [string]$Distro = 'Ubuntu-24.04',
    [string]$LinuxRoot,
    [string]$Assets,
    [string]$State,
    [string]$DockerBin,
    [string]$DockerdBin,
    [switch]$AllowInsecureLocalTest,
    [switch]$NoBrowser
)
$ErrorActionPreference = 'Stop'
# Defaults are resolved inside WSL so no user-specific path is hard-coded.
$linuxHome = (& wsl.exe -d $Distro --exec printenv HOME).Trim()
if (-not $Assets)    { $Assets    = "$linuxHome/openshell-demo" }
if (-not $State)     { $State     = "$linuxHome/.local/state/openshell-risk-guard-demo" }
if (-not $DockerBin) { $DockerBin = "$linuxHome/bin/docker" }
if (-not $DockerdBin) { $DockerdBin = "$linuxHome/bin/dockerd" }
if ($Action -eq 'start' -and -not $AllowInsecureLocalTest) {
    throw 'Start requires -AllowInsecureLocalTest. Loopback is not an authentication boundary.'
}
if (-not $LinuxRoot) {
    $workspace = Split-Path -Parent $PSScriptRoot
    $LinuxRoot = (& wsl.exe -d $Distro --exec wslpath -a $workspace).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve this workspace in WSL.' }
}
foreach ($value in @($LinuxRoot, $Assets, $State, $DockerBin, $DockerdBin)) {
    if ($value -notmatch '^/[a-zA-Z0-9_./-]+$' -or $value -match '(^|/)\.\.(/|$)') {
        throw "Unsupported Linux path: $value"
    }
}
$daemonScript = "$LinuxRoot/scripts/rail-guard-demo-docker.sh"
$demoScript = "$LinuxRoot/scripts/rail-guard-demo.sh"
$launchToken = [Guid]::NewGuid().ToString()
$rootArgs = @('-d', $Distro, '-u', 'root', '--exec', 'env',
    "DOCKER_BIN=$DockerBin", "DOCKERD_BIN=$DockerdBin",
    "RAIL_GUARD_DEMO_LAUNCH_TOKEN=$launchToken", 'bash', $daemonScript)
$demoArgs = @('-d', $Distro, '--exec', 'env',
    "RAIL_GUARD_DEMO_ASSETS=$Assets", "RAIL_GUARD_DEMO_STATE=$State", "DOCKER_BIN=$DockerBin",
    "RAIL_GUARD_DEMO_LAUNCH_TOKEN=$launchToken", 'bash', $demoScript)
function Start-AttachedWsl([string[]]$Arguments) {
    # WSL treats quoted option names as a Linux command, not Windows options.
    $quoted = $Arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_.Replace('"', '\"') + '"' } else { $_ }
    }
    $process = Start-Process -FilePath 'wsl.exe' -ArgumentList ($quoted -join ' ') -NoNewWindow -PassThru
    $null = $process.Handle
    return $process
}
$daemonOwner = $null
$stackOwner = $null
function Test-IsolatedDaemon {
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & wsl.exe @rootArgs --check *> $null
        return $LASTEXITCODE -eq 0
    } finally {
        $ErrorActionPreference = $previousPreference
    }
}
try {
    if (-not (Test-IsolatedDaemon)) {
        if ($Action -eq 'check') { throw 'Isolated daemon is unavailable; check does not start it.' }
        Write-Host 'Starting explicitly isolated rootful daemon (foreground WSL child; no global changes).'
        $daemonOwner = Start-AttachedWsl ($rootArgs + '--start')
        $daemonReady = $false
        for ($i = 0; $i -lt 65; $i++) {
            if ($daemonOwner.HasExited) { throw 'Isolated daemon owner exited; inspect its console output.' }
            if (Test-IsolatedDaemon) { $daemonReady = $true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $daemonReady) { throw 'Isolated daemon startup timed out.' }
    }
    & wsl.exe @demoArgs --check
    if ($LASTEXITCODE -ne 0) { throw 'Offline preflight failed. No build/download fallback is attempted.' }
    if ($Action -eq 'check') { return }
    Write-Host 'LOCAL INSECURE TEST ONLY: saved guardrails are preserved; unconfigured agents use the native rehearsal.'
    $stackOwner = Start-AttachedWsl ($demoArgs + @('--start', '--allow-insecure-local-test'))
    $ready = $false
    for ($i = 0; $i -lt 300; $i++) {
        if ($stackOwner.HasExited) { throw 'Native rehearsal failed; inspect Linux logs and console output.' }
        try {
            $token = & wsl.exe -d $Distro --exec bash -c `
                'if [[ -r "$1/pids/ready-token" ]]; then cat "$1/pids/ready-token"; fi' `
                demo-ready $State
            if ($token -ne $launchToken) { Start-Sleep -Seconds 1; continue }
            # Linux publishes readiness after rehearsal, or resumes monitoring without replaying probes against saved settings.
            $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 `
                -Uri 'http://127.0.0.1:8791/api/state'
            if ($response.StatusCode -eq 200) {
                $native = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 `
                    -Uri 'http://127.0.0.1:17672/readyz'
                if ($native.StatusCode -eq 200) { $ready = $true; break }
            }
        } catch { }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'Native readiness deadline exceeded; no browser was opened.' }
    if (-not $NoBrowser) { Start-Process 'http://127.0.0.1:8791/' }
    Write-Host 'Native Risk Guard ready. Saved settings are preserved; see Linux output for rehearsal versus monitoring-resume status.'
    Write-Host 'To edit guardrails, unlock the console using the private operator-token file in the Linux state directory.'
    Write-Host 'Keep this window open; Ctrl-C stops owned services.'
    $stackOwner.WaitForExit()
    if ($stackOwner.ExitCode -notin @(0, 130, 143)) {
        throw "Linux owner exited with code $($stackOwner.ExitCode)."
    }
} finally {
    # Signal only Linux ownership recorded in our state, never process names or wsl --terminate.
    if ($stackOwner -and -not $stackOwner.HasExited) {
        & wsl.exe -d $Distro --exec bash -c `
            'if [[ -r "$1/pids/owner-token" && -r "$1/pids/owner.pid" ]]; then read -r token <"$1/pids/owner-token"; if [[ "$token" = "$2" ]]; then read -r pid <"$1/pids/owner.pid"; [[ "$pid" =~ ^[0-9]+$ ]] && kill -TERM "$pid"; fi; fi' `
            demo-cleanup $State $launchToken
        $stackOwner.WaitForExit(15000) | Out-Null
    }
    if ($daemonOwner -and -not $daemonOwner.HasExited) {
        # The helper only starts a new daemon after refusing any existing live PID.
        & wsl.exe -d $Distro -u root --exec bash -c `
            'if [[ -r /run/openshell-risk-guard-demo/owner-token && -r /run/openshell-risk-guard-demo/docker.pid ]]; then read -r token </run/openshell-risk-guard-demo/owner-token; if [[ "$token" = "$1" ]]; then read -r pid </run/openshell-risk-guard-demo/docker.pid; [[ "$pid" =~ ^[0-9]+$ ]] && kill -TERM "$pid"; fi; fi' `
            demo-daemon-cleanup $launchToken
        $daemonOwner.WaitForExit(15000) | Out-Null
    }
}
