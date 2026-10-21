<#
.SYNOPSIS
  Build the Risk Guard sidecar image remotely in your Azure Container Registry.

.DESCRIPTION
  Risk Guard builds against crates in an OpenShell checkout (a path dependency), so the Docker build
  context holds both repositories side by side. This script stages a clean copy (no .git, no build
  output, no databases or env files) and runs `az acr build`, so no Docker daemon is needed locally.
  The image is tagged with the Risk Guard git commit and `latest`.
#>
[CmdletBinding()]
param(
    [string]$OpenShellPath,
    [string]$Tag,
    # Build with the local Docker engine and push, instead of `az acr build`. Use it when the ACR build service is
    # unreachable from this machine (the az client's connection to it is reset by some networks).
    [switch]$LocalDocker
)
. "$PSScriptRoot/common.ps1"
Assert-Tool az 'Install the Azure CLI.'

$state = Get-ClusterContext
$openshell = Get-OpenShellCheckout $OpenShellPath
if (-not $Tag) { $Tag = (Invoke-Native git @('-C', $script:RepoRoot, 'rev-parse', '--short', 'HEAD') | Select-Object -First 1).Trim() }

$stage = Join-Path ([IO.Path]::GetTempPath()) ("rg-acr-context-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory $stage | Out-Null
try {
    Write-Step "Staging build context in $stage"
    function Copy-Clean([string]$From, [string]$To, [string[]]$ExcludeDirs, [string[]]$ExcludeFiles) {
        $onUnix = Test-Unix
        if ($onUnix) {
            $excludes = @($ExcludeDirs + $ExcludeFiles | ForEach-Object { "--exclude=$_" })
            & rsync -a @excludes "$From/" "$To/"
            if ($LASTEXITCODE -ne 0) { throw 'rsync failed' }
        } else {
            $args = @($From, $To, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/XD') + $ExcludeDirs
            if ($ExcludeFiles) { $args += @('/XF') + $ExcludeFiles }
            & robocopy @args | Out-Null
            if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }
        }
    }
    Copy-Clean $openshell (Join-Path $stage 'OpenShell') @('.git', 'target', 'node_modules', '.venv') @()
    Copy-Clean $script:RepoRoot (Join-Path $stage 'openshell-risk-guard') @('.git', 'target', 'node_modules', '.venv', '.aks') @('*.db', '*.db-wal', '*.db-shm', '*.env')
    $mb = [math]::Round((Get-ChildItem $stage -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
    Write-Note "context: $mb MB"

    if ($LocalDocker) {
        Assert-Tool docker 'Install and start Docker Desktop.'
        $server = "$($state.acr).azurecr.io"
        Write-Step "Signing in to $server"
        Connect-AcrDocker $server
        Write-Step "Building openshell-risk-guard:$Tag locally (the first build takes about 10 minutes)"
        # Docker writes progress to stderr, which PowerShell 5.1 would turn into a terminating error.
        $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try {
            & docker build --progress=plain -t "$server/openshell-risk-guard:$Tag" -t "$server/openshell-risk-guard:latest" -f (Join-Path $stage 'openshell-risk-guard/Dockerfile') $stage 2>&1 | ForEach-Object { "$_" } | Select-Object -Last 30
            if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }
            & docker push "$server/openshell-risk-guard:$Tag" 2>&1 | Select-Object -Last 3; if ($LASTEXITCODE -ne 0) { throw 'docker push failed' }
            & docker push "$server/openshell-risk-guard:latest" 2>&1 | Select-Object -Last 3; if ($LASTEXITCODE -ne 0) { throw 'docker push failed' }
        } finally { $ErrorActionPreference = $previous }
        Save-State @{ imageTag = $Tag }
        Write-Host "`nPushed $server/openshell-risk-guard:$Tag" -ForegroundColor Green
        return
    }
    Write-Step "Building openshell-risk-guard:$Tag in $($state.acr) (several minutes, runs in Azure)"
    $queued = Invoke-Native az @('acr', 'build', '-r', $state.acr, '-t', "openshell-risk-guard:$Tag", '-t', 'openshell-risk-guard:latest',
        '-f', (Join-Path $stage 'openshell-risk-guard/Dockerfile'), $stage, '--no-logs', '--no-wait', '--only-show-errors') -Retries 1
    # --no-wait prints nothing useful with --only-show-errors, so read the newest run back instead.
    $runId = (Invoke-Native az @('acr', 'task', 'list-runs', '-r', $state.acr, '--top', '1', '--query', '[0].runId', '-o', 'tsv', '--only-show-errors') -Retries 5 | Select-Object -First 1)
    if (-not $runId) { throw 'Could not find the queued build run.' }
    Write-Note "run $runId queued; polling (the first build takes about 10 minutes)"
    $status = ''
    while ($true) {
        Start-Sleep -Seconds 20
        $status = (Invoke-Native az @('acr', 'task', 'show-run', '-r', $state.acr, '--run-id', $runId, '--query', 'status', '-o', 'tsv', '--only-show-errors') -Retries 5 | Select-Object -First 1)
        if ($status -in 'Succeeded', 'Failed', 'Canceled', 'Error', 'Timeout') { break }
    }
    if ($status -ne 'Succeeded') {
        throw "Build $runId finished with status $status. Logs: az acr task logs -r $($state.acr) --run-id $runId"
    }
}
finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
Save-State @{ imageTag = $Tag }
Write-Step 'Tags in the registry'
Invoke-Native az @('acr', 'repository', 'show-tags', '-n', $state.acr, '--repository', 'openshell-risk-guard', '-o', 'tsv')
Write-Host "`nDone. Next: scripts/aks/03-install-openshell.ps1" -ForegroundColor Green
