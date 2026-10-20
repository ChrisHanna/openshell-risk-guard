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
    [string]$Tag
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
        if ($IsLinux -or $IsMacOS) {
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

    Write-Step "Building openshell-risk-guard:$Tag in $($state.acr) (several minutes, runs in Azure)"
    Invoke-Native az @('acr', 'build', '-r', $state.acr, '-t', "openshell-risk-guard:$Tag", '-t', 'openshell-risk-guard:latest',
        '-f', 'openshell-risk-guard/Dockerfile', $stage, '--no-logs', '--only-show-errors') -Retries 1 | Out-Null
}
finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
Save-State @{ imageTag = $Tag }
Write-Step 'Tags in the registry'
Invoke-Native az @('acr', 'repository', 'show-tags', '-n', $state.acr, '--repository', 'openshell-risk-guard', '-o', 'tsv')
Write-Host "`nDone. Next: scripts/aks/03-install-openshell.ps1" -ForegroundColor Green
