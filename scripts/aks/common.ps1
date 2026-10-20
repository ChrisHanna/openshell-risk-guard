# Shared settings and helpers for the AKS scripts. Dot-source it: . "$PSScriptRoot/common.ps1"
#
# Requires: Azure CLI (az), kubectl, Helm 3.14+ or 4. Works in Windows PowerShell 5.1 and PowerShell 7+
# (Windows, Linux, macOS). Nothing here stores secrets in the repository: environment state lives in
# .aks/state.json, which is git-ignored.

Set-StrictMode -Version Latest

$script:RepoRoot = (Resolve-Path (Join-Path (Join-Path $PSScriptRoot '..') '..')).Path
$script:StateDir = Join-Path $script:RepoRoot '.aks'
$script:StateFile = Join-Path $script:StateDir 'state.json'

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Note([string]$Message) { Write-Host "    $Message" -ForegroundColor DarkGray }

function Assert-Tool([string]$Name, [string]$Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "'$Name' was not found on PATH. $Hint"
    }
}

function Assert-Tools {
    Assert-Tool az 'Install the Azure CLI: https://learn.microsoft.com/cli/azure/install-azure-cli'
    Assert-Tool kubectl 'Install kubectl: https://kubernetes.io/docs/tasks/tools/'
    Assert-Tool helm 'Install Helm: https://helm.sh/docs/intro/install/'
}

# Run a native command, return its output lines, and fail on a non-zero exit code. Transient network
# errors (DNS, reset connections) are retried, because cloud CLIs hit them regularly.
function Invoke-Native {
    param([Parameter(Mandatory)][string]$File, [string[]]$Arguments = @(), [int]$Retries = 3, [switch]$AllowFailure)
    $transient = 'Failed to resolve|getaddrinfo|ConnectionReset|Connection aborted|timed out|TLS handshake timeout|EOF'
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $output = & $File @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
        $ErrorActionPreference = $previous
        if ($code -eq 0) { return $output }
        if ($attempt -lt $Retries -and ($output -join "`n") -match $transient) {
            Write-Note "transient error from '$File', retrying ($attempt/$Retries)"
            Start-Sleep -Seconds (5 * $attempt)
            continue
        }
        if ($AllowFailure) { return $null }
        throw "'$File $($Arguments -join ' ')' failed (exit $code):`n$($output -join "`n")"
    }
}

function Get-State {
    if (Test-Path $script:StateFile) { return (Get-Content $script:StateFile -Raw | ConvertFrom-Json) }
    return $null
}

function Save-State([hashtable]$Values) {
    New-Item -ItemType Directory -Force $script:StateDir | Out-Null
    $current = @{}
    $existing = Get-State
    if ($existing) { $existing.PSObject.Properties | ForEach-Object { $current[$_.Name] = $_.Value } }
    foreach ($key in $Values.Keys) { $current[$key] = $Values[$key] }
    $current | ConvertTo-Json | Set-Content -Encoding utf8 $script:StateFile
}

# Resolve a setting from an explicit parameter, then saved state, then a default.
function Resolve-Setting($Explicit, [string]$StateKey, $Default) {
    if ($Explicit) { return $Explicit }
    $state = Get-State
    if ($state -and $state.PSObject.Properties.Name -contains $StateKey -and $state.$StateKey) { return $state.$StateKey }
    return $Default
}

function Get-ClusterContext {
    $state = Get-State
    if (-not $state -or -not $state.cluster) { throw 'No environment recorded. Run 01-create-environment.ps1 first.' }
    return $state
}

# Point kubectl at the cluster recorded in state.
function Use-Cluster {
    $s = Get-ClusterContext
    Invoke-Native az @('aks', 'get-credentials', '-g', $s.resourceGroup, '-n', $s.cluster, '--overwrite-existing', '--only-show-errors') | Out-Null
}

function Get-OpenShellCheckout {
    param([string]$Path)
    if ($Path) { return (Resolve-Path $Path).Path }
    $sibling = Join-Path (Split-Path $script:RepoRoot -Parent) 'OpenShell'
    if (Test-Path $sibling) { return (Resolve-Path $sibling).Path }
    throw "Pass -OpenShellPath: clone https://github.com/NVIDIA/OpenShell next to this repository, or point to a checkout."
}

# Apply a manifest passed as text (no temporary files, so secrets never touch disk).
function Invoke-KubectlApply([string]$Manifest) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = $Manifest | & kubectl apply -f - 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($code -ne 0) { throw "kubectl apply failed (exit $code):`n$($output -join "`n")" }
}
