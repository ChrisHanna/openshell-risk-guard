# Shared settings and helpers for the AKS scripts. Dot-source it: . "$PSScriptRoot/common.ps1"
#
# Requires: Azure CLI (az), kubectl, Helm 3.14+ or 4. Works in Windows PowerShell 5.1 and PowerShell 7+
# (Windows, Linux, macOS). Nothing here stores secrets in the repository: environment state lives in
# .aks/state.json, which is git-ignored.

Set-StrictMode -Version Latest
# Any error should stop the script; Invoke-Native handles native exit codes explicitly.
$ErrorActionPreference = 'Stop'

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
    # Reuse a working kubeconfig context; only fetch credentials from Azure when it is missing or stale.
    $ok = Invoke-Native kubectl @('--context', $s.cluster, 'get', 'namespace', 'default', '-o', 'name', '--request-timeout=15s') -AllowFailure -Retries 1
    if ($ok) {
        Invoke-Native kubectl @('config', 'use-context', $s.cluster) | Out-Null
        return
    }
    Invoke-Native az @('aks', 'get-credentials', '-g', $s.resourceGroup, '-n', $s.cluster, '--overwrite-existing', '--only-show-errors') -Retries 6 | Out-Null
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

# Read one value from saved state without tripping strict mode when the key is not there yet.
function Get-StateValue([string]$Name, $Default = $null) {
    $state = Get-State
    if ($state -and ($state.PSObject.Properties.Name -contains $Name) -and $state.$Name) { return $state.$Name }
    return $Default
}

# Run a shell command in a throwaway pod and return its output. The pod is started detached and polled,
# because attaching (kubectl run -i) gives up while a node is still pulling the image for the first time.
function Invoke-InCluster {
    param([string]$Name, [string]$Namespace, [string]$Image, [string]$ShellCommand, [int]$TimeoutSeconds = 420)
    Invoke-Native kubectl @('delete', 'pod', $Name, '-n', $Namespace, '--ignore-not-found', '--wait=true') | Out-Null
    # The script travels base64-encoded: Windows PowerShell 5.1 strips embedded double quotes from native arguments.
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ShellCommand))
    Invoke-Native kubectl @('run', $Name, '-n', $Namespace, "--image=$Image", '--restart=Never', '--command', '--', 'sh', '-c', "echo $encoded | base64 -d | sh") | Out-Null
    try {
        $phase = ''
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            $phase = (Invoke-Native kubectl @('get', 'pod', $Name, '-n', $Namespace, '-o', 'jsonpath={.status.phase}') -Retries 5 | Select-Object -First 1)
            if ($phase -in 'Succeeded', 'Failed') { break }
            $waiting = (Invoke-Native kubectl @('get', 'pod', $Name, '-n', $Namespace, '-o', 'jsonpath={.status.containerStatuses[0].state.waiting.reason}') -AllowFailure | Select-Object -First 1)
            if ($waiting -in 'ErrImagePull', 'ImagePullBackOff', 'InvalidImageName', 'CreateContainerConfigError') { $phase = "stuck: $waiting"; break }
            Start-Sleep -Seconds 3
        }
        $logs = Invoke-Native kubectl @('logs', $Name, '-n', $Namespace) -AllowFailure
        if ($phase -ne 'Succeeded') {
            $why = Invoke-Native kubectl @('describe', 'pod', $Name, '-n', $Namespace) -AllowFailure
            throw "Pod $Name ended in phase '$phase'.`n$($logs -join "`n")`n$(($why | Select-Object -Last 12) -join "`n")"
        }
        return $logs
    }
    finally {
        Invoke-Native kubectl @('delete', 'pod', $Name, '-n', $Namespace, '--ignore-not-found', '--wait=false') -AllowFailure | Out-Null
    }
}

# True on Linux and macOS. `$IsLinux` does not exist in Windows PowerShell 5.1, so test the platform safely.
function Test-Unix {
    return ($PSVersionTable.PSObject.Properties.Name -contains 'Platform') -and ($PSVersionTable.Platform -eq 'Unix')
}

# Sign the local Docker engine in to the registry without az's own registry login (some networks reset that
# connection while curl works): exchange the Azure token for a registry refresh token with curl.
function Connect-AcrDocker([string]$Server) {
    $aad = (Invoke-Native az @('account', 'get-access-token', '--resource', 'https://management.azure.com', '--query', 'accessToken', '-o', 'tsv') | Select-Object -First 1)
    $tenant = (Invoke-Native az @('account', 'show', '--query', 'tenantId', '-o', 'tsv') | Select-Object -First 1)
    $resp = & curl.exe -sS -m 30 -X POST "https://$Server/oauth2/exchange" -H 'Content-Type: application/x-www-form-urlencoded' --data "grant_type=access_token&service=$Server&tenant=$tenant&access_token=$aad" | ConvertFrom-Json
    if (-not $resp.refresh_token) { throw 'The registry did not return a refresh token.' }
    # Hand the token over through a file so PowerShell 5.1 cannot re-encode it on the pipe.
    $tokenFile = Join-Path ([IO.Path]::GetTempPath()) ("acr-" + [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllText($tokenFile, $resp.refresh_token, (New-Object Text.UTF8Encoding($false)))
        & cmd.exe /c "docker login $Server -u 00000000-0000-0000-0000-000000000000 --password-stdin < `"$tokenFile`"" | Out-Null
    } finally { if (Test-Path $tokenFile) { Remove-Item -Force $tokenFile } }
    if ($LASTEXITCODE -ne 0) { throw 'docker login failed' }
}
