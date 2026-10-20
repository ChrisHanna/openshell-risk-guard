<#
.SYNOPSIS
  Copy a secret from Key Vault into an OpenShell provider, so an agent can use it without ever holding it.

.DESCRIPTION
  Reads the secret with your Azure login and passes it over stdin to scripts/aks/set-provider-credential.sh
  (which exports it for the single `openshell` command that needs it). The value is never written to disk or
  put on a command line. Run it again after rotating the secret in Key Vault.

  On Windows the openshell CLI lives in WSL: pass -Distro. The gateway must already be registered with that
  CLI (scripts/aks/connect-gateway.sh).

.EXAMPLE
  ./12-sync-credentials.ps1 -SecretName nvidia-api-key -ProviderName nvidia-nat -EnvVar NVIDIA_API_KEY `
      -ProfileFile deploy/rail-guard-demo/agent/nvidia-nat-provider.yaml -Distro Ubuntu-24.04
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SecretName,
    [Parameter(Mandatory)][string]$ProviderName,
    [Parameter(Mandatory)][string]$EnvVar,
    [Parameter(Mandatory)][string]$ProfileFile,
    [string]$Distro,
    [string]$OpenShellBin = 'openshell'
)
. "$PSScriptRoot/common.ps1"
Assert-Tool az 'Install the Azure CLI.'
$vault = Get-StateValue 'keyVault'
if (-not $vault) { throw 'No Key Vault recorded. Run 10-create-key-vault.ps1 first.' }
$profilePath = (Resolve-Path (Join-Path $script:RepoRoot $ProfileFile)).Path
$helper = Join-Path $PSScriptRoot 'set-provider-credential.sh'

function ConvertTo-WslPath([string]$Path) {
    $full = (Resolve-Path $Path).Path
    if ($full -match '^([A-Za-z]):\\(.*)$') { return "/mnt/$($Matches[1].ToLower())/" + ($Matches[2] -replace '\\', '/') }
    return $full
}

Write-Step "Reading $SecretName from $vault"
$value = (Invoke-Native az @('keyvault', 'secret', 'show', '--vault-name', $vault, '--name', $SecretName, '--query', 'value', '-o', 'tsv', '--only-show-errors') -Retries 3 | Select-Object -First 1)
if (-not $value) { throw "Secret $SecretName is empty or missing." }

Write-Step "Updating provider $ProviderName in OpenShell"
try {
    if ($Distro) {
        $value | & wsl.exe -d $Distro -- env "OPENSHELL_BIN=$OpenShellBin" bash (ConvertTo-WslPath $helper) --stdin (ConvertTo-WslPath $profilePath) $ProviderName $EnvVar
    } else {
        $env:OPENSHELL_BIN = $OpenShellBin
        $value | & bash $helper --stdin $profilePath $ProviderName $EnvVar
    }
    if ($LASTEXITCODE -ne 0) { throw "The provider update failed (exit $LASTEXITCODE)." }
} finally { $value = $null }
Write-Host 'Done. The agent sees a placeholder; OpenShell injects the real value only for allowed requests.' -ForegroundColor Green
