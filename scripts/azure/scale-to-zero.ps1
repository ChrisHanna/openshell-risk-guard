<#
.SYNOPSIS
  Make Azure Container Apps scale to zero when idle, and report what is still holding a replica up.

.DESCRIPTION
  Dry run by default: lists every container app whose minimum replicas is above 0, with its scale rules and current replica count.
  -Apply sets minReplicas to 0 (maxReplicas is kept, and raised to 1 if it is 0). Before changing anything it saves each app's
  previous min/max to .aks/scale-backup-<time>.json; -Restore <file> puts those values back.

  The scale-rule polling interval (default 30 s) is how often the platform checks rules; it is not billed. What costs money is a replica
  that is running. A replica stays up past min=0 only while traffic, a scale rule (queue, cron, custom) or the cooldown period keeps it.

.EXAMPLE
  powershell -File scripts/azure/scale-to-zero.ps1                          # dry run, every app in the subscription
  powershell -File scripts/azure/scale-to-zero.ps1 -ResourceGroup rg-x -Apply
  powershell -File scripts/azure/scale-to-zero.ps1 -Restore .aks/scale-backup-20261024-1200.json
#>
param(
    [string]$ResourceGroup,
    [string[]]$Exclude = @(),
    [switch]$Apply,
    [string]$Restore
)
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

function Get-Apps {
    $arguments = @('containerapp', 'list', '-o', 'json')
    if ($ResourceGroup) { $arguments += @('-g', $ResourceGroup) }
    az @arguments | ConvertFrom-Json
}

if ($Restore) {
    foreach ($entry in (Get-Content $Restore -Raw | ConvertFrom-Json)) {
        Write-Host "restore $($entry.name): min $($entry.min), max $($entry.max)"
        az containerapp update -g $entry.group -n $entry.name --min-replicas $entry.min --max-replicas $entry.max --only-show-errors -o none
    }
    return
}

$rows = foreach ($app in (Get-Apps)) {
    $scale = $app.properties.template.scale
    $min = [int]($scale.minReplicas | ForEach-Object { if ($null -eq $_) { 0 } else { $_ } })
    $max = [int]($scale.maxReplicas | ForEach-Object { if ($null -eq $_) { 10 } else { $_ } })
    $rules = @($scale.rules | ForEach-Object { $_.name }) -join ','
    $listed = (az containerapp replica list -g $app.resourceGroup -n $app.name -o json 2>$null | Out-String).Trim()
    $replicas = if ($listed) { @($listed | ConvertFrom-Json | Where-Object { $_ }).Count } else { 0 }
    [pscustomobject]@{ Name = $app.name; Group = $app.resourceGroup; Min = $min; Max = $max; Rules = $rules; Running = $replicas }
}

$rows | Sort-Object Min -Descending | Format-Table Name, Group, Min, Max, Running, Rules -AutoSize | Out-String | Write-Host
$targets = @($rows | Where-Object { $_.Min -gt 0 -and $Exclude -notcontains $_.Name })
Write-Host "$($targets.Count) app(s) keep a replica running at all times."
$withRules = @($rows | Where-Object { $_.Rules })
if ($withRules) { Write-Host "Apps with scale rules (a rule can keep a replica up even at min 0): $(($withRules | ForEach-Object Name) -join ', ')" }

if (-not $Apply) { Write-Host 'Dry run. Re-run with -Apply to set min replicas to 0.'; return }
if (-not $targets) { return }

$backupDir = Join-Path $root '.aks'
New-Item -ItemType Directory -Force $backupDir | Out-Null
$backup = Join-Path $backupDir ("scale-backup-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
$targets | ForEach-Object { [pscustomobject]@{ name = $_.Name; group = $_.Group; min = $_.Min; max = $_.Max } } | ConvertTo-Json | Set-Content $backup -Encoding utf8
Write-Host "Previous settings saved to $backup"

foreach ($t in $targets) {
    $max = [Math]::Max($t.Max, 1)
    az containerapp update -g $t.Group -n $t.Name --min-replicas 0 --max-replicas $max --only-show-errors -o none
    Write-Host "  $($t.Name): min $($t.Min) -> 0 (max $max)"
}
Write-Host "Undo with: powershell -File scripts/azure/scale-to-zero.ps1 -Restore $backup"
