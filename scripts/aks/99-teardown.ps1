<#
.SYNOPSIS
  Delete everything these scripts created by removing the resource group (cluster, registry, disks).

.DESCRIPTION
  Irreversible: the SQLite evidence database lives on a disk inside the group. Pass -Yes to confirm.
  Without -Yes the script only lists what would be deleted.
#>
[CmdletBinding()]
param([switch]$Yes, [switch]$Wait)
. "$PSScriptRoot/common.ps1"
Assert-Tool az 'Install the Azure CLI.'
$state = Get-ClusterContext

Write-Step "Resources in $($state.resourceGroup)"
Invoke-Native az @('resource', 'list', '-g', $state.resourceGroup, '--query', '[].{name:name,type:type}', '-o', 'table')
if (-not $Yes) {
    Write-Host "`nNothing deleted. Re-run with -Yes to delete the whole resource group." -ForegroundColor Yellow
    return
}
Write-Step "Deleting resource group $($state.resourceGroup)"
$args = @('group', 'delete', '-n', $state.resourceGroup, '--yes', '--only-show-errors')
if (-not $Wait) { $args += '--no-wait' }
Invoke-Native az $args -Retries 1 | Out-Null
Invoke-Native kubectl @('config', 'delete-context', $state.cluster) -AllowFailure | Out-Null
Remove-Item -Force $script:StateFile -ErrorAction SilentlyContinue
Write-Host 'Deletion started (it finishes in a few minutes). Local state cleared.' -ForegroundColor Green
