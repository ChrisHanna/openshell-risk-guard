<#
.SYNOPSIS
  Back up and restore Risk Guard's decision database on AKS, and time it.

.DESCRIPTION
  -Backup        takes a verified snapshot inside the running pod (no downtime; decisions continue), into /var/lib/openshell-risk-guard/backups on the
                 same volume, and prints its size, rows, checksum and how long it took. This protects against a corrupt database, a bad migration or an
                 operator mistake; it does NOT protect against losing the volume. For that, add -DiskSnapshot.
  -DiskSnapshot  also takes an Azure snapshot of the managed disk behind the volume (a different failure domain). It is taken from the running disk, so
                 it is crash-consistent: SQLite recovers it like a power cut. The verified file snapshot above is the one to restore from when you can.
  -Restore NAME  stops Risk Guard, puts the named snapshot in place of the database (verified first; the database it replaces is kept as risk-guard.db.before-restore on the volume),
                 starts Risk Guard, and prints how long the outage lasted. EVERYTHING DECIDED AFTER THE SNAPSHOT IS LOST, including restrictions and quarantines made
                 since. See docs/recovery.md.
#>
[CmdletBinding()]
param(
    [switch]$Backup,
    [switch]$DiskSnapshot,
    [string]$Restore
)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster
$ns = Get-StateValue 'namespace' 'openshell'
$data = '/var/lib/openshell-risk-guard'
$binary = '/usr/local/bin/openshell-risk-guard'

function Invoke-InPod([string[]]$Arguments) {
    # The image has no shell, so the binary is called directly.
    return Invoke-Native kubectl (@('exec', '-n', $ns, 'deploy/risk-guard', '-c', 'risk-guard', '--', $binary) + $Arguments)
}

if (-not ($Backup -or $DiskSnapshot -or $Restore)) {
    Write-Step 'Nothing to do. Use -Backup, -DiskSnapshot or -Restore NAME.'
    return
}

if ($Backup -or $DiskSnapshot) {
    $name = 'risk-guard-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '.db'
    Write-Step "Snapshot $name (no downtime)"
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $report = (Invoke-InPod @('backup', "--db=$data/risk-guard.db", "--out=$data/backups/$name")) -join "`n"
    $took = $clock.Elapsed.TotalSeconds
    Write-Host $report
    Write-Note ("took {0:N1} s; verifying the copy on disk" -f $took)
    Invoke-InPod @('backup-verify', "--file=$data/backups/$name") | Out-Null
    Write-Note 'checksum and integrity check pass'
    Save-State @{ lastBackupAtMs = [int64][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); lastBackupName = $name }
}

if ($DiskSnapshot) {
    Write-Step 'Azure snapshot of the managed disk behind the volume'
    $pv = (kubectl get pvc risk-guard-data -n $ns -o 'jsonpath={.spec.volumeName}')
    $diskUri = (kubectl get pv $pv -o 'jsonpath={.spec.csi.volumeHandle}')
    if (-not $diskUri) { throw 'Could not find the managed disk behind the volume.' }
    $state = Get-ClusterContext
    $snap = 'risk-guard-data-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    Invoke-Native az @('snapshot', 'create', '-g', $state.resourceGroup, '-n', $snap, '--source', $diskUri, '--tags', 'purpose=openshell-risk-guard-backup', '--only-show-errors', '-o', 'none') -Retries 2 | Out-Null
    Write-Note "created Azure snapshot $snap in $($state.resourceGroup)"
}

if ($Restore) {
    if ($Restore -notmatch '^risk-guard-[0-9]{8}-[0-9]{6}\.db$') { throw 'Pass the snapshot name as printed by -Backup, e.g. risk-guard-20261023-101500.db' }
    Write-Step "Restoring $Restore"
    $deploy = kubectl get deploy risk-guard -n $ns -o json | ConvertFrom-Json
    $spec = $deploy.spec.template.spec
    $image = ($spec.containers | Where-Object { $_.name -eq 'risk-guard' }).image
    $clock = [Diagnostics.Stopwatch]::StartNew()
    Invoke-Native kubectl @('scale', 'deploy/risk-guard', '-n', $ns, '--replicas=0') | Out-Null
    Invoke-Native kubectl @('wait', '--for=delete', 'pod', '-l', 'app.kubernetes.io/name=risk-guard', '-n', $ns, '--timeout=120s') -AllowFailure | Out-Null
    $pod = @{
        apiVersion = 'v1'; kind = 'Pod'
        metadata = @{ name = 'risk-guard-restore'; namespace = $ns }
        spec = @{
            restartPolicy = 'Never'; automountServiceAccountToken = $false
            securityContext = @{ fsGroup = 65532; seccompProfile = @{ type = 'RuntimeDefault' } }
            containers = @(@{
                name = 'restore'; image = $image
                args = @('restore', "--from=$data/backups/$Restore", "--db=$data/risk-guard.db", '--force')
                securityContext = @{ runAsNonRoot = $true; runAsUser = 65532; runAsGroup = 65532; readOnlyRootFilesystem = $true; allowPrivilegeEscalation = $false; capabilities = @{ drop = @('ALL') } }
                resources = @{ requests = @{ cpu = '50m'; memory = '64Mi' }; limits = @{ memory = '256Mi' } }
                volumeMounts = @(@{ name = 'data'; mountPath = $data })
            })
            volumes = @(@{ name = 'data'; persistentVolumeClaim = @{ claimName = 'risk-guard-data' } })
        }
    }
    if ($spec.nodeSelector) { $pod.spec.nodeSelector = $spec.nodeSelector }
    if ($spec.tolerations) { $pod.spec.tolerations = $spec.tolerations }
    Invoke-Native kubectl @('delete', 'pod', 'risk-guard-restore', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    Invoke-KubectlApply ($pod | ConvertTo-Json -Depth 12)
    $phase = ''
    for ($i = 0; $i -lt 60 -and $phase -notin 'Succeeded', 'Failed'; $i++) { Start-Sleep -Seconds 3; $phase = kubectl get pod risk-guard-restore -n $ns -o 'jsonpath={.status.phase}' }
    kubectl logs risk-guard-restore -n $ns
    Invoke-Native kubectl @('delete', 'pod', 'risk-guard-restore', '-n', $ns, '--ignore-not-found') -AllowFailure | Out-Null
    if ($phase -ne 'Succeeded') {
        Invoke-Native kubectl @('scale', 'deploy/risk-guard', '-n', $ns, '--replicas=1') | Out-Null
        throw "The restore pod ended as $phase; Risk Guard was started again on the database as it was. Nothing was replaced."
    }
    Invoke-Native kubectl @('scale', 'deploy/risk-guard', '-n', $ns, '--replicas=1') | Out-Null
    Invoke-Native kubectl @('rollout', 'status', 'deploy/risk-guard', '-n', $ns, '--timeout=300s') | Out-Null
    Write-Host ("Restore complete. Risk Guard was down for {0:N0} s." -f $clock.Elapsed.TotalSeconds) -ForegroundColor Green
}
