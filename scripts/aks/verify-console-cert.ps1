<#
.SYNOPSIS
  Check that the public console presents a browser-trusted Let's Encrypt certificate.

.DESCRIPTION
  Waits up to -TimeoutSeconds for a trusted chain and fails with the certificate client's log if there is none.
  The deploy scripts (04, 09, 13) run the same check after they restart the Risk Guard pod.
#>
[CmdletBinding()]
param([int]$TimeoutSeconds = 360)
. "$PSScriptRoot/common.ps1"
Assert-Tools
Use-Cluster
Test-ConsoleCertificate -TimeoutSeconds $TimeoutSeconds
Write-Host "Certificate OK." -ForegroundColor Green
