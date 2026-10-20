param(
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "status", "once", "reset")]
    [string]$Action = "status",
    [int]$MinSeconds = 60,
    [int]$MaxSeconds = 120
)

# Runs scripts/rail-guard-demo-traffic.sh inside WSL, where the demo stack lives.
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$drive = $repo.Substring(0, 1).ToLower()
$wslRepo = "/mnt/$drive" + ($repo.Substring(2) -replace "\\", "/")
$command = "cd '$wslRepo' && bash scripts/rail-guard-demo-traffic.sh $Action"
if ($Action -eq "start") { $command += " $MinSeconds $MaxSeconds" }
wsl -d Ubuntu-24.04 -- bash -lc $command
