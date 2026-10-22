param(
    [string]$SessionId = ("OBS_" + (Get-Date -Format "yyyyMMdd_HHmmss")),
    [int]$Scans = 10,
    [double]$DelaySeconds = 3,
    [string]$Output = "data/raw/wifi_observations.csv"
)
$ErrorActionPreference = "Stop"
Write-Host "SentinelShield real observation capture" -ForegroundColor Cyan
Write-Host "Session: $SessionId"
Write-Host "Scans requested: $Scans; delay between requests: $DelaySeconds seconds"
Write-Host "Output: $Output"
Write-Host "No labels will be inferred. Use only networks you are authorized to observe."
$confirmation = Read-Host "Type CAPTURE to start"
if ($confirmation -cne "CAPTURE") { Write-Host "Cancelled."; exit 1 }
python collect_wifi_observations.py --session $SessionId --scans $Scans --delay $DelaySeconds --output $Output
if ($LASTEXITCODE -ne 0) { throw "Capture failed with exit code $LASTEXITCODE. Check Python environment and Wi-Fi adapter." }
Write-Host "Capture command completed. Preserve this raw file; annotate a separate copy." -ForegroundColor Green
Write-Host "Next: python annotate_wifi_ground_truth.py `"$Output`" --output data/raw/wifi_observations_annotated.csv"
