# Capture the plugin's get_app_cert construction: the HTTP request/response
# (cloud_tap) + every BCryptGenRandom draw (rng_tap), so we can recover the client
# AES key + how encAppKey/aes256 are built. No DR-flip needed -- get_app_cert fires
# UPSTREAM of the sign gate. Same fake-broker + real-cloud harness as run_flip_gate.
#
# Usage: powershell -File win\run_appcert_rng.ps1 [-Seconds 90]
param([int]$Seconds = 90)
$ErrorActionPreference = "Stop"

$root   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$build  = Join-Path $root "win\build"
$exe    = Join-Path $build "bambu_host.exe"
$broker = Join-Path $root "win\broker\fake_broker2.exe"
$plugin = Join-Path $env:APPDATA "BambuStudio\plugins\bambu_networking.dll"
$cert   = Join-Path $root "resources\cert"
$report = Join-Path $build "real_report.json"
$work   = Join-Path $build "run_appcert_rng"

if (-not (Test-Path $exe))    { throw "bambu_host.exe missing: $exe" }
if (-not (Test-Path $report)) { throw "real_report.json missing: $report" }

Get-Process bambu-studio,bambu_host,fake_broker2 -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path $work | Out-Null

$env:BAMBU_FAKE_REPORT  = $report
$env:BBL_TAP_LOG        = Join-Path $work "appcert_tap.log"
$env:BBL_RNG_LOG        = Join-Path $work "rng.log"
$env:BBL_AES_LOG        = Join-Path $work "aes.log"
$env:BBL_BLOCK_WATCHDOG = "1"     # keep the process alive past the ~40s watchdog exit

$argv = @(
  "--plugin",      $plugin,
  "--dev-id",      "01S00A2B3C4D5E6",
  "--broker",      $broker,
  "--cert-dir",    $cert,
  "--work-dir",    $work,
  "--cloud-settle","3",
  "--tap",
  "--rng-tap",
  "--aes-tap"
)
Write-Host "[appcert-rng] work=$work  (running ${Seconds}s)"
$p = Start-Process -FilePath $exe -ArgumentList $argv -WorkingDirectory $work `
     -RedirectStandardOutput (Join-Path $work "out.txt") `
     -RedirectStandardError  (Join-Path $work "err.txt") -NoNewWindow -PassThru
$done = $p.WaitForExit($Seconds * 1000)
if (-not $done) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Get-Process fake_broker2 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "`n=== err.txt (harness progress: local-connect, get_app_cert, rng-tap armed) ==="
if (Test-Path (Join-Path $work "err.txt")) {
  Get-Content (Join-Path $work "err.txt") |
    Select-String -Pattern "rng-tap|is_local_connected|local_connected|get_app_cert|applications|send rc|CONNACK|login|cloud|app_cert|enc_msg|FAILED|ARMED" |
    Select-Object -Last 25
}
Write-Host "`n=== rng.log summary ==="
$rl = Join-Path $work "rng.log"
if (Test-Path $rl) {
  "lines: $((Get-Content $rl | Measure-Object -Line).Lines)"
  Get-Content $rl | Group-Object { ($_ -split 'cb=')[1] -split ' ' | Select-Object -First 1 } -ErrorAction SilentlyContinue |
    Sort-Object Count -Descending | Select-Object -First 12 | Format-Table Count,Name -Auto | Out-String
} else { "NO rng.log produced" }
Write-Host "=== tap log: did get_app_cert fire? ==="
$tl = Join-Path $work "appcert_tap.log"
if (Test-Path $tl) {
  "tap size: $((Get-Item $tl).Length) bytes"
  (Select-String -Path $tl -Pattern "applications/.{0,20}/cert|aes256=" -AllMatches | Select-Object -First 1).Line -replace '(.{160}).*','$1...'
} else { "NO tap log" }