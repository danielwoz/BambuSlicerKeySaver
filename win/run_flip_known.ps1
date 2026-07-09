# Headless launcher for the DR-breakpoint-based live capture (main tree).
#
# Runs win/build/bambu_host.exe with the capture path. --work-dir MUST be ABSOLUTE
# so the broker can write printer_trust\printer.cer and the plugin's TLS to the
# fake printer succeeds -> the sign actually runs -> p/q materialise. bambu_host
# also forces --work-dir absolute internally.
#
# NOTE: this binds a local fake broker on 127.0.0.1:8883 and drives the plugin.
# Do NOT run two brokers at once (port collision). Build-only consolidation does
# NOT invoke this; it is the one-command reproduction for the live run.
#
# Usage: powershell -File win\run_flip_known.ps1 [-Mode "--flip-known"]
param(
  [string]$Mode    = "--flip-known",   # or --flip-scan / --flip-capture / --find-verdict
  [string]$OutName = "live_key.txt",
  [string]$LogTag  = "flipknown"
)
$ErrorActionPreference = "Stop"

# Repo root = two levels up from this script (win\ -> repo root).
$root   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$build  = Join-Path $root "win\build"
$broker = Join-Path $root "win\broker\fake_broker2.exe"
$plugin = Join-Path $env:APPDATA "BambuStudio\plugins\bambu_networking.dll"
$cert   = Join-Path $root "resources\cert"
$report = Join-Path $build "real_report.json"     # 23KB report WITH `fun` (enc-enable)
$gt     = Join-Path $build "d_extracted.json"      # reference key, search-key only

# Fresh ABSOLUTE scratch work dir so config staging + printer.cer are isolated.
$work = Join-Path $build ("run_" + $LogTag)
New-Item -ItemType Directory -Force -Path $work | Out-Null

$env:BAMBU_FAKE_REPORT = $report
$env:BBL_NO_FREEZE     = "1"     # DR breakpoint armed -> skip the double-suspend freeze pass
$env:BBL_REARM_MS      = "50"    # background DR re-arm cadence

$exe     = Join-Path $build "bambu_host.exe"
$outFile = Join-Path $work $OutName
$stdout  = Join-Path $work "$LogTag.out"
$stderr  = Join-Path $work "$LogTag.err"

$argv = @(
  "--plugin",     $plugin,
  "--dev-id",     "01S00A2B3C4D5E6",
  "--broker",     $broker,
  "--cert-dir",   $cert,
  "--work-dir",   $work,          # ABSOLUTE (Join-Path of an absolute $build)
  "--out",        $outFile,
  "--diag-known", $gt,
  "--cloud-settle", "3",
  $Mode
)

Write-Host "[launcher] exe=$exe"
Write-Host "[launcher] mode=$Mode work=$work"
Write-Host "[launcher] argv: $($argv -join ' ')"

$p = Start-Process -FilePath $exe -ArgumentList $argv -WorkingDirectory $work `
     -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
     -NoNewWindow -PassThru
Write-Host "[launcher] pid=$($p.Id) started; logs: $stderr"
$p.Id | Out-File -Encoding ascii (Join-Path $work "pid.txt")
