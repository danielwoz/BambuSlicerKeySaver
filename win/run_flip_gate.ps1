# Headless one-click launcher for the --flip-gate slicer-key capture (main tree).
# This is the default capturer; the --flip-scan / --flip-known sweeps are
# alternatives.
#
# How --flip-gate works:
#   The slicer RSA key materialises as a TRANSIENT (stored PLAIN, both big- and
#   little-endian) in a SMALL MEM_PRIVATE heap arena, resident only for a brief
#   async window per printer-free sign. A full-memory sweep (~3 min/pass) overlaps
#   a live sign only by luck. --flip-gate instead drives the sign ITSELF and then
#   SNAPSHOTS just the small MEM_PRIVATE regions with a fast pure-memcpy (capturing
#   p/q while resident), then analyses the frozen copy with a plain N-division
#   factor test (both byte orders). Sub-millisecond sweeps back-to-back cover the
#   whole residency window, so the primes are caught in the first burst. It
#   recovers + validates (p*q==N + all public envelopes) + writes the key.
#   Needle-free: only the public modulus N + public envelopes gate acceptance; the
#   reference d_extracted.json is NEVER used by the capture.
#
# Each attempt spawns a fresh bambu_host process; retry if a run does not produce
# a validated key.
#
# NOTE: this binds a local fake broker on 127.0.0.1:8883 and drives the plugin.
# Do NOT run two brokers at once (port collision). --work-dir MUST be ABSOLUTE so
# the broker can write printer_trust\printer.cer and the plugin's TLS to the fake
# printer succeeds -> the sign actually runs -> p/q materialise. bambu_host also
# forces --work-dir absolute internally (GetFullPathNameA).
#
# Usage: powershell -File win\run_flip_gate.ps1 [-MaxRuns 15] [-Diag]
param(
  [string]$Mode    = "--flip-gate",
  [string]$OutName = "live_key.txt",
  [string]$LogTag  = "flipgate",
  [string]$Build   = "build",       # build dir under win\ holding bambu_host.exe
  [string]$Needle  = "absent",      # absent -> move d_extracted.json aside (needle-free proof)
  [int]   $MaxRuns = 15,
  [int]   $ScanPasses   = 8,
  [int]   $ScanBudgetMs = 3000,
  [switch]$Diag                     # set BBL_GATE_DIAG to report the live-prime region
)
$ErrorActionPreference = "Stop"

# Repo root = two levels up from this script (win\ -> repo root).
$root   = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$build  = Join-Path $root "win\$Build"
$broker = Join-Path $root "win\broker\fake_broker2.exe"
$plugin = Join-Path $env:APPDATA "BambuStudio\plugins\bambu_networking.dll"
$cert   = Join-Path $root "resources\cert"
$report = Join-Path $build "real_report.json"     # 23KB report WITH `fun` (enc-enable)
$gt     = Join-Path $build "d_extracted.json"     # reference key, search-key/diag only
$exe    = Join-Path $build "bambu_host.exe"

if (-not (Test-Path $exe)) { throw "bambu_host.exe not found at $exe (build first, or pass -Build)" }

# Needle-free run: move d_extracted.json aside so the capture has no reference key.
$gtMoved = $false
if ($Needle -eq "absent" -and (Test-Path $gt)) {
  Move-Item -Force $gt "$gt.aside"; $gtMoved = $true
  Write-Host "[launcher] ground truth moved aside -> needle-free run"
}

$env:BAMBU_FAKE_REPORT  = $report
$env:BBL_NO_FREEZE      = "1"     # DR breakpoint armed -> skip the double-suspend freeze pass
$env:BBL_REARM_MS       = "50"    # background DR re-arm cadence
$env:BBL_GATE_REGION_MB = "4"     # target small MEM_PRIVATE regions (fast cadence)
if ($Diag) { $env:BBL_GATE_DIAG = $gt } else { Remove-Item Env:BBL_GATE_DIAG -ErrorAction SilentlyContinue }

$landed = $false
for ($runI = 1; $runI -le $MaxRuns -and -not $landed; $runI++) {
  Get-Process bambu-studio,bambu_host,fake_broker2 -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 300

  $tag  = "$LogTag$runI"
  $work = Join-Path $build ("run_" + $tag)      # ABSOLUTE (Join-Path of an absolute $build)
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $outFile = Join-Path $work $OutName
  $stdout  = Join-Path $work "$tag.out"
  $stderr  = Join-Path $work "$tag.err"

  $argv = @(
    "--plugin",       $plugin,
    "--dev-id",       "01S00A2B3C4D5E6",
    "--broker",       $broker,
    "--cert-dir",     $cert,
    "--work-dir",     $work,
    "--out",          $outFile,
    "--cloud-settle", "3",
    "--scan-budget-ms", "$ScanBudgetMs",
    "--scan-passes",  "$ScanPasses",
    "--sign-sleep-ms", "1",
    $Mode
  )
  Write-Host "[launcher] attempt $runI/$MaxRuns work=$work"
  $p = Start-Process -FilePath $exe -ArgumentList $argv -WorkingDirectory $work `
       -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
       -NoNewWindow -PassThru
  $p.Id | Out-File -Encoding ascii (Join-Path $work "pid.txt")
  $done = $p.WaitForExit(180000)
  if (-not $done) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }

  if (Test-Path $outFile) {
    $landed = $true
    Write-Host "[launcher] *** KEY CAPTURED on attempt $runI -> $outFile ***"
    Copy-Item -Force $outFile (Join-Path $build "live_key.txt")
  } else {
    Write-Host "[launcher] attempt ${runI}: no key (process ended); retrying fresh"
  }
}

if ($gtMoved -and (Test-Path "$gt.aside")) { Move-Item -Force "$gt.aside" $gt }
if ($landed) { Write-Host "[launcher] SUCCESS"; Get-Content (Join-Path $build "live_key.txt") | Select-Object -First 3 }
else { Write-Host "[launcher] FAILED after $MaxRuns attempts; no validated key recovered" }
