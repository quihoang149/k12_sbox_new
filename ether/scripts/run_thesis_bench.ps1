# Re-runs every experiment of the thesis and builds the tables.
#
#   powershell -ExecutionPolicy Bypass -File scripts\run_thesis_bench.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\run_thesis_bench.ps1 -Count 5 -Ghz 3.8
#
# -Count  repetitions of the whole suite (default 5; each table cell = median)
# -Out    output folder (default bench_out_<date>_<time>, never overwrites)
# -Ghz    if set, also report cycles/byte = ns/byte * Ghz
#
# Before running: plug the laptop in, close heavy apps, do not use the machine.
param([int]$Count = 5, [string]$Out = "", [double]$Ghz = 0)

$ErrorActionPreference = "Stop"

# Always run from the repository root (the folder that holds go.mod).
$root = Split-Path $PSScriptRoot -Parent
if (-not (Test-Path (Join-Path $root "go.mod")) -or -not (Test-Path (Join-Path $root "chain"))) {
    throw "Khong tim thay go.mod/chain trong '$root'. Hay dat thu muc scripts\ ben trong repo k12chain."
}
Set-Location $root
if ($Out -eq "") { $Out = "bench_out_" + (Get-Date -Format "yyyyMMdd_HHmm") }
Write-Host "repo: $root"
Write-Host "output: $Out"

# High performance power plan (best effort) and keep Windows awake while this
# script runs, without changing the user's sleep settings permanently.
powercfg /setactive SCHEME_MIN 2>$null
Add-Type -Namespace Win32 -Name Power -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);
'@
$ES_CONTINUOUS = [uint32]"0x80000000"; $ES_SYSTEM_REQUIRED = [uint32]"0x00000001"
[Win32.Power]::SetThreadExecutionState($ES_CONTINUOUS -bor $ES_SYSTEM_REQUIRED) | Out-Null

try {
    # 1. Correctness first: S-box vs reference table, official K12 vectors,
    #    parallel == sequential, chain tests.
    go test ./k12 ./chain -count 1
    if ($LASTEXITCODE -ne 0) { throw "tests failed - fix before measuring" }

    New-Item -ItemType Directory -Force $Out | Out-Null
    # Record the environment next to the results.
    @(
        "date:  " + (Get-Date -Format "yyyy-MM-dd HH:mm")
        "go:    " + (go version)
        "cpu:   " + (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
        "cores: " + (Get-CimInstance Win32_Processor | Measure-Object NumberOfCores -Sum).Sum +
            " physical / " + [Environment]::ProcessorCount + " logical"
        "power: " + ((powercfg /getactivescheme) -join " ")
        "count: $Count"
    ) | Out-File -Encoding utf8 "$Out\env.txt"

    $groups = [ordered]@{
        "perm"    = @("./k12",   "Permutation")                 # cost of one permutation call
        "t34"     = @("./chain", "T34")                         # table 3.4 + short-input throughput
        "t35"     = @("./chain", "T35Import")                   # table 3.5 (tx/s)
        "t35hash" = @("./chain", "T35HashShare")                # hash share inside block import
        "t36"     = @("./chain", "T36Large|T36Scaling")         # table 3.6 + large-input throughput
        "t37_t38" = @("./chain", "T37Snapshot|T38BlockBody")    # table 3.7 (proposed use cases)
    }

    $t0 = Get-Date
    for ($i = 1; $i -le $Count; $i++) {
        Write-Host ("=== repetition {0} / {1}  ({2:n0} min elapsed) ===" -f $i, $Count, ((Get-Date) - $t0).TotalMinutes)
        foreach ($g in $groups.Keys) {
            $pkg, $pat = $groups[$g]
            Write-Host "  $g"
            go test $pkg -run '^$' -bench $pat -benchmem -count 1 |
                Out-File -Append -Encoding utf8 "$Out\$g.txt"
            if ($LASTEXITCODE -ne 0) { throw "benchmark group $g failed" }
            Start-Sleep -Seconds 5   # let the CPU cool down a little between groups
        }
    }

    Write-Host "`n########## thesis tables ##########"
    if ($Ghz -gt 0) { python scripts\thesis_tables.py $Out --ghz $Ghz }
    else            { python scripts\thesis_tables.py $Out }
    Write-Host ("total time: {0:n0} min" -f ((Get-Date) - $t0).TotalMinutes)
}
finally {
    [Win32.Power]::SetThreadExecutionState($ES_CONTINUOUS) | Out-Null   # allow sleep again
}
