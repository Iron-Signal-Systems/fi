param(
    [string]$GovernedRoot = "",
    [switch]$ConfirmDisruptive
)

. "$PSScriptRoot\Common.ps1"

Write-Host ""
Write-Host "FI USN Verification - Test 04: Helper Failure and Catch-Up"
Write-Host "Run on the FILE SERVER in elevated Windows PowerShell."
Write-Host ""
Write-Host "WARNING: This test stops FIUSNReader until FICollector executes"
Write-Host "one configured collection cycle. FICollector must remain running."
Write-Host ""

if (-not $ConfirmDisruptive) {
    Write-FiFail "Not run. Re-run with -ConfirmDisruptive after approving the controlled helper outage."
    exit 2
}

if (-not $GovernedRoot) {
    $Roots = @(Get-FiConfiguredRoots)
    if ($Roots.Count -ne 1) {
        throw "More than one governed root is configured. Re-run with -GovernedRoot <path>."
    }
    $GovernedRoot = $Roots[0]
}

$RuntimePath = "C:\ProgramData\FI\state\service-runtime.jsonl"
$CheckpointPath = Get-FiCheckpointPath -GovernedRoot $GovernedRoot
$Before = Get-FiCheckpoint -CheckpointPath $CheckpointPath
$BeforeUSN = [UInt64]$Before.next_usn

$BeforeRuntime = Get-FiLatestConfiguredCollection -RuntimePath $RuntimePath
if (-not $BeforeRuntime) {
    throw "No ConfiguredCollection runtime record exists before the helper outage."
}
$BeforeRuntimeObserved = [string]$BeforeRuntime.observed_at

$FileName = "fi-usn-helper-down-$([Guid]::NewGuid().ToString('N')).txt"
$TestPath = Join-Path $GovernedRoot $FileName

$SpoolBefore = Get-ChildItem "C:\ProgramData\FI\spool" -Filter "*.jsonl" -File |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1

$SpoolBeforeTime = $null
if ($SpoolBefore) {
    $SpoolBeforeTime = $SpoolBefore.LastWriteTimeUtc
}

Write-FiInfo "Checkpoint before outage: $BeforeUSN"
Write-FiInfo "Last configured collection before outage: $BeforeRuntimeObserved"
Write-FiInfo "Stopping FIUSNReader."

try {
    Stop-Service FIUSNReader -ErrorAction Stop

    if (Test-FiServiceRunning -Name "FIUSNReader") {
        Write-FiFail "FIUSNReader did not stop."
        exit 1
    }
    Write-FiPass "FIUSNReader stopped."

    if (-not (Test-FiServiceRunning -Name "FICollector")) {
        Write-FiFail "FICollector stopped unexpectedly."
        exit 1
    }
    Write-FiPass "FICollector remained running."

    "FI helper outage verification $(Get-Date -Format o)" |
        Set-Content -LiteralPath $TestPath

    Write-FiInfo "Created test change while helper was down: $TestPath"
    Write-FiInfo "Waiting for FICollector to execute a configured collection cycle while FIUSNReader is down."

    $OutageRuntime = $null
    $Deadline = (Get-Date).AddSeconds(90)

    do {
        Start-Sleep -Seconds 2

        $CurrentRuntime = Get-FiLatestConfiguredCollection -RuntimePath $RuntimePath

        if (
            $CurrentRuntime -and
            [string]$CurrentRuntime.observed_at -ne $BeforeRuntimeObserved
        ) {
            $OutageRuntime = $CurrentRuntime
            break
        }
    } while ((Get-Date) -lt $Deadline)

    if (-not $OutageRuntime) {
        Write-FiFail "FICollector did not execute a configured collection cycle during the helper outage."
        exit 1
    }

    Write-FiPass "FICollector executed a configured collection cycle while FIUSNReader was down."
    Write-FiInfo "Outage collection observed_at: $($OutageRuntime.observed_at)"
    Write-FiInfo "Outage collection outcome: $($OutageRuntime.outcome)"

    $During = Get-FiCheckpoint -CheckpointPath $CheckpointPath
    $DuringUSN = [UInt64]$During.next_usn

    if ($DuringUSN -ne $BeforeUSN) {
        Write-FiFail "USN checkpoint advanced while FIUSNReader was down."
        exit 1
    }
    Write-FiPass "USN checkpoint did not advance while helper was down."

    if (
        $OutageRuntime.outcome -ne "Complete" -and
        $OutageRuntime.error -match 'FIUSNReader pipe unavailable'
    ) {
        Write-FiPass "FI reported FIUSNReader unavailability explicitly."
        Write-FiInfo "Outage collection error: $($OutageRuntime.error)"
    }
    else {
        Write-FiFail "Outage collection did not report the expected FIUSNReader unavailability."
        exit 1
    }

    $RecentSpoolBeforeRecovery = Get-ChildItem "C:\ProgramData\FI\spool" -Filter "*.jsonl" -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    if (
        $RecentSpoolBeforeRecovery -and
        (
            -not $SpoolBeforeTime -or
            $RecentSpoolBeforeRecovery.LastWriteTimeUtc -gt $SpoolBeforeTime
        )
    ) {
        Write-FiPass "FI spool continued receiving output while helper was unavailable."
    }
    else {
        Write-FiFail "No newer FI spool output was observed during the collection cycle with FIUSNReader unavailable."
        exit 1
    }
}
finally {
    if (-not (Test-FiServiceRunning -Name "FIUSNReader")) {
        Write-FiInfo "Restarting FIUSNReader."
        Start-Service FIUSNReader -ErrorAction Stop
    }

    if (-not (Test-FiServiceRunning -Name "FIUSNReader")) {
        throw "FIUSNReader did not restart."
    }

    Write-FiPass "FIUSNReader is running."
}

$After = Wait-FiCheckpointAdvance -CheckpointPath $CheckpointPath -BeforeUSN $BeforeUSN -TimeoutSeconds 90

if (-not $After) {
    Write-FiFail "USN checkpoint did not advance after helper recovery."
    exit 1
}
Write-FiPass "USN checkpoint advanced after helper recovery: $BeforeUSN -> $($After.next_usn)."

$Matches = @(Wait-FiSpoolFilename -FileName $FileName -NewestFiles 80 -TimeoutSeconds 90)
if ($Matches.Count -eq 0) {
    Write-FiFail "The file changed during helper outage was not found in catch-up spool output."
    exit 1
}

Write-FiPass "The change created during helper outage appeared in catch-up output."
$Matches |
    Select-Object Path,LineNumber |
    Format-Table -AutoSize

Remove-Item -LiteralPath $TestPath -Force -ErrorAction SilentlyContinue

Write-FiPass "TEST 04 PASSED."
exit 0
