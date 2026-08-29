param(
    [string]$GovernedRoot = "",
    [switch]$ConfirmDisruptive
)

. "$PSScriptRoot\Common.ps1"

Write-Host ""
Write-Host "FI USN Verification - Test 04: Helper Failure and Catch-Up"
Write-Host "Run on the FILE SERVER in elevated Windows PowerShell."
Write-Host ""
Write-Host "WARNING: This test stops FIUSNReader for about 35 seconds."
Write-Host "FICollector must remain running."
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

$CheckpointPath = Get-FiCheckpointPath -GovernedRoot $GovernedRoot
$Before = Get-FiCheckpoint -CheckpointPath $CheckpointPath
$BeforeUSN = [UInt64]$Before.next_usn
$BeforeUpdated = $Before.updated_at

$FileName = "fi-usn-helper-down-$([Guid]::NewGuid().ToString('N')).txt"
$TestPath = Join-Path $GovernedRoot $FileName

$SpoolBefore = Get-ChildItem "C:\ProgramData\FI\spool" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$SpoolBeforeTime = $null
if ($SpoolBefore) {
    $SpoolBeforeTime = $SpoolBefore.LastWriteTimeUtc
}

Write-FiInfo "Checkpoint before outage: $BeforeUSN"
Write-FiInfo "Stopping FIUSNReader."

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

$Stable = Wait-FiCheckpointStable -CheckpointPath $CheckpointPath -ExpectedUSN $BeforeUSN -Seconds 35

if (-not $Stable) {
    Write-FiFail "USN checkpoint advanced while FIUSNReader was down."
    Start-Service FIUSNReader -ErrorAction SilentlyContinue
    exit 1
}
Write-FiPass "USN checkpoint did not advance while helper was down."

$Runtime = Get-FiLatestConfiguredCollection
if ($Runtime -and $Runtime.error -match 'FIUSNReader pipe unavailable') {
    Write-FiPass "FI reported FIUSNReader unavailability explicitly."
} else {
    Write-FiInfo "Latest collection did not contain the expected pipe-unavailable text; review service-runtime.jsonl if needed."
}

$RecentSpoolBeforeRecovery = Get-ChildItem "C:\ProgramData\FI\spool" -File |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if (
    $RecentSpoolBeforeRecovery -and
    (
        -not $SpoolBeforeTime -or
        $RecentSpoolBeforeRecovery.LastWriteTimeUtc -gt $SpoolBeforeTime
    )
) {
    Write-FiPass "FI spool continued receiving output while helper was unavailable."
} else {
    Write-FiFail "No newer FI spool output was observed while helper was unavailable."
    Start-Service FIUSNReader -ErrorAction SilentlyContinue
    exit 1
}

Write-FiInfo "Restarting FIUSNReader."
Start-Service FIUSNReader -ErrorAction Stop

if (-not (Test-FiServiceRunning -Name "FIUSNReader")) {
    Write-FiFail "FIUSNReader did not restart."
    exit 1
}
Write-FiPass "FIUSNReader restarted."

$After = Wait-FiCheckpointAdvance -CheckpointPath $CheckpointPath -BeforeUSN $BeforeUSN -TimeoutSeconds 75

if (-not $After) {
    Write-FiFail "USN checkpoint did not advance after helper recovery."
    exit 1
}
Write-FiPass "USN checkpoint advanced after helper recovery: $BeforeUSN -> $($After.next_usn)."

$Matches = @(Wait-FiSpoolFilename -FileName $FileName -NewestFiles 80 -TimeoutSeconds 75)
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
