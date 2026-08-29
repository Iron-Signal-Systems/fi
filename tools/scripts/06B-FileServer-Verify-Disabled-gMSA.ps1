param(
    [string]$GovernedRoot = "",
    [switch]$ConfirmDisruptive
)

. "$PSScriptRoot\Common.ps1"

Write-Host ""
Write-Host "FI USN Verification - Test 06B: Disabled gMSA Service-Logon Control"
Write-Host "Run on the FILE SERVER after 06A disabled the helper gMSA."
Write-Host ""

if (-not $ConfirmDisruptive) {
    Write-FiFail "Not run. Re-run with -ConfirmDisruptive."
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

if (Test-FiServiceRunning -Name "FIUSNReader") {
    Write-FiPass "Already-running FIUSNReader remained running after AD account disable."
} else {
    Write-FiInfo "FIUSNReader was already stopped before this test."
}

Stop-Service FIUSNReader -ErrorAction SilentlyContinue

if (Test-FiServiceRunning -Name "FIUSNReader") {
    Write-FiFail "FIUSNReader could not be stopped."
    exit 1
}
Write-FiPass "FIUSNReader is stopped."

$RestartSucceeded = $false

try {
    Start-Service FIUSNReader -ErrorAction Stop
    $RestartSucceeded = $true
}
catch {
    Write-FiPass "Fresh FIUSNReader service logon failed while helper gMSA is disabled."
    Write-FiInfo $_.Exception.Message
}

if ($RestartSucceeded) {
    Write-FiFail "FIUSNReader unexpectedly restarted while helper gMSA is disabled."
    exit 1
}

if (-not (Test-FiServiceRunning -Name "FICollector")) {
    Write-FiFail "FICollector stopped unexpectedly."
    exit 1
}
Write-FiPass "FICollector remained running."

$FileName = "fi-usn-gmsa-disabled-$([Guid]::NewGuid().ToString('N')).txt"
$TestPath = Join-Path $GovernedRoot $FileName

"FI gMSA-disabled catch-up verification $(Get-Date -Format o)" |
    Set-Content -LiteralPath $TestPath

$Marker = "C:\ProgramData\FI\state\fi-usn-verification-gmsa-disabled.txt"
@(
    "checkpoint_path=$CheckpointPath"
    "before_usn=$($Before.next_usn)"
    "test_path=$TestPath"
    "file_name=$FileName"
) | Set-Content -LiteralPath $Marker -Encoding ASCII

Write-FiPass "Created a governed-root change while helper cannot start."
Write-FiInfo "Recovery marker written to: $Marker"
Write-FiInfo "Next: run 06C on the AD system, then 06D on this file server."

Write-FiPass "TEST 06B PASSED."
exit 0
