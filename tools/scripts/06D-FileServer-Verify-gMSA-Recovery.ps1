param()

. "$PSScriptRoot\Common.ps1"

Write-Host ""
Write-Host "FI USN Verification - Test 06D: gMSA Recovery and Catch-Up"
Write-Host "Run on the FILE SERVER after 06C re-enabled the helper gMSA."
Write-Host ""

$Marker = "C:\ProgramData\FI\state\fi-usn-verification-gmsa-disabled.txt"

if (-not (Test-Path -LiteralPath $Marker)) {
    throw "Verification marker not found. Run 06B first: $Marker"
}

$Values = @{}
foreach ($Line in Get-Content -LiteralPath $Marker) {
    if ($Line -match '^([^=]+)=(.*)$') {
        $Values[$Matches[1]] = $Matches[2]
    }
}

$CheckpointPath = $Values["checkpoint_path"]
$BeforeUSN = [UInt64]$Values["before_usn"]
$TestPath = $Values["test_path"]
$FileName = $Values["file_name"]

Start-Service FIUSNReader -ErrorAction Stop

if (-not (Test-FiServiceRunning -Name "FIUSNReader")) {
    Write-FiFail "FIUSNReader did not start after gMSA re-enable."
    exit 1
}
Write-FiPass "FIUSNReader started after gMSA re-enable."

if (-not (Test-FiServiceRunning -Name "FICollector")) {
    Write-FiFail "FICollector is not running."
    exit 1
}
Write-FiPass "FICollector remained running."

$After = Wait-FiCheckpointAdvance -CheckpointPath $CheckpointPath -BeforeUSN $BeforeUSN -TimeoutSeconds 90

if (-not $After) {
    Write-FiFail "USN checkpoint did not advance after helper gMSA recovery."
    exit 1
}

Write-FiPass "USN checkpoint advanced after recovery: $BeforeUSN -> $($After.next_usn)."

$Matches = @(Wait-FiSpoolFilename -FileName $FileName -NewestFiles 100 -TimeoutSeconds 90)

if ($Matches.Count -eq 0) {
    Write-FiFail "The file changed while helper gMSA was disabled was not found in catch-up output."
    exit 1
}

Write-FiPass "The gMSA-downtime change appeared in FI catch-up output."
$Matches |
    Select-Object Path,LineNumber |
    Format-Table -AutoSize

Remove-Item -LiteralPath $TestPath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue

Write-FiPass "TEST 06D PASSED."
exit 0
