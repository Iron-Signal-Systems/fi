# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

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
    $MarkerMatch = [regex]::Match(
        $Line,
        '^([^=]+)=(.*)$'
    )

    if ($MarkerMatch.Success) {
        $Values[$MarkerMatch.Groups[1].Value] = $MarkerMatch.Groups[2].Value
    }
}

$RequiredKeys = @(
    "checkpoint_path"
    "before_usn"
    "test_path"
    "file_name"
)

foreach ($Key in $RequiredKeys) {
    if (-not $Values.ContainsKey($Key) -or [string]::IsNullOrWhiteSpace($Values[$Key])) {
        throw "Verification marker is missing required value: $Key"
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

$After = Wait-FiCheckpointAdvance `
    -CheckpointPath $CheckpointPath `
    -BeforeUSN $BeforeUSN `
    -TimeoutSeconds 90

if (-not $After) {
    Write-FiFail "USN checkpoint did not advance after helper gMSA recovery."
    exit 1
}

Write-FiPass "USN checkpoint advanced after recovery: $BeforeUSN -> $($After.next_usn)."

$SpoolMatches = @(
    Wait-FiSpoolFilename `
        -FileName $FileName `
        -NewestFiles 100 `
        -TimeoutSeconds 90
)

if ($SpoolMatches.Count -eq 0) {
    Write-FiFail "The file changed while helper gMSA was disabled was not found in catch-up output."
    exit 1
}

Write-FiPass "The gMSA-downtime change appeared in FI catch-up output."

$SpoolMatches |
    Select-Object Path,LineNumber |
    Format-Table -AutoSize

Remove-Item `
    -LiteralPath $TestPath `
    -Force `
    -ErrorAction SilentlyContinue

Remove-Item `
    -LiteralPath $Marker `
    -Force `
    -ErrorAction SilentlyContinue

Write-FiPass "TEST 06D PASSED."
exit 0
