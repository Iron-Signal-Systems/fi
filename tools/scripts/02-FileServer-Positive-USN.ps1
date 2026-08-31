# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

param(
    [string]$GovernedRoot = ""
)

. "$PSScriptRoot\Common.ps1"

Write-Host ""
Write-Host "FI USN Verification - Test 02: Positive USN Collection"
Write-Host "Run on the FILE SERVER in elevated Windows PowerShell."
Write-Host ""

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

$FileName = "fi-usn-verification-positive-$([Guid]::NewGuid().ToString('N')).txt"
$TestPath = Join-Path $GovernedRoot $FileName

Write-FiInfo "Governed root: $GovernedRoot"
Write-FiInfo "Checkpoint before: $BeforeUSN"
Write-FiInfo "Creating: $TestPath"

"FI USN customer verification $(Get-Date -Format o)" |
    Set-Content -LiteralPath $TestPath

$After = Wait-FiCheckpointAdvance -CheckpointPath $CheckpointPath -BeforeUSN $BeforeUSN -TimeoutSeconds 60

if (-not $After) {
    Write-FiFail "USN checkpoint did not advance within 60 seconds."
    exit 1
}

Write-FiPass "USN checkpoint advanced from $BeforeUSN to $($After.next_usn)."

$SpoolMatches = @(Wait-FiSpoolFilename -FileName $FileName -TimeoutSeconds 60)

if ($SpoolMatches.Count -eq 0) {
    Write-FiFail "The test filename was not found in FI spool output within 60 seconds."
    exit 1
}

Write-FiPass "The test file appeared in FI USN spool output."
$SpoolMatches |
    Select-Object Path,LineNumber |
    Format-Table -AutoSize

Remove-Item -LiteralPath $TestPath -Force -ErrorAction SilentlyContinue

Write-FiPass "TEST 02 PASSED."
exit 0
