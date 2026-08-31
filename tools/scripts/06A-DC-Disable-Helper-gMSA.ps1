# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

param(
    [Parameter(Mandatory=$true)]
    [string]$HelperGMSA,

    [switch]$ConfirmDisruptive
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "FI USN Verification - Test 06A: Disable Helper gMSA"
Write-Host "Run on a DOMAIN CONTROLLER or AD admin system."
Write-Host ""
Write-Host "WARNING: This disables the privileged FI helper gMSA in Active Directory."
Write-Host ""

if (-not $ConfirmDisruptive) {
    Write-Host "[FAIL] Not run. Re-run with -ConfirmDisruptive after approving the AD account disable."
    exit 2
}

Import-Module ActiveDirectory

$Before = Get-ADServiceAccount -Identity $HelperGMSA -Properties Enabled
Write-Host "[INFO] Before: $($Before.Name) Enabled=$($Before.Enabled)"

if ($Before.Enabled -ne $true) {
    Write-Host "[FAIL] $($Before.Name) was not enabled before Test 06A. No change made."
    exit 1
}

Set-ADServiceAccount -Identity $HelperGMSA -Enabled $false

$After = Get-ADServiceAccount -Identity $HelperGMSA -Properties Enabled

if ($After.Enabled -eq $false) {
    Write-Host "[PASS] $($After.Name) is disabled."
    exit 0
}

Write-Host "[FAIL] $($After.Name) is still enabled."
exit 1
