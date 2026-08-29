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

Set-ADServiceAccount -Identity $HelperGMSA -Enabled $false

$After = Get-ADServiceAccount -Identity $HelperGMSA -Properties Enabled

if ($After.Enabled -eq $false) {
    Write-Host "[PASS] $($After.Name) is disabled."
    exit 0
}

Write-Host "[FAIL] $($After.Name) is still enabled."
exit 1
