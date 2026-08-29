param(
    [Parameter(Mandatory=$true)]
    [string]$HelperGMSA
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "FI USN Verification - Test 06C: Re-enable Helper gMSA"
Write-Host "Run on a DOMAIN CONTROLLER or AD admin system."
Write-Host ""

Import-Module ActiveDirectory

Set-ADServiceAccount -Identity $HelperGMSA -Enabled $true

$After = Get-ADServiceAccount -Identity $HelperGMSA -Properties Enabled

if ($After.Enabled -eq $true) {
    Write-Host "[PASS] $($After.Name) is enabled."
    exit 0
}

Write-Host "[FAIL] $($After.Name) is still disabled."
exit 1
