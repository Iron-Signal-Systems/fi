# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this source code is governed by the FI repository LICENSE.
# Read-only, pinned Server 2019 post-reboot persistence check.
# Requires an elevated console on ISS-FS-2019. Does not start or modify services.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExpectedHost = 'ISS-FS-2019'
$ExpectedBuild = '17763'
$File = 'C:\FI-Governed-Test\FI-TEST-20261012-101110\Archive\renamed.txt'
$ExpectedHash = 'E271BBBEAD08FB44AB23CACFD2B8EFD902E6BDAFCA64A3234C6611313B752DF6'
$ExpectedServiceAccounts = @{
    'FICollector'   = 'ISS\gFI-FS2019$'
    'FISender'      = 'ISS\gFI-FS2019$'
    'FIUSNReader'   = 'ISS\gFI-USN-FS2019$'
    'FIObjReader'   = 'ISS\gFI-OBJ-FS2019$'
    'FICRLRefresher' = 'ISS\gFI-CRL-FS2019$'
}

$OS = Get-CimInstance Win32_OperatingSystem
if ($env:COMPUTERNAME -ine $ExpectedHost -or $OS.BuildNumber -ne $ExpectedBuild) {
    throw "Wrong target host/build: $env:COMPUTERNAME/$($OS.BuildNumber); expected $ExpectedHost/$ExpectedBuild"
}

Write-Host '===== HOST BOOT ====='
$OS | Select-Object CSName, LastBootUpTime, BuildNumber | Format-List

Write-Host '===== SERVICE PERSISTENCE ====='
$Observed = @(Get-CimInstance Win32_Service | Where-Object { $ExpectedServiceAccounts.ContainsKey($_.Name) })
$Observed | Sort-Object Name |
    Select-Object Name, State, StartMode, StartName, ProcessId |
    Format-Table -AutoSize

if ($Observed.Count -ne $ExpectedServiceAccounts.Count) {
    throw "FI service count mismatch: expected $($ExpectedServiceAccounts.Count), observed $($Observed.Count)"
}
foreach ($Service in $Observed) {
    if ($Service.State -ne 'Running' -or $Service.StartMode -ne 'Auto' -or
        $Service.StartName -ine $ExpectedServiceAccounts[$Service.Name] -or
        $Service.ProcessId -le 0) {
        throw "FI service convergence failure: $($Service.Name) state=$($Service.State) start=$($Service.StartMode) account=$($Service.StartName) pid=$($Service.ProcessId)"
    }
}

Write-Host '===== SURVIVING FILE INTEGRITY ====='
$Item = Get-Item -LiteralPath $File -ErrorAction Stop
$Hash = Get-FileHash -LiteralPath $File -Algorithm SHA256
$Item | Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc | Format-List
$Hash | Select-Object Algorithm, Hash, Path | Format-List
if ($Item.Length -ne 49 -or $Hash.Hash -ine $ExpectedHash) {
    throw "FI surviving-file integrity mismatch: length=$($Item.Length) sha256=$($Hash.Hash)"
}

Write-Host 'FI WINDOWS SERVER 2019 POST-REBOOT HOST CHECK: PASS'
Write-Host 'Database post-reboot ingest must be validated separately with the companion read-only SQL.'
