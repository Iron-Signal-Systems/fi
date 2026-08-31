# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

$ErrorActionPreference = 'Stop'

$ExpectedHost  = 'ISS-FS-25'
$HelperAccount = 'ISS\gFI-USN-FS25$'
$ServiceName   = 'FIUSNProbe2025'

$WorkDir    = 'C:\FI-Test\usnprobe'
$InputFile  = "$WorkDir\input-2025.json"
$ResultFile = "$WorkDir\usn-access-matrix-2025.json"
$ErrorFile  = "$WorkDir\usn-access-matrix-2025-error.txt"

$PolicyExport = "$WorkDir\user-rights-before-admin-2025.inf"
$PolicyApply  = "$WorkDir\user-rights-without-explicit-semanagevolume-2025.inf"
$PolicyVerify = "$WorkDir\user-rights-admin-verify-2025.inf"
$PolicyDB     = "$WorkDir\admin-characterization-2025.sdb"

Write-Host ""
Write-Host "============================================================"
Write-Host "FI USN ACCESS CHARACTERIZATION - WINDOWS SERVER 2025"
Write-Host "Host: $ExpectedHost"
Write-Host "gMSA: $HelperAccount"
Write-Host "Phase: LOCAL ADMINISTRATOR"
Write-Host "============================================================"

Write-Host ""
Write-Host "=== VERIFY HOST / RELEASE ==="

$HostName = hostname

$OS = Get-CimInstance Win32_OperatingSystem

Write-Host "[INFO] Host: $HostName"
Write-Host "[INFO] Caption: $($OS.Caption)"
Write-Host "[INFO] Version: $($OS.Version)"
Write-Host "[INFO] Build: $($OS.BuildNumber)"

if ($HostName -ine $ExpectedHost) {
    throw "Expected $ExpectedHost. No changes made."
}

if ($OS.BuildNumber -ne '26100') {
    throw "Expected Windows Server 2025 build 26100. Observed build $($OS.BuildNumber)."
}

Write-Host "[PASS] Host and Server 2025 build match the characterization target."

Write-Host ""
Write-Host "=== VERIFY EXISTING PROBE SERVICE ==="

$Service = Get-Service `
    -Name $ServiceName `
    -ErrorAction SilentlyContinue

if ($null -eq $Service) {
    throw "$ServiceName does not exist. Run 01-USN-Access-Characterization.ps1 first."
}

if ($Service.Status -ne 'Stopped') {
    Stop-Service `
        -Name $ServiceName `
        -Force

    $Service.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(15)
    )
}

Write-Host "[PASS] $ServiceName exists and is stopped."

Write-Host ""
Write-Host "=== RESOLVE gMSA SID ==="

$Account = New-Object `
    System.Security.Principal.NTAccount(
        'ISS',
        'gFI-USN-FS25$'
    )

$SID = $Account.Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value

$SIDEntry = "*$SID"

Write-Host "[INFO] Account: $HelperAccount"
Write-Host "[INFO] SID:     $SID"

Write-Host ""
Write-Host "=== REMOVE EXPLICIT SeManageVolumePrivilege ASSIGNMENT ==="

Remove-Item `
    -LiteralPath $PolicyExport,$PolicyApply,$PolicyVerify,$PolicyDB `
    -Force `
    -ErrorAction SilentlyContinue

secedit.exe `
    /export `
    /cfg $PolicyExport `
    /areas USER_RIGHTS

if ($LASTEXITCODE -ne 0) {
    throw "secedit export failed with exit code $LASTEXITCODE."
}

$Lines = [System.IO.File]::ReadAllLines(
    $PolicyExport,
    [System.Text.Encoding]::Unicode
)

$PrivilegeIndex = -1

for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
    if (
        [regex]::IsMatch(
            $Lines[$Index],
            '^\s*SeManageVolumePrivilege\s*='
        )
    ) {
        $PrivilegeIndex = $Index
        break
    }
}

if ($PrivilegeIndex -lt 0) {
    throw 'SeManageVolumePrivilege was not present in the exported local policy.'
}

Write-Host "[INFO] Before:"
Write-Host $Lines[$PrivilegeIndex]

$Parts = $Lines[$PrivilegeIndex] -split '=', 2

$Entries = @()

if ($Parts.Count -eq 2 -and $Parts[1].Trim() -ne '') {
    $Entries = @(
        $Parts[1].Split(',') |
        ForEach-Object {
            $_.Trim()
        } |
        Where-Object {
            $_ -ne '' -and
            $_ -ne $SIDEntry
        }
    )
}

$Lines[$PrivilegeIndex] =
    'SeManageVolumePrivilege = ' + ($Entries -join ',')

Write-Host "[INFO] After:"
Write-Host $Lines[$PrivilegeIndex]

[System.IO.File]::WriteAllLines(
    $PolicyApply,
    $Lines,
    [System.Text.Encoding]::Unicode
)

secedit.exe `
    /configure `
    /db $PolicyDB `
    /cfg $PolicyApply `
    /areas USER_RIGHTS `
    /quiet

if ($LASTEXITCODE -ne 0) {
    throw "secedit configure failed with exit code $LASTEXITCODE."
}

secedit.exe `
    /export `
    /cfg $PolicyVerify `
    /areas USER_RIGHTS

if ($LASTEXITCODE -ne 0) {
    throw "secedit verification export failed with exit code $LASTEXITCODE."
}

$VerifyLines = [System.IO.File]::ReadAllLines(
    $PolicyVerify,
    [System.Text.Encoding]::Unicode
)

$VerifyLine = $VerifyLines |
    Where-Object {
        [regex]::IsMatch(
            $_,
            '^\s*SeManageVolumePrivilege\s*='
        )
    } |
    Select-Object -First 1

Write-Host "[INFO] Verified:"
Write-Host $VerifyLine

if ($VerifyLine -match [regex]::Escape($SIDEntry)) {
    throw 'The gMSA still has an explicit SeManageVolumePrivilege assignment.'
}

Write-Host "[PASS] Explicit gMSA SeManageVolumePrivilege assignment removed."

Write-Host ""
Write-Host "=== ADD gMSA TO LOCAL ADMINISTRATORS ==="

$Administrators = @(net.exe localgroup Administrators)

if (($Administrators -join "`n") -notmatch [regex]::Escape('gFI-USN-FS25$')) {
    net.exe localgroup Administrators $HelperAccount /add

    if ($LASTEXITCODE -ne 0) {
        throw "Could not add $HelperAccount to local Administrators."
    }
}

$Administrators = @(net.exe localgroup Administrators)

$Administrators | ForEach-Object {
    Write-Host $_
}

if (($Administrators -join "`n") -notmatch [regex]::Escape('gFI-USN-FS25$')) {
    throw "$HelperAccount is not present in local Administrators after the add."
}

Write-Host "[PASS] gFI-USN-FS25$ is a local Administrator."

Write-Host ""
Write-Host "=== CAPTURE FRESH USN START POINT ==="

$USNOutput = @(
    fsutil.exe usn queryjournal C: 2>&1
)

$USNExitCode = $LASTEXITCODE

$USNOutput | ForEach-Object {
    Write-Host $_
}

if ($USNExitCode -ne 0) {
    throw "fsutil USN query failed with exit code $USNExitCode."
}

$USNText = $USNOutput -join "`n"

$JournalMatch = [regex]::Match(
    $USNText,
    '(?im)^\s*Usn Journal ID\s*:\s*0x([0-9a-f]+)\s*$'
)

$NextUSNMatch = [regex]::Match(
    $USNText,
    '(?im)^\s*Next Usn\s*:\s*0x([0-9a-f]+)\s*$'
)

if (-not $JournalMatch.Success) {
    throw 'Could not parse USN Journal ID.'
}

if (-not $NextUSNMatch.Success) {
    throw 'Could not parse Next USN.'
}

$JournalID = [Convert]::ToUInt64(
    $JournalMatch.Groups[1].Value,
    16
)

$StartUSN = [Convert]::ToUInt64(
    $NextUSNMatch.Groups[1].Value,
    16
)

Write-Host "[INFO] Journal ID decimal: $JournalID"
Write-Host "[INFO] Start USN decimal:  $StartUSN"

[ordered]@{
    journal_id = $JournalID.ToString()
    start_usn  = $StartUSN.ToString()
} |
    ConvertTo-Json |
    Set-Content `
        -LiteralPath $InputFile `
        -Encoding ASCII

Remove-Item `
    -LiteralPath $ResultFile,$ErrorFile `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host "[PASS] Fresh Server 2025 characterization input created."

Write-Host ""
Write-Host "=== START LOCAL-ADMIN PROBE ==="

sc.exe start $ServiceName

$StartExitCode = $LASTEXITCODE

Write-Host "[INFO] sc.exe start exit code: $StartExitCode"

if ($StartExitCode -ne 0) {
    throw "$ServiceName failed to start."
}

Write-Host ""
Write-Host "=== WAIT FOR ACTUAL PROBE RESULT ==="

$Deadline = (Get-Date).AddSeconds(30)

while (
    -not (Test-Path -LiteralPath $ResultFile) -and
    -not (Test-Path -LiteralPath $ErrorFile) -and
    (Get-Date) -lt $Deadline
) {
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "=== SERVICE STATE ==="

sc.exe query $ServiceName

Write-Host ""
Write-Host "=== RESULT ==="

if (Test-Path -LiteralPath $ResultFile) {
    Get-Content -LiteralPath $ResultFile
}
else {
    Write-Host "[INFO] No result file was created."
}

Write-Host ""
Write-Host "=== PROBE ERROR ==="

if (Test-Path -LiteralPath $ErrorFile) {
    Get-Content -LiteralPath $ErrorFile
}
else {
    Write-Host "[INFO] No probe error file was created."
}

Write-Host ""
Write-Host "=== FINAL ADMINISTRATOR CHECK ==="

net.exe localgroup Administrators

Write-Host ""
Write-Host "[INFO] Leave gFI-USN-FS25$ in Administrators until this result is reviewed."
Write-Host "[INFO] Do not change production FI behavior yet."
