# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

$ErrorActionPreference = 'Stop'

$ExpectedHost  = 'ISS-FS-25'
$HelperAccount = 'ISS\gFI-USN-FS25$'
$ServiceName   = 'FIContainmentProbe2025'

$ProbeExe       = 'C:\FI-Test\containment\FI-Containment-Probe-2025.exe'
$WorkDir        = 'C:\FI-Test\containment'
$GovernedRoot   = 'C:\FI-Test\governed-2025'
$InputFile      = "$WorkDir\input-2025.json"
$ResultFile     = "$WorkDir\containment-2025.json"
$ErrorFile      = "$WorkDir\containment-2025-error.txt"
$ProtectedRoot  = 'C:\Windows\System32\LogFiles\WMI\RtBackup'

Write-Host ""
Write-Host "============================================================"
Write-Host "FI PROTECTED CONTAINMENT CHARACTERIZATION - SERVER 2025"
Write-Host "Host: $ExpectedHost"
Write-Host "gMSA: $HelperAccount"
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
    throw "Expected Server 2025 build 26100. Observed build $($OS.BuildNumber)."
}

Write-Host "[PASS] Server 2025 build 26100 confirmed."

Write-Host ""
Write-Host "=== VERIFY HELPER IS LOCAL ADMINISTRATOR ==="

$Administrators = @(net.exe localgroup Administrators)

$Administrators | ForEach-Object {
    Write-Host $_
}

if (($Administrators -join "`n") -notmatch [regex]::Escape('gFI-USN-FS25$')) {
    throw 'gFI-USN-FS25$ must still be a local Administrator for this characterization.'
}

Write-Host "[PASS] gFI-USN-FS25$ is a local Administrator."

Write-Host ""
Write-Host "=== VERIFY PROBE EXECUTABLE ==="

if (-not (Test-Path -LiteralPath $ProbeExe -PathType Leaf)) {
    throw "Probe executable is missing: $ProbeExe"
}

Write-Host "[PASS] Probe executable exists."

Write-Host ""
Write-Host "=== PREPARE CHARACTERIZATION WORKSPACE ==="

New-Item `
    -Path $WorkDir,$GovernedRoot `
    -ItemType Directory `
    -Force |
    Out-Null

icacls.exe 'C:\FI-Test' `
    /grant "$HelperAccount`:(RX)"

if ($LASTEXITCODE -ne 0) {
    throw 'Could not grant C:\FI-Test traversal access.'
}

icacls.exe $WorkDir /inheritance:r

if ($LASTEXITCODE -ne 0) {
    throw "Could not disable inherited ACLs on $WorkDir."
}

icacls.exe $WorkDir `
    /grant:r `
    'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' `
    'BUILTIN\Administrators:(OI)(CI)(F)' `
    "$HelperAccount`:(OI)(CI)(M)"

if ($LASTEXITCODE -ne 0) {
    throw 'Could not establish containment workspace ACL.'
}

icacls.exe $GovernedRoot /inheritance:r

if ($LASTEXITCODE -ne 0) {
    throw "Could not disable inherited ACLs on $GovernedRoot."
}

icacls.exe $GovernedRoot `
    /grant:r `
    'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' `
    'BUILTIN\Administrators:(OI)(CI)(F)' `
    "$HelperAccount`:(OI)(CI)(RX)"

if ($LASTEXITCODE -ne 0) {
    throw 'Could not establish governed-root ACL.'
}

icacls.exe $ProbeExe /inheritance:r

if ($LASTEXITCODE -ne 0) {
    throw "Could not disable inherited ACLs on $ProbeExe."
}

icacls.exe $ProbeExe `
    /grant:r `
    'NT AUTHORITY\SYSTEM:(F)' `
    'BUILTIN\Administrators:(F)' `
    "$HelperAccount`:(RX)"

if ($LASTEXITCODE -ne 0) {
    throw 'Could not establish containment probe executable ACL.'
}

Write-Host "[PASS] Characterization workspace prepared."

Write-Host ""
Write-Host "=== SELECT PROTECTED SYSTEM TARGET ==="

if (-not (Test-Path -LiteralPath $ProtectedRoot -PathType Container)) {
    throw "Protected target directory is missing: $ProtectedRoot"
}

$Target = Get-ChildItem `
    -LiteralPath $ProtectedRoot `
    -File `
    -Force |
    Sort-Object Name |
    Select-Object -First 1

if ($null -eq $Target) {
    throw "No protected target file was found under $ProtectedRoot."
}

Write-Host "[INFO] Protected root: $ProtectedRoot"
Write-Host "[INFO] Target: $($Target.FullName)"

Write-Host ""
Write-Host "=== TARGET ACL READ (INFORMATIONAL) ==="

$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'

$ACLReadOutput = @(
    & icacls.exe $Target.FullName 2>&1
)
$ACLReadExitCode = $LASTEXITCODE

$ErrorActionPreference = $PreviousErrorActionPreference

$ACLReadOutput | ForEach-Object {
    Write-Host $_
}

if ($ACLReadExitCode -eq 0) {
    Write-Host "[INFO] Target ACL was readable."
}
else {
    Write-Host "[INFO] Target ACL read was denied or unavailable."
    Write-Host "[INFO] icacls exit code: $ACLReadExitCode"
    Write-Host "[INFO] This is not fatal; the protected-target OpenFileById behavior is the subject of this characterization."
}

Write-Host ""
Write-Host "=== QUERY NTFS FILE ID ==="

$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'

$FileIDOutput = @(
    & fsutil.exe file queryfileid $Target.FullName 2>&1
)
$FileIDExitCode = $LASTEXITCODE

$ErrorActionPreference = $PreviousErrorActionPreference

$FileIDOutput | ForEach-Object {
    Write-Host $_
}

if ($FileIDExitCode -ne 0) {
    throw "fsutil file queryfileid failed with exit code $FileIDExitCode."
}

$FileIDText = $FileIDOutput -join "`n"

$FileIDMatch = [regex]::Match(
    $FileIDText,
    '(?i)0x([0-9a-f]{32})'
)

if (-not $FileIDMatch.Success) {
    throw 'Could not parse the 128-bit fsutil file ID.'
}

$FileIDHex = $FileIDMatch.Groups[1].Value.ToLowerInvariant()
$High64Hex = $FileIDHex.Substring(0,16)
$Low64Hex  = $FileIDHex.Substring(16,16)

if ($High64Hex -ne '0000000000000000') {
    throw "Expected an NTFS 64-bit file ID represented in the low 64 bits. Observed 0x$FileIDHex."
}

$FileID64 = [Convert]::ToUInt64(
    $Low64Hex,
    16
)

$FileReferenceNumber = $FileID64 -band [UInt64]0x0000FFFFFFFFFFFF
$SequenceNumber      = ($FileID64 -shr 48) -band [UInt64]0xFFFF

Write-Host "[INFO] File ID 128: 0x$FileIDHex"
Write-Host "[INFO] File ID 64:  0x$Low64Hex"
Write-Host "[INFO] FRN:         $FileReferenceNumber"
Write-Host "[INFO] Sequence:    $SequenceNumber"

Write-Host ""
Write-Host "=== VALIDATE FILE ID LOOKUP (INFORMATIONAL) ==="

$PreviousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'

$FileNameByIDOutput = @(
    & fsutil.exe file queryfilenamebyid C: "0x$FileIDHex" 2>&1
)
$FileNameByIDExitCode = $LASTEXITCODE

$ErrorActionPreference = $PreviousErrorActionPreference

$FileNameByIDOutput | ForEach-Object {
    Write-Host $_
}

if ($FileNameByIDExitCode -eq 0) {
    Write-Host "[INFO] fsutil queryfilenamebyid resolved the selected file ID."
}
else {
    Write-Host "[INFO] fsutil queryfilenamebyid could not resolve the protected target from this administrative shell."
    Write-Host "[INFO] Exit code: $FileNameByIDExitCode"
    Write-Host "[INFO] Continuing because the service-token OpenFileById call is the characterization target."
}

Write-Host ""
Write-Host "=== CREATE PROBE INPUT ==="

[ordered]@{
    governed_root         = $GovernedRoot
    file_reference_number = $FileReferenceNumber.ToString()
    sequence_number       = $SequenceNumber.ToString()
    target_description    = $Target.FullName
} |
    ConvertTo-Json |
    Set-Content `
        -LiteralPath $InputFile `
        -Encoding ASCII

Remove-Item `
    -LiteralPath $ResultFile,$ErrorFile `
    -Force `
    -ErrorAction SilentlyContinue

Get-Content -LiteralPath $InputFile

Write-Host "[PASS] Containment characterization input created."

Write-Host ""
Write-Host "=== CREATE CHARACTERIZATION SERVICE ==="

$ExistingService = Get-Service `
    -Name $ServiceName `
    -ErrorAction SilentlyContinue

if ($null -ne $ExistingService) {
    throw "$ServiceName already exists. Inspect/remove it before rerunning."
}

sc.exe create $ServiceName `
    binPath= $ProbeExe `
    start= demand `
    obj= $HelperAccount `
    DisplayName= 'FI Protected Containment Probe - Windows Server 2025'

if ($LASTEXITCODE -ne 0) {
    throw "$ServiceName service creation failed."
}

sc.exe managedaccount $ServiceName true

if ($LASTEXITCODE -ne 0) {
    throw "Could not mark $ServiceName as using a managed account."
}

Write-Host "[PASS] $ServiceName created."

Write-Host ""
sc.exe qc $ServiceName
sc.exe qmanagedaccount $ServiceName

Write-Host ""
Write-Host "=== RUN PROTECTED CONTAINMENT CHARACTERIZATION ==="

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
    Write-Host '[INFO] No result file was created.'
}

Write-Host ""
Write-Host "=== PROBE ERROR ==="

if (Test-Path -LiteralPath $ErrorFile) {
    Get-Content -LiteralPath $ErrorFile
}
else {
    Write-Host '[INFO] No probe error file was created.'
}

Write-Host ""
Write-Host "[INFO] FIContainmentProbe2025 is intentionally left in place."
Write-Host "[INFO] gFI-USN-FS25$ remains a local Administrator."
Write-Host "[INFO] The probe only enables SeBackupPrivilege inside its own process and restores the prior token state before returning."
Write-Host "[INFO] Do not change production FI containment behavior until this result is reviewed."
