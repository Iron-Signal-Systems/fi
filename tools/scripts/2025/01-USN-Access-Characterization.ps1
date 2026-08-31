# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

$ErrorActionPreference = 'Stop'

$ExpectedHost  = 'ISS-FS-25'
$ExpectedBuild = '26100'
$HelperAccount = 'ISS\gFI-USN-FS25$'
$ServiceName   = 'FIUSNProbe2025'

$ProbeExe   = 'C:\FI-Test\usnprobe\FI-USN-Probe-2025.exe'
$WorkDir    = 'C:\FI-Test\usnprobe'
$InputFile  = "$WorkDir\input-2025.json"
$ResultFile = "$WorkDir\usn-access-matrix-2025.json"
$ErrorFile  = "$WorkDir\usn-access-matrix-2025-error.txt"

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI USN ACCESS CHARACTERIZATION - WINDOWS SERVER 2025'
Write-Host "Host: $ExpectedHost"
Write-Host "gMSA: $HelperAccount"
Write-Host 'Phase: NON-ADMIN BASELINE'
Write-Host '============================================================'
Write-Host ''

Write-Host '=== VERIFY HOST / RELEASE ==='

$HostName = hostname
$OS = Get-CimInstance Win32_OperatingSystem

Write-Host "[INFO] Host: $HostName"
Write-Host "[INFO] Caption: $($OS.Caption)"
Write-Host "[INFO] Version: $($OS.Version)"
Write-Host "[INFO] Build: $($OS.BuildNumber)"

if ($HostName -ine $ExpectedHost) {
    throw "Expected $ExpectedHost. No changes made."
}

if ($OS.BuildNumber -ne $ExpectedBuild) {
    throw "Expected Windows Server 2025 build $ExpectedBuild. Observed $($OS.BuildNumber). No changes made."
}

Write-Host '[PASS] Host and Server 2025 build match the characterization target.'

Write-Host ''
Write-Host '=== VERIFY ZERO-ELEVATION BASELINE ==='

$Administrators = (net.exe localgroup Administrators) -join "`n"

if ($Administrators -match [regex]::Escape('gFI-USN-FS25$')) {
    throw 'gFI-USN-FS25$ is already a local Administrator. Non-admin characterization would be invalid.'
}

Write-Host '[PASS] gFI-USN-FS25$ is not a local Administrator.'

Write-Host ''
Write-Host '=== VERIFY PROBE EXECUTABLE ==='

if (-not (Test-Path -LiteralPath $ProbeExe -PathType Leaf)) {
    throw "Probe executable is missing: $ProbeExe"
}

Write-Host "[PASS] Probe executable exists: $ProbeExe"

Write-Host ''
Write-Host '=== PREPARE CHARACTERIZATION WORKSPACE ==='

New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null

icacls.exe 'C:\FI-Test' /grant "$HelperAccount`:(RX)"
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
    throw 'Could not establish characterization workspace ACL.'
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
    throw 'Could not establish probe executable ACL.'
}

Write-Host '[PASS] Characterization workspace prepared.'

Write-Host ''
Write-Host '=== CAPTURE CURRENT USN JOURNAL STATE ==='

$USNOutput = @(fsutil.exe usn queryjournal C: 2>&1)
$USNExitCode = $LASTEXITCODE
$USNOutput | ForEach-Object { Write-Host $_ }

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

$JournalID = [Convert]::ToUInt64($JournalMatch.Groups[1].Value, 16)
$StartUSN = [Convert]::ToUInt64($NextUSNMatch.Groups[1].Value, 16)

Write-Host "[INFO] Journal ID decimal: $JournalID"
Write-Host "[INFO] Start USN decimal: $StartUSN"

[ordered]@{
    journal_id = $JournalID.ToString()
    start_usn  = $StartUSN.ToString()
} |
    ConvertTo-Json |
    Set-Content -LiteralPath $InputFile -Encoding ASCII

Remove-Item `
    -LiteralPath $ResultFile,$ErrorFile `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host '[PASS] Windows Server 2025 characterization input created.'

Write-Host ''
Write-Host '=== CREATE CHARACTERIZATION SERVICE ==='

$ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $ExistingService) {
    throw "$ServiceName already exists. Remove or inspect it before rerunning."
}

$ServiceClass = Get-WmiObject -Class Win32_Service -List
$CreateResult = $ServiceClass.Create(
    $ServiceName,
    'FI USN Access Probe - Windows Server 2025',
    "`"$ProbeExe`"",
    16,
    1,
    'Manual',
    $false,
    $HelperAccount,
    $null,
    $null,
    $null,
    $null
)

if ($CreateResult.ReturnValue -ne 0) {
    throw "$ServiceName service creation failed. Win32_Service.Create returned $($CreateResult.ReturnValue)."
}

sc.exe managedaccount $ServiceName true
if ($LASTEXITCODE -ne 0) {
    throw "Could not mark $ServiceName as using a managed account."
}

Write-Host "[PASS] $ServiceName created using $HelperAccount."

Write-Host ''
sc.exe qc $ServiceName
sc.exe qmanagedaccount $ServiceName

Write-Host ''
Write-Host '=== NON-ADMIN USN CHARACTERIZATION ==='

sc.exe start $ServiceName
$StartExitCode = $LASTEXITCODE
Write-Host "[INFO] sc.exe start exit code: $StartExitCode"

Start-Sleep -Seconds 3

Write-Host ''
Write-Host '=== SERVICE STATE ==='
sc.exe query $ServiceName

Write-Host ''
Write-Host '=== RESULT ==='
if (Test-Path -LiteralPath $ResultFile) {
    Get-Content -LiteralPath $ResultFile
}
else {
    Write-Host '[INFO] No result file was created.'
}

Write-Host ''
Write-Host '=== PROBE ERROR ==='
if (Test-Path -LiteralPath $ErrorFile) {
    Get-Content -LiteralPath $ErrorFile
}
else {
    Write-Host '[INFO] No probe error file was created.'
}

Write-Host ''
Write-Host '=== FINAL ADMINISTRATOR CHECK ==='
net.exe localgroup Administrators

Write-Host ''
Write-Host "[INFO] $ServiceName is intentionally left in place after characterization."
Write-Host '[INFO] Do not grant SeManageVolumePrivilege or local Administrator yet.'
Write-Host '[INFO] Paste this output for review before changing the token boundary.'
