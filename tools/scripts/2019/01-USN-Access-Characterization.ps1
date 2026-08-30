$ExpectedHost  = "ISS-FS-19"
$HelperAccount = "ISS\gFI-USN-FS19$"
$ServiceName   = "FIUSNProbe2019"

$ProbeExe   = "C:\FI-Test\fi-usn-probe-2019.exe"
$WorkDir    = "C:\FI-Test\usnprobe"
$InputFile  = "$WorkDir\input-2019.json"
$ResultFile = "$WorkDir\usn-access-matrix-2019.json"
$ErrorFile  = "$WorkDir\usn-access-matrix-2019-error.txt"

Write-Host ""
Write-Host "============================================================"
Write-Host "FI USN ACCESS CHARACTERIZATION - WINDOWS SERVER 2019"
Write-Host "Host: $ExpectedHost"
Write-Host "gMSA: $HelperAccount"
Write-Host "============================================================"
Write-Host ""

Write-Host "=== VERIFY HOST ==="

$HostName = hostname
Write-Host "[INFO] Host: $HostName"

if ($HostName -ine $ExpectedHost) {
    throw "Expected $ExpectedHost. No changes made."
}

Write-Host "[PASS] Running on $ExpectedHost."

Write-Host ""
Write-Host "=== VERIFY ZERO-ELEVATION BASELINE ==="

$Administrators = (net.exe localgroup Administrators) -join "`n"

if ($Administrators -match [regex]::Escape("gFI-USN-FS19$")) {
    throw "gFI-USN-FS19$ is already a local Administrator. Zero-elevation characterization would be invalid."
}

Write-Host "[PASS] gFI-USN-FS19$ is not a local Administrator."

Write-Host ""
Write-Host "=== VERIFY PROBE EXECUTABLE ==="

if (-not (Test-Path -LiteralPath $ProbeExe -PathType Leaf)) {
    throw "Probe executable is missing: $ProbeExe"
}

Write-Host "[PASS] Probe executable exists: $ProbeExe"

Write-Host ""
Write-Host "=== PREPARE CHARACTERIZATION WORKSPACE ==="

New-Item `
    -Path $WorkDir `
    -ItemType Directory `
    -Force |
    Out-Null

icacls.exe "C:\FI-Test" `
    /grant "$HelperAccount`:(RX)"

if ($LASTEXITCODE -ne 0) {
    throw "Could not grant C:\FI-Test traversal access."
}

icacls.exe $WorkDir /inheritance:r

if ($LASTEXITCODE -ne 0) {
    throw "Could not disable inherited ACLs on $WorkDir."
}

icacls.exe $WorkDir `
    /grant:r `
    "NT AUTHORITY\SYSTEM:(OI)(CI)(F)" `
    "BUILTIN\Administrators:(OI)(CI)(F)" `
    "$HelperAccount`:(OI)(CI)(M)"

if ($LASTEXITCODE -ne 0) {
    throw "Could not establish characterization workspace ACL."
}

icacls.exe $ProbeExe /inheritance:r

if ($LASTEXITCODE -ne 0) {
    throw "Could not disable inherited ACLs on $ProbeExe."
}

icacls.exe $ProbeExe `
    /grant:r `
    "NT AUTHORITY\SYSTEM:(F)" `
    "BUILTIN\Administrators:(F)" `
    "$HelperAccount`:(RX)"

if ($LASTEXITCODE -ne 0) {
    throw "Could not establish probe executable ACL."
}

Write-Host "[PASS] Characterization workspace prepared."

Write-Host ""
Write-Host "=== CAPTURE CURRENT USN JOURNAL STATE ==="

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
    throw "Could not parse USN Journal ID."
}

if (-not $NextUSNMatch.Success) {
    throw "Could not parse Next USN."
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
Write-Host "[INFO] Start USN decimal: $StartUSN"

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

Write-Host "[PASS] Windows Server 2019 characterization input created."

Write-Host ""
Write-Host "=== CREATE CHARACTERIZATION SERVICE ==="

$ExistingService = Get-Service `
    -Name $ServiceName `
    -ErrorAction SilentlyContinue

if ($null -ne $ExistingService) {
    throw "$ServiceName already exists. Remove or inspect it before rerunning."
}

sc.exe create $ServiceName `
    binPath= $ProbeExe `
    start= demand `
    obj= $HelperAccount `
    DisplayName= "FI USN Access Probe - Windows Server 2019"

if ($LASTEXITCODE -ne 0) {
    throw "$ServiceName service creation failed."
}

sc.exe managedaccount $ServiceName true

if ($LASTEXITCODE -ne 0) {
    throw "Could not mark $ServiceName as using a managed account."
}

Write-Host "[PASS] $ServiceName created using $HelperAccount."

Write-Host ""
sc.exe qc $ServiceName
sc.exe qmanagedaccount $ServiceName

Write-Host ""
Write-Host "=== ZERO-ELEVATION USN CHARACTERIZATION ==="

sc.exe start $ServiceName
$StartExitCode = $LASTEXITCODE

Write-Host "[INFO] sc.exe start exit code: $StartExitCode"

Start-Sleep -Seconds 3

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
Write-Host "[INFO] $ServiceName is intentionally left in place after characterization."
Write-Host "[INFO] Do not grant additional privileges or delete it until the result is reviewed."
