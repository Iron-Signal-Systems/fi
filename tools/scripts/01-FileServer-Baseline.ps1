param(
    [string]$GovernedRoot = ""
)

. "$PSScriptRoot\Common.ps1"

$CollectorService = "FICollector"
$HelperService = "FIUSNReader"
$ConfigPath = "C:\ProgramData\FI\config\fi.conf"
$ConfigDir = Split-Path -Parent $ConfigPath

Write-Host ""
Write-Host "FI USN Verification - Test 01: File Server Baseline"
Write-Host "Run on the FILE SERVER in elevated Windows PowerShell."
Write-Host ""

$Failures = 0

$Collector = Get-FiServiceInfo -Name $CollectorService
$Helper = Get-FiServiceInfo -Name $HelperService

if ($Collector.State -eq "Running") {
    Write-FiPass "$CollectorService is running."
}
else {
    Write-FiFail "$CollectorService is not running."
    $Failures++
}

if ($Helper.State -eq "Running") {
    Write-FiPass "$HelperService is running."
}
else {
    Write-FiFail "$HelperService is not running."
    $Failures++
}

Write-FiInfo "$CollectorService account: $($Collector.StartName)"
Write-FiInfo "$HelperService account: $($Helper.StartName)"

$AdminOutput = (net localgroup Administrators) -join "`n"

if ($AdminOutput -match [Regex]::Escape($Helper.StartName)) {
    Write-FiPass "$HelperService account is a local Administrator."
}
else {
    Write-FiFail "$HelperService account is NOT a local Administrator."
    $Failures++
}

if ($AdminOutput -match [Regex]::Escape($Collector.StartName)) {
    Write-FiFail "$CollectorService account is a local Administrator. It should be restricted."
    $Failures++
}
else {
    Write-FiPass "$CollectorService account is not a local Administrator."
}

$CollectorManaged = (sc.exe qmanagedaccount $CollectorService) -join "`n"
if ($CollectorManaged -match 'ACCOUNT MANAGED\s*:\s*TRUE') {
    Write-FiPass "$CollectorService is configured as a managed account."
}
else {
    Write-FiFail "$CollectorService is not configured as a managed account."
    $Failures++
}

$HelperManaged = (sc.exe qmanagedaccount $HelperService) -join "`n"
if ($HelperManaged -match 'ACCOUNT MANAGED\s*:\s*TRUE') {
    Write-FiPass "$HelperService is configured as a managed account."
}
else {
    Write-FiFail "$HelperService is not configured as a managed account."
    $Failures++
}

$SidType = (sc.exe qsidtype $CollectorService) -join "`n"
if ($SidType -match 'SERVICE_SID_TYPE:\s+UNRESTRICTED') {
    Write-FiPass "$CollectorService service SID type is UNRESTRICTED."
}
else {
    Write-FiFail "$CollectorService service SID type is not UNRESTRICTED."
    $Failures++
}

if (Test-Path "\\.\pipe\FI-USN") {
    Write-FiPass "Local FI-USN named pipe exists."
}
else {
    Write-FiFail "Local FI-USN named pipe does not exist."
    $Failures++
}

if (-not $GovernedRoot) {
    $Roots = @(Get-FiConfiguredRoots -ConfigPath $ConfigPath)

    if ($Roots.Count -ne 1) {
        Write-FiFail "More than one governed root is configured. Re-run with -GovernedRoot <path>."
        $Failures++
    }
    else {
        $GovernedRoot = $Roots[0]
    }
}

if ($GovernedRoot) {
    Write-FiInfo "Governed root under test: $GovernedRoot"

    try {
        $CheckpointPath = Get-FiCheckpointPath -GovernedRoot $GovernedRoot
        $Checkpoint = Get-FiCheckpoint -CheckpointPath $CheckpointPath

        Write-FiPass "Found USN checkpoint: $CheckpointPath"
        Write-FiInfo "Journal ID: $($Checkpoint.journal_id)"
        Write-FiInfo "Next USN: $($Checkpoint.next_usn)"
        Write-FiInfo "Updated at: $($Checkpoint.updated_at)"
    }
    catch {
        Write-FiFail $_.Exception.Message
        $Failures++
    }
}

Write-Host ""
Write-Host "Config ACL:"

$ConfigDirAudit = Get-FiIcaclsAudit -Path $ConfigDir
$ConfigFileAudit = Get-FiIcaclsAudit -Path $ConfigPath

$ConfigDirAudit.Output | ForEach-Object { Write-Host $_ }
$ConfigFileAudit.Output | ForEach-Object { Write-Host $_ }

if ($ConfigDirAudit.HasProblems -or $ConfigFileAudit.HasProblems) {
    Write-FiFail "FI config ACL inspection did not complete cleanly."
    $Failures++
}
else {
    Write-FiPass "FI config ACL inspection completed without access or traversal failures."
}

$ConfigAclText = @(
    $ConfigDirAudit.Output
    $ConfigFileAudit.Output
) -join "`n"

if ($ConfigAclText -match 'BUILTIN\\Users') {
    Write-FiFail "BUILTIN\Users is present in FI config ACLs."
    $Failures++
}
else {
    Write-FiPass "FI config ACLs do not grant BUILTIN\Users access."
}

Write-Host ""
if ($Failures -eq 0) {
    Write-FiPass "TEST 01 PASSED."
    exit 0
}

Write-FiFail "TEST 01 FAILED with $Failures problem(s)."
exit 1
