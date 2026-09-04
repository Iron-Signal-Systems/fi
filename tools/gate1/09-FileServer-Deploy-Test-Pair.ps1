# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# Reproducible Gate 1 test deployment for the currently accepted Windows Server
# builds. This is intentionally a test/acceptance installer, not a declaration of
# final production collection cadence or a general-purpose enterprise installer.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CollectorCandidate,

    [Parameter(Mandatory = $true)]
    [string]$CollectorSHA256,

    [Parameter(Mandatory = $true)]
    [string]$HelperCandidate,

    [Parameter(Mandatory = $true)]
    [string]$HelperSHA256,

    [Parameter(Mandatory = $true)]
    [string]$CollectorAccount,

    [Parameter(Mandatory = $true)]
    [string]$HelperAccount,

    [Parameter(Mandatory = $true)]
    [string]$GovernedRoot,

    [switch]$ReplaceExistingFilesAndConfig,
    [switch]$ReconfigureExistingServices,
    [switch]$GrantTestRootReadAccess,
    [switch]$ConfirmDeploy
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator

if (-not $ConfirmDeploy) {
    throw 'This script installs/changes FI binaries, ACLs, services, local group membership, and configuration. Re-run with -ConfirmDeploy.'
}

$SupportedBuilds = @{
    '14393' = 'Windows Server 2016'
    '17763' = 'Windows Server 2019'
    '20348' = 'Windows Server 2022'
    '26100' = 'Windows Server 2025'
}

$OS = Get-CimInstance Win32_OperatingSystem
$Build = [string]$OS.BuildNumber
if (-not $SupportedBuilds.ContainsKey($Build)) {
    throw "Windows build $Build is not in the current Gate 1 accepted build set. Characterize it before deployment acceptance."
}

if (-not (Test-Path -LiteralPath $GovernedRoot -PathType Container)) {
    throw "Governed root does not exist: $GovernedRoot. This installer does not create customer governed data roots."
}

$GovernedRoot = (Get-Item -LiteralPath $GovernedRoot -Force).FullName.TrimEnd('\')
if ($GovernedRoot -notmatch '^[A-Za-z]:\\') {
    throw "Governed root must be an absolute local drive path: $GovernedRoot"
}

foreach ($Candidate in @($CollectorCandidate, $HelperCandidate)) {
    if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
        throw "Candidate binary not found: $Candidate"
    }
}

$CollectorSHA256 = $CollectorSHA256.Trim().ToUpperInvariant()
$HelperSHA256 = $HelperSHA256.Trim().ToUpperInvariant()
if ($CollectorSHA256 -notmatch '^[0-9A-F]{64}$') { throw 'CollectorSHA256 must be 64 hexadecimal characters.' }
if ($HelperSHA256 -notmatch '^[0-9A-F]{64}$') { throw 'HelperSHA256 must be 64 hexadecimal characters.' }

$ObservedCollectorSHA256 = (Get-FileHash -LiteralPath $CollectorCandidate -Algorithm SHA256).Hash.ToUpperInvariant()
$ObservedHelperSHA256 = (Get-FileHash -LiteralPath $HelperCandidate -Algorithm SHA256).Hash.ToUpperInvariant()
if ($ObservedCollectorSHA256 -ne $CollectorSHA256) {
    throw "Collector candidate hash mismatch. Expected $CollectorSHA256; observed $ObservedCollectorSHA256."
}
if ($ObservedHelperSHA256 -ne $HelperSHA256) {
    throw "Helper candidate hash mismatch. Expected $HelperSHA256; observed $ObservedHelperSHA256."
}

if ($CollectorAccount -ieq $HelperAccount) {
    throw 'FICollector and FIUSNReader must use separate identities.'
}
foreach ($Account in @($CollectorAccount,$HelperAccount)) {
    if ($Account -notmatch '^[^\\]+\\[^\\]+\$$') {
        throw "FI service account must be a domain-qualified gMSA ending in `$; observed: $Account"
    }
}

$AdminText = (@(& net.exe localgroup Administrators 2>&1) -join "`n")
if ($AdminText -match ('(?im)^\s*' + [regex]::Escape($CollectorAccount) + '\s*$')) {
    throw "Collector account is a local Administrator: $CollectorAccount"
}
if ($AdminText -notmatch ('(?im)^\s*' + [regex]::Escape($HelperAccount) + '\s*$')) {
    throw "Helper account is not a local Administrator: $HelperAccount. Establish the intended helper trust boundary before deployment."
}

$ProgramDir = 'C:\Program Files\FI'
$ProgramDataDir = 'C:\ProgramData\FI'
$ConfigDir = 'C:\ProgramData\FI\config'
$ConfigFile = 'C:\ProgramData\FI\config\fi.conf'
$StateDir = 'C:\ProgramData\FI\state'
$SpoolDir = 'C:\ProgramData\FI\spool'
$StagingDir = 'C:\ProgramData\FI\deployment-staging'
$CollectorInstalled = Join-Path $ProgramDir 'fi.exe'
$HelperInstalled = Join-Path $ProgramDir 'fi-usn.exe'
$CollectorStaged = Join-Path $StagingDir 'fi.exe'
$HelperStaged = Join-Path $StagingDir 'fi-usn.exe'
$CollectorService = 'FICollector'
$HelperService = 'FIUSNReader'
$CollectorPathName = '"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m'
$HelperPathName = '"C:\Program Files\FI\fi-usn.exe"'

function Invoke-FiIcaclsChange {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $Output = @(& icacls.exe @Arguments 2>&1 | ForEach-Object { $_.ToString() })
    $ExitCode = $LASTEXITCODE
    $Problems = @($Output | Select-String -Pattern 'Access is denied','Failed processing\s+[1-9][0-9]*\s+files?')
    if ($ExitCode -ne 0 -or $Problems.Count -gt 0) {
        $Output | Select-Object -Last 20 | ForEach-Object { Write-Host $_ }
        throw "$Description failed. icacls exit code: $ExitCode"
    }
    Write-FiPass $Description
}

function Get-FiInstalledHash {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Wait-FiServiceState {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$State,
        [int]$TimeoutSeconds = 60
    )
    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $Current = (Get-Service -Name $Name -ErrorAction Stop).Status.ToString()
        if ($Current -eq $State) { return }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $Deadline)
    throw "$Name did not reach $State within $TimeoutSeconds seconds."
}

function New-Or-Verify-FiService {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [Parameter(Mandatory = $true)][string]$BootstrapPath,
        [Parameter(Mandatory = $true)][string]$ProductionPathName,
        [Parameter(Mandatory = $true)][string]$StartName
    )

    $Existing = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        Write-FiInfo "Creating $Name using no-space deployment staging path."
        $Output = @(& sc.exe create $Name binPath= $BootstrapPath start= auto obj= $StartName DisplayName= $DisplayName 2>&1)
        if ($LASTEXITCODE -ne 0) {
            $Output | ForEach-Object { Write-Host $_ }
            throw "sc.exe create failed for $Name."
        }
        & sc.exe managedaccount $Name true | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Could not mark $Name as a managed-account service." }
        $Existing = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        $Change = Invoke-CimMethod -InputObject $Existing -MethodName Change -Arguments @{ PathName = $ProductionPathName }
        if ($Change.ReturnValue -ne 0) { throw "$Name PathName change failed. ReturnValue=$($Change.ReturnValue)" }
        $Existing = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    } else {
        if ($Existing.StartName -ine $StartName) {
            throw "$Name already exists under $($Existing.StartName). This Gate 1 installer will not change an existing service identity."
        }
        if ($Existing.PathName -ne $ProductionPathName) {
            if (-not $ReconfigureExistingServices) {
                throw "$Name already exists with a different command line. Re-run with -ReconfigureExistingServices only after reviewing the existing and requested PathName values."
            }
            Write-FiInfo "Reconfiguring existing $Name command line after explicit -ReconfigureExistingServices approval."
            $Change = Invoke-CimMethod -InputObject $Existing -MethodName Change -Arguments @{ PathName = $ProductionPathName }
            if ($Change.ReturnValue -ne 0) { throw "$Name PathName change failed. ReturnValue=$($Change.ReturnValue)" }
            $Existing = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        }
    }

    if ($Existing.PathName -ne $ProductionPathName) {
        throw "$Name PathName mismatch. Expected: $ProductionPathName Observed: $($Existing.PathName)"
    }
    if ($Existing.StartName -ine $StartName) {
        throw "$Name StartName mismatch. Expected: $StartName Observed: $($Existing.StartName)"
    }

    & sc.exe config $Name start= auto | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not configure $Name for automatic start." }
    & sc.exe managedaccount $Name true | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not mark $Name as a managed-account service." }

    $Managed = (@(& sc.exe qmanagedaccount $Name 2>&1) -join "`n")
    if ($Managed -notmatch 'ACCOUNT MANAGED\s*:\s*TRUE') {
        throw "$Name is not configured as a managed-account service."
    }
    Write-FiPass "$Name service configuration matches the requested test deployment."
}

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - REPRODUCIBLE TEST DEPLOYMENT'
Write-Host "Host:                 $env:COMPUTERNAME"
Write-Host "Windows:              $($SupportedBuilds[$Build]) build $Build"
Write-Host "Governed root:         $GovernedRoot"
Write-Host "Collector account:     $CollectorAccount"
Write-Host "Helper account:        $HelperAccount"
Write-Host 'Collection interval:   1m (fixed Gate 1 acceptance setting)'
Write-Host 'Supporting interval:   30m (fixed Gate 1 acceptance setting)'
Write-Host '============================================================'

# Fail-fast preflight: detect every expected replacement/reconfiguration reason
# before stopping services or changing files/ACLs.
$ExistingCollectorConfig = Get-CimInstance Win32_Service -Filter "Name='$CollectorService'" -ErrorAction SilentlyContinue
$ExistingHelperConfig = Get-CimInstance Win32_Service -Filter "Name='$HelperService'" -ErrorAction SilentlyContinue
foreach ($ExistingPair in @(
    @($ExistingCollectorConfig,$CollectorPathName,$CollectorAccount,$CollectorService),
    @($ExistingHelperConfig,$HelperPathName,$HelperAccount,$HelperService)
)) {
    $ExistingConfig = $ExistingPair[0]
    if ($null -eq $ExistingConfig) { continue }
    $ExpectedPath = [string]$ExistingPair[1]
    $ExpectedAccount = [string]$ExistingPair[2]
    $ExistingName = [string]$ExistingPair[3]

    if ($ExistingConfig.StartName -ine $ExpectedAccount) {
        throw "$ExistingName already exists under $($ExistingConfig.StartName). Refusing to change an existing service identity."
    }
    if ($ExistingConfig.PathName -ne $ExpectedPath -and -not $ReconfigureExistingServices) {
        throw "$ExistingName command line differs from the Gate 1 acceptance command line. Existing: $($ExistingConfig.PathName) Requested: $ExpectedPath. No changes were made. Re-run with -ReconfigureExistingServices only after reviewing this difference."
    }
}

foreach ($PreflightPair in @(
    @($CollectorInstalled,$CollectorSHA256),
    @($HelperInstalled,$HelperSHA256)
)) {
    $Destination = [string]$PreflightPair[0]
    $Expected = [string]$PreflightPair[1]
    $ExistingHash = Get-FiInstalledHash -Path $Destination
    if ($ExistingHash -and $ExistingHash -ne $Expected -and -not $ReplaceExistingFilesAndConfig) {
        throw "Existing binary differs from reviewed candidate: $Destination SHA256=$ExistingHash. No changes were made. Re-run with -ReplaceExistingFilesAndConfig only after reviewing the replacement."
    }
}

$ExpectedConfig = @('version_id: 1.0',"governed_root: $GovernedRoot")
if (Test-Path -LiteralPath $ConfigFile -PathType Leaf) {
    $ObservedConfig = @(Get-Content -LiteralPath $ConfigFile)
    if (($ObservedConfig -join "`n") -ne ($ExpectedConfig -join "`n") -and -not $ReplaceExistingFilesAndConfig) {
        throw 'Existing FI config differs from requested Gate 1 test configuration. No changes were made. Re-run with -ReplaceExistingFilesAndConfig only after reviewing the replacement.'
    }
}

$ExistingCollectorService = Get-Service -Name $CollectorService -ErrorAction SilentlyContinue
$ExistingHelperService = Get-Service -Name $HelperService -ErrorAction SilentlyContinue
if ($null -ne $ExistingCollectorService -and $ExistingCollectorService.Status -eq 'Running') {
    Stop-Service -Name $CollectorService -ErrorAction Stop
    Wait-FiServiceState -Name $CollectorService -State 'Stopped'
}
if ($null -ne $ExistingHelperService -and $ExistingHelperService.Status -eq 'Running') {
    Stop-Service -Name $HelperService -ErrorAction Stop
    Wait-FiServiceState -Name $HelperService -State 'Stopped'
}

New-Item -Path $ProgramDir,$ProgramDataDir,$ConfigDir,$StateDir,$SpoolDir,$StagingDir -ItemType Directory -Force | Out-Null
Invoke-FiIcaclsChange -Arguments @($StagingDir,'/inheritance:r') -Description 'Removed inherited ACLs from FI deployment staging directory.'
Invoke-FiIcaclsChange -Arguments @(
    $StagingDir,'/grant:r',
    'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
    'BUILTIN\Administrators:(OI)(CI)(F)'
) -Description 'Restricted FI deployment staging to SYSTEM and Administrators.'

Get-ChildItem -LiteralPath $StagingDir -Force -ErrorAction Stop | Remove-Item -Recurse -Force -ErrorAction Stop
Copy-Item -LiteralPath $CollectorCandidate -Destination $CollectorStaged -Force
Copy-Item -LiteralPath $HelperCandidate -Destination $HelperStaged -Force
if ((Get-FiInstalledHash -Path $CollectorStaged) -ne $CollectorSHA256) { throw 'Staged collector hash mismatch.' }
if ((Get-FiInstalledHash -Path $HelperStaged) -ne $HelperSHA256) { throw 'Staged helper hash mismatch.' }

Invoke-FiIcaclsChange -Arguments @($ProgramDir,'/inheritance:r') -Description 'Removed inherited ACLs from FI program directory.'
Invoke-FiIcaclsChange -Arguments @(
    $ProgramDir,'/grant:r',
    'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
    'BUILTIN\Administrators:(OI)(CI)(F)',
    "${CollectorAccount}:(OI)(CI)(RX)",
    "${HelperAccount}:(OI)(CI)(RX)"
) -Description 'Applied FI program-directory ACL boundary.'

foreach ($Pair in @(@($CollectorInstalled,$CollectorStaged,$CollectorSHA256),@($HelperInstalled,$HelperStaged,$HelperSHA256))) {
    $Destination = [string]$Pair[0]
    $Source = [string]$Pair[1]
    $Expected = [string]$Pair[2]
    $ExistingHash = Get-FiInstalledHash -Path $Destination
    if ($ExistingHash -and $ExistingHash -ne $Expected -and -not $ReplaceExistingFilesAndConfig) {
        throw "Existing binary differs from reviewed candidate: $Destination SHA256=$ExistingHash. Refusing replacement without -ReplaceExistingFilesAndConfig."
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    if ((Get-FiInstalledHash -Path $Destination) -ne $Expected) { throw "Installed binary hash mismatch: $Destination" }
    Invoke-FiIcaclsChange -Arguments @($Destination,'/reset') -Description "Reset installed binary ACL to inherit the FI program-directory boundary: $Destination"
}

Invoke-FiIcaclsChange -Arguments @($ConfigDir,'/inheritance:r') -Description 'Removed inherited ACLs from FI config directory.'
Invoke-FiIcaclsChange -Arguments @(
    $ConfigDir,'/grant:r',
    'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
    'BUILTIN\Administrators:(OI)(CI)(F)',
    "${CollectorAccount}:(OI)(CI)(RX)",
    "${HelperAccount}:(OI)(CI)(RX)"
) -Description 'Applied administrator-controlled FI config ACL boundary.'

$ExpectedConfig | Set-Content -LiteralPath $ConfigFile -Encoding ASCII
Invoke-FiIcaclsChange -Arguments @($ConfigFile,'/reset') -Description 'Reset fi.conf ACL to inherit the administrator-controlled FI config boundary.'

New-Or-Verify-FiService -Name $CollectorService -DisplayName 'FI Collector' -BootstrapPath $CollectorStaged -ProductionPathName $CollectorPathName -StartName $CollectorAccount
New-Or-Verify-FiService -Name $HelperService -DisplayName 'FI USN Reader' -BootstrapPath $HelperStaged -ProductionPathName $HelperPathName -StartName $HelperAccount

& sc.exe sidtype $CollectorService unrestricted | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Could not set FICollector service SID type to UNRESTRICTED.' }

$EventLogReaders = (@(& net.exe localgroup 'Event Log Readers' 2>&1) -join "`n")
if ($EventLogReaders -notmatch ('(?im)^\s*' + [regex]::Escape($CollectorAccount) + '\s*$')) {
    & net.exe localgroup 'Event Log Readers' $CollectorAccount /add | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not add $CollectorAccount to Event Log Readers." }
}
Write-FiPass 'FICollector is in Event Log Readers.'

if ($GrantTestRootReadAccess) {
    if (-not (Test-FiGate1RootLooksNonProduction -GovernedRoot $GovernedRoot)) {
        throw '-GrantTestRootReadAccess is restricted to roots clearly named FI-Test/FI-Lab/Lab/Test. FI does not rewrite customer data ACLs as a normal deployment action.'
    }
    Invoke-FiIcaclsChange -Arguments @(
        $GovernedRoot,'/grant',
        "${CollectorAccount}:(OI)(CI)(RX)",
        "${HelperAccount}:(OI)(CI)(RX)"
    ) -Description 'Granted FI test identities read/traverse access to the explicitly named test governed root.'
}

# Normalize state/spool through the existing deployment hardener. It handles
# populated trees safely and preserves the intended collector custody boundary.
$Hardener = Join-Path (Join-Path (Split-Path -Parent $Here) 'deployment') 'Harden-FI-Data-ACL.ps1'
if (-not (Test-Path -LiteralPath $Hardener -PathType Leaf)) { throw "Missing existing FI data ACL hardener: $Hardener" }
& $Hardener -ConfirmChange

Start-Service -Name $HelperService -ErrorAction Stop
Wait-FiServiceState -Name $HelperService -State 'Running'
$PipeDeadline = (Get-Date).AddSeconds(120)
while (-not (Test-Path '\\.\pipe\FI-USN')) {
    if ((Get-Service -Name $HelperService).Status -ne 'Running') { throw 'FIUSNReader stopped while waiting for FI-USN pipe.' }
    if ((Get-Date) -ge $PipeDeadline) { throw 'FI-USN pipe was not observed within 120 seconds.' }
    Start-Sleep -Milliseconds 500
}
Write-FiPass 'FIUSNReader is running and FI-USN pipe is present.'

$CollectionBefore = Get-FiGate1ConfiguredCollectionCount
Start-Service -Name $CollectorService -ErrorAction Stop
Wait-FiServiceState -Name $CollectorService -State 'Running'
$Collection = Wait-FiGate1ConfiguredCollectionAfter -BeforeCount $CollectionBefore -TimeoutSeconds 180
if ($null -eq $Collection) { throw 'No configured collection completed after Gate 1 test deployment.' }
if ($Collection.outcome -eq 'Failed') { throw "First configured collection after deployment failed: $($Collection.error)" }
Write-FiPass 'FICollector is running and completed a configured collection cycle.'

$AcceptanceScript = Join-Path $Here '11-FileServer-Deployment-Acceptance.ps1'
& $AcceptanceScript -GovernedRoot $GovernedRoot

Remove-Item -LiteralPath $StagingDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-FiPass 'Gate 1 reproducible test deployment completed.'
Write-FiInfo 'The 1m/30m command line is the fixed Gate 1 acceptance setting required by the existing Test 08 restoration contract; it is not an accepted production cadence.'
Write-FiInfo 'Windows audit policy and governed-root SACL configuration remain separate administrator-controlled deployment actions.'
