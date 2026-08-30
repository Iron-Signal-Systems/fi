# FI gMSA - Collector host install
# Windows Server 2016 / Windows PowerShell 5.1
#
# Run this from an elevated PowerShell prompt on each FI collector host.
# The script finds this computer in config\gmsa.psd1, installs both host-specific
# FI gMSAs locally, and verifies that the computer can retrieve both managed
# passwords.
#
# This script does not register Windows services or grant local Administrator
# membership. Those are separate deliberate deployment actions.

[CmdletBinding()]
param(
    [string]$Config = (Join-Path $PSScriptRoot '..\config\gmsa.psd1')
)

$ErrorActionPreference = 'Stop'

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell prompt."
}

$configPath = (Resolve-Path -LiteralPath $Config).Path
$settings = Import-PowerShellDataFile -Path $configPath

if ($settings.Version -ne '1.0') {
    throw "Unsupported gMSA config version '$($settings.Version)'. Expected 1.0."
}

$computerName = $env:COMPUTERNAME

$matches = @(
    $settings.Collectors | Where-Object {
        ([string]$_.Host) -ieq $computerName
    }
)

if ($matches.Count -eq 0) {
    throw "No FI collector entry exists for this computer: $computerName"
}

if ($matches.Count -gt 1) {
    throw "More than one FI collector entry exists for this computer: $computerName"
}

$collectorGMSA = [string]$matches[0].CollectorGMSA
$usnGMSA = [string]$matches[0].USNGMSA

if ([string]::IsNullOrWhiteSpace($collectorGMSA)) {
    throw "Collector '$computerName' does not have a CollectorGMSA value."
}

if ([string]::IsNullOrWhiteSpace($usnGMSA)) {
    throw "Collector '$computerName' does not have a USNGMSA value."
}

if ($collectorGMSA -ieq $usnGMSA) {
    throw "Collector '$computerName' must use different CollectorGMSA and USNGMSA values."
}

# Install the AD PowerShell module if this Server 2016 host does not have it.
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Import-Module ServerManager

    Write-Host "Installing RSAT-AD-PowerShell..."
    $featureResult = Install-WindowsFeature RSAT-AD-PowerShell

    if (-not $featureResult.Success) {
        throw "Failed to install RSAT-AD-PowerShell."
    }
}

Import-Module ActiveDirectory

function Install-And-Test-FIGMSA {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Role
    )

    $alreadyWorks = $false

    try {
        $alreadyWorks = Test-ADServiceAccount -Identity $Name -ErrorAction Stop
    }
    catch {
        $alreadyWorks = $false
    }

    if (-not $alreadyWorks) {
        Write-Host "Installing $Role gMSA $Name on $computerName..."
        Install-ADServiceAccount -Identity $Name
    }

    $works = Test-ADServiceAccount -Identity $Name

    if (-not $works) {
        throw "gMSA validation failed for $Role account $Name on $computerName."
    }

    return $true
}

$collectorWorks = Install-And-Test-FIGMSA -Name $collectorGMSA -Role "FICollector"
$usnWorks = Install-And-Test-FIGMSA -Name $usnGMSA -Role "FIUSNReader"

$domain = Get-ADDomain

Write-Host ""
Write-Host "FI gMSA collector-host setup complete."
Write-Host "  Host:              $computerName"
Write-Host "  FICollector:       $($domain.NetBIOSName)\$collectorGMSA$"
Write-Host "  Collector test:    $collectorWorks"
Write-Host "  FIUSNReader:       $($domain.NetBIOSName)\$usnGMSA$"
Write-Host "  USN helper test:   $usnWorks"
