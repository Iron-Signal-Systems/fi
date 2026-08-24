# FI gMSA - Collector host install
# Windows Server 2016 / Windows PowerShell 5.1
#
# Run this from an elevated PowerShell prompt on each FI collector host.
# The script finds this computer in config\gmsa.psd1, installs its assigned
# gMSA locally, and verifies that the computer can retrieve the managed password.

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

$gmsaName = [string]$matches[0].GMSA

if ([string]::IsNullOrWhiteSpace($gmsaName)) {
    throw "Collector '$computerName' does not have a GMSA value."
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

$alreadyWorks = $false

try {
    $alreadyWorks = Test-ADServiceAccount -Identity $gmsaName -ErrorAction Stop
}
catch {
    $alreadyWorks = $false
}

if (-not $alreadyWorks) {
    Write-Host "Installing gMSA $gmsaName on $computerName..."
    Install-ADServiceAccount -Identity $gmsaName
}

$works = Test-ADServiceAccount -Identity $gmsaName

if (-not $works) {
    throw "gMSA validation failed for $gmsaName on $computerName."
}

$domain = Get-ADDomain

Write-Host ""
Write-Host "FI gMSA collector setup complete."
Write-Host "  Host:    $computerName"
Write-Host "  Account: $($domain.NetBIOSName)\$gmsaName$"
Write-Host "  Test:    True"
