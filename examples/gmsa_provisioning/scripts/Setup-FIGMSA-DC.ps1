# FI gMSA - Domain Controller setup
# Windows Server 2016 / Windows PowerShell 5.1
#
# Run this once from an elevated PowerShell prompt on a domain controller.
# It:
#   1. Loads config\gmsa.psd1
#   2. Creates the KDS root key only if the forest does not already have one
#   3. Creates/updates one gMSA per configured FI collector host
#   4. Allows only that collector computer to retrieve that gMSA password

[CmdletBinding()]
param(
    [string]$Config = (Join-Path $PSScriptRoot '..\config\gmsa.psd1')
)

$ErrorActionPreference = 'Stop'

function Get-FIServiceAccount {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        return Get-ADServiceAccount -Identity $Name -Properties DNSHostName,PrincipalsAllowedToRetrieveManagedPassword -ErrorAction Stop
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return $null
    }
}

Import-Module ActiveDirectory

$configPath = (Resolve-Path -LiteralPath $Config).Path
$settings = Import-PowerShellDataFile -Path $configPath

if ($settings.Version -ne '1.0') {
    throw "Unsupported gMSA config version '$($settings.Version)'. Expected 1.0."
}

if (-not $settings.Collectors -or @($settings.Collectors).Count -eq 0) {
    throw "No Collectors are defined in $configPath."
}

# Validate the template before changing AD.
$seenHosts = @{}
$seenGMSAs = @{}
$validated = @()

foreach ($collector in @($settings.Collectors)) {
    $hostName = [string]$collector.Host
    $gmsaName = [string]$collector.GMSA

    if ([string]::IsNullOrWhiteSpace($hostName)) {
        throw "A collector entry is missing Host."
    }

    if ([string]::IsNullOrWhiteSpace($gmsaName)) {
        throw "Collector '$hostName' is missing GMSA."
    }

    $hostKey = $hostName.ToLowerInvariant()
    $gmsaKey = $gmsaName.ToLowerInvariant()

    if ($seenHosts.ContainsKey($hostKey)) {
        throw "Duplicate collector host '$hostName'."
    }

    if ($seenGMSAs.ContainsKey($gmsaKey)) {
        throw "Duplicate gMSA '$gmsaName'."
    }

    $seenHosts[$hostKey] = $true
    $seenGMSAs[$gmsaKey] = $true

    $computer = Get-ADComputer -Identity $hostName -ErrorAction Stop

    $validated += [pscustomobject]@{
        HostName = $hostName
        GMSAName = $gmsaName
        Computer = $computer
    }
}

$domain = Get-ADDomain
$forest = Get-ADForest

# KDS root key is required once per forest.
$kdsKeys = @(Get-KdsRootKey)

if ($kdsKeys.Count -eq 0) {
    $currentDomainDCs = @(Get-ADDomainController -Filter *)

    if (($forest.Domains.Count -eq 1) -and ($currentDomainDCs.Count -eq 1)) {
        Write-Host "No KDS root key found."
        Write-Host "Single-DC forest detected. Creating lab/test KDS root key..."
        Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null
    }
    else {
        Write-Host "No KDS root key found."
        Write-Host "Creating production-style KDS root key..."
        Add-KdsRootKey -EffectiveImmediately | Out-Null

        throw "KDS root key created. This forest has multiple DCs/domains. Wait at least 10 hours for replication, then run this script again."
    }
}
else {
    Write-Host "KDS root key already exists."
}

foreach ($item in $validated) {
    $dnsHostName = '{0}.{1}' -f $item.GMSAName, $domain.DNSRoot
    $existing = Get-FIServiceAccount -Name $item.GMSAName

    if ($null -eq $existing) {
        Write-Host "Creating gMSA $($item.GMSAName) for $($item.HostName)..."

        New-ADServiceAccount `
            -Name $item.GMSAName `
            -DNSHostName $dnsHostName `
            -PrincipalsAllowedToRetrieveManagedPassword $item.Computer
    }
    else {
        Write-Host "Updating gMSA $($item.GMSAName) for $($item.HostName)..."

        Set-ADServiceAccount `
            -Identity $item.GMSAName `
            -PrincipalsAllowedToRetrieveManagedPassword $item.Computer
    }
}

Write-Host ""
Write-Host "FI gMSA domain setup complete."
Write-Host ""

foreach ($item in $validated) {
    Write-Host ("  {0,-20} -> {1}\{2}$" -f $item.HostName, $domain.NetBIOSName, $item.GMSAName)
}
