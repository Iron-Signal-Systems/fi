# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# FI gMSA - Domain Controller setup
# Windows Server 2016 / Windows PowerShell 5.1
#
# Run this from an elevated PowerShell prompt on a domain controller.
# It:
#   1. Loads config\gmsa.psd1
#   2. Creates the KDS root key only if the forest does not already have one
#   3. Creates/updates two unique gMSAs per configured FI host
#   4. Allows only that host computer to retrieve either managed password
#
# Per host:
#   CollectorGMSA -> FICollector, restricted/non-admin
#   USNGMSA       -> FIUSNReader, privileged on that host only

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
        return Get-ADServiceAccount `
            -Identity $Name `
            -Properties DNSHostName,PrincipalsAllowedToRetrieveManagedPassword `
            -ErrorAction Stop
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

# Validate the complete template before changing AD.
$seenHosts = @{}
$seenGMSAs = @{}
$validated = @()

foreach ($collector in @($settings.Collectors)) {
    $hostName = [string]$collector.Host
    $collectorGMSA = [string]$collector.CollectorGMSA
    $usnGMSA = [string]$collector.USNGMSA

    if ([string]::IsNullOrWhiteSpace($hostName)) {
        throw "A collector entry is missing Host."
    }

    if ([string]::IsNullOrWhiteSpace($collectorGMSA)) {
        throw "Collector '$hostName' is missing CollectorGMSA."
    }

    if ([string]::IsNullOrWhiteSpace($usnGMSA)) {
        throw "Collector '$hostName' is missing USNGMSA."
    }

    if ($collectorGMSA -ieq $usnGMSA) {
        throw "Collector '$hostName' must use different CollectorGMSA and USNGMSA values."
    }

    $hostKey = $hostName.ToLowerInvariant()

    if ($seenHosts.ContainsKey($hostKey)) {
        throw "Duplicate collector host '$hostName'."
    }

    $seenHosts[$hostKey] = $true

    foreach ($gmsaName in @($collectorGMSA, $usnGMSA)) {
        $gmsaKey = $gmsaName.ToLowerInvariant()

        if ($seenGMSAs.ContainsKey($gmsaKey)) {
            throw "Duplicate gMSA '$gmsaName'. Each FI gMSA must be unique to one host and one function."
        }

        $seenGMSAs[$gmsaKey] = $true
    }

    $computer = Get-ADComputer -Identity $hostName -ErrorAction Stop

    $validated += [pscustomobject]@{
        HostName      = $hostName
        CollectorGMSA = $collectorGMSA
        USNGMSA       = $usnGMSA
        Computer      = $computer
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
    foreach ($account in @(
        [pscustomobject]@{ Name = $item.CollectorGMSA; Role = 'FICollector' },
        [pscustomobject]@{ Name = $item.USNGMSA;       Role = 'FIUSNReader' }
    )) {
        $dnsHostName = '{0}.{1}' -f $account.Name, $domain.DNSRoot
        $existing = Get-FIServiceAccount -Name $account.Name

        if ($null -eq $existing) {
            Write-Host "Creating $($account.Role) gMSA $($account.Name) for $($item.HostName)..."

            New-ADServiceAccount `
                -Name $account.Name `
                -DNSHostName $dnsHostName `
                -PrincipalsAllowedToRetrieveManagedPassword $item.Computer
        }
        else {
            Write-Host "Updating $($account.Role) gMSA $($account.Name) for $($item.HostName)..."

            Set-ADServiceAccount `
                -Identity $account.Name `
                -PrincipalsAllowedToRetrieveManagedPassword $item.Computer
        }
    }
}

Write-Host ""
Write-Host "FI gMSA domain setup complete."
Write-Host ""

foreach ($item in $validated) {
    Write-Host ("  {0,-20} FICollector  -> {1}\{2}$" -f $item.HostName, $domain.NetBIOSName, $item.CollectorGMSA)
    Write-Host ("  {0,-20} FIUSNReader  -> {1}\{2}$" -f "", $domain.NetBIOSName, $item.USNGMSA)
}
