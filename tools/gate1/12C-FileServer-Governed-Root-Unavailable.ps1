# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# LAB-ONLY controlled source-unavailable test. The configured governed root is
# renamed only while FICollector is stopped and is restored in a finally block.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results',
    [int]$ObservationSeconds = 90,
    [int]$RecoveryTimeoutSeconds = 180,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmRootUnavailable,
    [switch]$AllowNonTestRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator
$GovernedRoot = Get-FiGate1SingleGovernedRoot -GovernedRoot $GovernedRoot
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory

if (-not $ConfirmRootUnavailable) { throw '-ConfirmRootUnavailable is required.' }
if (-not $AllowNonTestRoot -and -not (Test-FiGate1RootLooksNonProduction -GovernedRoot $GovernedRoot)) {
    throw 'This test defaults to clearly named FI-Test/FI-Lab/Lab/Test roots. Use -AllowNonTestRoot only in an explicitly approved test environment.'
}
if (-not (Test-Path -LiteralPath $GovernedRoot -PathType Container)) { throw "Governed root not found: $GovernedRoot" }

$RunID = [Guid]::NewGuid().ToString('N').Substring(0,12)
$Leaf = Split-Path -Leaf $GovernedRoot
$Parent = Split-Path -Parent $GovernedRoot
$OfflineLeaf = "$Leaf.fi-gate1-offline-$RunID"
$OfflinePath = Join-Path $Parent $OfflineLeaf
$CollectionBefore = Get-FiGate1ConfiguredCollectionCount
$Renamed = $false
$During = $null
$RecoveryCollectionBefore = 0

try {
    Stop-Service FICollector -Force -ErrorAction Stop
    (Get-Service FICollector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))

    Rename-Item -LiteralPath $GovernedRoot -NewName $OfflineLeaf -ErrorAction Stop
    $Renamed = $true
    Write-FiInfo "Governed root temporarily unavailable at configured path: $GovernedRoot"

    Start-Service FICollector -ErrorAction Stop
    $During = Wait-FiGate1ConfiguredCollectionAfter -BeforeCount $CollectionBefore -TimeoutSeconds $ObservationSeconds
}
finally {
    Stop-Service FICollector -Force -ErrorAction SilentlyContinue
    if ($Renamed -and (Test-Path -LiteralPath $OfflinePath -PathType Container)) {
        Rename-Item -LiteralPath $OfflinePath -NewName $Leaf -ErrorAction Stop
        Write-FiInfo 'Governed root restored to its configured path.'
    }
    $RecoveryCollectionBefore = Get-FiGate1ConfiguredCollectionCount
    Start-Service FICollector -ErrorAction SilentlyContinue
}

$Recovered = Wait-FiGate1ConfiguredCollectionAfter -BeforeCount $RecoveryCollectionBefore -TimeoutSeconds $RecoveryTimeoutSeconds
$Report = [PSCustomObject]@{
    RecordKind = 'FIGate1GovernedRootUnavailable'
    RunID = $RunID
    Host = $env:COMPUTERNAME
    GovernedRoot = $GovernedRoot
    DuringUnavailableCollection = $During
    RecoveryCollection = $Recovered
    RootRestored = (Test-Path -LiteralPath $GovernedRoot -PathType Container)
    FinishedUTC = [DateTime]::UtcNow.ToString('o')
}
$ReportPath = Join-Path $ResultDirectory "gate1-root-unavailable-$($env:COMPUTERNAME)-$RunID.json"
Write-FiGate1Json -InputObject $Report -Path $ReportPath

if (-not (Test-Path -LiteralPath $GovernedRoot -PathType Container)) { throw 'Governed root was not restored.' }
if ($null -eq $Recovered) { throw 'No configured collection was observed after governed-root recovery.' }
Write-FiPass "Governed-root unavailable/recovery workload completed. Inspect DuringUnavailableCollection for explicit non-success semantics. Report: $ReportPath"
