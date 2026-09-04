# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results',
    [int]$RecoveryTimeoutSeconds = 180,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmDisruptive
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator
$GovernedRoot = Get-FiGate1SingleGovernedRoot -GovernedRoot $GovernedRoot
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory

if (-not $ConfirmDisruptive) { throw '-ConfirmDisruptive is required.' }
if (-not (Test-Path -LiteralPath $GovernedRoot -PathType Container)) { throw "Governed root not found: $GovernedRoot" }

$RunID = [Guid]::NewGuid().ToString('N').Substring(0,12)
$TestName = "restart-$RunID.txt"
$TestPath = Join-Path $GovernedRoot $TestName
$CheckpointPath = Get-FiCheckpointPath -GovernedRoot $GovernedRoot
$BeforeCheckpoint = Get-FiCheckpoint -CheckpointPath $CheckpointPath
$BeforeUSN = [UInt64]$BeforeCheckpoint.next_usn
$CollectionBefore = Get-FiGate1ConfiguredCollectionCount
$StoppedUTC = $null
$StartedUTC = $null

try {
    Write-FiInfo 'Stopping FICollector for controlled restart/recovery acceptance.'
    Stop-Service FICollector -Force -ErrorAction Stop
    (Get-Service FICollector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    $StoppedUTC = [DateTime]::UtcNow

    "FI Gate 1 collector stopped at $($StoppedUTC.ToString('o'))" | Set-Content -LiteralPath $TestPath -Encoding ASCII
    'change while collector stopped' | Add-Content -LiteralPath $TestPath -Encoding ASCII

    Write-FiInfo 'Starting FICollector.'
    Start-Service FICollector -ErrorAction Stop
    (Get-Service FICollector).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    $StartedUTC = [DateTime]::UtcNow

    $Advanced = Wait-FiCheckpointAdvance -CheckpointPath $CheckpointPath -BeforeUSN $BeforeUSN -TimeoutSeconds $RecoveryTimeoutSeconds
    $Collection = Wait-FiGate1ConfiguredCollectionAfter -BeforeCount $CollectionBefore -TimeoutSeconds $RecoveryTimeoutSeconds
    $SpoolMatches = @(Wait-FiSpoolFilename -FileName $TestName -TimeoutSeconds $RecoveryTimeoutSeconds)

    $Report = [PSCustomObject]@{
        RecordKind = 'FIGate1CollectorRestartRecovery'
        RunID = $RunID
        Host = $env:COMPUTERNAME
        GovernedRoot = $GovernedRoot
        TestFile = $TestPath
        StoppedUTC = if ($StoppedUTC) {$StoppedUTC.ToString('o')} else {''}
        StartedUTC = if ($StartedUTC) {$StartedUTC.ToString('o')} else {''}
        BeforeUSN = $BeforeUSN
        AfterUSN = if ($Advanced) {[UInt64]$Advanced.next_usn} else {$BeforeUSN}
        CheckpointAdvanced = [bool]($null -ne $Advanced)
        ConfiguredCollectionObserved = [bool]($null -ne $Collection)
        ConfiguredCollection = $Collection
        TestFileSpoolMatchCount = $SpoolMatches.Count
        FinishedUTC = [DateTime]::UtcNow.ToString('o')
    }
    $ReportPath = Join-Path $ResultDirectory "gate1-collector-restart-$($env:COMPUTERNAME)-$RunID.json"
    Write-FiGate1Json -InputObject $Report -Path $ReportPath

    if ($null -eq $Advanced) { throw 'USN checkpoint did not advance after collector restart.' }
    if ($SpoolMatches.Count -eq 0) { throw 'Stopped-window test file was not found in FI spool catch-up output.' }
    Write-FiPass "Collector restart/recovery acceptance passed. Report: $ReportPath"
}
finally {
    if ((Get-Service FICollector -ErrorAction SilentlyContinue).Status -ne 'Running') {
        Start-Service FICollector -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $TestPath -Force -ErrorAction SilentlyContinue
}
