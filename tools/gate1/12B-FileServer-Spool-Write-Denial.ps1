# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# LAB-ONLY controlled fault injection. This script temporarily removes the
# collector's ability to create new local spool material and then restores the
# exact spool-root SDDL in a finally block.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results',
    [int]$ObservationSeconds = 90,
    [int]$RecoveryTimeoutSeconds = 180,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmStorageDenial,
    [switch]$AllowNonTestRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator
$GovernedRoot = Get-FiGate1SingleGovernedRoot -GovernedRoot $GovernedRoot
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory

if (-not $ConfirmStorageDenial) { throw '-ConfirmStorageDenial is required.' }
if (-not $AllowNonTestRoot -and -not (Test-FiGate1RootLooksNonProduction -GovernedRoot $GovernedRoot)) {
    throw 'This fault-injection test defaults to a governed root whose path clearly contains FI-Test, FI-Lab, Lab, or Test. Supply -AllowNonTestRoot only in an explicitly approved test environment.'
}

$SpoolPath = 'C:\ProgramData\FI\spool'
if (-not (Test-Path -LiteralPath $SpoolPath -PathType Container)) { throw "Spool path not found: $SpoolPath" }

$RunID = [Guid]::NewGuid().ToString('N').Substring(0,12)
$TestName = "spool-denial-$RunID.txt"
$TestPath = Join-Path $GovernedRoot $TestName
$CheckpointPath = Get-FiCheckpointPath -GovernedRoot $GovernedRoot
$BeforeUSN = [UInt64](Get-FiCheckpoint -CheckpointPath $CheckpointPath).next_usn
$CollectionBefore = Get-FiGate1ConfiguredCollectionCount
$SpoolBefore = Get-FiGate1SpoolSnapshot -SpoolPath $SpoolPath
$OriginalAcl = Get-Acl -LiteralPath $SpoolPath
$OriginalSddl = $OriginalAcl.Sddl
$FaultApplied = $false
$ObservedCollection = $null
$ObservedService = $null
$StableDuringFault = $false
$RecoveryCollectionBefore = 0

function New-FIFullControlRule {
    param([string]$SID)
    $Principal = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList $SID
    return New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $Principal,
        [Security.AccessControl.FileSystemRights]::FullControl,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
}

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - LAB SPOOL WRITE-DENIAL ACCEPTANCE'
Write-Host "Governed root: $GovernedRoot"
Write-Host "Spool:         $SpoolPath"
Write-Host "Run ID:        $RunID"
Write-Host '============================================================'

try {
    Stop-Service FICollector -Force -ErrorAction Stop
    (Get-Service FICollector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))

    $DeniedAcl = New-Object -TypeName Security.AccessControl.DirectorySecurity
    $DeniedAcl.SetAccessRuleProtection($true,$false)
    $DeniedAcl.AddAccessRule((New-FIFullControlRule -SID 'S-1-5-18')) | Out-Null
    $DeniedAcl.AddAccessRule((New-FIFullControlRule -SID 'S-1-5-32-544')) | Out-Null
    Set-Acl -LiteralPath $SpoolPath -AclObject $DeniedAcl
    $FaultApplied = $true
    Write-FiInfo 'Temporary spool root ACL applied: SYSTEM/Administrators Full Control; collector has no FI spool grant.'

    "FI Gate 1 spool denial at $([DateTime]::UtcNow.ToString('o'))" | Set-Content -LiteralPath $TestPath -Encoding ASCII

    Start-Service FICollector -ErrorAction Stop
    $ObservedCollection = Wait-FiGate1ConfiguredCollectionAfter -BeforeCount $CollectionBefore -TimeoutSeconds $ObservationSeconds
    $ObservedService = (Get-Service FICollector -ErrorAction SilentlyContinue)
    $ObservedService = if ($null -eq $ObservedService) { 'Missing' } else { $ObservedService.Status.ToString() }
    $StableDuringFault = Wait-FiCheckpointStable -CheckpointPath $CheckpointPath -ExpectedUSN $BeforeUSN -Seconds 2

    Write-FiInfo "During fault: FICollector=$ObservedService; checkpoint stable=$StableDuringFault"
}
finally {
    try { Stop-Service FICollector -Force -ErrorAction SilentlyContinue } catch { }

    if ($FaultApplied) {
        $RestoreAcl = New-Object -TypeName Security.AccessControl.DirectorySecurity
        $RestoreAcl.SetSecurityDescriptorSddlForm($OriginalSddl)
        Set-Acl -LiteralPath $SpoolPath -AclObject $RestoreAcl
        Write-FiInfo 'Original spool-root SDDL restored.'
    }

    $RecoveryCollectionBefore = Get-FiGate1ConfiguredCollectionCount
    Start-Service FICollector -ErrorAction SilentlyContinue
}

$Advanced = Wait-FiCheckpointAdvance -CheckpointPath $CheckpointPath -BeforeUSN $BeforeUSN -TimeoutSeconds $RecoveryTimeoutSeconds
$Matches = @(Wait-FiSpoolFilename -FileName $TestName -TimeoutSeconds $RecoveryTimeoutSeconds)
$SpoolAfter = Get-FiGate1SpoolSnapshot -SpoolPath $SpoolPath
$RecoveryCollection = Wait-FiGate1ConfiguredCollectionAfter -BeforeCount $RecoveryCollectionBefore -TimeoutSeconds $RecoveryTimeoutSeconds

$Report = [PSCustomObject]@{
    RecordKind = 'FIGate1SpoolWriteDenial'
    RunID = $RunID
    Host = $env:COMPUTERNAME
    GovernedRoot = $GovernedRoot
    TestFile = $TestPath
    BeforeUSN = $BeforeUSN
    CheckpointStableDuringFault = $StableDuringFault
    CollectorStateDuringFault = $ObservedService
    LatestCollectionDuringFault = $ObservedCollection
    SpoolBefore = $SpoolBefore
    SpoolAfter = $SpoolAfter
    RecoveryCheckpointAdvanced = [bool]($null -ne $Advanced)
    RecoveryCollection = $RecoveryCollection
    RecoveryTestFileSpoolMatchCount = $Matches.Count
    FinishedUTC = [DateTime]::UtcNow.ToString('o')
}
$ReportPath = Join-Path $ResultDirectory "gate1-spool-denial-$($env:COMPUTERNAME)-$RunID.json"
Write-FiGate1Json -InputObject $Report -Path $ReportPath

Remove-Item -LiteralPath $TestPath -Force -ErrorAction SilentlyContinue

if (-not $StableDuringFault) { throw 'Checkpoint advanced while the local spool durable boundary was intentionally unavailable.' }
if ($null -eq $Advanced) { throw 'Checkpoint did not advance after spool access was restored.' }
if ($Matches.Count -eq 0) { throw 'Fault-window test file was not found after recovery catch-up.' }
Write-FiPass "Spool write-denial/recovery acceptance passed. Report: $ReportPath"
