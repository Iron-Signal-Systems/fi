# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# Run on the FI file server after 10B was executed from a separate SMB client.
# This script is read-only. It correlates the unique remote-workload RunID with
# selected Windows Security events and FI spool content.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{12}$')]
    [string]$RunID,

    [ValidateRange(1,1440)]
    [int]$LookbackMinutes = 60,

    [ValidateRange(100,100000)]
    [int]$MaxEvents = 20000,

    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory

$RunID = $RunID.ToLowerInvariant()
$Marker = "_fi_gate1_remote_$RunID"
$StartTime = (Get-Date).AddMinutes(-1 * $LookbackMinutes)
$SelectedIDs = @(4656,4663,4660,4664,4670,4907,5145)
$Events = New-Object System.Collections.Generic.List[object]

try {
    $Candidates = @(
        Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$SelectedIDs; StartTime=$StartTime } -MaxEvents $MaxEvents -ErrorAction Stop
    )
} catch {
    $Candidates = @()
    Write-FiInfo "Security-event query unavailable: $($_.Exception.Message)"
}

foreach ($Event in $Candidates) {
    $Xml = $Event.ToXml()
    if ($Xml -notlike "*$Marker*") { continue }
    $Events.Add([PSCustomObject]@{
        TimeCreated = $Event.TimeCreated
        EventRecordID = [UInt64]$Event.RecordId
        EventID = [int]$Event.Id
        Provider = $Event.ProviderName
        MachineName = $Event.MachineName
        XML = $Xml
    })
}

$Names = @(
    "remote-smb-$RunID.txt",
    "remote-smb-renamed-$RunID.txt"
)
$SpoolMatches = @(
    foreach ($Name in $Names) {
        $Matches = @(Find-FiSpoolFilename -FileName $Name -SpoolPath 'C:\ProgramData\FI\spool' -NewestFiles 500)
        [PSCustomObject]@{
            FileName = $Name
            MatchCount = $Matches.Count
        }
    }
)

$ByEvent = @(
    $Events |
        Group-Object EventID |
        Sort-Object Name |
        ForEach-Object {
            [PSCustomObject]@{ EventID=[int]$_.Name; Count=$_.Count }
        }
)

$Event5145Count = @($Events | Where-Object { $_.EventID -eq 5145 }).Count
$SpoolMatchTotal = [int](($SpoolMatches | Measure-Object MatchCount -Sum).Sum)
$Report = [PSCustomObject]@{
    RecordKind = 'FIGate1RemoteSMBCorrelation'
    RunID = $RunID
    Host = $env:COMPUTERNAME
    Marker = $Marker
    LookbackMinutes = $LookbackMinutes
    MaxEvents = $MaxEvents
    SecurityQueryMayBeTruncated = ($Candidates.Count -ge $MaxEvents)
    ObservedUTC = [DateTime]::UtcNow.ToString('o')
    LatestConfiguredCollection = Get-FiLatestConfiguredCollection
    SecurityEventSummary = $ByEvent
    SecurityEvents = $Events.ToArray()
    Event5145Count = $Event5145Count
    SpoolMatches = $SpoolMatches
    SpoolMatchTotal = $SpoolMatchTotal
    Interpretation = 'Presence/absence is recorded as observed. A missing selected event is not proof that remote activity did not occur; verify effective Advanced Audit Policy, SACL coverage, SMB path, and source-specific prerequisites.'
}
$ReportPath = Join-Path $ResultDirectory "gate1-remote-smb-correlation-$($env:COMPUTERNAME)-$RunID.json"
Write-FiGate1Json -InputObject $Report -Path $ReportPath

if ($ByEvent.Count) { $ByEvent | Format-Table -AutoSize }
else { Write-FiInfo 'No selected Security events matched the remote workload marker in the lookback window.' }
$SpoolMatches | Format-Table -AutoSize
Write-FiPass "Remote SMB server-side correlation captured. Report: $ReportPath"
