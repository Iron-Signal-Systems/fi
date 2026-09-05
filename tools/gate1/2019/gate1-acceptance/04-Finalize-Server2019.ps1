[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Common-Server2019-Sweep.ps1')

Assert-FI2019Controller

function Get-LatestJson {
    param([string]$Path,[string]$Filter)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
    $File = Get-ChildItem -LiteralPath $Path -Filter $Filter -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $File) { return $null }
    return [IO.File]::ReadAllText($File.FullName) | ConvertFrom-Json
}

$Sweep = Get-LatestJson -Path $FI2019.LocalResultDirectory -Filter 'server2019-sweep-summary-*.json'
$RemoteSMB = Get-LatestJson -Path (Join-Path $FI2019.LocalResultDirectory 'remote-smb') -Filter 'server2019-remote-smb-summary-*.json'

$D12Path = Join-Path $FI2019.LocalResultDirectory '12d'
$Before = Get-LatestJson -Path $D12Path -Filter 'server2019-12d-before-summary.json'
$During = Get-LatestJson -Path $D12Path -Filter 'server2019-12d-during-summary.json'
$After = Get-LatestJson -Path $D12Path -Filter 'server2019-12d-after-summary.json'

$Checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param([string]$Name,[string]$Status,[string]$Basis)
    $Checks.Add([PSCustomObject]@{Name=$Name;Status=$Status;Basis=$Basis})
}

if ($null -eq $Sweep) {
    foreach ($Name in @(
        'Artifact identity','Deployment boundary','USN query/read','File-ID re-observation',
        'Protected containment','ReadSACL','Security source/checkpoint','Content-prefix custody',
        'Local activity','Restart/helper catch-up','Normal configured collection'
    )) {
        Add-Check $Name 'INCOMPLETE' 'Core Server 2019 sweep has not produced a PASS summary.'
    }
}
elseif ([string]$Sweep.OverallStatus -ne 'PASS') {
    foreach ($Name in @(
        'Artifact identity','Deployment boundary','USN query/read','File-ID re-observation',
        'Protected containment','ReadSACL','Security source/checkpoint','Content-prefix custody',
        'Local activity','Restart/helper catch-up','Normal configured collection'
    )) {
        Add-Check $Name 'FAIL' 'Core Server 2019 sweep summary is not PASS.'
    }
}
else {
    Add-Check 'Artifact identity' 'PASS' "Exact collector/helper SHA256 and repository checkpoint were pinned."
    Add-Check 'Deployment boundary' 'PASS' 'Gate 1 deployment acceptance and collector service-token boundary returned PASS.'
    Add-Check 'USN query/read' 'PASS' 'Exact Gate 1 build completed configured collection and helper outage/catch-up.'
    Add-Check 'File-ID re-observation' 'PASS' '10A accepted a current USNObjectObservation after the activity matrix.'
    Add-Check 'Protected containment' 'PASS' ([string]$Sweep.ProtectedContainmentBasis)
    Add-Check 'ReadSACL' 'PASS' '10A SACLCurrentStateValidation was Present through the Gate 1 build four-operation broker.'
    Add-Check 'Security source/checkpoint' 'PASS' '10A required exact denied-read/write Security events and FI spool preservation.'
    Add-Check 'Content-prefix custody' 'PASS' 'Exact 16-byte prefix for the known 10A create marker matched the finalized FI USN observation.'
    Add-Check 'Local activity' 'PASS' '10A WorkloadExecutionPass was true.'
    Add-Check 'Restart/helper catch-up' 'PASS' 'Readiness orchestrator completed collector restart and helper outage/catch-up steps.'
    Add-Check 'Normal configured collection' 'PASS' 'Post-deployment configured collection and post-sweep service state were healthy.'
}

if ($null -eq $RemoteSMB) {
    Add-Check 'Remote SMB' 'INCOMPLETE' 'True remote SMB pass has not been completed.'
}
elseif ([string]$RemoteSMB.OverallStatus -eq 'PASS') {
    Add-Check 'Remote SMB' 'PASS' "RunID=$($RemoteSMB.RunID); Event5145Count=$($RemoteSMB.Event5145Count); SpoolMatchTotal=$($RemoteSMB.SpoolMatchTotal)"
}
else {
    Add-Check 'Remote SMB' 'FAIL' 'Remote SMB summary is not PASS.'
}

$D12Complete = (
    $null -ne $Before -and
    $null -ne $During -and
    $null -ne $After -and
    [string]$Before.OverallStatus -eq 'PASS' -and
    [string]$During.OverallStatus -eq 'PASS' -and
    [string]$After.OverallStatus -eq 'PASS' -and
    [bool]$During.ExternalFaultConfirmedActive -and
    [bool]$After.DependencyRestoredConfirmed
)

if ($D12Complete) {
    Add-Check '12D dependency observation' 'PASS' 'Accepted passive Before/During/After reports exist; During records external-fault confirmation and After records restoration confirmation.'
}
else {
    $Any12DFail = @($Before,$During,$After | Where-Object { $null -ne $_ -and [string]$_.OverallStatus -eq 'FAIL' }).Count -gt 0
    if ($Any12DFail) {
        Add-Check '12D dependency observation' 'FAIL' 'At least one 12D stage summary is FAIL.'
    }
    else {
        Add-Check '12D dependency observation' 'INCOMPLETE' 'Need accepted Before/During/After reports with external-fault/restoration confirmations.'
    }
}

$FailCount = @($Checks | Where-Object { $_.Status -eq 'FAIL' }).Count
$IncompleteCount = @($Checks | Where-Object { $_.Status -eq 'INCOMPLETE' }).Count

if ($FailCount -gt 0) {
    $Gate1Status = 'FAIL'
}
elseif ($IncompleteCount -gt 0) {
    $Gate1Status = 'INCOMPLETE'
}
else {
    $Gate1Status = 'COMPLETE'
}

$Final = [ordered]@{
    RecordKind = 'FIGate1Server2019FinalAcceptance'
    Host = $FI2019.TargetHost
    Build = $FI2019.ExpectedBuild
    RepositoryCommit = $FI2019.ExpectedRepoCommit
    CollectorSHA256 = $FI2019.CollectorSHA256
    HelperSHA256 = $FI2019.HelperSHA256
    ObservedUTC = [DateTime]::UtcNow.ToString('o')
    Checks = $Checks.ToArray()
    Gate1Status = $Gate1Status
}

$Stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$JsonPath = Join-Path $FI2019.LocalResultDirectory "SERVER2019-GATE1-FINAL-$Stamp.json"
$TextPath = Join-Path $FI2019.LocalResultDirectory "SERVER2019-GATE1-FINAL-$Stamp.txt"

$Final | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $JsonPath -Encoding UTF8

$Lines = New-Object System.Collections.Generic.List[string]
$Lines.Add('FI Gate 1 build - Windows Server 2019 / build 17763')
$Lines.Add('')
foreach ($Check in $Checks) {
    $Lines.Add(('{0,-32} {1}' -f $Check.Name,$Check.Status))
}
$Lines.Add('')
$Lines.Add(('Gate 1 status             {0}' -f $Gate1Status))
$Lines.Add('')
$Lines.Add("Repository commit: $($FI2019.ExpectedRepoCommit)")
$Lines.Add("Collector SHA256:  $($FI2019.CollectorSHA256)")
$Lines.Add("Helper SHA256:     $($FI2019.HelperSHA256)")
$Lines | Set-Content -LiteralPath $TextPath -Encoding UTF8

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI CANDIDATE #4 - SERVER 2019 FINAL'
Write-Host '============================================================'
$Checks | Format-Table Name,Status -AutoSize
Write-Host ''
Write-Host "Gate 1 status: $Gate1Status"
Write-Host "JSON: $JsonPath"
Write-Host "Text: $TextPath"

if ($Gate1Status -eq 'FAIL') {
    throw 'Server 2019 Gate 1 acceptance contains a FAIL result.'
}
