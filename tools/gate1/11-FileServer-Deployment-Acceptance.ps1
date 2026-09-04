# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results',
    [switch]$IncludeCollectorBoundary
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory
$GovernedRoot = Get-FiGate1SingleGovernedRoot -GovernedRoot $GovernedRoot

$ScriptsRoot = Join-Path (Split-Path -Parent $Here) 'scripts'
$OS = Get-CimInstance Win32_OperatingSystem
$Build = [string]$OS.BuildNumber
$Supported = @{
    '14393' = 'Windows Server 2016'
    '17763' = 'Windows Server 2019'
    '20348' = 'Windows Server 2022'
    '26100' = 'Windows Server 2025'
}

if (-not $Supported.ContainsKey($Build)) {
    throw "Uncharacterized Windows build $Build. Do not treat an adjacent release procedure as accepted."
}

$RunID = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$Checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param([string]$Name,[string]$Status,[string]$Detail = '')
    $Checks.Add([PSCustomObject]@{ Name=$Name; Status=$Status; Detail=$Detail })
    switch ($Status) {
        'PASS' { Write-FiPass "$Name - $Detail" }
        'INFO' { Write-FiInfo "$Name - $Detail" }
        default { Write-FiFail "$Name - $Detail" }
    }
}

function Get-ServiceManagedAccountText {
    param([string]$Name)
    return (@(& sc.exe qmanagedaccount $Name 2>&1) -join "`n")
}

function Get-ServiceSIDTypeText {
    param([string]$Name)
    return (@(& sc.exe qsidtype $Name 2>&1) -join "`n")
}

function Get-LocalAdministratorsText {
    return (@(& net.exe localgroup Administrators 2>&1) -join "`n")
}

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - DEPLOYMENT ACCEPTANCE'
Write-Host "Host:    $env:COMPUTERNAME"
Write-Host "Release: $($Supported[$Build])"
Write-Host "Build:   $Build"
Write-Host '============================================================'

$Collector = Get-FiServiceInfo -Name 'FICollector'
$Helper = Get-FiServiceInfo -Name 'FIUSNReader'
$AdminText = Get-LocalAdministratorsText

if ($Collector.StartName -ieq $Helper.StartName) {
    Add-Check -Name 'Separate service identities' -Status 'FAIL' -Detail "Both services use $($Collector.StartName)."
} else {
    Add-Check -Name 'Separate service identities' -Status 'PASS' -Detail "$($Collector.StartName) / $($Helper.StartName)"
}


if ($AdminText -match ('(?im)^\s*' + [regex]::Escape($Collector.StartName) + '\s*$')) {
    Add-Check -Name 'Collector non-admin' -Status 'FAIL' -Detail "$($Collector.StartName) appears in local Administrators."
} else {
    Add-Check -Name 'Collector non-admin' -Status 'PASS' -Detail $Collector.StartName
}

if ($AdminText -match ('(?im)^\s*' + [regex]::Escape($Helper.StartName) + '\s*$')) {
    Add-Check -Name 'Helper administrative boundary' -Status 'PASS' -Detail "$($Helper.StartName) is in local Administrators."
} else {
    Add-Check -Name 'Helper administrative boundary' -Status 'FAIL' -Detail "$($Helper.StartName) is not in local Administrators."
}

foreach ($Pair in @(@('FICollector',$Collector),@('FIUSNReader',$Helper))) {
    $Name = [string]$Pair[0]
    $Info = $Pair[1]
    $Managed = Get-ServiceManagedAccountText -Name $Name

    if ($Managed -match 'ACCOUNT MANAGED\s*:\s*TRUE') {
        Add-Check -Name "$Name managed account" -Status 'PASS' -Detail $Info.StartName
    } else {
        Add-Check -Name "$Name managed account" -Status 'FAIL' -Detail $Managed
    }

    $BinaryMatch = [regex]::Match($Info.PathName, '^\s*"?([^" ]+.*?\.exe)"?(?:\s|$)', 'IgnoreCase')
    if ($BinaryMatch.Success -and (Test-Path -LiteralPath $BinaryMatch.Groups[1].Value -PathType Leaf)) {
        $Hash = (Get-FileHash -LiteralPath $BinaryMatch.Groups[1].Value -Algorithm SHA256).Hash
        Add-Check -Name "$Name binary" -Status 'PASS' -Detail "$($BinaryMatch.Groups[1].Value) SHA256=$Hash"
    } else {
        Add-Check -Name "$Name binary" -Status 'FAIL' -Detail "Could not resolve deployed binary from PathName: $($Info.PathName)"
    }
}

$SIDType = Get-ServiceSIDTypeText -Name 'FICollector'
if ($SIDType -match 'SERVICE_SID_TYPE\s*:\s*UNRESTRICTED') {
    Add-Check -Name 'FICollector service SID' -Status 'PASS' -Detail 'UNRESTRICTED'
} else {
    Add-Check -Name 'FICollector service SID' -Status 'FAIL' -Detail $SIDType
}

foreach ($Name in @('FICollector','FIUSNReader')) {
    if (Test-FiServiceRunning -Name $Name) {
        Add-Check -Name "$Name running" -Status 'PASS' -Detail 'Running'
    } else {
        Add-Check -Name "$Name running" -Status 'FAIL' -Detail 'Not running'
    }
}

foreach ($Pair in @(@('FICollector',$Collector),@('FIUSNReader',$Helper))) {
    $Name = [string]$Pair[0]
    $Info = $Pair[1]
    if ($Info.StartMode -eq 'Auto') {
        Add-Check -Name "$Name start mode" -Status 'PASS' -Detail 'Auto'
    } else {
        Add-Check -Name "$Name start mode" -Status 'FAIL' -Detail ([string]$Info.StartMode)
    }
}

# Run the existing, already accepted read-only verification paths rather than
# duplicating their ACL and broker checks here.
$BaselineScript = Join-Path $ScriptsRoot '01-FileServer-Baseline.ps1'
$ACLScript = if ($Build -eq '20348') {
    Join-Path $ScriptsRoot '2022\07-FileServer-Config-ACL.ps1'
} else {
    Join-Path $ScriptsRoot '07-FileServer-Config-ACL.ps1'
}

foreach ($Script in @($BaselineScript,$ACLScript)) {
    Write-FiInfo "Running existing verification script in a child Windows PowerShell process: $Script"
    $Arguments = @()
    if ($Script -eq $BaselineScript) { $Arguments = @('-GovernedRoot',$GovernedRoot) }
    $Child = Invoke-FiGate1PowerShellFile -Path $Script -Arguments $Arguments
    if ($Child.ExitCode -eq 0) {
        Add-Check -Name ([IO.Path]::GetFileName($Script)) -Status 'PASS' -Detail 'Child verification returned exit code 0.'
    } else {
        Add-Check -Name ([IO.Path]::GetFileName($Script)) -Status 'FAIL' -Detail "Child verification exit code $($Child.ExitCode)."
    }
}

if ($IncludeCollectorBoundary) {
    $BoundaryScript = if ($Build -eq '20348') {
        Join-Path $ScriptsRoot '2022\08-FileServer-Collector-Boundary.ps1'
    } else {
        Join-Path $ScriptsRoot '08-FileServer-Collector-Boundary.ps1'
    }
    $BoundaryExpectedCollectorPath = '"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m'
    if ($Collector.PathName -ne $BoundaryExpectedCollectorPath) {
        Add-Check -Name 'Collector exact service-token boundary' -Status 'FAIL' -Detail 'Test 08 was NOT run because its existing restoration contract is fixed at the 1m/30m Gate 1 acceptance command line. Running it against a different command line could restore the wrong configuration.'
    } else {
        Write-FiInfo 'Running controlled Test 08 in a child Windows PowerShell process because -IncludeCollectorBoundary was supplied.'
        $Child = Invoke-FiGate1PowerShellFile -Path $BoundaryScript
        if ($Child.ExitCode -eq 0) {
            Add-Check -Name 'Collector exact service-token boundary' -Status 'PASS' -Detail 'Test 08 returned exit code 0.'
        } else {
            Add-Check -Name 'Collector exact service-token boundary' -Status 'FAIL' -Detail "Test 08 exit code $($Child.ExitCode)."
        }
    }
} else {
    Add-Check -Name 'Collector exact service-token boundary' -Status 'INFO' -Detail 'Not run. Supply -IncludeCollectorBoundary for controlled Test 08.'
}

$ServiceDACLs = [PSCustomObject]@{
    FICollector = (@(& sc.exe sdshow FICollector 2>&1) -join "`n")
    FIUSNReader = (@(& sc.exe sdshow FIUSNReader 2>&1) -join "`n")
}

$Report = [PSCustomObject]@{
    RecordKind = 'FIGate1DeploymentAcceptance'
    RunID = $RunID
    Host = $env:COMPUTERNAME
    WindowsCaption = $OS.Caption
    WindowsVersion = $OS.Version
    WindowsBuild = $Build
    AcceptedRelease = $Supported[$Build]
    ObservedUTC = [DateTime]::UtcNow.ToString('o')
    GovernedRoot = $GovernedRoot
    Collector = $Collector
    Helper = $Helper
    ServiceDACLs = $ServiceDACLs
    Checks = $Checks.ToArray()
}
$ReportPath = Join-Path $ResultDirectory "gate1-deployment-$($env:COMPUTERNAME)-$RunID.json"
Write-FiGate1Json -InputObject $Report -Path $ReportPath

$Failures = @($Checks | Where-Object { $_.Status -eq 'FAIL' })
Write-Host ''
Write-Host "[INFO] Report: $ReportPath"
if ($Failures.Count -gt 0) {
    throw "Gate 1 deployment acceptance recorded $($Failures.Count) failed check(s)."
}
Write-FiPass 'Gate 1 deployment acceptance completed without a failed check.'
