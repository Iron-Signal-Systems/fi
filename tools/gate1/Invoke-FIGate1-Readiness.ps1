# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [string]$FIExecutable = 'C:\Program Files\FI\fi.exe',
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results',
    [switch]$IncludeCollectorBoundary,
    [switch]$IncludeLocalActivity,
    [switch]$IncludePerformanceBaseline,
    [switch]$StopCollectorForPerformance,
    [switch]$IncludeCollectorRestart,
    [switch]$IncludeHelperOutage,
    [switch]$IncludeChurn,
    [switch]$IncludeSpoolPressure,
    [switch]$IncludeLabFaultInjection
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator
$GovernedRoot = Get-FiGate1SingleGovernedRoot -GovernedRoot $GovernedRoot
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory
$RunID = [Guid]::NewGuid().ToString('N').Substring(0,12)
$Steps = New-Object System.Collections.Generic.List[object]

function Invoke-Step {
    param([string]$Name,[scriptblock]$Action)
    $Started = [DateTime]::UtcNow
    try {
        & $Action
        $Steps.Add([PSCustomObject]@{Name=$Name;Status='PASS';StartedUTC=$Started.ToString('o');FinishedUTC=[DateTime]::UtcNow.ToString('o');Error=''})
    } catch {
        $Steps.Add([PSCustomObject]@{Name=$Name;Status='FAIL';StartedUTC=$Started.ToString('o');FinishedUTC=[DateTime]::UtcNow.ToString('o');Error=$_.Exception.Message})
        throw
    }
}

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - READINESS ORCHESTRATOR'
Write-Host "Host:          $env:COMPUTERNAME"
Write-Host "Governed root: $GovernedRoot"
Write-Host "Run ID:        $RunID"
Write-Host '============================================================'

try {
    Invoke-Step 'DeploymentAcceptance' {
        $StepParams = @{ ResultDirectory = $ResultDirectory; GovernedRoot = $GovernedRoot }
        if ($IncludeCollectorBoundary) { $StepParams.IncludeCollectorBoundary = $true }
        & (Join-Path $Here '11-FileServer-Deployment-Acceptance.ps1') @StepParams
    }

    if ($IncludeLocalActivity) {
        Invoke-Step 'ActivityMatrixLocal' {
            & (Join-Path $Here '10A-FileServer-Activity-Matrix.ps1') -GovernedRoot $GovernedRoot -ResultDirectory $ResultDirectory -ConfirmWorkload
        }
    }

    if ($IncludePerformanceBaseline) {
        Invoke-Step 'PerformanceBaseline' {
            $PerfParams = @{
                GovernedRoot = $GovernedRoot
                FIExecutable = $FIExecutable
                Runs = 3
                ResultDirectory = (Join-Path $ResultDirectory 'performance')
                ConfirmSourceImpact = $true
            }
            if ($StopCollectorForPerformance) { $PerfParams.StopCollectorForRun = $true }
            else { $PerfParams.AllowConcurrentCollector = $true }
            & (Join-Path $Here '13-FileServer-Performance-Baseline.ps1') @PerfParams
        }
    }

    Invoke-Step 'OperationResourceSummary' {
        & (Join-Path $Here '16-FileServer-Operation-Resource-Summary.ps1') -ResultDirectory (Join-Path $ResultDirectory 'performance')
    }

    if ($IncludeCollectorRestart) {
        Invoke-Step 'CollectorRestartRecovery' {
            & (Join-Path $Here '12A-FileServer-Collector-Restart-Recovery.ps1') -GovernedRoot $GovernedRoot -ResultDirectory $ResultDirectory -ConfirmDisruptive
        }
    }

    if ($IncludeHelperOutage) {
        $Test04 = Join-Path (Join-Path (Split-Path -Parent $Here) 'scripts') '04-FileServer-Failure-Recovery.ps1'
        Invoke-Step 'HelperOutageCatchup' {
            $Child = Invoke-FiGate1PowerShellFile -Path $Test04 -Arguments @('-ConfirmDisruptive')
            if ($Child.ExitCode -ne 0) { throw "Helper outage Test 04 exit code $($Child.ExitCode)." }
        }
    }

    if ($IncludeChurn) {
        Invoke-Step 'BoundedChurn' {
            & (Join-Path $Here '14-FileServer-Churn-Campaign.ps1') -GovernedRoot $GovernedRoot -ResultDirectory (Join-Path $ResultDirectory 'performance') -ConfirmWorkload
        }
    }

    if ($IncludeSpoolPressure) {
        Invoke-Step 'SpoolPressure' {
            & (Join-Path $Here '15-FileServer-Spool-Pressure.ps1') -GovernedRoot $GovernedRoot -ResultDirectory (Join-Path $ResultDirectory 'performance') -ConfirmWorkload
        }
    }

    if ($IncludeLabFaultInjection) {
        if (-not (Test-FiGate1RootLooksNonProduction -GovernedRoot $GovernedRoot)) {
            throw '-IncludeLabFaultInjection requires a governed root clearly named as FI-Test/FI-Lab/Lab/Test.'
        }
        Invoke-Step 'SpoolWriteDenial' {
            & (Join-Path $Here '12B-FileServer-Spool-Write-Denial.ps1') -GovernedRoot $GovernedRoot -ResultDirectory $ResultDirectory -ConfirmStorageDenial
        }
        Invoke-Step 'GovernedRootUnavailable' {
            & (Join-Path $Here '12C-FileServer-Governed-Root-Unavailable.ps1') -GovernedRoot $GovernedRoot -ResultDirectory $ResultDirectory -ConfirmRootUnavailable
        }
    }
}
finally {
    $Summary = [PSCustomObject]@{
        RecordKind = 'FIGate1ReadinessRun'
        RunID = $RunID
        Host = $env:COMPUTERNAME
        GovernedRoot = $GovernedRoot
        FinishedUTC = [DateTime]::UtcNow.ToString('o')
        Steps = $Steps.ToArray()
        RemainingExternalWork = @(
            'Run 10B true remote SMB activity from a separate client.',
            'Use 12D before/during/after any controlled AD/LDAPS, Security-log, SMB/local-identity dependency outage.',
            'Repeat performance/churn/spool campaigns on representative file-server datasets and workloads.',
            'Do not set production cadence until repeated measurement results are reviewed.'
        )
    }
    $SummaryPath = Join-Path $ResultDirectory "gate1-readiness-$($env:COMPUTERNAME)-$RunID.json"
    Write-FiGate1Json -InputObject $Summary -Path $SummaryPath
    Write-Host "[INFO] Gate 1 readiness summary: $SummaryPath"
}
