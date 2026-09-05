[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Before','During','After')]
    [string]$Stage,

    [switch]$ConfirmExternalFaultActive,
    [switch]$ConfirmDependencyRestored
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Common-Server2019-Sweep.ps1')

Assert-FI2019Controller

switch ($Stage) {
    'Before' {
        if ($ConfirmExternalFaultActive -or $ConfirmDependencyRestored) {
            throw 'Before stage must be captured before the dependency fault and does not accept confirmation switches.'
        }
    }
    'During' {
        if (-not $ConfirmExternalFaultActive) {
            throw 'During requires -ConfirmExternalFaultActive. This script does NOT create the LDAPS fault.'
        }
        if ($ConfirmDependencyRestored) {
            throw 'During cannot also declare the dependency restored.'
        }
    }
    'After' {
        if (-not $ConfirmDependencyRestored) {
            throw 'After requires -ConfirmDependencyRestored. Restore the dependency before capturing After.'
        }
        if ($ConfirmExternalFaultActive) {
            throw 'After cannot also declare the external fault active.'
        }
    }
}

$Session = $null
$StartedUTC = [DateTime]::UtcNow

try {
    $Session = New-FI2019Session
    $null = Get-FI2019RemotePreflight -Session $Session

    $Remote12D = Join-Path $FI2019.RemoteToolsRoot 'gate1\12D-FileServer-Dependency-Observation.ps1'
    $Exists = Invoke-Command -Session $Session -ArgumentList $Remote12D -ScriptBlock {
        param($Path)
        Test-Path -LiteralPath $Path -PathType Leaf
    }
    if (-not $Exists) {
        throw 'The Server 2019 sweep tooling is not staged. Run 01-Server2019-Sweep.ps1 -ConfirmSweep first.'
    }

    Write-Host ''
    Write-Host '============================================================'
    Write-Host "FI SERVER 2019 - PASSIVE 12D $Stage"
    Write-Host '============================================================'
    Write-Host '[INFO] This wrapper does not alter AD, LDAPS, networking, Windows Firewall,'
    Write-Host '[INFO] FI services, or any other dependency.'

    Invoke-Command -Session $Session -ArgumentList @(
        $Remote12D,$Stage,$FI2019.RemoteResultDirectory
    ) -ScriptBlock {
        param($Script,$Stage,$ResultDirectory)
        & $Script `
            -Dependency 'AD-LDAPS' `
            -Stage $Stage `
            -ResultDirectory $ResultDirectory `
            -ObservationTimeoutSeconds 60 `
            -HeartbeatSeconds 15 `
            -MaxRuntimeTailBytesMB 1 `
            -RuntimeTailLines 40 `
            -Note 'Gate 1 build Windows Server 2019 exact acceptance sweep'
    }

    $RemoteReport = Invoke-Command -Session $Session -ArgumentList @(
        $FI2019.RemoteResultDirectory,$Stage,$StartedUTC
    ) -ScriptBlock {
        param($ResultDirectory,$Stage,$Started)
        Get-ChildItem -LiteralPath $ResultDirectory -Filter "gate1-dependency-AD-LDAPS-$Stage-*.json" -File |
            Where-Object { $_.LastWriteTimeUtc -ge $Started.AddMinutes(-1) } |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }

    if ([string]::IsNullOrWhiteSpace([string]$RemoteReport)) {
        throw "No accepted 12D $Stage report was found."
    }

    $Local12D = Join-Path $FI2019.LocalResultDirectory '12d'
    New-Item -Path $Local12D -ItemType Directory -Force | Out-Null
    $LocalReport = Join-Path $Local12D ([IO.Path]::GetFileName([string]$RemoteReport))
    Copy-Item -FromSession $Session -LiteralPath ([string]$RemoteReport) -Destination $LocalReport -Force

    $ReportHash = (Get-FileHash -LiteralPath $LocalReport -Algorithm SHA256).Hash.ToUpperInvariant()

    $StageSummary = [ordered]@{
        RecordKind = 'FIGate1Server2019DependencyStage'
        Host = $FI2019.TargetHost
        Dependency = 'AD-LDAPS'
        Stage = $Stage
        OverallStatus = 'PASS'
        ExternalFaultConfirmedActive = [bool]$ConfirmExternalFaultActive
        DependencyRestoredConfirmed = [bool]$ConfirmDependencyRestored
        CapturedUTC = [DateTime]::UtcNow.ToString('o')
        Report = $LocalReport
        ReportSHA256 = $ReportHash
    }

    $StageSummaryPath = Join-Path $Local12D "server2019-12d-$($Stage.ToLowerInvariant())-summary.json"
    $StageSummary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StageSummaryPath -Encoding UTF8

    Write-Host ''
    Write-Host "[PASS] 12D $Stage captured."
    Write-Host "Report SHA256: $ReportHash"
    Write-Host "Local report:  $LocalReport"
    Write-Host ''

    switch ($Stage) {
        'Before' {
            Write-Host '[NEXT] Establish the separately controlled, bounded LDAPS transport fault.'
            Write-Host '[NEXT] Then run this script with: -Stage During -ConfirmExternalFaultActive'
        }
        'During' {
            Write-Host '[NEXT] Restore the dependency completely.'
            Write-Host '[NEXT] Then run this script with: -Stage After -ConfirmDependencyRestored'
        }
        'After' {
            Write-Host '[NEXT] Run 04-Finalize-Server2019.ps1.'
        }
    }
}
finally {
    if ($null -ne $Session) {
        Remove-PSSession $Session -ErrorAction SilentlyContinue
    }
}
