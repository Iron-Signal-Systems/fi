[CmdletBinding()]
param(
    [string]$UNCPath = '',
    [switch]$ConfirmWorkload
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Common-Server2019-Sweep.ps1')

Assert-FI2019Controller
if (-not $ConfirmWorkload) {
    throw '-ConfirmWorkload is required because this true remote SMB pass creates/modifies/deletes bounded test data inside the governed test root.'
}

$Session = $null
$StartedUTC = [DateTime]::UtcNow

try {
    $Session = New-FI2019Session
    $null = Get-FI2019RemotePreflight -Session $Session

    if ([string]::IsNullOrWhiteSpace($UNCPath)) {
        $ShareChoice = Invoke-Command -Session $Session -ArgumentList $FI2019.GovernedRoot -ScriptBlock {
            param($GovernedRoot)

            $RootFull = [IO.Path]::GetFullPath($GovernedRoot).TrimEnd('\')
            $Candidates = @(
                Get-SmbShare -ErrorAction Stop |
                    Where-Object { $_.Path -and -not $_.Special } |
                    Sort-Object { $_.Path.Length } -Descending
            )

            foreach ($Share in $Candidates) {
                $ShareFull = [IO.Path]::GetFullPath($Share.Path).TrimEnd('\')
                if (
                    $RootFull -ieq $ShareFull -or
                    $RootFull.StartsWith($ShareFull + '\',[StringComparison]::OrdinalIgnoreCase)
                ) {
                    $Relative = $RootFull.Substring($ShareFull.Length).TrimStart('\')
                    return [PSCustomObject]@{
                        Name = $Share.Name
                        Relative = $Relative
                    }
                }
            }

            return $null
        }

        if ($null -ne $ShareChoice) {
            $UNCPath = "\\$($FI2019.TargetHost)\$($ShareChoice.Name)"
            if (-not [string]::IsNullOrWhiteSpace([string]$ShareChoice.Relative)) {
                $UNCPath = Join-Path $UNCPath ([string]$ShareChoice.Relative)
            }
            Write-Host "[INFO] Using existing non-special share: $UNCPath"
        }
        else {
            $UNCPath = "\\$($FI2019.TargetHost)\C$\FI-Governed-Test"
            Write-Host "[INFO] No existing non-special share exposes the governed root."
            Write-Host "[INFO] Falling back to the administrative-share SMB path for true remote transport: $UNCPath"
        }
    }

    if (-not (Test-Path -LiteralPath $UNCPath -PathType Container)) {
        throw "Remote SMB path is not reachable from $env:COMPUTERNAME: $UNCPath"
    }

    $RemoteSMBDir = Join-Path $FI2019.LocalResultDirectory 'remote-smb'
    New-Item -Path $RemoteSMBDir -ItemType Directory -Force | Out-Null

    $BeforeCount = Invoke-Command -Session $Session -ScriptBlock {
        $Path = 'C:\ProgramData\FI\state\service-runtime.jsonl'
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 0 }
        $Count = 0
        foreach ($Line in @(Get-Content -LiteralPath $Path -Tail 512 -ErrorAction Stop)) {
            try {
                $Record = $Line | ConvertFrom-Json
                if ($Record.record_kind -eq 'ConfiguredCollection') { $Count++ }
            }
            catch {}
        }
        return $Count
    }

    $Test10B = Join-Path $FI2019.RepoRoot 'tools\gate1\10B-RemoteClient-SMB-Activity.ps1'
    & $Test10B -UNCPath $UNCPath -ResultDirectory $RemoteSMBDir -ConfirmWorkload

    $ClientReport = Get-ChildItem -LiteralPath $RemoteSMBDir -Filter 'gate1-remote-smb-*.json' -File |
        Where-Object { $_.LastWriteTimeUtc -ge $StartedUTC.AddMinutes(-1) } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    if ($null -eq $ClientReport) {
        throw '10B completed without a discoverable client report.'
    }

    $Client = [IO.File]::ReadAllText($ClientReport.FullName) | ConvertFrom-Json
    $RunID = [string]$Client.RunID

    Write-Host ''
    Write-Host "[INFO] Remote SMB RunID: $RunID"
    Write-Host '[INFO] Waiting for a post-workload configured collection before server correlation...'

    $Deadline = [DateTime]::UtcNow.AddSeconds(180)
    $NextHeartbeat = [DateTime]::UtcNow.AddSeconds(15)
    $ObservedCollection = $false

    while ([DateTime]::UtcNow -lt $Deadline) {
        $Latest = Invoke-Command -Session $Session -ArgumentList ([DateTime]$Client.FinishedUTC) -ScriptBlock {
            param($AfterUTC)
            $Path = 'C:\ProgramData\FI\state\service-runtime.jsonl'
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }

            $Lines = @(Get-Content -LiteralPath $Path -Tail 512 -ErrorAction Stop)
            for ($Index = $Lines.Count - 1; $Index -ge 0; $Index--) {
                try {
                    $Record = $Lines[$Index] | ConvertFrom-Json
                    if ($Record.record_kind -ne 'ConfiguredCollection') { continue }
                    $Observed = [DateTime]::Parse(
                        [string]$Record.observed_at,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind
                    ).ToUniversalTime()
                    if ($Observed -gt $AfterUTC.ToUniversalTime()) {
                        return $Record
                    }
                }
                catch {}
            }
            return $null
        }

        if ($null -ne $Latest) {
            $ObservedCollection = $true
            Write-Host "[PASS] Post-remote-SMB configured collection observed: $($Latest.observed_at)"
            break
        }

        if ([DateTime]::UtcNow -ge $NextHeartbeat) {
            $Remaining = [int][Math]::Max(0,($Deadline - [DateTime]::UtcNow).TotalSeconds)
            Write-Host "[INFO] Waiting for FI collection; approximately $Remaining seconds remain in the bounded wait."
            $NextHeartbeat = $NextHeartbeat.AddSeconds(15)
        }

        Start-Sleep -Seconds 3
    }

    if (-not $ObservedCollection) {
        throw 'No post-remote-SMB configured collection completed within 180 seconds.'
    }

    $Correlation = Invoke-Command -Session $Session -ArgumentList @(
        $FI2019.RemoteToolsRoot,$RunID,$FI2019.RemoteResultDirectory
    ) -ScriptBlock {
        param($Tools,$RunID,$ResultDirectory)

        $Test10C = Join-Path $Tools 'gate1\10C-FileServer-Remote-SMB-Correlation.ps1'
        & $Test10C -RunID $RunID -LookbackMinutes 60 -ResultDirectory $ResultDirectory

        $Path = Join-Path $ResultDirectory "gate1-remote-smb-correlation-$($env:COMPUTERNAME)-$($RunID.ToLowerInvariant()).json"
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "10C correlation report not found: $Path"
        }
        $Report = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
        [PSCustomObject]@{
            Path = $Path
            Event5145Count = [int]$Report.Event5145Count
            SpoolMatchTotal = [int]$Report.SpoolMatchTotal
            SecurityQueryMayBeTruncated = [bool]$Report.SecurityQueryMayBeTruncated
        }
    }

    if ($Correlation.SecurityQueryMayBeTruncated) {
        throw '10C Security query hit its event bound; remote SMB acceptance would be ambiguous.'
    }
    if ($Correlation.Event5145Count -lt 1) {
        throw 'No matching true-remote Event ID 5145 was observed.'
    }
    if ($Correlation.SpoolMatchTotal -lt 1) {
        throw 'No matching FI spool record was observed for the true remote SMB workload.'
    }

    $CorrelationLocal = Join-Path $RemoteSMBDir ([IO.Path]::GetFileName([string]$Correlation.Path))
    Copy-Item -FromSession $Session -LiteralPath ([string]$Correlation.Path) -Destination $CorrelationLocal -Force

    $Summary = [ordered]@{
        RecordKind = 'FIGate1Server2019RemoteSMB'
        Host = $FI2019.TargetHost
        ClientHost = $env:COMPUTERNAME
        RunID = $RunID
        UNCPath = $UNCPath
        StartedUTC = $StartedUTC.ToString('o')
        FinishedUTC = [DateTime]::UtcNow.ToString('o')
        OverallStatus = 'PASS'
        Event5145Count = $Correlation.Event5145Count
        SpoolMatchTotal = $Correlation.SpoolMatchTotal
        ClientReport = $ClientReport.FullName
        CorrelationReport = $CorrelationLocal
    }

    $SummaryPath = Join-Path $RemoteSMBDir "server2019-remote-smb-summary-$RunID.json"
    $Summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

    Write-Host ''
    Write-Host '============================================================'
    Write-Host '[PASS] SERVER 2019 TRUE REMOTE SMB PASS COMPLETE'
    Write-Host '============================================================'
    Write-Host "RunID:            $RunID"
    Write-Host "Event 5145 count: $($Correlation.Event5145Count)"
    Write-Host "FI spool matches: $($Correlation.SpoolMatchTotal)"
    Write-Host "Summary:          $SummaryPath"
}
finally {
    if ($null -ne $Session) {
        Remove-PSSession $Session -ErrorAction SilentlyContinue
    }
}
