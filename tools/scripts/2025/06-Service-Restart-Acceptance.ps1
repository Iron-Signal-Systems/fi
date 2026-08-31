# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

param(
    [string]$Target = "ISS-FS-25"
)

$ErrorActionPreference = "Stop"

$ExpectedCollectorPath = '"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m'
$ExpectedHelperPath = '"C:\Program Files\FI\fi-usn.exe"'

Write-Host ""
Write-Host "============================================================"
Write-Host "FI SERVER 2025 - PRODUCTION SERVICE RESTART ACCEPTANCE"
Write-Host "Target: $Target"
Write-Host "Build:  26100"
Write-Host "============================================================"

$Session = New-PSSession -ComputerName $Target

try {
    Invoke-Command -Session $Session -ArgumentList $ExpectedCollectorPath,$ExpectedHelperPath -ScriptBlock {
        param(
            [string]$ExpectedCollectorPath,
            [string]$ExpectedHelperPath
        )

        $ErrorActionPreference = "Stop"

        function Get-FILatestConfiguredCollection {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Path
            )

            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
                return $null
            }

            $Lines = Get-Content -LiteralPath $Path

            for ($Index = $Lines.Count - 1; $Index -ge 0; $Index--) {
                try {
                    $Record = $Lines[$Index] | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    continue
                }

                if ($Record.record_kind -eq "ConfiguredCollection") {
                    return $Record
                }
            }

            return $null
        }

        function Get-FIConfiguredRoot {
            $ConfigPath = "C:\ProgramData\FI\config\fi.conf"

            if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
                throw "FI config not found: $ConfigPath"
            }

            $Roots = @()

            foreach ($Line in Get-Content -LiteralPath $ConfigPath) {
                $RootMatch = [regex]::Match(
                    $Line,
                    '^\s*governed_root\s*:\s*(.+?)\s*$'
                )

                if ($RootMatch.Success) {
                    $Roots += $RootMatch.Groups[1].Value.Trim()
                }
            }

            if ($Roots.Count -ne 1) {
                throw "Service restart acceptance requires exactly one configured governed root. Observed: $($Roots.Count)"
            }

            return $Roots[0]
        }

        function Get-FIUSNCheckpointPath {
            $Candidates = @(
                Get-ChildItem `
                    -LiteralPath "C:\ProgramData\FI\state" `
                    -Filter "root-*-usn.json" `
                    -File `
                    -ErrorAction Stop
            )

            if ($Candidates.Count -ne 1) {
                throw "Service restart acceptance requires exactly one root USN checkpoint. Observed: $($Candidates.Count)"
            }

            return $Candidates[0].FullName
        }

        function ConvertTo-FIUTF16LEBase64Url {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Value
            )

            return [Convert]::ToBase64String(
                [Text.Encoding]::Unicode.GetBytes($Value)
            ).TrimEnd('=').Replace('+','-').Replace('/','_')
        }

        function Wait-FIFileInSpool {
            param(
                [Parameter(Mandatory = $true)]
                [string]$FileName,

                [int]$TimeoutSeconds = 120
            )

            $EncodedFileName = ConvertTo-FIUTF16LEBase64Url -Value $FileName

            $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

            do {
                $Files = @(
                    Get-ChildItem `
                        -LiteralPath "C:\ProgramData\FI\spool" `
                        -Filter "*.jsonl" `
                        -File `
                        -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTimeUtc -Descending |
                        Select-Object -First 100
                )

                foreach ($File in $Files) {
                    $Found = Select-String `
                        -LiteralPath $File.FullName `
                        -SimpleMatch `
                        -Pattern $EncodedFileName `
                        -ErrorAction SilentlyContinue

                    if ($Found) {
                        return $Found
                    }
                }

                Start-Sleep -Milliseconds 500
            }
            while ((Get-Date) -lt $Deadline)

            return $null
        }

        function Wait-FIPipe {
            param(
                [int]$TimeoutSeconds = 120
            )

            $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

            do {
                $Helper = Get-Service -Name "FIUSNReader" -ErrorAction Stop

                if ($Helper.Status -ne "Running") {
                    throw "FIUSNReader stopped while waiting for the FI-USN pipe."
                }

                if (Test-Path '\\.\pipe\FI-USN') {
                    return
                }

                Start-Sleep -Milliseconds 500
            }
            while ((Get-Date) -lt $Deadline)

            throw "FI-USN pipe was not observed within $TimeoutSeconds seconds."
        }

        function Wait-FIServiceState {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Name,

                [Parameter(Mandatory = $true)]
                [string]$State,

                [int]$TimeoutSeconds = 30
            )

            $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

            do {
                $Current = (Get-Service -Name $Name -ErrorAction Stop).Status.ToString()

                if ($Current -eq $State) {
                    return
                }

                Start-Sleep -Milliseconds 250
            }
            while ((Get-Date) -lt $Deadline)

            throw "$Name did not reach $State within $TimeoutSeconds seconds."
        }

        function Wait-FIUSNAdvance {
            param(
                [Parameter(Mandatory = $true)]
                [string]$CheckpointPath,

                [Parameter(Mandatory = $true)]
                [UInt64]$BeforeUSN,

                [int]$TimeoutSeconds = 120
            )

            $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

            do {
                try {
                    $Current = Get-Content -LiteralPath $CheckpointPath -Raw |
                        ConvertFrom-Json -ErrorAction Stop

                    if ([UInt64]$Current.next_usn -gt $BeforeUSN) {
                        return $Current
                    }
                }
                catch {
                }

                Start-Sleep -Milliseconds 500
            }
            while ((Get-Date) -lt $Deadline)

            return $null
        }

        function Wait-FIFreshConfiguredCollection {
            param(
                [Parameter(Mandatory = $true)]
                [string]$RuntimePath,

                [string]$BeforeObservedAt,

                [int]$TimeoutSeconds = 120
            )

            $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

            do {
                $Current = Get-FILatestConfiguredCollection -Path $RuntimePath

                if (
                    $Current -and
                    [string]$Current.observed_at -ne $BeforeObservedAt
                ) {
                    return $Current
                }

                Start-Sleep -Milliseconds 500
            }
            while ((Get-Date) -lt $Deadline)

            return $null
        }

        $OS = Get-CimInstance Win32_OperatingSystem

        Write-Host ""
        Write-Host "=== PREFLIGHT ==="
        Write-Host "[INFO] Host:    $env:COMPUTERNAME"
        Write-Host "[INFO] Caption: $($OS.Caption)"
        Write-Host "[INFO] Version: $($OS.Version)"
        Write-Host "[INFO] Build:   $($OS.BuildNumber)"

        if ($OS.BuildNumber -ne "26100") {
            throw "This acceptance is scoped only to Windows Server 2025 build 26100."
        }

        $CollectorConfig = Get-CimInstance Win32_Service -Filter "Name='FICollector'"
        $HelperConfig = Get-CimInstance Win32_Service -Filter "Name='FIUSNReader'"

        if ($CollectorConfig.PathName -ne $ExpectedCollectorPath) {
            throw "FICollector PathName does not match the reviewed production value."
        }

        if ($HelperConfig.PathName -ne $ExpectedHelperPath) {
            throw "FIUSNReader PathName does not match the reviewed production value."
        }

        if ((Get-Service FICollector).Status -ne "Running") {
            throw "FICollector is not running before restart acceptance."
        }

        if ((Get-Service FIUSNReader).Status -ne "Running") {
            throw "FIUSNReader is not running before restart acceptance."
        }

        if (-not (Test-Path '\\.\pipe\FI-USN')) {
            throw "FI-USN pipe is not present before restart acceptance."
        }

        $GovernedRoot = Get-FIConfiguredRoot
        $CheckpointPath = Get-FIUSNCheckpointPath
        $BeforeCheckpoint = Get-Content -LiteralPath $CheckpointPath -Raw |
            ConvertFrom-Json -ErrorAction Stop
        $BeforeUSN = [UInt64]$BeforeCheckpoint.next_usn

        $RuntimePath = "C:\ProgramData\FI\state\service-runtime.jsonl"
        $BeforeRuntime = Get-FILatestConfiguredCollection -Path $RuntimePath

        if (-not $BeforeRuntime) {
            throw "No ConfiguredCollection record exists before restart acceptance."
        }

        $BeforeRuntimeObserved = [string]$BeforeRuntime.observed_at
        $FileName = "fi-service-restart-2025-$([Guid]::NewGuid().ToString('N')).txt"
        $TestPath = Join-Path $GovernedRoot $FileName

        Write-Host "[INFO] Governed root: $GovernedRoot"
        Write-Host "[INFO] Checkpoint:    $CheckpointPath"
        Write-Host "[INFO] Before USN:    $BeforeUSN"
        Write-Host "[INFO] Runtime before: $BeforeRuntimeObserved"
        Write-Host "[PASS] Production restart preflight passed."

        $AcceptancePassed = $false

        try {
            Write-Host ""
            Write-Host "=== STOP PRODUCTION PAIR ==="

            Stop-Service FICollector -ErrorAction Stop
            Wait-FIServiceState -Name "FICollector" -State "Stopped"
            Write-Host "[PASS] FICollector stopped."

            Stop-Service FIUSNReader -ErrorAction Stop
            Wait-FIServiceState -Name "FIUSNReader" -State "Stopped"
            Write-Host "[PASS] FIUSNReader stopped."

            "FI Server 2025 service restart acceptance $(Get-Date -Format o)" |
                Set-Content -LiteralPath $TestPath

            Write-Host "[INFO] Created governed-root change while production pair was stopped:"
            Write-Host "       $TestPath"

            $StoppedCheckpoint = Get-Content -LiteralPath $CheckpointPath -Raw |
                ConvertFrom-Json -ErrorAction Stop

            if ([UInt64]$StoppedCheckpoint.next_usn -ne $BeforeUSN) {
                throw "USN checkpoint advanced while both FI services were stopped."
            }

            Write-Host "[PASS] USN checkpoint remained frozen while production pair was stopped."

            Write-Host ""
            Write-Host "=== START PRODUCTION PAIR ==="

            Start-Service FIUSNReader -ErrorAction Stop
            Wait-FIServiceState -Name "FIUSNReader" -State "Running"
            Wait-FIPipe -TimeoutSeconds 120
            Write-Host "[PASS] FIUSNReader restarted and FI-USN pipe is present."

            Start-Service FICollector -ErrorAction Stop
            Wait-FIServiceState -Name "FICollector" -State "Running"
            Write-Host "[PASS] FICollector restarted."

            $AfterCheckpoint = Wait-FIUSNAdvance `
                -CheckpointPath $CheckpointPath `
                -BeforeUSN $BeforeUSN `
                -TimeoutSeconds 120

            if (-not $AfterCheckpoint) {
                throw "USN checkpoint did not advance after production service restart."
            }

            Write-Host "[PASS] USN checkpoint advanced after restart: $BeforeUSN -> $($AfterCheckpoint.next_usn)."

            $AfterRuntime = Wait-FIFreshConfiguredCollection `
                -RuntimePath $RuntimePath `
                -BeforeObservedAt $BeforeRuntimeObserved `
                -TimeoutSeconds 120

            if (-not $AfterRuntime) {
                throw "No fresh ConfiguredCollection was observed after restart."
            }

            Write-Host ""
            Write-Host "=== FRESH CONFIGURED COLLECTION ==="
            $AfterRuntime |
                ConvertTo-Json -Depth 8 |
                Write-Host

            if ($AfterRuntime.outcome -ne "Complete") {
                throw "Fresh ConfiguredCollection after restart was not Complete."
            }

            Write-Host "[PASS] Fresh ConfiguredCollection after restart is Complete."

            $SpoolHit = Wait-FIFileInSpool `
                -FileName $FileName `
                -TimeoutSeconds 120

            if (-not $SpoolHit) {
                throw "The change created while services were stopped was not found in catch-up spool output."
            }

            Write-Host "[PASS] The stopped-service change appeared in catch-up spool output."

            $CollectorAfter = Get-CimInstance Win32_Service -Filter "Name='FICollector'"
            $HelperAfter = Get-CimInstance Win32_Service -Filter "Name='FIUSNReader'"

            if ($CollectorAfter.PathName -ne $ExpectedCollectorPath) {
                throw "FICollector PathName changed during restart acceptance."
            }

            if ($HelperAfter.PathName -ne $ExpectedHelperPath) {
                throw "FIUSNReader PathName changed during restart acceptance."
            }

            Write-Host "[PASS] Exact production service PathName values remained unchanged."

            $AcceptancePassed = $true
        }
        finally {
            Write-Host ""
            Write-Host "=== FINAL SERVICE HEALTH ==="

            if ((Get-Service FIUSNReader).Status -ne "Running") {
                Write-Host "[INFO] Recovering FIUSNReader."
                Start-Service FIUSNReader -ErrorAction Stop
                Wait-FIServiceState -Name "FIUSNReader" -State "Running"
            }

            Wait-FIPipe -TimeoutSeconds 120

            if ((Get-Service FICollector).Status -ne "Running") {
                Write-Host "[INFO] Recovering FICollector."
                Start-Service FICollector -ErrorAction Stop
                Wait-FIServiceState -Name "FICollector" -State "Running"
            }

            Get-Service FICollector,FIUSNReader |
                Format-Table Name,Status -AutoSize

            if ($TestPath -and (Test-Path -LiteralPath $TestPath)) {
                Remove-Item `
                    -LiteralPath $TestPath `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }

        if (-not $AcceptancePassed) {
            throw "Server 2025 production service restart acceptance failed."
        }

        Write-Host ""
        Write-Host "[PASS] SERVER 2025 PRODUCTION SERVICE RESTART ACCEPTANCE PASSED."
    }
}
finally {
    Remove-PSSession $Session -ErrorAction SilentlyContinue
}
