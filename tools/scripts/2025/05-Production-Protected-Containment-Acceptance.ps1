# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

$ErrorActionPreference = 'Stop'

$Server = 'ISS-FS-25'
$ExpectedBuild = '26100'

$CollectorService = 'FICollector'
$HelperService = 'FIUSNReader'

$ExpectedCollectorPath = '"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m'
$ExpectedHelperPath = '"C:\Program Files\FI\fi-usn.exe"'

$GovernedRoot = 'C:\FI-Test\governed-2025'
$ProtectedRoot = 'C:\Windows\System32\LogFiles\WMI\RtBackup'

$LocalProbe = 'C:\FI-Test\production-containment\FI-Containment-Client-Probe-2025.exe'
$RemoteProbe = 'C:\FI-Test\production-containment\FI-Containment-Client-Probe-2025.exe'

$InputFile = 'C:\FI-Test\production-containment\containment-client-2025-input.json'
$ResultFile = 'C:\FI-Test\production-containment\containment-client-2025-result.json'
$ErrorFile = 'C:\FI-Test\production-containment\containment-client-2025-error.txt'
$RuntimeLog = 'C:\ProgramData\FI\state\service-runtime.jsonl'

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
        $Current = (
            Get-Service -Name $Name -ErrorAction Stop
        ).Status.ToString()

        if ($Current -eq $State) {
            return
        }

        Start-Sleep -Milliseconds 250
    }
    while ((Get-Date) -lt $Deadline)

    throw "$Name did not reach $State within $TimeoutSeconds seconds."
}

Write-Host ""
Write-Host "============================================================"
Write-Host "FI SERVER 2025 - PRODUCTION PROTECTED CONTAINMENT ACCEPTANCE"
Write-Host "Target: $Server"
Write-Host "Build:  $ExpectedBuild"
Write-Host "============================================================"

if (-not (Test-Path -LiteralPath $LocalProbe -PathType Leaf)) {
    throw "Local production-containment client probe is missing: $LocalProbe"
}

Write-Host ""
Write-Host "=== LOCAL PROBE ==="

Get-Item -LiteralPath $LocalProbe |
    Select-Object FullName,Length,LastWriteTime

Get-FileHash -LiteralPath $LocalProbe -Algorithm SHA256 |
    Format-List Algorithm,Hash,Path

$Session = New-PSSession -ComputerName $Server

try {
    Write-Host ""
    Write-Host "=== TARGET PREFLIGHT ==="

    Invoke-Command -Session $Session -ScriptBlock {
        param(
            $ExpectedBuild,
            $CollectorService,
            $HelperService,
            $ExpectedCollectorPath,
            $ExpectedHelperPath,
            $GovernedRoot,
            $ProtectedRoot
        )

        $OS = Get-CimInstance Win32_OperatingSystem

        Write-Host "[INFO] Host:    $env:COMPUTERNAME"
        Write-Host "[INFO] Caption: $($OS.Caption)"
        Write-Host "[INFO] Version: $($OS.Version)"
        Write-Host "[INFO] Build:   $($OS.BuildNumber)"

        if ($env:COMPUTERNAME -ine 'ISS-FS-25') {
            throw 'Expected ISS-FS-25.'
        }

        if ($OS.BuildNumber -ne $ExpectedBuild) {
            throw "Expected build $ExpectedBuild. Observed $($OS.BuildNumber)."
        }

        $Collector = Get-CimInstance `
            Win32_Service `
            -Filter "Name='$CollectorService'" `
            -ErrorAction Stop

        $Helper = Get-CimInstance `
            Win32_Service `
            -Filter "Name='$HelperService'" `
            -ErrorAction Stop

        if ($Collector.PathName -ne $ExpectedCollectorPath) {
            throw "FICollector PathName mismatch.`nExpected: $ExpectedCollectorPath`nObserved: $($Collector.PathName)"
        }

        if ($Helper.PathName -ne $ExpectedHelperPath) {
            throw "FIUSNReader PathName mismatch.`nExpected: $ExpectedHelperPath`nObserved: $($Helper.PathName)"
        }

        if ($Collector.State -ne 'Running') {
            throw "FICollector must be Running before acceptance. Observed: $($Collector.State)"
        }

        if ($Helper.State -ne 'Running') {
            throw "FIUSNReader must be Running before acceptance. Observed: $($Helper.State)"
        }

        if (-not (Test-Path '\\.\pipe\FI-USN')) {
            throw 'FI-USN pipe was not observed.'
        }

        if (-not (Test-Path -LiteralPath $GovernedRoot -PathType Container)) {
            throw "Governed root is missing: $GovernedRoot"
        }

        if (-not (Test-Path -LiteralPath $ProtectedRoot -PathType Container)) {
            throw "Protected root is missing: $ProtectedRoot"
        }

        Write-Host "[PASS] Production pair preflight passed."
    } -ArgumentList `
        $ExpectedBuild,
        $CollectorService,
        $HelperService,
        $ExpectedCollectorPath,
        $ExpectedHelperPath,
        $GovernedRoot,
        $ProtectedRoot

    Write-Host ""
    Write-Host "=== COPY CLIENT PROBE ==="

    Invoke-Command -Session $Session -ScriptBlock {
        New-Item `
            -Path 'C:\FI-Test\production-containment' `
            -ItemType Directory `
            -Force |
            Out-Null
    }

    Copy-Item `
        -LiteralPath $LocalProbe `
        -Destination $RemoteProbe `
        -ToSession $Session `
        -Force

    Invoke-Command -Session $Session -ScriptBlock {
        param($RemoteProbe)

        Get-Item -LiteralPath $RemoteProbe |
            Select-Object FullName,Length,LastWriteTime

        Get-FileHash -LiteralPath $RemoteProbe -Algorithm SHA256 |
            Format-List Algorithm,Hash,Path
    } -ArgumentList $RemoteProbe

    Write-Host ""
    Write-Host "=== RUN PRODUCTION BROKER CONTAINMENT ACCEPTANCE ==="

    Invoke-Command -Session $Session -ScriptBlock {
        param(
            $CollectorService,
            $HelperService,
            $ExpectedCollectorPath,
            $GovernedRoot,
            $ProtectedRoot,
            $RemoteProbe,
            $InputFile,
            $ResultFile,
            $ErrorFile,
            $RuntimeLog
        )

        function Set-FIServicePath {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Name,

                [Parameter(Mandatory = $true)]
                [string]$PathName
            )

            $Service = Get-CimInstance `
                Win32_Service `
                -Filter "Name='$Name'" `
                -ErrorAction Stop

            $Result = Invoke-CimMethod `
                -InputObject $Service `
                -MethodName Change `
                -Arguments @{
                    PathName = $PathName
                }

            if ($Result.ReturnValue -ne 0) {
                throw "$Name PathName change failed. ReturnValue=$($Result.ReturnValue)"
            }
        }

        function Wait-LocalServiceState {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Name,

                [Parameter(Mandatory = $true)]
                [string]$State,

                [int]$TimeoutSeconds = 30
            )

            $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

            do {
                $Current = (
                    Get-Service -Name $Name -ErrorAction Stop
                ).Status.ToString()

                if ($Current -eq $State) {
                    return
                }

                Start-Sleep -Milliseconds 250
            }
            while ((Get-Date) -lt $Deadline)

            throw "$Name did not reach $State within $TimeoutSeconds seconds."
        }

        Write-Host ""
        Write-Host "--- SELECT PROTECTED TARGET ---"

        $Target = Get-ChildItem `
            -LiteralPath $ProtectedRoot `
            -File `
            -Force |
            Sort-Object Name |
            Select-Object -First 1

        if ($null -eq $Target) {
            throw "No protected ETL target found under $ProtectedRoot."
        }

        Write-Host "[INFO] Target: $($Target.FullName)"

        Write-Host ""
        Write-Host "--- QUERY FILE ID ---"

        $PreviousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'

        $FileIDOutput = @(
            & fsutil.exe file queryfileid $Target.FullName 2>&1
        )
        $FileIDExitCode = $LASTEXITCODE

        $ErrorActionPreference = $PreviousErrorActionPreference

        $FileIDOutput | ForEach-Object {
            Write-Host $_
        }

        if ($FileIDExitCode -ne 0) {
            throw "fsutil file queryfileid failed with exit code $FileIDExitCode."
        }

        $FileIDText = $FileIDOutput -join "`n"

        $FileIDMatch = [regex]::Match(
            $FileIDText,
            '(?i)0x([0-9a-f]{32})'
        )

        if (-not $FileIDMatch.Success) {
            throw 'Could not parse the 128-bit NTFS file ID.'
        }

        $FileIDHex = $FileIDMatch.Groups[1].Value.ToLowerInvariant()
        $High64Hex = $FileIDHex.Substring(0,16)
        $Low64Hex = $FileIDHex.Substring(16,16)

        if ($High64Hex -ne '0000000000000000') {
            throw "Expected NTFS 64-bit file ID in low 64 bits. Observed 0x$FileIDHex."
        }

        $FileID64 = [Convert]::ToUInt64($Low64Hex,16)
        $FRN = $FileID64 -band [UInt64]0x0000FFFFFFFFFFFF
        $Sequence = ($FileID64 -shr 48) -band [UInt64]0xFFFF

        Write-Host "[INFO] FRN:      $FRN"
        Write-Host "[INFO] Sequence: $Sequence"

        Write-Host ""
        Write-Host "--- CREATE CLIENT INPUT ---"

        [ordered]@{
            governed_root         = $GovernedRoot
            file_reference_number = $FRN.ToString()
            sequence_number       = $Sequence.ToString()
            target_description    = $Target.FullName
        } |
            ConvertTo-Json |
            Set-Content `
                -LiteralPath $InputFile `
                -Encoding ASCII

        Get-Content -LiteralPath $InputFile

        Remove-Item `
            -LiteralPath $ResultFile,$ErrorFile `
            -Force `
            -ErrorAction SilentlyContinue

        $Collector = Get-CimInstance `
            Win32_Service `
            -Filter "Name='$CollectorService'" `
            -ErrorAction Stop

        $OriginalPath = $Collector.PathName

        if ($OriginalPath -ne $ExpectedCollectorPath) {
            throw 'FICollector production PathName changed before the acceptance probe.'
        }

        $LastConfiguredBefore = $null

        if (Test-Path -LiteralPath $RuntimeLog -PathType Leaf) {
            $RuntimeRecords = @(
                Get-Content -LiteralPath $RuntimeLog |
                    ForEach-Object {
                        if (-not [string]::IsNullOrWhiteSpace($_)) {
                            $_ | ConvertFrom-Json
                        }
                    }
            )

            $ConfiguredBefore = @(
                $RuntimeRecords |
                    Where-Object {
                        $_.record_kind -eq 'ConfiguredCollection'
                    } |
                    Select-Object -Last 1
            )

            if ($ConfiguredBefore.Count -gt 0) {
                $LastConfiguredBefore = $ConfiguredBefore[0].observed_at
            }
        }

        Write-Host "[INFO] Last production ConfiguredCollection before probe: $LastConfiguredBefore"

        try {
            Write-Host ""
            Write-Host "--- STOP PRODUCTION COLLECTOR ---"

            Stop-Service -Name $CollectorService -ErrorAction Stop
            Wait-LocalServiceState -Name $CollectorService -State 'Stopped'

            Write-Host "[PASS] Production FICollector stopped."

            Write-Host ""
            Write-Host "--- TEMPORARILY POINT FICollector SERVICE AT CLIENT PROBE ---"

            Set-FIServicePath `
                -Name $CollectorService `
                -PathName $RemoteProbe

            $ProbeService = Get-CimInstance `
                Win32_Service `
                -Filter "Name='$CollectorService'" `
                -ErrorAction Stop

            Write-Host "[INFO] Probe PathName: $($ProbeService.PathName)"

            Write-Host ""
            Write-Host "--- START CLIENT PROBE UNDER REAL FICollector SERVICE TOKEN ---"

            # The client probe is intentionally short-lived. PowerShell's
            # Start-Service waits for a stable Running state and can report a
            # false start failure after the probe has already completed
            # successfully. Start through sc.exe, record its diagnostic result,
            # and judge acceptance from the probe result/error files instead.
            $PreviousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'

            $ProbeStartOutput = @(
                & sc.exe start $CollectorService 2>&1 |
                    ForEach-Object { $_.ToString() }
            )
            $ProbeStartExitCode = $LASTEXITCODE

            $ErrorActionPreference = $PreviousErrorActionPreference

            $ProbeStartOutput | ForEach-Object {
                Write-Host $_
            }

            Write-Host "[INFO] sc.exe start exit code: $ProbeStartExitCode"

            $Deadline = (Get-Date).AddSeconds(30)

            while (
                -not (Test-Path -LiteralPath $ResultFile) -and
                -not (Test-Path -LiteralPath $ErrorFile) -and
                (Get-Date) -lt $Deadline
            ) {
                Start-Sleep -Milliseconds 250
            }

            Write-Host ""
            Write-Host "--- CLIENT PROBE RESULT ---"

            if (Test-Path -LiteralPath $ErrorFile -PathType Leaf) {
                Get-Content -LiteralPath $ErrorFile
                throw 'Production containment client probe reported an error.'
            }

            if (-not (Test-Path -LiteralPath $ResultFile -PathType Leaf)) {
                sc.exe query $CollectorService | Out-Host
                throw "Production containment client probe produced no result. sc.exe start exit code: $ProbeStartExitCode"
            }

            $ProbeResult = Get-Content `
                -LiteralPath $ResultFile `
                -Raw |
                ConvertFrom-Json

            $ProbeResult |
                ConvertTo-Json -Depth 8 |
                Write-Host

            if ($ProbeResult.broker_result -ne 'Outside') {
                throw "Expected production broker result Outside. Observed: $($ProbeResult.broker_result)"
            }

            Write-Host "[PASS] Production FIUSNReader returned Outside for the protected out-of-scope ETL."
        }
        finally {
            Write-Host ""
            Write-Host "--- RESTORE PRODUCTION FICollector ---"

            Stop-Service `
                -Name $CollectorService `
                -ErrorAction SilentlyContinue

            $StopDeadline = (Get-Date).AddSeconds(15)

            while (
                (Get-Service -Name $CollectorService).Status -ne 'Stopped' -and
                (Get-Date) -lt $StopDeadline
            ) {
                Start-Sleep -Milliseconds 250
            }

            Set-FIServicePath `
                -Name $CollectorService `
                -PathName $OriginalPath

            $Restored = Get-CimInstance `
                Win32_Service `
                -Filter "Name='$CollectorService'" `
                -ErrorAction Stop

            if ($Restored.PathName -ne $OriginalPath) {
                throw 'FICollector exact production PathName was not restored.'
            }

            Start-Service -Name $CollectorService -ErrorAction Stop
            Wait-LocalServiceState -Name $CollectorService -State 'Running'

            Write-Host "[PASS] Exact production FICollector PathName restored and service restarted."
        }

        Write-Host ""
        Write-Host "--- WAIT FOR FRESH PRODUCTION COLLECTION AFTER RESTORE ---"

        $CollectionDeadline = (Get-Date).AddSeconds(120)
        $FreshCollection = $null

        while (
            $null -eq $FreshCollection -and
            (Get-Date) -lt $CollectionDeadline
        ) {
            if (Test-Path -LiteralPath $RuntimeLog -PathType Leaf) {
                $Records = @(
                    Get-Content -LiteralPath $RuntimeLog |
                        ForEach-Object {
                            if (-not [string]::IsNullOrWhiteSpace($_)) {
                                $_ | ConvertFrom-Json
                            }
                        }
                )

                $CollectionMatches = @(
                    $Records |
                        Where-Object {
                            $_.record_kind -eq 'ConfiguredCollection' -and
                            (
                                $null -eq $LastConfiguredBefore -or
                                [string]::CompareOrdinal(
                                    [string]$_.observed_at,
                                    [string]$LastConfiguredBefore
                                ) -gt 0
                            )
                        } |
                        Select-Object -Last 1
                )

                if ($CollectionMatches.Count -gt 0) {
                    $FreshCollection = $CollectionMatches[0]
                    break
                }
            }

            Start-Sleep -Seconds 1
        }

        if ($null -eq $FreshCollection) {
            throw 'No fresh ConfiguredCollection was observed after restoring production FICollector.'
        }

        $FreshCollection |
            ConvertTo-Json -Depth 8 |
            Write-Host

        if ($FreshCollection.outcome -ne 'Complete') {
            throw "Restored production collection was not Complete. Outcome: $($FreshCollection.outcome)"
        }

        if ((Get-Service -Name $HelperService).Status -ne 'Running') {
            throw 'FIUSNReader is not Running after production containment acceptance.'
        }

        if (-not (Test-Path '\\.\pipe\FI-USN')) {
            throw 'FI-USN pipe is not present after production containment acceptance.'
        }

        Write-Host "[PASS] Restored production FICollector completed a fresh normal collection."
        Write-Host "[PASS] FIUSNReader remained healthy."
        Write-Host ""
        Write-Host "[PASS] SERVER 2025 PRODUCTION PROTECTED CONTAINMENT ACCEPTANCE PASSED."
    } -ArgumentList `
        $CollectorService,
        $HelperService,
        $ExpectedCollectorPath,
        $GovernedRoot,
        $ProtectedRoot,
        $RemoteProbe,
        $InputFile,
        $ResultFile,
        $ErrorFile,
        $RuntimeLog
}
finally {
    if ($null -ne $Session) {
        Remove-PSSession $Session
    }
}
