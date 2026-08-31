# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

param(
    [string]$Target = "ISS-FS-25",
    [switch]$ConfirmDisruptive
)

$ErrorActionPreference = "Stop"

$ExpectedCollectorPath = '"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m'
$ExpectedHelperPath = '"C:\Program Files\FI\fi-usn.exe"'

Write-Host ""
Write-Host "============================================================"
Write-Host "FI SERVER 2025 - COLD REBOOT / STARTUP ACCEPTANCE"
Write-Host "Target: $Target"
Write-Host "Build:  26100"
Write-Host "============================================================"
Write-Host ""
Write-Host "WARNING: This test stops both FI services, creates one governed-root"
Write-Host "change, and reboots the Windows Server 2025 file server."
Write-Host "The reboot is initiated locally on the target over the existing WinRM session."
Write-Host ""

if (-not $ConfirmDisruptive) {
    Write-Host "[FAIL] Not run. Re-run with -ConfirmDisruptive after approving the cold reboot."
    exit 2
}

$TestFileName = "fi-cold-reboot-2025-$([Guid]::NewGuid().ToString('N')).txt"

Write-Host "=== PRE-REBOOT PREPARATION ==="

$Before = Invoke-Command `
    -ComputerName $Target `
    -ArgumentList $ExpectedCollectorPath,$ExpectedHelperPath,$TestFileName `
    -ScriptBlock {
        param(
            [string]$ExpectedCollectorPath,
            [string]$ExpectedHelperPath,
            [string]$TestFileName
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
                throw "Cold reboot acceptance requires exactly one configured governed root. Observed: $($Roots.Count)"
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
                throw "Cold reboot acceptance requires exactly one root USN checkpoint. Observed: $($Candidates.Count)"
            }

            return $Candidates[0].FullName
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

        $OS = Get-CimInstance Win32_OperatingSystem

        Write-Host "[INFO] Host:      $env:COMPUTERNAME"
        Write-Host "[INFO] Caption:   $($OS.Caption)"
        Write-Host "[INFO] Version:   $($OS.Version)"
        Write-Host "[INFO] Build:     $($OS.BuildNumber)"
        Write-Host "[INFO] Boot time: $($OS.LastBootUpTime.ToString('o'))"

        if ($OS.BuildNumber -ne "26100") {
            throw "This acceptance is scoped only to Windows Server 2025 build 26100."
        }

        $Collector = Get-CimInstance Win32_Service -Filter "Name='FICollector'"
        $Helper = Get-CimInstance Win32_Service -Filter "Name='FIUSNReader'"

        if ($Collector.PathName -ne $ExpectedCollectorPath) {
            throw "FICollector PathName does not match the reviewed production value."
        }

        if ($Helper.PathName -ne $ExpectedHelperPath) {
            throw "FIUSNReader PathName does not match the reviewed production value."
        }

        if ($Collector.StartMode -ne "Auto") {
            throw "FICollector is not configured for automatic startup."
        }

        if ($Helper.StartMode -ne "Auto") {
            throw "FIUSNReader is not configured for automatic startup."
        }

        if ((Get-Service FICollector).Status -ne "Running") {
            throw "FICollector is not running before cold reboot acceptance."
        }

        if ((Get-Service FIUSNReader).Status -ne "Running") {
            throw "FIUSNReader is not running before cold reboot acceptance."
        }

        if (-not (Test-Path '\\.\pipe\FI-USN')) {
            throw "FI-USN pipe is not present before cold reboot acceptance."
        }

        $GovernedRoot = Get-FIConfiguredRoot
        $CheckpointPath = Get-FIUSNCheckpointPath
        $Checkpoint = Get-Content -LiteralPath $CheckpointPath -Raw |
            ConvertFrom-Json -ErrorAction Stop
        $RuntimePath = "C:\ProgramData\FI\state\service-runtime.jsonl"
        $Runtime = Get-FILatestConfiguredCollection -Path $RuntimePath

        if (-not $Runtime) {
            throw "No ConfiguredCollection record exists before cold reboot acceptance."
        }

        $BeforeUSN = [UInt64]$Checkpoint.next_usn
        $TestPath = Join-Path $GovernedRoot $TestFileName

        Write-Host "[INFO] Governed root: $GovernedRoot"
        Write-Host "[INFO] Checkpoint:    $CheckpointPath"
        Write-Host "[INFO] Before USN:    $BeforeUSN"
        Write-Host "[INFO] Runtime before: $($Runtime.observed_at)"

        Stop-Service FICollector -ErrorAction Stop
        Wait-FIServiceState -Name "FICollector" -State "Stopped"
        Write-Host "[PASS] FICollector stopped for cold reboot setup."

        Stop-Service FIUSNReader -ErrorAction Stop
        Wait-FIServiceState -Name "FIUSNReader" -State "Stopped"
        Write-Host "[PASS] FIUSNReader stopped for cold reboot setup."

        "FI Server 2025 cold reboot acceptance $(Get-Date -Format o)" |
            Set-Content -LiteralPath $TestPath

        $StoppedCheckpoint = Get-Content -LiteralPath $CheckpointPath -Raw |
            ConvertFrom-Json -ErrorAction Stop

        if ([UInt64]$StoppedCheckpoint.next_usn -ne $BeforeUSN) {
            throw "USN checkpoint advanced after both FI services were stopped."
        }

        Write-Host "[PASS] Created an uncollected governed-root change with checkpoint frozen."
        Write-Host "[INFO] Test path: $TestPath"

        [PSCustomObject]@{
            boot_time = $OS.LastBootUpTime.ToString("o")
            checkpoint_path = $CheckpointPath
            before_usn = [string]$BeforeUSN
            before_runtime_observed = [string]$Runtime.observed_at
            governed_root = $GovernedRoot
            test_path = $TestPath
            file_name = $TestFileName
        }
    }

Write-Host ""
Write-Host "=== INITIATE COLD REBOOT ==="

try {
    $RebootRequest = Invoke-Command `
        -ComputerName $Target `
        -ScriptBlock {
            $Output = @(
                & shutdown.exe `
                    /r `
                    /t 5 `
                    /f `
                    /c "FI Server 2025 reboot/startup acceptance" `
                    2>&1 |
                    ForEach-Object { $_.ToString() }
            )

            [PSCustomObject]@{
                exit_code = $LASTEXITCODE
                output = $Output
            }
        } `
        -ErrorAction Stop

    if ($RebootRequest.exit_code -ne 0) {
        throw "Target-local shutdown.exe reboot request failed with exit code $($RebootRequest.exit_code): $($RebootRequest.output -join ' ')"
    }
}
catch {
    Write-Host "[FAIL] Target-local reboot request failed before the host restarted. Attempting service recovery."

    Invoke-Command -ComputerName $Target -ScriptBlock {
        Start-Service FIUSNReader -ErrorAction SilentlyContinue
        Start-Service FICollector -ErrorAction SilentlyContinue
    } -ErrorAction SilentlyContinue

    throw
}

Write-Host "[PASS] Target-local reboot request accepted over PowerShell remoting."
Write-Host "[INFO] Waiting for a new boot instance and PowerShell remoting."

$BeforeBootTime = [DateTime]::Parse([string]$Before.boot_time)
$BootDeadline = (Get-Date).AddMinutes(10)
$NewBootObserved = $false

do {
    try {
        $BootProbe = Invoke-Command -ComputerName $Target -ScriptBlock {
            $OS = Get-CimInstance Win32_OperatingSystem

            [PSCustomObject]@{
                boot_time = $OS.LastBootUpTime.ToString("o")
                collector_status = (Get-Service FICollector -ErrorAction SilentlyContinue).Status.ToString()
                helper_status = (Get-Service FIUSNReader -ErrorAction SilentlyContinue).Status.ToString()
                pipe_present = [bool](Test-Path '\\.\pipe\FI-USN')
            }
        } -ErrorAction Stop

        $ObservedBootTime = [DateTime]::Parse([string]$BootProbe.boot_time)

        if ($ObservedBootTime -gt $BeforeBootTime) {
            $NewBootObserved = $true
            break
        }
    }
    catch {
    }

    Start-Sleep -Seconds 2
}
while ((Get-Date) -lt $BootDeadline)

if (-not $NewBootObserved) {
    throw "A new boot instance was not observed within 10 minutes."
}

Write-Host "[PASS] New Windows boot instance observed: $($BootProbe.boot_time)"

Write-Host ""
Write-Host "=== WAIT FOR AUTOMATIC FI STARTUP ==="

$StartupDeadline = (Get-Date).AddMinutes(4)
$StartupHealthy = $false

do {
    try {
        $Startup = Invoke-Command -ComputerName $Target -ScriptBlock {
            [PSCustomObject]@{
                collector_status = (Get-Service FICollector -ErrorAction Stop).Status.ToString()
                helper_status = (Get-Service FIUSNReader -ErrorAction Stop).Status.ToString()
                pipe_present = [bool](Test-Path '\\.\pipe\FI-USN')
            }
        } -ErrorAction Stop

        if (
            $Startup.collector_status -eq "Running" -and
            $Startup.helper_status -eq "Running" -and
            $Startup.pipe_present
        ) {
            $StartupHealthy = $true
            break
        }
    }
    catch {
    }

    Start-Sleep -Seconds 2
}
while ((Get-Date) -lt $StartupDeadline)

if (-not $StartupHealthy) {
    throw "FI production pair did not become healthy automatically after cold reboot."
}

Write-Host "[PASS] FICollector auto-started."
Write-Host "[PASS] FIUSNReader auto-started."
Write-Host "[PASS] FI-USN pipe is present after cold startup."

Write-Host ""
Write-Host "=== POST-REBOOT CONTINUITY ==="

$Post = Invoke-Command `
    -ComputerName $Target `
    -ArgumentList `
        ([string]$Before.checkpoint_path),`
        ([UInt64]$Before.before_usn),`
        ([string]$Before.before_runtime_observed),`
        ([string]$Before.file_name),`
        $ExpectedCollectorPath,`
        $ExpectedHelperPath `
    -ScriptBlock {
        param(
            [string]$CheckpointPath,
            [UInt64]$BeforeUSN,
            [string]$BeforeRuntimeObserved,
            [string]$FileName,
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

                [int]$TimeoutSeconds = 180
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
                        Select-Object -First 120
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

        $RuntimePath = "C:\ProgramData\FI\state\service-runtime.jsonl"
        $Deadline = (Get-Date).AddMinutes(3)
        $CheckpointAfter = $null
        $RuntimeAfter = $null

        do {
            try {
                $CheckpointCandidate = Get-Content -LiteralPath $CheckpointPath -Raw |
                    ConvertFrom-Json -ErrorAction Stop

                if ([UInt64]$CheckpointCandidate.next_usn -gt $BeforeUSN) {
                    $CheckpointAfter = $CheckpointCandidate
                }
            }
            catch {
            }

            $RuntimeCandidate = Get-FILatestConfiguredCollection -Path $RuntimePath

            if (
                $RuntimeCandidate -and
                [string]$RuntimeCandidate.observed_at -ne $BeforeRuntimeObserved -and
                $RuntimeCandidate.outcome -eq "Complete"
            ) {
                $RuntimeAfter = $RuntimeCandidate
            }

            if ($CheckpointAfter -and $RuntimeAfter) {
                break
            }

            Start-Sleep -Milliseconds 500
        }
        while ((Get-Date) -lt $Deadline)

        if (-not $CheckpointAfter) {
            throw "USN checkpoint did not advance after cold reboot."
        }

        if (-not $RuntimeAfter) {
            throw "No fresh Complete ConfiguredCollection was observed after cold reboot."
        }

        $SpoolHit = Wait-FIFileInSpool `
            -FileName $FileName `
            -TimeoutSeconds 180

        if (-not $SpoolHit) {
            throw "The pre-reboot uncollected change was not found in post-reboot catch-up spool output."
        }

        $Collector = Get-CimInstance Win32_Service -Filter "Name='FICollector'"
        $Helper = Get-CimInstance Win32_Service -Filter "Name='FIUSNReader'"

        if ($Collector.PathName -ne $ExpectedCollectorPath) {
            throw "FICollector PathName changed across cold reboot."
        }

        if ($Helper.PathName -ne $ExpectedHelperPath) {
            throw "FIUSNReader PathName changed across cold reboot."
        }

        if ($Collector.StartMode -ne "Auto" -or $Helper.StartMode -ne "Auto") {
            throw "FI production services are not both Automatic after cold reboot."
        }

        $CollectorManaged = (sc.exe qmanagedaccount FICollector) -join "`n"
        $HelperManaged = (sc.exe qmanagedaccount FIUSNReader) -join "`n"
        $CollectorSIDType = (sc.exe qsidtype FICollector) -join "`n"

        if ($CollectorManaged -notmatch 'ACCOUNT MANAGED\s*:\s*TRUE') {
            throw "FICollector is not configured as a managed account after cold reboot."
        }

        if ($HelperManaged -notmatch 'ACCOUNT MANAGED\s*:\s*TRUE') {
            throw "FIUSNReader is not configured as a managed account after cold reboot."
        }

        if ($CollectorSIDType -notmatch 'SERVICE_SID_TYPE:\s+UNRESTRICTED') {
            throw "FICollector service SID type is not UNRESTRICTED after cold reboot."
        }

        [PSCustomObject]@{
            checkpoint_before = [string]$BeforeUSN
            checkpoint_after = [string]$CheckpointAfter.next_usn
            configured_collection = $RuntimeAfter
            spool_path = [string]$SpoolHit.Path
            spool_line = [int]$SpoolHit.LineNumber
            collector_status = (Get-Service FICollector).Status.ToString()
            helper_status = (Get-Service FIUSNReader).Status.ToString()
            pipe_present = [bool](Test-Path '\\.\pipe\FI-USN')
        }
    }

Write-Host "[PASS] USN checkpoint advanced after cold reboot: $($Post.checkpoint_before) -> $($Post.checkpoint_after)"
Write-Host ""
Write-Host "=== POST-BOOT CONFIGURED COLLECTION ==="
$Post.configured_collection |
    ConvertTo-Json -Depth 8 |
    Write-Host

Write-Host "[PASS] Fresh post-boot ConfiguredCollection is Complete."
Write-Host "[PASS] Pre-reboot uncollected change appeared in post-boot catch-up spool."
Write-Host "[INFO] Spool: $($Post.spool_path):$($Post.spool_line)"
Write-Host "[PASS] Exact production service configuration survived cold reboot."
Write-Host "[PASS] Managed-account configuration survived cold reboot."
Write-Host "[PASS] FICollector service SID remained UNRESTRICTED."
Write-Host "[PASS] Both production services are Running and FI-USN pipe is present."

Invoke-Command `
    -ComputerName $Target `
    -ArgumentList ([string]$Before.test_path) `
    -ScriptBlock {
        param([string]$TestPath)

        Remove-Item `
            -LiteralPath $TestPath `
            -Force `
            -ErrorAction SilentlyContinue
    }

Write-Host ""
Write-Host "[PASS] SERVER 2025 COLD REBOOT / STARTUP ACCEPTANCE PASSED."
