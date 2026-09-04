# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [string]$FIExecutable = 'C:\Program Files\FI\fi.exe',
    [ValidateRange(1,20)]
    [int]$Runs = 3,
    [ValidateRange(5,300)]
    [int]$HeartbeatSeconds = 15,
    [ValidateRange(30,86400)]
    [int]$MaxRunSeconds = 3600,
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results\performance',
    [switch]$StopCollectorForRun,
    [switch]$AllowConcurrentCollector,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmSourceImpact
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $ConfirmSourceImpact) { throw '-ConfirmSourceImpact is required because -perf-root performs a full recursive source read/hash workload.' }
if ($StopCollectorForRun -and $AllowConcurrentCollector) { throw 'Choose either -StopCollectorForRun or -AllowConcurrentCollector, not both.' }
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator
$GovernedRoot = Get-FiGate1SingleGovernedRoot -GovernedRoot $GovernedRoot
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory

if (-not (Test-Path -LiteralPath $FIExecutable -PathType Leaf)) { throw "FI executable not found: $FIExecutable" }
if (-not (Test-Path -LiteralPath $GovernedRoot -PathType Container)) { throw "Governed root not found: $GovernedRoot" }

$RunSetID = [Guid]::NewGuid().ToString('N').Substring(0,12)
$FIHash = (Get-FileHash -LiteralPath $FIExecutable -Algorithm SHA256).Hash
$Reports = New-Object System.Collections.Generic.List[object]
$CollectorService = Get-Service FICollector -ErrorAction SilentlyContinue
$CollectorWasRunning = ($null -ne $CollectorService -and $CollectorService.Status -eq 'Running')
if ($CollectorWasRunning -and -not $StopCollectorForRun -and -not $AllowConcurrentCollector) {
    throw 'FICollector is running. Use -StopCollectorForRun for an isolated baseline or -AllowConcurrentCollector for an intentionally concurrent measurement.'
}
$ConcurrentCollector = ($CollectorWasRunning -and $AllowConcurrentCollector)

if ($CollectorWasRunning -and $StopCollectorForRun) {
    Write-FiInfo 'Stopping FICollector for isolated -perf-root measurements.'
    Stop-Service FICollector -Force -ErrorAction Stop
    (Get-Service FICollector).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
}

function Invoke-FiGate1PerformanceRun {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [string]$StderrPath,

        [Parameter(Mandatory = $true)]
        [int]$RunNumber,

        [Parameter(Mandatory = $true)]
        [int]$RunCount,

        [Parameter(Mandatory = $true)]
        [int]$HeartbeatIntervalSeconds,

        [Parameter(Mandatory = $true)]
        [int]$HardTimeoutSeconds
    )

    if ($Root.Contains('"')) {
        throw 'Governed root contains an unsupported quote character.'
    }

    Remove-Item -LiteralPath $StdoutPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StderrPath -Force -ErrorAction SilentlyContinue

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $Process.StartInfo.FileName = $Executable
    $Process.StartInfo.Arguments = '-perf-root "' + $Root + '"'
    $Process.StartInfo.UseShellExecute = $false
    $Process.StartInfo.CreateNoWindow = $true
    $Process.StartInfo.RedirectStandardOutput = $true
    $Process.StartInfo.RedirectStandardError = $true

    $Started = Get-Date
    $NextHeartbeat = $Started.AddSeconds($HeartbeatIntervalSeconds)
    $StdoutTask = $null
    $StderrTask = $null

    try {
        if (-not $Process.Start()) {
            throw "Could not start fi.exe performance run $RunNumber."
        }

        # Begin both reads immediately so neither redirected pipe can fill and
        # block the child while the harness is supervising it.
        $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        $StderrTask = $Process.StandardError.ReadToEndAsync()

        Write-FiInfo "Performance run $RunNumber of $RunCount started; PID=$($Process.Id); heartbeat=${HeartbeatIntervalSeconds}s; hard timeout=${HardTimeoutSeconds}s."

        while (-not $Process.HasExited) {
            Start-Sleep -Seconds 2
            $Now = Get-Date
            $ElapsedSeconds = [int][Math]::Floor(($Now - $Started).TotalSeconds)

            if ($ElapsedSeconds -ge $HardTimeoutSeconds) {
                Write-FiFail "Performance run $RunNumber exceeded the hard timeout after ${ElapsedSeconds}s; terminating PID $($Process.Id)."
                try {
                    $Process.Kill()
                    [void]$Process.WaitForExit(10000)
                }
                catch {
                    Write-FiFail "Could not terminate timed-out performance PID $($Process.Id): $($_.Exception.Message)"
                }
                throw "fi.exe -perf-root exceeded hard timeout of $HardTimeoutSeconds seconds on run $RunNumber."
            }

            if ($Now -ge $NextHeartbeat) {
                $CPUSeconds = 'unknown'
                $WorkingSetMiB = 'unknown'

                try {
                    $Process.Refresh()
                    $CPUSeconds = [Math]::Round($Process.TotalProcessorTime.TotalSeconds, 1)
                    $WorkingSetMiB = [Math]::Round($Process.WorkingSet64 / 1MB, 1)
                }
                catch {
                    # Process metrics can race with process exit; the next loop observes HasExited.
                }

                Write-FiInfo "Performance run $RunNumber of $RunCount still active: ${ElapsedSeconds}s elapsed; PID=$($Process.Id); CPU=${CPUSeconds}s; working_set=${WorkingSetMiB}MiB."
                $NextHeartbeat = $Now.AddSeconds($HeartbeatIntervalSeconds)
            }
        }

        $Process.WaitForExit()
        $Process.Refresh()

        $Stdout = $StdoutTask.GetAwaiter().GetResult()
        $Stderr = $StderrTask.GetAwaiter().GetResult()

        [System.IO.File]::WriteAllText($StdoutPath, $Stdout, [System.Text.Encoding]::UTF8)
        [System.IO.File]::WriteAllText($StderrPath, $Stderr, [System.Text.Encoding]::UTF8)

        $ExitCode = [int]$Process.ExitCode
        $ElapsedSeconds = [int][Math]::Floor(((Get-Date) - $Started).TotalSeconds)
        Write-FiInfo "Performance run $RunNumber of $RunCount exited after ${ElapsedSeconds}s with code $ExitCode."

        return [PSCustomObject]@{
            ExitCode = $ExitCode
            ElapsedWallSeconds = $ElapsedSeconds
        }
    }
    finally {
        if ($null -ne $Process) {
            try {
                if (-not $Process.HasExited) {
                    $Process.Kill()
                    [void]$Process.WaitForExit(10000)
                }
            }
            catch {
                # Best-effort cleanup only; the primary error is preserved.
            }
            $Process.Dispose()
        }
    }
}

try {
    Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - REAL NTFS PERFORMANCE BASELINE'
Write-Host "Root: $GovernedRoot"
Write-Host "Runs: $Runs"
Write-Host "FI:   $FIExecutable"
Write-Host "SHA:  $FIHash"
Write-Host "Heartbeat: ${HeartbeatSeconds}s"
Write-Host "Hard timeout per run: ${MaxRunSeconds}s"
Write-Host '============================================================'

for ($i = 1; $i -le $Runs; $i++) {
    $RawPath = Join-Path $ResultDirectory "perf-$($env:COMPUTERNAME)-$RunSetID-run$i.json"
    $ErrorPath = Join-Path $ResultDirectory "perf-$($env:COMPUTERNAME)-$RunSetID-run$i.stderr.txt"

    $RunResult = Invoke-FiGate1PerformanceRun `
        -Executable $FIExecutable `
        -Root $GovernedRoot `
        -StdoutPath $RawPath `
        -StderrPath $ErrorPath `
        -RunNumber $i `
        -RunCount $Runs `
        -HeartbeatIntervalSeconds $HeartbeatSeconds `
        -HardTimeoutSeconds $MaxRunSeconds

    $ExitCode = $RunResult.ExitCode
    if ($ExitCode -ne 0) {
        $ErrorTail = @(Get-Content -LiteralPath $ErrorPath -Tail 40 -ErrorAction SilentlyContinue) -join "`n"
        if ($ErrorTail) {
            Write-FiFail "fi.exe stderr tail for run ${i}:`n$ErrorTail"
        }
        throw "fi.exe -perf-root failed on run $i with exit code $ExitCode. See $ErrorPath"
    }

    $Raw = Get-Content -LiteralPath $RawPath -Raw -ErrorAction Stop

    try { $Parsed = $Raw | ConvertFrom-Json }
    catch { throw "Could not parse performance JSON from run $i. Raw report: $RawPath" }

    if ($Parsed.performance_thresholds -ne 'NOT_EVALUATED') {
        throw "Unexpected performance threshold state: $($Parsed.performance_thresholds)"
    }

    $Reports.Add([PSCustomObject]@{
        Run = $i
        RawReport = $RawPath
        RunState = $Parsed.run_state
        ElapsedSeconds = [double]$Parsed.timing.elapsed_seconds
        ObjectsPerSecond = [double]$Parsed.timing.objects_per_second
        FilesPerSecond = [double]$Parsed.timing.files_per_second
        Observations = [UInt64]$Parsed.collection.observations
        Files = [UInt64]$Parsed.collection.files
        Directories = [UInt64]$Parsed.collection.directories
        Warnings = [UInt64]$Parsed.collection.warnings
        ObjectErrors = [UInt64]$Parsed.collection.object_errors
        Partial = [UInt64]$Parsed.collection.partial
        ChangedDuringCollection = [UInt64]$Parsed.collection.changed_during_collection
        ReplacedDuringCollection = [UInt64]$Parsed.collection.replaced_during_collection
        CPUSeconds = [double]$Parsed.process.cpu_seconds
        WorkingSetBytes = [UInt64]$Parsed.process.working_set_bytes
        PeakWorkingSetBytes = [UInt64]$Parsed.process.peak_working_set_bytes
        PrivateBytes = [UInt64]$Parsed.process.private_bytes
        ResourceObservation = $Parsed.resource_observation
    })
}

function Get-Median {
    param([double[]]$Values)
    $Sorted = @($Values | Sort-Object)
    if ($Sorted.Count -eq 0) { return 0.0 }
    $Mid = [int][Math]::Floor($Sorted.Count / 2)
    if ($Sorted.Count % 2 -eq 1) { return [double]$Sorted[$Mid] }
    return ([double]$Sorted[$Mid-1] + [double]$Sorted[$Mid]) / 2.0
}

$Summary = [PSCustomObject]@{
    RecordKind = 'FIGate1PerformanceBaselineSet'
    RunSetID = $RunSetID
    Host = $env:COMPUTERNAME
    GovernedRoot = $GovernedRoot
    FIExecutable = $FIExecutable
    FISHA256 = $FIHash
    RunCount = $Reports.Count
    Observations = [UInt64]$Reports[0].Observations
    Files = [UInt64]$Reports[0].Files
    Directories = [UInt64]$Reports[0].Directories
    ElapsedSecondsMin = [double](($Reports | Measure-Object ElapsedSeconds -Minimum).Minimum)
    ElapsedSecondsMedian = Get-Median -Values @($Reports | ForEach-Object { [double]$_.ElapsedSeconds })
    ElapsedSecondsMax = [double](($Reports | Measure-Object ElapsedSeconds -Maximum).Maximum)
    ObjectsPerSecondMin = [double](($Reports | Measure-Object ObjectsPerSecond -Minimum).Minimum)
    ObjectsPerSecondMedian = Get-Median -Values @($Reports | ForEach-Object { [double]$_.ObjectsPerSecond })
    ObjectsPerSecondMax = [double](($Reports | Measure-Object ObjectsPerSecond -Maximum).Maximum)
    PeakWorkingSetBytesMax = [UInt64](($Reports | Measure-Object PeakWorkingSetBytes -Maximum).Maximum)
    CPUSecondsMedian = Get-Median -Values @($Reports | ForEach-Object { [double]$_.CPUSeconds })
    CollectorWasRunningAtStart = $CollectorWasRunning
    CollectorConcurrentDuringMeasurement = $ConcurrentCollector
    ThresholdDecision = 'NOT_EVALUATED - Gate 1 thresholds/cadence are set only after representative repeated measurements.'
    Runs = $Reports.ToArray()
    FinishedUTC = [DateTime]::UtcNow.ToString('o')
}
$SummaryPath = Join-Path $ResultDirectory "perf-summary-$($env:COMPUTERNAME)-$RunSetID.json"
Write-FiGate1Json -InputObject $Summary -Path $SummaryPath

$Reports | Format-Table Run,ElapsedSeconds,ObjectsPerSecond,FilesPerSecond,CPUSeconds,PeakWorkingSetBytes,Warnings,ObjectErrors -AutoSize
Write-FiPass "Performance baseline set complete. Summary: $SummaryPath"
}
finally {
    if ($CollectorWasRunning -and $StopCollectorForRun) {
        Write-FiInfo 'Restarting FICollector after isolated performance measurement.'
        Start-Service FICollector -ErrorAction Stop
        (Get-Service FICollector).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
        Write-FiPass 'FICollector restarted after isolated performance measurement.'
    }
}
