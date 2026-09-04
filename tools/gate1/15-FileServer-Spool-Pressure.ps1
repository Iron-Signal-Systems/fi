# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# Bounded spool-growth characterization. This script is intentionally lab-gated.
# MaxSpoolGrowthMB is a measurement stop threshold, not a claim that asynchronous
# FI output can be byte-stopped at an exact boundary. Disk safety is enforced by
# a free-space reserve plus preflight headroom, bounded source generation, bounded
# child processes, bounded spool snapshots, and bounded collection waits.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [ValidateRange(1,20)]
    [int]$Waves = 5,
    [ValidateRange(10,10000)]
    [int]$FilesPerWave = 500,
    [ValidateRange(1,1024)]
    [int]$PayloadKB = 4,
    [ValidateRange(1,4096)]
    [int]$MaxSpoolGrowthMB = 512,
    [ValidateRange(1,4096)]
    [int]$MaxSourceDatasetMB = 2048,
    [ValidateRange(100,100000)]
    [int]$MaxSourceFiles = 25000,
    [ValidateRange(1,1024)]
    [int]$MinimumFreeSpaceGB = 10,
    [ValidateRange(30,1800)]
    [int]$CollectionTimeoutSeconds = 300,
    [ValidateRange(5,60)]
    [int]$HeartbeatSeconds = 15,
    [ValidateRange(30,600)]
    [int]$SpoolSnapshotTimeoutSeconds = 120,
    [ValidateRange(1000,1000000)]
    [int]$MaxSpoolFiles = 100000,
    [ValidateRange(30,1800)]
    [int]$WaveTimeoutSeconds = 300,
    [ValidateRange(30,1800)]
    [int]$CleanupTimeoutSeconds = 300,
    [ValidateRange(50,5000)]
    [int]$RuntimeTailLines = 500,
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results\performance',
    [switch]$KeepArtifacts,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmWorkload
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $ConfirmWorkload) { throw '-ConfirmWorkload is required because this script creates/modifies/deletes test data.' }
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator
$GovernedRoot = Get-FiGate1SingleGovernedRoot -GovernedRoot $GovernedRoot
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory

if (-not (Test-FiGate1RootLooksNonProduction -GovernedRoot $GovernedRoot)) {
    throw "Test 15 is lab-gated. Governed root does not look like an FI test/lab root: $GovernedRoot"
}

function ConvertTo-FiGate1SingleQuotedLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Invoke-FiGate1BoundedChildPowerShell {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$ScriptText,
        [ValidateRange(1,3600)][int]$HardTimeoutSeconds,
        [ValidateRange(1,300)][int]$HeartbeatIntervalSeconds = 15
    )

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($ScriptText)
    $Encoded = [Convert]::ToBase64String($Bytes)
    $PowerShellPath = Join-Path $PSHOME 'powershell.exe'

    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $PowerShellPath
    $StartInfo.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $Encoded"
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $StartInfo

    if (-not $Process.Start()) {
        throw "Failed to start bounded child PowerShell for $Label."
    }

    $Started = Get-Date
    $Deadline = $Started.AddSeconds($HardTimeoutSeconds)
    $NextHeartbeat = $Started.AddSeconds($HeartbeatIntervalSeconds)
    Write-FiInfo "$Label started; PID=$($Process.Id); hard timeout=${HardTimeoutSeconds}s."

    try {
        while (-not $Process.HasExited) {
            $Now = Get-Date
            if ($Now -ge $Deadline) {
                try { $Process.Kill() } catch { }
                try { [void]$Process.WaitForExit(5000) } catch { }
                throw "$Label exceeded hard timeout of $HardTimeoutSeconds seconds; child process was terminated."
            }

            if ($Now -ge $NextHeartbeat) {
                $ElapsedSeconds = [int][Math]::Floor(($Now - $Started).TotalSeconds)
                Write-FiInfo "$Label still active: ${ElapsedSeconds}s elapsed; PID=$($Process.Id)."
                $NextHeartbeat = $Now.AddSeconds($HeartbeatIntervalSeconds)
            }

            Start-Sleep -Milliseconds 500
        }

        $Process.WaitForExit()
        $ExitCode = $Process.ExitCode
        $ElapsedSeconds = [int][Math]::Floor(((Get-Date) - $Started).TotalSeconds)
        Write-FiInfo "$Label exited after ${ElapsedSeconds}s with code $ExitCode."

        if ($ExitCode -ne 0) {
            throw "$Label failed with child exit code $ExitCode."
        }
    }
    finally {
        $Process.Dispose()
    }
}

function Get-FiGate1BoundedSpoolSnapshot {
    param(
        [string]$SpoolPath = 'C:\ProgramData\FI\spool',
        [int]$HeartbeatIntervalSeconds = 15,
        [int]$HardTimeoutSeconds = 120,
        [int]$MaximumFiles = 100000
    )

    $SnapshotPath = Join-Path $env:TEMP ("fi-gate1-spool-snapshot-{0}.json" -f ([Guid]::NewGuid().ToString('N')))
    $SpoolLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $SpoolPath
    $SnapshotLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $SnapshotPath

    $Child = @"
`$ErrorActionPreference = 'Stop'
`$spool = $SpoolLiteral
`$out = $SnapshotLiteral
`$maxFiles = $MaximumFiles
if (-not (Test-Path -LiteralPath `$spool -PathType Container)) {
    [PSCustomObject]@{ Exists = `$false; FileCount = 0; Bytes = [UInt64]0; JsonlCount = 0; ManifestCount = 0 } |
        ConvertTo-Json -Compress | Set-Content -LiteralPath `$out -Encoding UTF8
    exit 0
}
`$fileCount = 0
`$jsonlCount = 0
`$manifestCount = 0
`$bytes = [UInt64]0
`$directory = New-Object System.IO.DirectoryInfo -ArgumentList `$spool
foreach (`$file in `$directory.EnumerateFiles('*', [System.IO.SearchOption]::AllDirectories)) {
    `$fileCount++
    if (`$fileCount -gt `$maxFiles) { throw "Spool snapshot exceeded maximum file count of `$maxFiles." }
    try { `$bytes += [UInt64]`$file.Length } catch { continue }
    if (`$file.Extension -ieq '.jsonl') { `$jsonlCount++ }
    if (`$file.Name -like '*.manifest.json') { `$manifestCount++ }
}
[PSCustomObject]@{
    Exists = `$true
    FileCount = `$fileCount
    Bytes = `$bytes
    JsonlCount = `$jsonlCount
    ManifestCount = `$manifestCount
} | ConvertTo-Json -Compress | Set-Content -LiteralPath `$out -Encoding UTF8
"@

    try {
        Invoke-FiGate1BoundedChildPowerShell -Label 'bounded spool snapshot' -ScriptText $Child -HardTimeoutSeconds $HardTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatIntervalSeconds
        if (-not (Test-Path -LiteralPath $SnapshotPath -PathType Leaf)) {
            throw 'Bounded spool snapshot child completed without producing its result file.'
        }
        $Result = Get-Content -LiteralPath $SnapshotPath -Raw -ErrorAction Stop | ConvertFrom-Json
        Write-FiInfo "Spool snapshot complete: files=$($Result.FileCount); bytes=$($Result.Bytes)."
        return $Result
    }
    finally {
        Remove-Item -LiteralPath $SnapshotPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-FiGate1LatestConfiguredCollectionTail {
    param(
        [string]$RuntimePath = 'C:\ProgramData\FI\state\service-runtime.jsonl',
        [int]$TailLines = 500
    )

    if (-not (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) {
        return $null
    }

    $Lines = @(Get-Content -LiteralPath $RuntimePath -Tail $TailLines -ErrorAction Stop)
    for ($Index = $Lines.Count - 1; $Index -ge 0; $Index--) {
        $Line = [string]$Lines[$Index]
        if ($Line -notlike '*"record_kind":"ConfiguredCollection"*') {
            continue
        }
        try {
            return $Line | ConvertFrom-Json
        }
        catch {
            continue
        }
    }
    return $null
}

function Wait-FiGate1ConfiguredCollectionNewerThan {
    param(
        [Parameter(Mandatory = $true)][DateTimeOffset]$AfterObservedAt,
        [int]$TimeoutSeconds = 300,
        [int]$HeartbeatIntervalSeconds = 15,
        [int]$TailLines = 500,
        [string]$Label = 'configured collection'
    )

    $Started = Get-Date
    $Deadline = $Started.AddSeconds($TimeoutSeconds)
    $NextHeartbeat = $Started.AddSeconds($HeartbeatIntervalSeconds)

    do {
        $Current = Get-FiGate1LatestConfiguredCollectionTail -TailLines $TailLines
        if ($null -ne $Current) {
            $CurrentTime = [DateTimeOffset]::Parse($Current.observed_at)
            if ($CurrentTime -gt $AfterObservedAt) {
                $ElapsedSeconds = [int][Math]::Floor(((Get-Date) - $Started).TotalSeconds)
                Write-FiInfo "$Label completed after ${ElapsedSeconds}s; outcome=$($Current.outcome)."
                return $Current
            }
        }

        $Now = Get-Date
        if ($Now -ge $NextHeartbeat) {
            $ElapsedSeconds = [int][Math]::Floor(($Now - $Started).TotalSeconds)
            $LatestText = if ($null -ne $Current) { "$($Current.observed_at) / $($Current.outcome)" } else { 'none' }
            Write-FiInfo "Waiting for ${Label}: ${ElapsedSeconds}s elapsed; latest=$LatestText."
            $NextHeartbeat = $Now.AddSeconds($HeartbeatIntervalSeconds)
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $Deadline)

    throw "Timed out after $TimeoutSeconds seconds waiting for $Label."
}

function Invoke-FiGate1BoundedWaveCreate {
    param(
        [Parameter(Mandatory = $true)][string]$WaveRoot,
        [Parameter(Mandatory = $true)][int]$FileCount,
        [Parameter(Mandatory = $true)][int]$PayloadKilobytes,
        [Parameter(Mandatory = $true)][int]$WaveNumber,
        [int]$HardTimeoutSeconds = 300,
        [int]$HeartbeatIntervalSeconds = 15
    )

    $RootLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $WaveRoot
    $Child = @"
`$ErrorActionPreference = 'Stop'
`$root = $RootLiteral
`$count = $FileCount
`$payloadKB = $PayloadKilobytes
`$payload = 'X' * (`$payloadKB * 1024)
New-Item -Path `$root -ItemType Directory -Force | Out-Null
for (`$i = 0; `$i -lt `$count; `$i++) {
    `$path = Join-Path `$root ('file-{0:D8}.txt' -f `$i)
    `$payload | Set-Content -LiteralPath `$path -Encoding ASCII
}
"@
    Invoke-FiGate1BoundedChildPowerShell -Label "wave $WaveNumber source creation" -ScriptText $Child -HardTimeoutSeconds $HardTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatIntervalSeconds
}

function Invoke-FiGate1BoundedCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$HardTimeoutSeconds = 300,
        [int]$HeartbeatIntervalSeconds = 15
    )

    $PathLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $Path
    $Child = @"
`$ErrorActionPreference = 'Stop'
`$path = $PathLiteral
if (Test-Path -LiteralPath `$path -PathType Container) {
    Remove-Item -LiteralPath `$path -Recurse -Force -ErrorAction Stop
}
"@
    Invoke-FiGate1BoundedChildPowerShell -Label 'bounded Test 15 source cleanup' -ScriptText $Child -HardTimeoutSeconds $HardTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatIntervalSeconds
}

$SpoolPath = 'C:\ProgramData\FI\spool'
$ReserveBytes = [UInt64]$MinimumFreeSpaceGB * 1GB
$MaxGrowthBytes = [UInt64]$MaxSpoolGrowthMB * 1MB
$RequestedFileCount = [UInt64]$Waves * [UInt64]$FilesPerWave
$RequestedSourceBytes = $RequestedFileCount * [UInt64]$PayloadKB * 1KB
$MaxSourceBytes = [UInt64]$MaxSourceDatasetMB * 1MB

if ($RequestedFileCount -gt [UInt64]$MaxSourceFiles) {
    throw "Requested source workload is $RequestedFileCount files, above the configured $MaxSourceFiles-file safety cap."
}
if ($RequestedSourceBytes -gt $MaxSourceBytes) {
    throw "Requested source workload is $([Math]::Round($RequestedSourceBytes / 1MB,2)) MB, above the configured ${MaxSourceDatasetMB}MB safety cap."
}

$InitialFree = Get-FiGate1FreeBytes -Path $SpoolPath
$RequiredInitialHeadroom = $ReserveBytes + $MaxGrowthBytes + $RequestedSourceBytes
if ($InitialFree -le $RequiredInitialHeadroom) {
    throw "Spool volume lacks required headroom. Free=$([Math]::Round($InitialFree/1GB,2))GB; required reserve+growth-threshold+source=$([Math]::Round($RequiredInitialHeadroom/1GB,2))GB."
}

$SourceFree = Get-FiGate1FreeBytes -Path $GovernedRoot
if ($SourceFree -le ($ReserveBytes + $RequestedSourceBytes)) {
    throw 'Governed-root volume does not have enough free space to preserve the configured reserve for this bounded source workload.'
}

$RunID = [Guid]::NewGuid().ToString('N').Substring(0,12)
$TestRoot = Join-Path $GovernedRoot "_fi_gate1_spool_$RunID"
$InitialSpool = Get-FiGate1BoundedSpoolSnapshot -SpoolPath $SpoolPath -HeartbeatIntervalSeconds $HeartbeatSeconds -HardTimeoutSeconds $SpoolSnapshotTimeoutSeconds -MaximumFiles $MaxSpoolFiles
$WaveReports = New-Object System.Collections.Generic.List[object]
$CleanupAttempted = $false
$CleanupCollection = $null
$PostWorkloadSpool = $null

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - BOUNDED SPOOL-PRESSURE CHARACTERIZATION'
Write-Host "Waves:                  $Waves"
Write-Host "Files per wave:         $FilesPerWave"
Write-Host "Payload KB:             $PayloadKB"
Write-Host "Source file cap:        $MaxSourceFiles"
Write-Host "Source dataset cap MB:  $MaxSourceDatasetMB"
Write-Host "Spool stop threshold MB:$MaxSpoolGrowthMB"
Write-Host "Minimum free reserve GB:$MinimumFreeSpaceGB"
Write-Host "Heartbeat:              ${HeartbeatSeconds}s"
Write-Host "Test root:              $TestRoot"
Write-Host '============================================================'

try {
    for ($Wave = 1; $Wave -le $Waves; $Wave++) {
        $FreeBefore = Get-FiGate1FreeBytes -Path $SpoolPath
        $SpoolBefore = Get-FiGate1BoundedSpoolSnapshot -SpoolPath $SpoolPath -HeartbeatIntervalSeconds $HeartbeatSeconds -HardTimeoutSeconds $SpoolSnapshotTimeoutSeconds -MaximumFiles $MaxSpoolFiles

        if ($FreeBefore -le $ReserveBytes) {
            throw "Free-space reserve was reached before wave $Wave."
        }

        $PreWaveGrowth = if ([UInt64]$SpoolBefore.Bytes -ge [UInt64]$InitialSpool.Bytes) {
            [UInt64]([UInt64]$SpoolBefore.Bytes - [UInt64]$InitialSpool.Bytes)
        } else { [UInt64]0 }

        if ($PreWaveGrowth -ge $MaxGrowthBytes) {
            Write-FiInfo "Stopping before wave ${Wave}: spool-growth stop threshold reached."
            break
        }

        $RemainingSourceBytes = [UInt64]($Waves - $Wave + 1) * [UInt64]$FilesPerWave * [UInt64]$PayloadKB * 1KB
        if ($FreeBefore -le ($ReserveBytes + $RemainingSourceBytes)) {
            throw "Insufficient free-space headroom before wave $Wave to preserve reserve plus remaining bounded source workload."
        }

        $WaveRoot = Join-Path $TestRoot ("wave-{0:D3}" -f $Wave)
        Invoke-FiGate1BoundedWaveCreate -WaveRoot $WaveRoot -FileCount $FilesPerWave -PayloadKilobytes $PayloadKB -WaveNumber $Wave -HardTimeoutSeconds $WaveTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds
        $WaveFinished = [DateTimeOffset]::UtcNow

        $FirstCollection = Wait-FiGate1ConfiguredCollectionNewerThan -AfterObservedAt $WaveFinished -TimeoutSeconds $CollectionTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds -TailLines $RuntimeTailLines -Label "wave $Wave first post-workload configured collection"
        $FirstTime = [DateTimeOffset]::Parse($FirstCollection.observed_at)
        $Collection = Wait-FiGate1ConfiguredCollectionNewerThan -AfterObservedAt $FirstTime -TimeoutSeconds $CollectionTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds -TailLines $RuntimeTailLines -Label "wave $Wave fully post-workload configured collection"
        if ($Collection.outcome -ne 'Complete') {
            throw "Wave $Wave fully post-workload configured collection outcome was $($Collection.outcome), want Complete."
        }

        $SpoolAfter = Get-FiGate1BoundedSpoolSnapshot -SpoolPath $SpoolPath -HeartbeatIntervalSeconds $HeartbeatSeconds -HardTimeoutSeconds $SpoolSnapshotTimeoutSeconds -MaximumFiles $MaxSpoolFiles
        $FreeAfter = Get-FiGate1FreeBytes -Path $SpoolPath
        $TotalGrowth = if ([UInt64]$SpoolAfter.Bytes -ge [UInt64]$InitialSpool.Bytes) { [UInt64]([UInt64]$SpoolAfter.Bytes - [UInt64]$InitialSpool.Bytes) } else { [UInt64]0 }

        $WaveReports.Add([PSCustomObject]@{
            Wave = $Wave
            FilesCreated = $FilesPerWave
            PayloadKB = $PayloadKB
            SpoolBytesBefore = [UInt64]$SpoolBefore.Bytes
            SpoolBytesAfter = [UInt64]$SpoolAfter.Bytes
            WaveSpoolGrowthBytes = if ([UInt64]$SpoolAfter.Bytes -ge [UInt64]$SpoolBefore.Bytes) { [UInt64]([UInt64]$SpoolAfter.Bytes - [UInt64]$SpoolBefore.Bytes) } else { [UInt64]0 }
            TotalSpoolGrowthBytes = $TotalGrowth
            FreeBytesBefore = $FreeBefore
            FreeBytesAfter = $FreeAfter
            FirstPostWorkloadCollection = $FirstCollection
            ConfiguredCollection = $Collection
        })

        if ($FreeAfter -le $ReserveBytes) {
            throw "Free-space reserve was crossed after wave $Wave."
        }
        if ($TotalGrowth -ge $MaxGrowthBytes) {
            Write-FiInfo "Spool-growth stop threshold reached after wave $Wave; no further waves will be generated."
            break
        }
    }

    $PostWorkloadSpool = Get-FiGate1BoundedSpoolSnapshot -SpoolPath $SpoolPath -HeartbeatIntervalSeconds $HeartbeatSeconds -HardTimeoutSeconds $SpoolSnapshotTimeoutSeconds -MaximumFiles $MaxSpoolFiles

    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $TestRoot -PathType Container)) {
        $CleanupAttempted = $true
        Invoke-FiGate1BoundedCleanup -Path $TestRoot -HardTimeoutSeconds $CleanupTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds
        $CleanupFinished = [DateTimeOffset]::UtcNow

        $CleanupFirst = Wait-FiGate1ConfiguredCollectionNewerThan -AfterObservedAt $CleanupFinished -TimeoutSeconds $CollectionTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds -TailLines $RuntimeTailLines -Label 'first post-cleanup configured collection'
        $CleanupFirstTime = [DateTimeOffset]::Parse($CleanupFirst.observed_at)
        $CleanupCollection = Wait-FiGate1ConfiguredCollectionNewerThan -AfterObservedAt $CleanupFirstTime -TimeoutSeconds $CollectionTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds -TailLines $RuntimeTailLines -Label 'fully post-cleanup configured collection'
        if ($CleanupCollection.outcome -ne 'Complete') {
            throw "Fully post-cleanup configured collection outcome was $($CleanupCollection.outcome), want Complete."
        }
    }

    $FinalSpool = Get-FiGate1BoundedSpoolSnapshot -SpoolPath $SpoolPath -HeartbeatIntervalSeconds $HeartbeatSeconds -HardTimeoutSeconds $SpoolSnapshotTimeoutSeconds -MaximumFiles $MaxSpoolFiles
    $FinalFree = Get-FiGate1FreeBytes -Path $SpoolPath
    if ($FinalFree -le $ReserveBytes) {
        throw 'Final free space is at/below the configured reserve.'
    }

    $FinalGrowth = if ([UInt64]$FinalSpool.Bytes -ge [UInt64]$InitialSpool.Bytes) { [UInt64]([UInt64]$FinalSpool.Bytes - [UInt64]$InitialSpool.Bytes) } else { [UInt64]0 }
    $ThresholdExceeded = $FinalGrowth -gt $MaxGrowthBytes

    $Report = [PSCustomObject]@{
        RecordKind = 'FIGate1SpoolPressureCharacterization'
        RunID = $RunID
        Host = $env:COMPUTERNAME
        GovernedRoot = $GovernedRoot
        TestRoot = $TestRoot
        WavesRequested = $Waves
        WavesCompleted = $WaveReports.Count
        FilesPerWave = $FilesPerWave
        PayloadKB = $PayloadKB
        MinimumFreeSpaceGB = $MinimumFreeSpaceGB
        MaxSpoolGrowthMB = $MaxSpoolGrowthMB
        MaxSourceDatasetMB = $MaxSourceDatasetMB
        MaxSourceFiles = $MaxSourceFiles
        RequestedFileCount = $RequestedFileCount
        RequestedSourceBytes = $RequestedSourceBytes
        InitialSpool = $InitialSpool
        PostWorkloadSpool = $PostWorkloadSpool
        FinalSpool = $FinalSpool
        TotalSpoolGrowthBytes = $FinalGrowth
        SpoolGrowthStopThresholdExceeded = $ThresholdExceeded
        InitialFreeBytes = $InitialFree
        FinalFreeBytes = $FinalFree
        CleanupPerformed = (-not $KeepArtifacts)
        FullyPostCleanupCollection = $CleanupCollection
        Waves = $WaveReports.ToArray()
        Interpretation = 'Characterization only. MaxSpoolGrowthMB is a stop threshold rather than an exact byte limiter. Disk safety is enforced separately by reserve/headroom checks and bounded workload/process/snapshot limits. FinalSpool includes cleanup-generated FI activity when cleanup is enabled.'
        FinishedUTC = [DateTime]::UtcNow.ToString('o')
    }

    $ReportPath = Join-Path $ResultDirectory "spool-pressure-$($env:COMPUTERNAME)-$RunID.json"
    Write-FiGate1Json -InputObject $Report -Path $ReportPath
    Write-FiPass "Bounded spool-pressure characterization complete. Report: $ReportPath"

    if ($ThresholdExceeded) {
        throw "Final FI spool growth exceeded the configured $MaxSpoolGrowthMB MB stop threshold. Review the report before any larger workload."
    }
}
finally {
    if (-not $KeepArtifacts -and -not $CleanupAttempted -and (Test-Path -LiteralPath $TestRoot -PathType Container)) {
        try {
            Invoke-FiGate1BoundedCleanup -Path $TestRoot -HardTimeoutSeconds $CleanupTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds
        }
        catch {
            Write-FiInfo "Emergency Test 15 cleanup did not complete: $($_.Exception.Message)"
        }
    }
}
