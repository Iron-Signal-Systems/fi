# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [ValidateRange(10,25000)]
    [int]$FileCount = 1000,
    [ValidateRange(1,100)]
    [int]$ModifyPasses = 2,
    [ValidateRange(0,100)]
    [int]$RenamePercent = 10,
    [ValidateRange(0,100)]
    [int]$DeletePercent = 10,
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results\performance',
    [ValidateRange(30,1800)]
    [int]$CollectionTimeoutSeconds = 600,
    [ValidateRange(5,60)]
    [int]$HeartbeatSeconds = 15,
    [ValidateRange(30,600)]
    [int]$SpoolSnapshotTimeoutSeconds = 120,
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

function Get-FiGate1BoundedSpoolSnapshot {
    param(
        [string]$SpoolPath = 'C:\ProgramData\FI\spool',
        [int]$HeartbeatIntervalSeconds = 15,
        [int]$HardTimeoutSeconds = 120
    )

    if (-not (Test-Path -LiteralPath $SpoolPath -PathType Container)) {
        return [PSCustomObject]@{
            Exists = $false
            FileCount = 0
            Bytes = [UInt64]0
            JsonlCount = 0
            ManifestCount = 0
            ElapsedSeconds = 0
        }
    }

    $Started = Get-Date
    $NextHeartbeat = $Started.AddSeconds($HeartbeatIntervalSeconds)
    $FileCount = 0
    $JsonlCount = 0
    $ManifestCount = 0
    $Bytes = [UInt64]0
    $Directory = New-Object System.IO.DirectoryInfo -ArgumentList $SpoolPath

    Write-FiInfo "Starting bounded spool snapshot: $SpoolPath"

    foreach ($File in $Directory.EnumerateFiles('*', [System.IO.SearchOption]::AllDirectories)) {
        $FileCount++
        $Bytes += [UInt64]$File.Length
        if ($File.Extension -ieq '.jsonl') { $JsonlCount++ }
        if ($File.Name -like '*.manifest.json') { $ManifestCount++ }

        $Now = Get-Date
        $ElapsedSeconds = [int][Math]::Floor(($Now - $Started).TotalSeconds)

        if ($ElapsedSeconds -ge $HardTimeoutSeconds) {
            throw "Spool snapshot exceeded hard timeout of $HardTimeoutSeconds seconds after $FileCount files."
        }

        if ($Now -ge $NextHeartbeat) {
            $MiB = [Math]::Round($Bytes / 1MB, 2)
            Write-FiInfo "Spool snapshot still active: ${ElapsedSeconds}s elapsed; files=$FileCount; bytes=${MiB}MiB."
            $NextHeartbeat = $Now.AddSeconds($HeartbeatIntervalSeconds)
        }
    }

    $ElapsedSeconds = [int][Math]::Floor(((Get-Date) - $Started).TotalSeconds)
    Write-FiInfo "Spool snapshot complete: files=$FileCount; elapsed=${ElapsedSeconds}s."

    return [PSCustomObject]@{
        Exists = $true
        FileCount = $FileCount
        Bytes = $Bytes
        JsonlCount = $JsonlCount
        ManifestCount = $ManifestCount
        ElapsedSeconds = $ElapsedSeconds
    }
}

function Get-FiGate1LatestConfiguredCollectionTail {
    param(
        [string]$RuntimePath = 'C:\ProgramData\FI\state\service-runtime.jsonl',
        [ValidateRange(50,5000)]
        [int]$TailLines = 500
    )

    if (-not (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) {
        return $null
    }

    $Match = Get-Content -LiteralPath $RuntimePath -Tail $TailLines -ErrorAction Stop |
        Select-String -SimpleMatch '"record_kind":"ConfiguredCollection"' |
        Select-Object -Last 1

    if (-not $Match) {
        return $null
    }

    return $Match.Line | ConvertFrom-Json
}

function Wait-FiGate1ConfiguredCollectionNewerThan {
    param(
        [Parameter(Mandatory = $true)]
        [DateTimeOffset]$AfterObservedAt,
        [int]$TimeoutSeconds = 600,
        [int]$HeartbeatIntervalSeconds = 15,
        [string]$Label = 'configured collection'
    )

    $Started = Get-Date
    $Deadline = $Started.AddSeconds($TimeoutSeconds)
    $NextHeartbeat = $Started.AddSeconds($HeartbeatIntervalSeconds)

    do {
        $Current = Get-FiGate1LatestConfiguredCollectionTail
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

function Write-FiGate1WorkloadProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Phase,
        [Parameter(Mandatory = $true)]
        [int]$Completed,
        [Parameter(Mandatory = $true)]
        [int]$Total,
        [Parameter(Mandatory = $true)]
        [DateTime]$Started,
        [Parameter(Mandatory = $true)]
        [ref]$NextHeartbeat,
        [int]$HeartbeatIntervalSeconds = 15,
        [switch]$Force
    )

    $Now = Get-Date
    if (-not $Force -and $Now -lt $NextHeartbeat.Value) {
        return
    }

    $ElapsedSeconds = [int][Math]::Floor(($Now - $Started).TotalSeconds)
    Write-FiInfo "$Phase progress: $Completed/$Total; ${ElapsedSeconds}s elapsed."
    $NextHeartbeat.Value = $Now.AddSeconds($HeartbeatIntervalSeconds)
}

$RunID = [Guid]::NewGuid().ToString('N').Substring(0,12)
$TestRoot = Get-FiGate1TestRoot -GovernedRoot $GovernedRoot -Name "_fi_gate1_churn_$RunID"
$CheckpointPath = Get-FiCheckpointPath -GovernedRoot $GovernedRoot
$USNBefore = [UInt64](Get-FiCheckpoint -CheckpointPath $CheckpointPath).next_usn
$SecurityBefore = Get-FiGate1LatestSecurityRecordID
$ProcessBefore = Get-FiGate1CollectorProcessSnapshot
$SpoolBefore = Get-FiGate1BoundedSpoolSnapshot -HeartbeatIntervalSeconds $HeartbeatSeconds -HardTimeoutSeconds $SpoolSnapshotTimeoutSeconds
$Started = Get-Date

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - BOUNDED CHURN CAMPAIGN'
Write-Host "Files:          $FileCount"
Write-Host "Modify passes:  $ModifyPasses"
Write-Host "Rename percent: $RenamePercent"
Write-Host "Delete percent: $DeletePercent"
Write-Host "Heartbeat:      ${HeartbeatSeconds}s"
Write-Host "Test root:      $TestRoot"
Write-Host '============================================================'

try {
    $PhaseStarted = Get-Date
    $NextHeartbeat = $PhaseStarted.AddSeconds($HeartbeatSeconds)
    Write-FiInfo "Create phase started: $FileCount files."
    for ($i = 0; $i -lt $FileCount; $i++) {
        $Path = Join-Path $TestRoot ('file-{0:D8}.txt' -f $i)
        "FI Gate 1 churn $RunID $i" | Set-Content -LiteralPath $Path -Encoding ASCII
        Write-FiGate1WorkloadProgress -Phase 'Create' -Completed ($i + 1) -Total $FileCount -Started $PhaseStarted -NextHeartbeat ([ref]$NextHeartbeat) -HeartbeatIntervalSeconds $HeartbeatSeconds
    }
    Write-FiGate1WorkloadProgress -Phase 'Create' -Completed $FileCount -Total $FileCount -Started $PhaseStarted -NextHeartbeat ([ref]$NextHeartbeat) -HeartbeatIntervalSeconds $HeartbeatSeconds -Force

    for ($Pass = 1; $Pass -le $ModifyPasses; $Pass++) {
        $Files = @(Get-ChildItem -LiteralPath $TestRoot -File -ErrorAction Stop)
        $PhaseStarted = Get-Date
        $NextHeartbeat = $PhaseStarted.AddSeconds($HeartbeatSeconds)
        Write-FiInfo "Modify phase $Pass of $ModifyPasses started: $($Files.Count) files."
        for ($Index = 0; $Index -lt $Files.Count; $Index++) {
            "modify pass $Pass" | Add-Content -LiteralPath $Files[$Index].FullName -Encoding ASCII
            Write-FiGate1WorkloadProgress -Phase "Modify $Pass" -Completed ($Index + 1) -Total $Files.Count -Started $PhaseStarted -NextHeartbeat ([ref]$NextHeartbeat) -HeartbeatIntervalSeconds $HeartbeatSeconds
        }
        Write-FiGate1WorkloadProgress -Phase "Modify $Pass" -Completed $Files.Count -Total $Files.Count -Started $PhaseStarted -NextHeartbeat ([ref]$NextHeartbeat) -HeartbeatIntervalSeconds $HeartbeatSeconds -Force
    }

    $RenameCount = [int][Math]::Floor($FileCount * ($RenamePercent / 100.0))
    if ($RenameCount -gt 0) {
        $RenameFiles = @(Get-ChildItem -LiteralPath $TestRoot -File -ErrorAction Stop | Select-Object -First $RenameCount)
        $PhaseStarted = Get-Date
        $NextHeartbeat = $PhaseStarted.AddSeconds($HeartbeatSeconds)
        Write-FiInfo "Rename phase started: $($RenameFiles.Count) files."
        for ($Index = 0; $Index -lt $RenameFiles.Count; $Index++) {
            Rename-Item -LiteralPath $RenameFiles[$Index].FullName -NewName ("renamed-" + $RenameFiles[$Index].Name)
            Write-FiGate1WorkloadProgress -Phase 'Rename' -Completed ($Index + 1) -Total $RenameFiles.Count -Started $PhaseStarted -NextHeartbeat ([ref]$NextHeartbeat) -HeartbeatIntervalSeconds $HeartbeatSeconds
        }
        Write-FiGate1WorkloadProgress -Phase 'Rename' -Completed $RenameFiles.Count -Total $RenameFiles.Count -Started $PhaseStarted -NextHeartbeat ([ref]$NextHeartbeat) -HeartbeatIntervalSeconds $HeartbeatSeconds -Force
    }

    $DeleteCount = [int][Math]::Floor($FileCount * ($DeletePercent / 100.0))
    if ($DeleteCount -gt 0) {
        $DeleteFiles = @(Get-ChildItem -LiteralPath $TestRoot -File -ErrorAction Stop | Select-Object -Last $DeleteCount)
        $PhaseStarted = Get-Date
        $NextHeartbeat = $PhaseStarted.AddSeconds($HeartbeatSeconds)
        Write-FiInfo "Delete phase started: $($DeleteFiles.Count) files."
        for ($Index = 0; $Index -lt $DeleteFiles.Count; $Index++) {
            Remove-Item -LiteralPath $DeleteFiles[$Index].FullName -Force
            Write-FiGate1WorkloadProgress -Phase 'Delete' -Completed ($Index + 1) -Total $DeleteFiles.Count -Started $PhaseStarted -NextHeartbeat ([ref]$NextHeartbeat) -HeartbeatIntervalSeconds $HeartbeatSeconds
        }
        Write-FiGate1WorkloadProgress -Phase 'Delete' -Completed $DeleteFiles.Count -Total $DeleteFiles.Count -Started $PhaseStarted -NextHeartbeat ([ref]$NextHeartbeat) -HeartbeatIntervalSeconds $HeartbeatSeconds -Force
    }

    $WorkloadFinished = Get-Date
    Write-FiInfo 'Workload complete. Establishing a fully post-workload collection fence.'

    $Fence = Get-FiGate1LatestConfiguredCollectionTail
    $FenceTime = if ($null -ne $Fence) { [DateTimeOffset]::Parse($Fence.observed_at) } else { [DateTimeOffset]::MinValue }

    $FirstCollection = Wait-FiGate1ConfiguredCollectionNewerThan -AfterObservedAt $FenceTime -TimeoutSeconds $CollectionTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds -Label 'first post-workload configured collection'
    $FirstTime = [DateTimeOffset]::Parse($FirstCollection.observed_at)
    $Collection = Wait-FiGate1ConfiguredCollectionNewerThan -AfterObservedAt $FirstTime -TimeoutSeconds $CollectionTimeoutSeconds -HeartbeatIntervalSeconds $HeartbeatSeconds -Label 'fully post-workload configured collection'

    if ($Collection.outcome -ne 'Complete') {
        throw "Fully post-workload configured collection outcome was $($Collection.outcome), want Complete."
    }

    $CheckpointAfter = Get-FiCheckpoint -CheckpointPath $CheckpointPath
    $USNAfter = [UInt64]$CheckpointAfter.next_usn
    if ($USNAfter -le $USNBefore) {
        throw "USN checkpoint did not advance after churn workload: before=$USNBefore after=$USNAfter."
    }

    $SpoolAfter = Get-FiGate1BoundedSpoolSnapshot -HeartbeatIntervalSeconds $HeartbeatSeconds -HardTimeoutSeconds $SpoolSnapshotTimeoutSeconds
    $SecurityAfter = Get-FiGate1LatestSecurityRecordID
    $ProcessAfter = Get-FiGate1CollectorProcessSnapshot
    $ProcessDelta = $null

    if ($null -ne $ProcessBefore -and $null -ne $ProcessAfter -and $ProcessBefore.ProcessID -eq $ProcessAfter.ProcessID) {
        $ProcessDelta = [PSCustomObject]@{
            ProcessID = $ProcessAfter.ProcessID
            ReadOperations = Get-FiGate1UnsignedDelta -After $ProcessAfter.ReadOperationCount -Before $ProcessBefore.ReadOperationCount
            WriteOperations = Get-FiGate1UnsignedDelta -After $ProcessAfter.WriteOperationCount -Before $ProcessBefore.WriteOperationCount
            ReadBytes = Get-FiGate1UnsignedDelta -After $ProcessAfter.ReadTransferCount -Before $ProcessBefore.ReadTransferCount
            WriteBytes = Get-FiGate1UnsignedDelta -After $ProcessAfter.WriteTransferCount -Before $ProcessBefore.WriteTransferCount
            CPUSeconds = ((Get-FiGate1UnsignedDelta -After $ProcessAfter.KernelModeTime100ns -Before $ProcessBefore.KernelModeTime100ns) + (Get-FiGate1UnsignedDelta -After $ProcessAfter.UserModeTime100ns -Before $ProcessBefore.UserModeTime100ns)) / 10000000.0
            WorkingSetBytesAfter = $ProcessAfter.WorkingSetBytes
        }
    }

    $Report = [PSCustomObject]@{
        RecordKind = 'FIGate1ChurnCampaign'
        RunID = $RunID
        Host = $env:COMPUTERNAME
        GovernedRoot = $GovernedRoot
        TestRoot = $TestRoot
        FileCount = $FileCount
        ModifyPasses = $ModifyPasses
        RenameCount = $RenameCount
        DeleteCount = $DeleteCount
        WorkloadSeconds = ($WorkloadFinished - $Started).TotalSeconds
        USNBefore = $USNBefore
        USNAfter = $USNAfter
        CheckpointAdvanced = $true
        SecurityRecordIDBefore = $SecurityBefore
        SecurityRecordIDAfter = $SecurityAfter
        SecurityRecordGrowth = if ($SecurityAfter -ge $SecurityBefore) { [UInt64]($SecurityAfter - $SecurityBefore) } else { [UInt64]0 }
        SpoolBefore = $SpoolBefore
        SpoolAfter = $SpoolAfter
        SpoolGrowthBytes = if ($SpoolAfter.Bytes -ge $SpoolBefore.Bytes) { [UInt64]($SpoolAfter.Bytes - $SpoolBefore.Bytes) } else { [UInt64]0 }
        FirstPostWorkloadCollection = $FirstCollection
        ConfiguredCollection = $Collection
        CollectorProcessBefore = $ProcessBefore
        CollectorProcessAfter = $ProcessAfter
        CollectorProcessDelta = $ProcessDelta
        FinishedUTC = [DateTime]::UtcNow.ToString('o')
    }

    $ReportPath = Join-Path $ResultDirectory "churn-$($env:COMPUTERNAME)-$RunID.json"
    Write-FiGate1Json -InputObject $Report -Path $ReportPath
    Write-FiPass "Churn campaign completed. Report: $ReportPath"
}
finally {
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $TestRoot -PathType Container)) {
        Write-FiInfo "Cleaning churn test root: $TestRoot"
        Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
        Write-FiInfo 'Churn test-root cleanup complete.'
    }
}
