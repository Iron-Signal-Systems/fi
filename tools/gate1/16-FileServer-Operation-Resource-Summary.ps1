# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [ValidateRange(1,720)]
    [int]$Hours = 24,
    [ValidateSet('All','ActivityRead','Baseline','ProtectedRead','Reconciliation','ReObservation','SupportingSourceRefresh','USNCatchUp','USNRead','WindowsSecurityCatchUp')]
    [string]$OperationKind = 'All',
    [string]$StatePath = 'C:\ProgramData\FI\state',
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results\performance',
    [ValidateRange(5,60)]
    [int]$HeartbeatSeconds = 15,
    [ValidateRange(30,1800)]
    [int]$ScanTimeoutSeconds = 180,
    [ValidateRange(1,256)]
    [int]$MaxJournalFiles = 64,
    [ValidateRange(1,2048)]
    [int]$MaxJournalBytesMB = 512,
    [ValidateRange(1000,5000000)]
    [int]$MaxJournalLines = 1000000,
    [ValidateRange(1,500000)]
    [int]$MaxMatchingRecords = 100000,
    [switch]$WorkerMode,
    [string]$WorkerOutputPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $Here 'Common-Gate1.ps1')
Assert-FiGate1Administrator

function ConvertTo-FiGate1SingleQuotedLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-FiGate1JsonPropertyValue {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) { return $null }
    return $Property.Value
}

function Get-FiGate1JsonUInt64OrZero {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][hashtable]$UnavailableFieldCounts,
        [Parameter(Mandatory = $true)][ref]$RecordComplete
    )

    $Value = Get-FiGate1JsonPropertyValue -Object $Object -Name $Name
    if ($null -ne $Value) {
        try { return [UInt64]$Value } catch { }
    }

    $RecordComplete.Value = $false
    if ($UnavailableFieldCounts.ContainsKey($Name)) {
        $UnavailableFieldCounts[$Name] = [int]$UnavailableFieldCounts[$Name] + 1
    }
    else {
        $UnavailableFieldCounts[$Name] = 1
    }
    return [UInt64]0
}

function Invoke-FiGate1OperationResourceWorker {
    param(
        [Parameter(Mandatory = $true)][string]$CommandText,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$HeartbeatSeconds
    )

    $Encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($CommandText))
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $Process.StartInfo.FileName = (Join-Path $PSHOME 'powershell.exe')
    $Process.StartInfo.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $Encoded"
    $Process.StartInfo.UseShellExecute = $false
    $Process.StartInfo.CreateNoWindow = $true
    $Process.StartInfo.RedirectStandardOutput = $true
    $Process.StartInfo.RedirectStandardError = $true

    try {
        if (-not $Process.Start()) { throw 'Could not start bounded operation/resource journal worker.' }
        $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        $StderrTask = $Process.StandardError.ReadToEndAsync()
        $Started = [DateTime]::UtcNow
        $NextHeartbeat = $Started.AddSeconds($HeartbeatSeconds)

        Write-FiInfo "Bounded operation/resource journal scan started; PID=$($Process.Id); hard timeout=${TimeoutSeconds}s."

        while (-not $Process.HasExited) {
            Start-Sleep -Milliseconds 250
            $Now = [DateTime]::UtcNow
            $Elapsed = ($Now - $Started).TotalSeconds

            if ($Elapsed -ge $TimeoutSeconds) {
                try { $Process.Kill() } catch { }
                [void]$Process.WaitForExit(10000)
                throw "Operation/resource journal scan exceeded hard timeout of ${TimeoutSeconds}s and was terminated."
            }

            if ($Now -ge $NextHeartbeat) {
                try { $Process.Refresh() } catch { }
                $WorkingSet = 0
                $CPU = 0.0
                try { $WorkingSet = [UInt64]$Process.WorkingSet64 } catch { }
                try { $CPU = [double]$Process.TotalProcessorTime.TotalSeconds } catch { }
                Write-FiInfo ("Operation/resource scan still active: {0:N0}s elapsed; PID={1}; working_set={2}; cpu_seconds={3:N2}." -f $Elapsed,$Process.Id,$WorkingSet,$CPU)
                $NextHeartbeat = $Now.AddSeconds($HeartbeatSeconds)
            }
        }

        $Process.WaitForExit()
        $Process.Refresh()
        $ExitCode = [int]$Process.ExitCode
        $Stdout = $StdoutTask.GetAwaiter().GetResult()
        $Stderr = $StderrTask.GetAwaiter().GetResult()
        $ElapsedFinal = ([DateTime]::UtcNow - $Started).TotalSeconds

        Write-FiInfo ("Bounded operation/resource journal scan exited after {0:N1}s with code {1}." -f $ElapsedFinal,$ExitCode)

        if ($Stdout.Trim()) { $Stdout.TrimEnd() -split "`r?`n" | ForEach-Object { Write-Host $_ } }
        if ($ExitCode -ne 0) {
            $Tail = @($Stderr.TrimEnd() -split "`r?`n" | Select-Object -Last 40)
            $Tail | ForEach-Object { Write-Host $_ }
            throw "Operation/resource journal worker failed with exit code $ExitCode."
        }

        return [PSCustomObject]@{ ExitCode=$ExitCode; ElapsedSeconds=$ElapsedFinal }
    }
    finally {
        try {
            if ($Process -and -not $Process.HasExited) {
                $Process.Kill()
                [void]$Process.WaitForExit(5000)
            }
        }
        catch { }
        if ($Process) { $Process.Dispose() }
    }
}

if ($WorkerMode) {
    if (-not $WorkerOutputPath) { throw '-WorkerOutputPath is required in worker mode.' }
    if (-not (Test-Path -LiteralPath $StatePath -PathType Container)) { throw "FI state path not found: $StatePath" }

    $Cutoff = [DateTime]::UtcNow.AddHours(-1 * $Hours)
    $StateDirectory = New-Object System.IO.DirectoryInfo -ArgumentList $StatePath
    $OperationFiles = @($StateDirectory.EnumerateFiles('*-operations.jsonl',[System.IO.SearchOption]::TopDirectoryOnly))
    $ResourceFiles = @($StateDirectory.EnumerateFiles('*-resources.jsonl',[System.IO.SearchOption]::TopDirectoryOnly))
    $JournalFiles = @($OperationFiles + $ResourceFiles | Sort-Object FullName -Unique)

    if ($JournalFiles.Count -gt $MaxJournalFiles) {
        throw "Journal file count $($JournalFiles.Count) exceeds MaxJournalFiles=$MaxJournalFiles."
    }

    [UInt64]$JournalBytes = 0
    foreach ($File in $JournalFiles) { $JournalBytes += [UInt64]$File.Length }
    [UInt64]$MaxJournalBytes = [UInt64]$MaxJournalBytesMB * 1MB
    if ($JournalBytes -gt $MaxJournalBytes) {
        throw "Journal bytes $JournalBytes exceed MaxJournalBytesMB=$MaxJournalBytesMB."
    }

    $Outcomes = @{}
    [int]$JournalLinesRead = 0
    [int]$MalformedJsonLines = 0
    [int]$ResourceRowsMissingObservedAt = 0
    $UnavailableResourceFieldCounts = @{}

    foreach ($File in $OperationFiles) {
        foreach ($Line in [System.IO.File]::ReadLines($File.FullName)) {
            $JournalLinesRead++
            if ($JournalLinesRead -gt $MaxJournalLines) {
                throw "Journal line count exceeds MaxJournalLines=$MaxJournalLines."
            }
            if (-not $Line.Trim()) { continue }
            try { $Record = $Line | ConvertFrom-Json } catch { $MalformedJsonLines++; continue }

            $Event = [string](Get-FiGate1JsonPropertyValue -Object $Record -Name 'event')
            $OperationID = [string](Get-FiGate1JsonPropertyValue -Object $Record -Name 'operation_id')
            if ($Event -eq 'Finished' -and $OperationID) {
                $OutcomeValue = Get-FiGate1JsonPropertyValue -Object $Record -Name 'outcome'
                $ReasonCodeValue = Get-FiGate1JsonPropertyValue -Object $Record -Name 'reason_code'
                $FinishedAtValue = Get-FiGate1JsonPropertyValue -Object $Record -Name 'finished_at'
                $Outcomes[$OperationID] = [PSCustomObject]@{
                    Outcome = if ($null -ne $OutcomeValue -and [string]$OutcomeValue) { [string]$OutcomeValue } else { 'Unknown' }
                    ReasonCode = if ($null -ne $ReasonCodeValue) { [string]$ReasonCodeValue } else { '' }
                    FinishedAt = if ($null -ne $FinishedAtValue) { [string]$FinishedAtValue } else { '' }
                }
            }
        }
    }

    $Rows = New-Object System.Collections.Generic.List[object]
    foreach ($File in $ResourceFiles) {
        foreach ($Line in [System.IO.File]::ReadLines($File.FullName)) {
            $JournalLinesRead++
            if ($JournalLinesRead -gt $MaxJournalLines) {
                throw "Journal line count exceeds MaxJournalLines=$MaxJournalLines."
            }
            if (-not $Line.Trim()) { continue }
            try { $Record = $Line | ConvertFrom-Json } catch { $MalformedJsonLines++; continue }

            $RecordKind = [string](Get-FiGate1JsonPropertyValue -Object $Record -Name 'record_kind')
            if ($RecordKind -ne 'ResourceSummary') { continue }

            $RecordOperationKind = [string](Get-FiGate1JsonPropertyValue -Object $Record -Name 'operation_kind')
            if (-not $RecordOperationKind) { $RecordOperationKind = 'Unknown' }
            if ($OperationKind -ne 'All' -and $RecordOperationKind -ne $OperationKind) { continue }

            $ObservedValue = Get-FiGate1JsonPropertyValue -Object $Record -Name 'observed_at'
            if ($null -eq $ObservedValue -or -not [string]$ObservedValue) {
                $ResourceRowsMissingObservedAt++
                continue
            }
            try { $Observed = [DateTime]::Parse([string]$ObservedValue).ToUniversalTime() }
            catch { $ResourceRowsMissingObservedAt++; continue }
            if ($Observed -lt $Cutoff) { continue }

            $RecordOperationID = [string](Get-FiGate1JsonPropertyValue -Object $Record -Name 'operation_id')
            $Outcome = $null
            if ($RecordOperationID -and $Outcomes.ContainsKey($RecordOperationID)) {
                $Outcome = $Outcomes[$RecordOperationID]
            }

            if ($Rows.Count -ge $MaxMatchingRecords) {
                throw "Matching ResourceSummary record count would exceed MaxMatchingRecords=$MaxMatchingRecords."
            }

            $ResourceFieldsComplete = $true
            $Elapsed100ns = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'elapsed_100ns' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $CPU100ns = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'cpu_100ns' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $WorkingSetBytes = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'working_set_bytes' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $PeakWorkingSetBytes = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'peak_working_set_bytes' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $PrivateBytes = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'private_bytes' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $PeakPrivateBytes = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'peak_private_bytes' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $ReadOperations = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'read_operations' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $ReadBytes = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'read_bytes' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $WriteOperations = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'write_operations' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $WriteBytes = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'write_bytes' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $OtherOperations = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'other_operations' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)
            $OtherBytes = Get-FiGate1JsonUInt64OrZero -Object $Record -Name 'other_bytes' -UnavailableFieldCounts $UnavailableResourceFieldCounts -RecordComplete ([ref]$ResourceFieldsComplete)

            $Rows.Add([PSCustomObject]@{
                ScopeID = [string](Get-FiGate1JsonPropertyValue -Object $Record -Name 'scope_id')
                OperationID = $RecordOperationID
                OperationKind = $RecordOperationKind
                Outcome = if ($Outcome) {$Outcome.Outcome} else {'Unknown'}
                ReasonCode = if ($Outcome) {$Outcome.ReasonCode} else {''}
                ObservedUTC = $Observed.ToString('o')
                ResourceFieldsComplete = [bool]$ResourceFieldsComplete
                ElapsedSeconds = ([double]$Elapsed100ns / 10000000.0)
                CPUSeconds = ([double]$CPU100ns / 10000000.0)
                WorkingSetBytes = $WorkingSetBytes
                PeakWorkingSetBytes = $PeakWorkingSetBytes
                PrivateBytes = $PrivateBytes
                PeakPrivateBytes = $PeakPrivateBytes
                ReadOperations = $ReadOperations
                ReadBytes = $ReadBytes
                WriteOperations = $WriteOperations
                WriteBytes = $WriteBytes
                OtherOperations = $OtherOperations
                OtherBytes = $OtherBytes
                ExecutableSHA256 = [string](Get-FiGate1JsonPropertyValue -Object $Record -Name 'executable_sha256')
                ResourceJournal = $File.FullName
            })
        }
    }

    $ByKind = @(
        $Rows | Group-Object OperationKind | Sort-Object Name | ForEach-Object {
            $Group = @($_.Group)
            $MetricGroup = @($Group | Where-Object {$_.ResourceFieldsComplete})
            [PSCustomObject]@{
                OperationKind = $_.Name
                Count = $Group.Count
                Complete = @($Group | Where-Object {$_.Outcome -eq 'Complete'}).Count
                Partial = @($Group | Where-Object {$_.Outcome -eq 'Partial'}).Count
                Failed = @($Group | Where-Object {$_.Outcome -eq 'Failed'}).Count
                Interrupted = @($Group | Where-Object {$_.Outcome -eq 'Interrupted'}).Count
                ResourceMetricsComplete = $MetricGroup.Count
                ResourceMetricsIncomplete = $Group.Count - $MetricGroup.Count
                ElapsedSecondsAverage = if ($MetricGroup.Count) { [double](($MetricGroup | Measure-Object ElapsedSeconds -Average).Average) } else { 0.0 }
                ElapsedSecondsMax = if ($MetricGroup.Count) { [double](($MetricGroup | Measure-Object ElapsedSeconds -Maximum).Maximum) } else { 0.0 }
                CPUSecondsAverage = if ($MetricGroup.Count) { [double](($MetricGroup | Measure-Object CPUSeconds -Average).Average) } else { 0.0 }
                ReadBytesTotal = if ($MetricGroup.Count) { [UInt64](($MetricGroup | Measure-Object ReadBytes -Sum).Sum) } else { [UInt64]0 }
                WriteBytesTotal = if ($MetricGroup.Count) { [UInt64](($MetricGroup | Measure-Object WriteBytes -Sum).Sum) } else { [UInt64]0 }
                PeakWorkingSetBytesMax = if ($MetricGroup.Count) { [UInt64](($MetricGroup | Measure-Object PeakWorkingSetBytes -Maximum).Maximum) } else { [UInt64]0 }
            }
        }
    )

    $Report = [PSCustomObject]@{
        RecordKind = 'FIGate1OperationResourceSummary'
        Host = $env:COMPUTERNAME
        WindowHours = $Hours
        OperationKindFilter = $OperationKind
        CutoffUTC = $Cutoff.ToString('o')
        ObservedUTC = [DateTime]::UtcNow.ToString('o')
        OperationCount = $Rows.Count
        JournalFileCount = $JournalFiles.Count
        JournalBytes = $JournalBytes
        JournalLinesRead = $JournalLinesRead
        MalformedJsonLines = $MalformedJsonLines
        ResourceRowsMissingObservedAt = $ResourceRowsMissingObservedAt
        UnavailableResourceFieldCounts = @(
            $UnavailableResourceFieldCounts.GetEnumerator() | Sort-Object Name | ForEach-Object {
                [PSCustomObject]@{ Field = $_.Name; Count = [int]$_.Value }
            }
        )
        SafetyLimits = [PSCustomObject]@{
            MaxJournalFiles = $MaxJournalFiles
            MaxJournalBytesMB = $MaxJournalBytesMB
            MaxJournalLines = $MaxJournalLines
            MaxMatchingRecords = $MaxMatchingRecords
        }
        ByKind = $ByKind
        Operations = $Rows.ToArray()
    }

    $Stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $ReportPath = Join-Path $ResultDirectory "operation-resources-$($env:COMPUTERNAME)-$Stamp.json"
    Write-FiGate1Json -InputObject $Report -Path $ReportPath

    $Control = [PSCustomObject]@{
        ReportPath = $ReportPath
        OperationCount = $Rows.Count
        JournalFileCount = $JournalFiles.Count
        JournalBytes = $JournalBytes
        JournalLinesRead = $JournalLinesRead
        MalformedJsonLines = $MalformedJsonLines
        ResourceRowsMissingObservedAt = $ResourceRowsMissingObservedAt
        UnavailableResourceFieldCounts = @(
            $UnavailableResourceFieldCounts.GetEnumerator() | Sort-Object Name | ForEach-Object {
                [PSCustomObject]@{ Field = $_.Name; Count = [int]$_.Value }
            }
        )
        ByKind = $ByKind
    }
    [System.IO.File]::WriteAllText($WorkerOutputPath,($Control | ConvertTo-Json -Depth 5 -Compress),[System.Text.Encoding]::UTF8)
    exit 0
}

$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory
if (-not (Test-Path -LiteralPath $StatePath -PathType Container)) { throw "FI state path not found: $StatePath" }

$ControlPath = Join-Path $ResultDirectory ("operation-resource-worker-$([guid]::NewGuid().ToString('N')).json")
$ScriptLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $MyInvocation.MyCommand.Path
$ControlLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $ControlPath
$StateLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $StatePath
$ResultLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $ResultDirectory
$KindLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $OperationKind
$CommandText = "& $ScriptLiteral -WorkerMode -WorkerOutputPath $ControlLiteral -Hours $Hours -OperationKind $KindLiteral -StatePath $StateLiteral -ResultDirectory $ResultLiteral -HeartbeatSeconds $HeartbeatSeconds -ScanTimeoutSeconds $ScanTimeoutSeconds -MaxJournalFiles $MaxJournalFiles -MaxJournalBytesMB $MaxJournalBytesMB -MaxJournalLines $MaxJournalLines -MaxMatchingRecords $MaxMatchingRecords"

try {
    [void](Invoke-FiGate1OperationResourceWorker -CommandText $CommandText -TimeoutSeconds $ScanTimeoutSeconds -HeartbeatSeconds $HeartbeatSeconds)
    if (-not (Test-Path -LiteralPath $ControlPath -PathType Leaf)) { throw 'Operation/resource worker completed without a control record.' }
    $Control = Get-Content -LiteralPath $ControlPath -Raw | ConvertFrom-Json
    if (-not $Control.ReportPath -or -not (Test-Path -LiteralPath ([string]$Control.ReportPath) -PathType Leaf)) {
        throw 'Operation/resource worker did not produce the expected report.'
    }

    if (@($Control.ByKind).Count) { @($Control.ByKind) | Format-Table -AutoSize }
    else { Write-FiInfo "No matching ResourceSummary records found in the last $Hours hour(s)." }

    Write-FiInfo "Matching operations: $($Control.OperationCount); journal files: $($Control.JournalFileCount); journal bytes: $($Control.JournalBytes); lines read: $($Control.JournalLinesRead); malformed JSON lines: $($Control.MalformedJsonLines); ResourceSummary rows missing/invalid observed_at: $($Control.ResourceRowsMissingObservedAt)."
    if (@($Control.UnavailableResourceFieldCounts).Count) {
        Write-FiInfo 'Some matching ResourceSummary rows lacked one or more resource metric fields; aggregate resource metrics exclude incomplete rows.'
        @($Control.UnavailableResourceFieldCounts) | Format-Table -AutoSize
    }
    Write-FiPass "Operation/resource journal summary complete. Report: $($Control.ReportPath)"
}
finally {
    Remove-Item -LiteralPath $ControlPath -Force -ErrorAction SilentlyContinue
}
