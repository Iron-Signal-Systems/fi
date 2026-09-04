# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# Test 12D is a passive dependency observer. It does NOT disable, stop, restart,
# reconfigure, or otherwise alter AD/LDAPS, networking, Security logs, SMB,
# FICollector, FIUSNReader, or any other dependency. A separately controlled
# outage is observed with Before / During / After invocations.
#
# Safety contract:
# - the entire observation runs in a child PowerShell process;
# - the parent enforces a hard timeout and heartbeat and kills a hung worker;
# - service-runtime inspection is a bounded tail read by bytes and lines;
# - the spool tree is never enumerated;
# - Security-log probing is limited to one event and is covered by the worker
#   timeout;
# - the only writes are the bounded Gate 1 report and a temporary control file.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('AD-LDAPS','SecurityLog','SMB-LocalIdentity','Other')]
    [string]$Dependency,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Before','During','After')]
    [string]$Stage,

    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results',
    [string]$RuntimePath = 'C:\ProgramData\FI\state\service-runtime.jsonl',
    [string]$SpoolPath = 'C:\ProgramData\FI\spool',

    [ValidateRange(10,300)]
    [int]$ObservationTimeoutSeconds = 60,

    [ValidateRange(5,60)]
    [int]$HeartbeatSeconds = 15,

    [ValidateRange(1,16)]
    [int]$MaxRuntimeTailBytesMB = 1,

    [ValidateRange(10,200)]
    [int]$RuntimeTailLines = 40,

    [ValidateLength(0,1024)]
    [string]$Note = '',

    [switch]$WorkerMode,
    [string]$WorkerOutputPath = '',
    [string]$WorkerReportPath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Assert-FiGate1Administrator {
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal -ArgumentList $Identity
    if (-not $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Gate 1 Test 12D must run from elevated Windows PowerShell.'
    }
}

function ConvertTo-FiGate1SingleQuotedLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-FiGate1DriveFreeBytes {
    param([Parameter(Mandatory = $true)][string]$Path)

    $FullPath = [System.IO.Path]::GetFullPath($Path)
    $Root = [System.IO.Path]::GetPathRoot($FullPath)
    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw "Could not determine volume root for $Path."
    }

    $Drive = New-Object System.IO.DriveInfo -ArgumentList $Root
    return [UInt64]$Drive.AvailableFreeSpace
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

function Get-FiGate1DependencySpoolState {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [PSCustomObject]@{
            Exists = $false
            Path = $Path
            DirectoryLastWriteUTC = ''
            FreeBytes = [UInt64]0
            TreeEnumerated = $false
        }
    }

    $Item = Get-Item -LiteralPath $Path -ErrorAction Stop
    return [PSCustomObject]@{
        Exists = $true
        Path = $Item.FullName
        DirectoryLastWriteUTC = $Item.LastWriteTimeUtc.ToString('o')
        FreeBytes = Get-FiGate1DriveFreeBytes -Path $Path
        TreeEnumerated = $false
    }
}

function Read-FiGate1RuntimeTailBounded {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$MaxBytesMB,
        [Parameter(Mandatory = $true)][int]$TailLines
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [PSCustomObject]@{
            Exists = $false
            Path = $Path
            FileLengthBytes = [UInt64]0
            BytesRead = [UInt64]0
            StartedMidFile = $false
            LinesReturned = 0
            LatestConfiguredCollection = $null
            Lines = @()
        }
    }

    [Int64]$MaxBytes = [Int64]$MaxBytesMB * 1MB
    $Share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    $Stream = $null

    try {
        $Stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            $Share
        )

        [Int64]$Length = $Stream.Length
        [Int64]$StartOffset = [Math]::Max([Int64]0, $Length - $MaxBytes)
        [int]$BytesToRead = [int]($Length - $StartOffset)
        [void]$Stream.Seek($StartOffset, [System.IO.SeekOrigin]::Begin)

        $Buffer = New-Object byte[] $BytesToRead
        [int]$TotalRead = 0
        while ($TotalRead -lt $BytesToRead) {
            $Read = $Stream.Read($Buffer, $TotalRead, $BytesToRead - $TotalRead)
            if ($Read -le 0) { break }
            $TotalRead += $Read
        }
    }
    finally {
        if ($null -ne $Stream) { $Stream.Dispose() }
    }

    $Text = [System.Text.Encoding]::UTF8.GetString($Buffer, 0, $TotalRead)
    $StartedMidFile = ($StartOffset -gt 0)

    if ($StartedMidFile) {
        $FirstNewLine = $Text.IndexOf("`n", [System.StringComparison]::Ordinal)
        if ($FirstNewLine -ge 0) {
            $Text = $Text.Substring($FirstNewLine + 1)
        }
        else {
            $Text = ''
        }
    }

    $AllLines = @($Text -split "`r?`n" | Where-Object { $_ -ne '' })
    if ($AllLines.Count -gt $TailLines) {
        $Lines = @($AllLines | Select-Object -Last $TailLines)
    }
    else {
        $Lines = $AllLines
    }

    # Search every complete line inside the bounded byte window for the latest
    # ConfiguredCollection. RuntimeTailLines limits only what is retained in the
    # report; it must not make the latest-collection lookup less complete than the
    # bounded byte window itself.
    $LatestConfiguredCollection = $null
    for ($Index = $AllLines.Count - 1; $Index -ge 0; $Index--) {
        $Line = [string]$AllLines[$Index]
        if ($Line.IndexOf('"record_kind":"ConfiguredCollection"', [System.StringComparison]::Ordinal) -lt 0) {
            continue
        }

        try {
            $Candidate = $Line | ConvertFrom-Json
        }
        catch {
            continue
        }

        $Kind = [string](Get-FiGate1JsonPropertyValue -Object $Candidate -Name 'record_kind')
        if ($Kind -eq 'ConfiguredCollection') {
            $LatestConfiguredCollection = $Candidate
            break
        }
    }

    return [PSCustomObject]@{
        Exists = $true
        Path = $Path
        FileLengthBytes = [UInt64]$Length
        BytesRead = [UInt64]$TotalRead
        StartedMidFile = $StartedMidFile
        LinesReturned = $Lines.Count
        LatestConfiguredCollection = $LatestConfiguredCollection
        Lines = $Lines
    }
}

function Write-FiGate1AtomicUtf8Json {
    param(
        [Parameter(Mandatory = $true)][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateRange(2,20)][int]$Depth = 8
    )

    $Parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($Parent)) {
        throw "Output path has no parent directory: $Path"
    }
    [void][System.IO.Directory]::CreateDirectory($Parent)

    $Json = $InputObject | ConvertTo-Json -Depth $Depth
    $Encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
    $TempPath = $Path + '.tmp'

    try {
        [System.IO.File]::WriteAllText($TempPath, $Json, $Encoding)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            throw "Refusing to overwrite existing Gate 1 report: $Path"
        }
        [System.IO.File]::Move($TempPath, $Path)
    }
    finally {
        if (Test-Path -LiteralPath $TempPath -PathType Leaf) {
            Remove-Item -LiteralPath $TempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-FiGate1DependencyObservationWorker {
    param(
        [Parameter(Mandatory = $true)][string]$CommandText,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$HeartbeatIntervalSeconds
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
        if (-not $Process.Start()) {
            throw 'Could not start bounded Test 12D observation worker.'
        }

        $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        $StderrTask = $Process.StandardError.ReadToEndAsync()
        $Started = [DateTime]::UtcNow
        $NextHeartbeat = $Started.AddSeconds($HeartbeatIntervalSeconds)

        Write-Host "[INFO] Test 12D observation worker started; PID=$($Process.Id); hard timeout=${TimeoutSeconds}s."

        while (-not $Process.HasExited) {
            Start-Sleep -Milliseconds 250
            $Now = [DateTime]::UtcNow
            $Elapsed = ($Now - $Started).TotalSeconds

            if ($Elapsed -ge $TimeoutSeconds) {
                try { $Process.Kill() } catch { }
                try { [void]$Process.WaitForExit(10000) } catch { }
                throw "Test 12D observation exceeded hard timeout of ${TimeoutSeconds}s and was terminated."
            }

            if ($Now -ge $NextHeartbeat) {
                try { $Process.Refresh() } catch { }
                [UInt64]$WorkingSet = 0
                [double]$CPUSeconds = 0.0
                try { $WorkingSet = [UInt64]$Process.WorkingSet64 } catch { }
                try { $CPUSeconds = [double]$Process.TotalProcessorTime.TotalSeconds } catch { }
                Write-Host ("[INFO] Test 12D worker still active: {0:N0}s elapsed; PID={1}; working_set={2}; cpu_seconds={3:N2}." -f $Elapsed,$Process.Id,$WorkingSet,$CPUSeconds)
                $NextHeartbeat = $Now.AddSeconds($HeartbeatIntervalSeconds)
            }
        }

        $Process.WaitForExit()
        $Process.Refresh()
        $ExitCode = [int]$Process.ExitCode
        $Stdout = $StdoutTask.GetAwaiter().GetResult()
        $Stderr = $StderrTask.GetAwaiter().GetResult()
        $ElapsedFinal = ([DateTime]::UtcNow - $Started).TotalSeconds

        Write-Host ("[INFO] Test 12D worker exited after {0:N1}s with code {1}." -f $ElapsedFinal,$ExitCode)

        if ($Stdout.Trim()) {
            @($Stdout.TrimEnd() -split "`r?`n" | Select-Object -Last 40) |
                ForEach-Object { Write-Host $_ }
        }

        if ($ExitCode -ne 0) {
            @($Stderr.TrimEnd() -split "`r?`n" | Select-Object -Last 40) |
                ForEach-Object { Write-Host $_ }
            throw "Test 12D observation worker failed with exit code $ExitCode."
        }

        return [PSCustomObject]@{
            ExitCode = $ExitCode
            ElapsedSeconds = $ElapsedFinal
        }
    }
    finally {
        try {
            if ($null -ne $Process -and -not $Process.HasExited) {
                $Process.Kill()
                [void]$Process.WaitForExit(5000)
            }
        }
        catch { }
        if ($null -ne $Process) { $Process.Dispose() }
    }
}

Assert-FiGate1Administrator

if ($WorkerMode) {
    if ([string]::IsNullOrWhiteSpace($WorkerOutputPath)) {
        throw '-WorkerOutputPath is required in worker mode.'
    }
    if ([string]::IsNullOrWhiteSpace($WorkerReportPath)) {
        throw '-WorkerReportPath is required in worker mode.'
    }

    $WorkerStarted = [DateTime]::UtcNow
    $Runtime = Read-FiGate1RuntimeTailBounded `
        -Path $RuntimePath `
        -MaxBytesMB $MaxRuntimeTailBytesMB `
        -TailLines $RuntimeTailLines

    $CollectorService = Get-Service FICollector -ErrorAction SilentlyContinue
    $HelperService = Get-Service FIUSNReader -ErrorAction SilentlyContinue
    $CollectorState = if ($null -eq $CollectorService) { 'Missing' } else { $CollectorService.Status.ToString() }
    $HelperState = if ($null -eq $HelperService) { 'Missing' } else { $HelperService.Status.ToString() }

    $SecurityReadable = $true
    $SecurityError = ''
    try {
        $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    }
    catch {
        $SecurityReadable = $false
        $SecurityError = $_.Exception.Message
    }

    $Spool = Get-FiGate1DependencySpoolState -Path $SpoolPath
    $ObservedUTC = [DateTime]::UtcNow.ToString('o')

    $Report = [PSCustomObject]@{
        RecordKind = 'FIGate1DependencyObservation'
        Host = $env:COMPUTERNAME
        Dependency = $Dependency
        Stage = $Stage
        ObservedUTC = $ObservedUTC
        Note = $Note
        FICollector = $CollectorState
        FIUSNReader = $HelperState
        LatestConfiguredCollection = $Runtime.LatestConfiguredCollection
        Spool = $Spool
        SecurityLogReadableByAdministrator = $SecurityReadable
        SecurityLogAdministratorError = $SecurityError
        RuntimeTail = $Runtime.Lines
        RuntimeObservation = [PSCustomObject]@{
            Path = $Runtime.Path
            Exists = $Runtime.Exists
            FileLengthBytes = $Runtime.FileLengthBytes
            BytesRead = $Runtime.BytesRead
            StartedMidFile = $Runtime.StartedMidFile
            LinesReturned = $Runtime.LinesReturned
        }
        SafetyLimits = [PSCustomObject]@{
            ObservationTimeoutSeconds = $ObservationTimeoutSeconds
            HeartbeatSeconds = $HeartbeatSeconds
            MaxRuntimeTailBytesMB = $MaxRuntimeTailBytesMB
            RuntimeTailLines = $RuntimeTailLines
            SecurityLogMaxEvents = 1
            SpoolTreeEnumerated = $false
        }
        WorkerElapsedSeconds = ([DateTime]::UtcNow - $WorkerStarted).TotalSeconds
    }

    Write-FiGate1AtomicUtf8Json -InputObject $Report -Path $WorkerReportPath -Depth 10
    $ReportInfo = Get-Item -LiteralPath $WorkerReportPath -ErrorAction Stop
    if ($ReportInfo.Length -gt 2MB) {
        throw "Test 12D report exceeded 2 MiB safety limit: $($ReportInfo.Length) bytes."
    }

    $LatestOutcome = ''
    if ($null -ne $Runtime.LatestConfiguredCollection) {
        $LatestOutcome = [string](Get-FiGate1JsonPropertyValue -Object $Runtime.LatestConfiguredCollection -Name 'outcome')
    }

    $Control = [PSCustomObject]@{
        RecordKind = 'FIGate1DependencyObservationControl'
        ReportPath = $WorkerReportPath
        ReportBytes = [UInt64]$ReportInfo.Length
        Host = $env:COMPUTERNAME
        Dependency = $Dependency
        Stage = $Stage
        ObservedUTC = $ObservedUTC
        FICollector = $CollectorState
        FIUSNReader = $HelperState
        LatestConfiguredCollectionOutcome = $LatestOutcome
        SecurityLogReadableByAdministrator = $SecurityReadable
        RuntimeBytesRead = $Runtime.BytesRead
        RuntimeLinesReturned = $Runtime.LinesReturned
    }

    Write-FiGate1AtomicUtf8Json -InputObject $Control -Path $WorkerOutputPath -Depth 6
    exit 0
}

[void][System.IO.Directory]::CreateDirectory($ResultDirectory)

$Stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$Nonce = [Guid]::NewGuid().ToString('N').Substring(0,8)
$ReportPath = Join-Path $ResultDirectory "gate1-dependency-$Dependency-$Stage-$($env:COMPUTERNAME)-$Stamp-$Nonce.json"
$ControlPath = Join-Path $env:TEMP "fi-gate1-12d-control-$Nonce.json"
$ReportTempPath = $ReportPath + '.tmp'
$ControlTempPath = $ControlPath + '.tmp'

$ScriptLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $MyInvocation.MyCommand.Path
$DependencyLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $Dependency
$StageLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $Stage
$ResultLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $ResultDirectory
$RuntimeLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $RuntimePath
$SpoolLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $SpoolPath
$NoteLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $Note
$ControlLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $ControlPath
$ReportLiteral = ConvertTo-FiGate1SingleQuotedLiteral -Value $ReportPath

$CommandText = "& $ScriptLiteral -WorkerMode -WorkerOutputPath $ControlLiteral -WorkerReportPath $ReportLiteral -Dependency $DependencyLiteral -Stage $StageLiteral -ResultDirectory $ResultLiteral -RuntimePath $RuntimeLiteral -SpoolPath $SpoolLiteral -ObservationTimeoutSeconds $ObservationTimeoutSeconds -HeartbeatSeconds $HeartbeatSeconds -MaxRuntimeTailBytesMB $MaxRuntimeTailBytesMB -RuntimeTailLines $RuntimeTailLines -Note $NoteLiteral"

$ObservationAccepted = $false

try {
    [void](Invoke-FiGate1DependencyObservationWorker `
        -CommandText $CommandText `
        -TimeoutSeconds $ObservationTimeoutSeconds `
        -HeartbeatIntervalSeconds $HeartbeatSeconds)

    if (-not (Test-Path -LiteralPath $ControlPath -PathType Leaf)) {
        throw 'Test 12D worker completed without producing the bounded control record.'
    }

    $ControlInfo = Get-Item -LiteralPath $ControlPath -ErrorAction Stop
    if ($ControlInfo.Length -gt 64KB) {
        throw "Test 12D control record exceeded 64 KiB: $($ControlInfo.Length) bytes."
    }

    $ControlText = [System.IO.File]::ReadAllText($ControlPath)
    $Control = $ControlText | ConvertFrom-Json
    if ([string](Get-FiGate1JsonPropertyValue -Object $Control -Name 'RecordKind') -ne 'FIGate1DependencyObservationControl') {
        throw 'Test 12D control record kind is invalid.'
    }

    $ReportedPath = [string](Get-FiGate1JsonPropertyValue -Object $Control -Name 'ReportPath')
    if ($ReportedPath -ne $ReportPath) {
        throw 'Test 12D worker returned an unexpected report path.'
    }
    if ([string](Get-FiGate1JsonPropertyValue -Object $Control -Name 'Dependency') -ne $Dependency) {
        throw 'Test 12D control record dependency does not match the requested dependency.'
    }
    if ([string](Get-FiGate1JsonPropertyValue -Object $Control -Name 'Stage') -ne $Stage) {
        throw 'Test 12D control record stage does not match the requested stage.'
    }
    if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
        throw 'Test 12D worker did not produce the expected report.'
    }

    $ReportInfo = Get-Item -LiteralPath $ReportPath -ErrorAction Stop
    if ($ReportInfo.Length -gt 2MB) {
        throw "Test 12D report exceeded 2 MiB: $($ReportInfo.Length) bytes."
    }
    if ([UInt64](Get-FiGate1JsonPropertyValue -Object $Control -Name 'ReportBytes') -ne [UInt64]$ReportInfo.Length) {
        throw 'Test 12D control/report byte count mismatch.'
    }

    $ReportText = [System.IO.File]::ReadAllText($ReportPath)
    $FinalReport = $ReportText | ConvertFrom-Json
    if ([string](Get-FiGate1JsonPropertyValue -Object $FinalReport -Name 'RecordKind') -ne 'FIGate1DependencyObservation') {
        throw 'Test 12D final report record kind is invalid.'
    }
    if ([string](Get-FiGate1JsonPropertyValue -Object $FinalReport -Name 'Dependency') -ne $Dependency) {
        throw 'Test 12D final report dependency does not match the request.'
    }
    if ([string](Get-FiGate1JsonPropertyValue -Object $FinalReport -Name 'Stage') -ne $Stage) {
        throw 'Test 12D final report stage does not match the request.'
    }

    $ReportHash = (Get-FileHash -LiteralPath $ReportPath -Algorithm SHA256).Hash
    $ObservationAccepted = $true

    Write-Host ''
    Write-Host '=== TEST 12D DEPENDENCY OBSERVATION ==='
    Write-Host "Host:                 $($Control.Host)"
    Write-Host "Dependency:           $($Control.Dependency)"
    Write-Host "Stage:                $($Control.Stage)"
    Write-Host "Observed UTC:         $($Control.ObservedUTC)"
    Write-Host "FICollector:          $($Control.FICollector)"
    Write-Host "FIUSNReader:          $($Control.FIUSNReader)"
    Write-Host "Latest collection:    $($Control.LatestConfiguredCollectionOutcome)"
    Write-Host "Security log readable:$($Control.SecurityLogReadableByAdministrator)"
    Write-Host "Runtime bytes read:   $($Control.RuntimeBytesRead)"
    Write-Host "Runtime lines kept:   $($Control.RuntimeLinesReturned)"
    Write-Host "Report bytes:         $($ReportInfo.Length)"
    Write-Host "Report SHA256:        $ReportHash"
    Write-Host "Report:               $ReportPath"
    Write-Host ''
    Write-Host '[PASS] Dependency observation captured without changing the dependency.'
}
finally {
    Remove-Item -LiteralPath $ControlPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ControlTempPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ReportTempPath -Force -ErrorAction SilentlyContinue

    # A timed-out or otherwise rejected worker must not leave behind a report
    # that could later be mistaken for an accepted 12D observation.
    if (-not $ObservationAccepted) {
        Remove-Item -LiteralPath $ReportPath -Force -ErrorAction SilentlyContinue
    }
}
