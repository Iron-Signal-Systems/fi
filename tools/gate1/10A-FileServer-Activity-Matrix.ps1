# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [string]$GovernedRoot = '',
    [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results',
    [int]$CollectionTimeoutSeconds = 180,
    [switch]$KeepArtifacts,
    [switch]$SkipSACLChange,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmWorkload
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $ConfirmWorkload) { throw '-ConfirmWorkload is required because this script creates/modifies/deletes test data.' }

. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Common-Gate1.ps1')

Assert-FiGate1Administrator
$GovernedRoot = Get-FiGate1SingleGovernedRoot -GovernedRoot $GovernedRoot
$ResultDirectory = New-FiGate1ResultDirectory -ResultDirectory $ResultDirectory

if (-not (Test-Path -LiteralPath $GovernedRoot -PathType Container)) {
    throw "Governed root does not exist: $GovernedRoot"
}

function Get-FiGate110ABoundedSpoolSnapshot {
    param(
        [string]$SpoolPath = 'C:\ProgramData\FI\spool',
        [int]$TimeoutSeconds = 120,
        [int]$HeartbeatSeconds = 15,
        [int]$MaxFiles = 100000
    )

    if (-not (Test-Path -LiteralPath $SpoolPath -PathType Container)) {
        return [PSCustomObject]@{
            Exists = $false
            FileCount = 0
            Bytes = [UInt64]0
            JsonlCount = 0
            ManifestCount = 0
            ElapsedSeconds = 0
            EnumerationScope = 'TopDirectoryOnly'
        }
    }

    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $NextHeartbeat = $HeartbeatSeconds
    $FileCount = 0
    $JsonlCount = 0
    $ManifestCount = 0
    $Bytes = [UInt64]0
    $Directory = New-Object -TypeName System.IO.DirectoryInfo -ArgumentList $SpoolPath

    foreach ($File in $Directory.EnumerateFiles('*',[IO.SearchOption]::TopDirectoryOnly)) {
        $FileCount++
        if ($FileCount -gt $MaxFiles) {
            throw "10A bounded spool snapshot exceeded MaxFiles=$MaxFiles under $SpoolPath."
        }

        $Bytes += [UInt64]$File.Length
        if ($File.Extension -ieq '.jsonl') { $JsonlCount++ }
        if ($File.Name -like '*.manifest.json') { $ManifestCount++ }

        if ($Stopwatch.Elapsed.TotalSeconds -ge $NextHeartbeat) {
            Write-Host "[INFO] 10A spool snapshot: $FileCount files scanned; $([int]$Stopwatch.Elapsed.TotalSeconds)s elapsed."
            $NextHeartbeat += $HeartbeatSeconds
        }
        if ($Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            throw "10A bounded spool snapshot exceeded ${TimeoutSeconds}s under $SpoolPath after $FileCount files."
        }
    }

    return [PSCustomObject]@{
        Exists = $true
        FileCount = $FileCount
        Bytes = $Bytes
        JsonlCount = $JsonlCount
        ManifestCount = $ManifestCount
        ElapsedSeconds = [int]$Stopwatch.Elapsed.TotalSeconds
        EnumerationScope = 'TopDirectoryOnly'
    }
}

function Get-FiGate110ALatestConfiguredCollection {
    param(
        [string]$RuntimePath = 'C:\ProgramData\FI\state\service-runtime.jsonl',
        [int]$TailLines = 256
    )

    if (-not (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) {
        return $null
    }

    $Lines = @(Get-Content -LiteralPath $RuntimePath -Tail $TailLines -ErrorAction Stop)
    for ($Index = $Lines.Count - 1; $Index -ge 0; $Index--) {
        try {
            $Record = $Lines[$Index] | ConvertFrom-Json
            if ($Record.record_kind -eq 'ConfiguredCollection') {
                return $Record
            }
        }
        catch {
            continue
        }
    }

    return $null
}

function Wait-FiGate110AConfiguredCollectionAfterTime {
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$AfterUTC,
        [int]$TimeoutSeconds = 180,
        [int]$HeartbeatSeconds = 15
    )

    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $NextHeartbeat = $HeartbeatSeconds

    while ($Stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $Record = Get-FiGate110ALatestConfiguredCollection
        if ($null -ne $Record) {
            try {
                $ObservedUTC = [DateTime]::Parse(
                    [string]$Record.observed_at,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind
                ).ToUniversalTime()
                if ($ObservedUTC -gt $AfterUTC.ToUniversalTime()) {
                    return $Record
                }
            }
            catch {
                # Ignore malformed tail records and continue the bounded wait.
            }
        }

        if ($Stopwatch.Elapsed.TotalSeconds -ge $NextHeartbeat) {
            Write-Host "[INFO] 10A collection fence: $([int]$Stopwatch.Elapsed.TotalSeconds)s elapsed waiting after $($AfterUTC.ToUniversalTime().ToString('o'))."
            $NextHeartbeat += $HeartbeatSeconds
        }
        Start-Sleep -Seconds 2
    }

    return $null
}

function Get-FiGate110ARecentFinalizedBatches {
    param(
        [Parameter(Mandatory = $true)]
        [DateTime]$SinceUTC,
        [string]$SpoolPath = 'C:\ProgramData\FI\spool',
        [int]$TimeoutSeconds = 30,
        [int]$MaxFiles = 1000
    )

    if (-not (Test-Path -LiteralPath $SpoolPath -PathType Container)) {
        return @()
    }

    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $NextHeartbeat = 15
    $ScannedFiles = 0
    $Results = New-Object System.Collections.Generic.List[string]
    $Directory = New-Object -TypeName System.IO.DirectoryInfo -ArgumentList $SpoolPath

    foreach ($File in $Directory.EnumerateFiles('batch-*.jsonl',[IO.SearchOption]::TopDirectoryOnly)) {
        $ScannedFiles++
        if ($Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            throw "10A recent-batch enumeration exceeded ${TimeoutSeconds}s under $SpoolPath after $ScannedFiles files."
        }
        if ($Stopwatch.Elapsed.TotalSeconds -ge $NextHeartbeat) {
            Write-Host "[INFO] 10A recent-batch enumeration: $ScannedFiles files scanned; $([int]$Stopwatch.Elapsed.TotalSeconds)s elapsed."
            $NextHeartbeat += 15
        }
        if ($File.LastWriteTimeUtc -lt $SinceUTC.ToUniversalTime()) {
            continue
        }
        $Results.Add($File.FullName)
        if ($Results.Count -gt $MaxFiles) {
            throw "10A recent-batch enumeration exceeded MaxFiles=$MaxFiles since $($SinceUTC.ToUniversalTime().ToString('o'))."
        }
    }

    return $Results.ToArray()
}

function Convert-FiGate110AUTF16LEBase64URL {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $Bytes = [Text.Encoding]::Unicode.GetBytes($Value)
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Find-FiGate110ARecentSpoolToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token,
        [Parameter(Mandatory = $true)]
        [string[]]$BatchFiles,
        [int]$TimeoutSeconds = 30,
        [int]$MaxLines = 100000
    )

    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw '10A recent spool token search requires a non-empty token.'
    }

    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $NextHeartbeat = 15
    $LinesRead = 0
    $Matches = New-Object System.Collections.Generic.List[object]

    foreach ($BatchPath in $BatchFiles) {
        $LineNumber = 0
        foreach ($Line in [IO.File]::ReadLines($BatchPath)) {
            $LineNumber++
            $LinesRead++
            if ($LinesRead -gt $MaxLines) {
                throw "10A recent spool token search exceeded MaxLines=$MaxLines."
            }
            if ($Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                throw "10A recent spool token search exceeded ${TimeoutSeconds}s after $LinesRead lines."
            }
            if ($Stopwatch.Elapsed.TotalSeconds -ge $NextHeartbeat) {
                Write-Host "[INFO] 10A recent spool token search: $LinesRead lines scanned; $([int]$Stopwatch.Elapsed.TotalSeconds)s elapsed."
                $NextHeartbeat += 15
            }
            if (-not $Line.Contains($Token)) { continue }
            try {
                $Record = $Line | ConvertFrom-Json
                $Matches.Add([PSCustomObject]@{
                    Path = $BatchPath
                    LineNumber = $LineNumber
                    Line = $Line
                    Record = $Record
                })
            }
            catch {
                continue
            }
        }
    }
    return $Matches.ToArray()
}

function Find-FiGate110ARecentSpoolFilename {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName,
        [Parameter(Mandatory = $true)]
        [string[]]$BatchFiles,
        [int]$TimeoutSeconds = 30,
        [int]$MaxLines = 100000
    )

    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $NextHeartbeat = 15
    $LinesRead = 0
    $Matches = New-Object System.Collections.Generic.List[object]

    foreach ($BatchPath in $BatchFiles) {
        $LineNumber = 0
        foreach ($Line in [IO.File]::ReadLines($BatchPath)) {
            $LineNumber++
            $LinesRead++
            if ($LinesRead -gt $MaxLines) {
                throw "10A recent spool filename search exceeded MaxLines=$MaxLines."
            }
            if ($Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                throw "10A recent spool filename search exceeded ${TimeoutSeconds}s after $LinesRead lines."
            }
            if ($Stopwatch.Elapsed.TotalSeconds -ge $NextHeartbeat) {
                Write-Host "[INFO] 10A recent spool filename search: $LinesRead lines scanned; $([int]$Stopwatch.Elapsed.TotalSeconds)s elapsed."
                $NextHeartbeat += 15
            }
            if (-not $Line.Contains($FileName)) { continue }
            try {
                $Record = $Line | ConvertFrom-Json
                $Matches.Add([PSCustomObject]@{
                    Path = $BatchPath
                    LineNumber = $LineNumber
                    Line = $Line
                    Record = $Record
                })
            }
            catch {
                continue
            }
        }
    }
    return $Matches.ToArray()
}

function Invoke-FiGate110AHardLinkCreate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LinkPath,
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,
        [int]$TimeoutSeconds = 15
    )

    $StartInfo = New-Object Diagnostics.ProcessStartInfo
    $StartInfo.FileName = (Join-Path $env:SystemRoot 'System32\fsutil.exe')
    $StartInfo.Arguments = 'hardlink create "{0}" "{1}"' -f $LinkPath,$TargetPath
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true

    $Process = New-Object Diagnostics.Process
    $Process.StartInfo = $StartInfo
    if (-not $Process.Start()) {
        throw '10A could not start fsutil.exe for the hard-link workload.'
    }

    if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
        try { $Process.Kill() } catch {}
        throw "10A fsutil hardlink create exceeded ${TimeoutSeconds}s and was terminated."
    }

    $Process.Refresh()
    $StdOut = $Process.StandardOutput.ReadToEnd()
    $StdErr = $Process.StandardError.ReadToEnd()

    return [PSCustomObject]@{
        ExitCode = [int]$Process.ExitCode
        Output = (($StdOut + "`n" + $StdErr).Trim())
    }
}


$RunID = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$TestRoot = Get-FiGate1TestRoot -GovernedRoot $GovernedRoot -Name "_fi_gate1_activity_$RunID"
$StartedUTC = [DateTime]::UtcNow
$SecurityBefore = Get-FiGate1LatestSecurityRecordID
$CollectionAtScriptStart = Get-FiGate110ALatestConfiguredCollection
$SpoolBefore = Get-FiGate110ABoundedSpoolSnapshot
$Operations = New-Object System.Collections.Generic.List[object]
$TrackedNames = New-Object System.Collections.Generic.List[string]

function Add-OperationResult {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Path = '',
        [string]$Detail = ''
    )

    $Operations.Add([PSCustomObject]@{
        Name = $Name
        Status = $Status
        Path = $Path
        Detail = $Detail
        ObservedUTC = [DateTime]::UtcNow.ToString('o')
    })
}

function Add-TrackedName {
    param([string]$Path)

    if ($Path) {
        $TrackedNames.Add([IO.Path]::GetFileName($Path))
    }
}

if (-not ('FIGate1NativeFile' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class FIGate1NativeFile
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
}
'@
}

function Invoke-FiGate1NativeDeniedWrite {
    param([string]$Path)

    $FileWriteData = [UInt32]0x00000002
    $FileShareRead = [UInt32]0x00000001
    $FileShareWrite = [UInt32]0x00000002
    $FileShareDelete = [UInt32]0x00000004
    $OpenExisting = [UInt32]3
    $FileAttributeNormal = [UInt32]0x00000080

    $Handle = [FIGate1NativeFile]::CreateFileW(
        $Path,
        $FileWriteData,
        ($FileShareRead -bor $FileShareWrite -bor $FileShareDelete),
        [IntPtr]::Zero,
        $OpenExisting,
        $FileAttributeNormal,
        [IntPtr]::Zero
    )
    $Win32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Handle.ToInt64() -eq -1) {
        return [PSCustomObject]@{
            Opened = $false
            DesiredAccess = 'FILE_WRITE_DATA'
            DesiredAccessMask = '0x00000002'
            Win32Error = [int]$Win32Error
        }
    }

    $CloseSucceeded = [FIGate1NativeFile]::CloseHandle($Handle)
    $CloseError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    return [PSCustomObject]@{
        Opened = $true
        DesiredAccess = 'FILE_WRITE_DATA'
        DesiredAccessMask = '0x00000002'
        Win32Error = [int]$Win32Error
        CloseSucceeded = [bool]$CloseSucceeded
        CloseWin32Error = [int]$CloseError
    }
}

function Find-FiGate1DeniedFailureEvent {
    param(
        [object[]]$Events,
        [UInt64]$AfterRecordID,
        [string]$ObjectPath,
        [string]$SubjectSID,
        [UInt64]$RequiredAccessBits
    )

    foreach ($Event in @($Events | Sort-Object EventRecordID)) {
        if (
            [UInt64]$Event.EventRecordID -le $AfterRecordID -or
            [int]$Event.EventID -ne 4656
        ) {
            continue
        }

        try {
            [xml]$Document = $Event.XML
            $KeywordsText = [string]$Document.Event.System.Keywords
            if (-not $KeywordsText.StartsWith('0x',[StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $Keywords = [Convert]::ToUInt64($KeywordsText.Substring(2),16)
            $AuditFailureBit = [Convert]::ToUInt64('0010000000000000',16)
            if (($Keywords -band $AuditFailureBit) -eq 0) {
                continue
            }

            $Fields = @{}
            foreach ($Data in @($Document.Event.EventData.Data)) {
                $Fields[[string]$Data.Name] = [string]$Data.'#text'
            }

            if ($Fields['ObjectName'] -ine $ObjectPath) { continue }
            if ($Fields['SubjectUserSid'] -ine $SubjectSID) { continue }

            $AccessMaskText = [string]$Fields['AccessMask']
            if (-not $AccessMaskText.StartsWith('0x',[StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $AccessMask = [Convert]::ToUInt64($AccessMaskText.Substring(2),16)
            if (($AccessMask -band $RequiredAccessBits) -eq 0) {
                continue
            }

            return [PSCustomObject]@{
                EventRecordID = [UInt64]$Event.EventRecordID
                EventID = [int]$Event.EventID
                AuditResult = 'Failure'
                SubjectUserSID = [string]$Fields['SubjectUserSid']
                SubjectUserName = [string]$Fields['SubjectUserName']
                ObjectName = [string]$Fields['ObjectName']
                AccessMask = $AccessMaskText
                ProcessName = [string]$Fields['ProcessName']
            }
        }
        catch {
            continue
        }
    }

    return $null
}

function Wait-FiGate1DeniedFailureEvent {
    param(
        [UInt64]$AfterRecordID,
        [string]$ObjectPath,
        [string]$SubjectSID,
        [UInt64]$RequiredAccessBits,
        [int]$TimeoutSeconds = 10,
        [int]$PollMilliseconds = 100
    )

    $Deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $PathName = [IO.Path]::GetFileName($ObjectPath)

    do {
        $Events = @(
            Get-FiGate1SecurityEvents `
                -AfterRecordID $AfterRecordID `
                -PathContains $PathName `
                -EventIDs @(4656)
        )

        $Failure = Find-FiGate1DeniedFailureEvent `
            -Events $Events `
            -AfterRecordID $AfterRecordID `
            -ObjectPath $ObjectPath `
            -SubjectSID $SubjectSID `
            -RequiredAccessBits $RequiredAccessBits

        if ($null -ne $Failure) {
            return [PSCustomObject]@{
                FailureEvent = $Failure
                LastSecurityRecordID = Get-FiGate1LatestSecurityRecordID
                TimedOut = $false
                TimeoutSeconds = $TimeoutSeconds
                PollMilliseconds = $PollMilliseconds
            }
        }

        if ([DateTime]::UtcNow -ge $Deadline) {
            break
        }

        Start-Sleep -Milliseconds $PollMilliseconds
    }
    while ($true)

    return [PSCustomObject]@{
        FailureEvent = $null
        LastSecurityRecordID = Get-FiGate1LatestSecurityRecordID
        TimedOut = $true
        TimeoutSeconds = $TimeoutSeconds
        PollMilliseconds = $PollMilliseconds
    }
}

function Find-FiGate1SpoolSecurityEvent {
    param(
        [UInt64]$EventRecordID,
        [Parameter(Mandatory = $true)]
        [string[]]$BatchFiles,
        [int]$TimeoutSeconds = 30,
        [int]$MaxLines = 100000
    )

    $Needle = [string]$EventRecordID
    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $NextHeartbeat = 15
    $LinesRead = 0

    foreach ($BatchPath in $BatchFiles) {
        $LineNumber = 0
        foreach ($Line in [IO.File]::ReadLines($BatchPath)) {
            $LineNumber++
            $LinesRead++
            if ($LinesRead -gt $MaxLines) {
                throw "10A security spool search exceeded MaxLines=$MaxLines."
            }
            if ($Stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
                throw "10A security spool search exceeded ${TimeoutSeconds}s after $LinesRead lines."
            }
            if ($Stopwatch.Elapsed.TotalSeconds -ge $NextHeartbeat) {
                Write-Host "[INFO] 10A security spool search: $LinesRead lines scanned; $([int]$Stopwatch.Elapsed.TotalSeconds)s elapsed."
                $NextHeartbeat += 15
            }
            if (-not $Line.Contains($Needle)) { continue }
            try {
                $Record = $Line | ConvertFrom-Json
                if (
                    $Record.record_kind -eq 'WindowsSecurityEvent' -and
                    [UInt64]$Record.payload.event_record_id -eq $EventRecordID -and
                    $Record.payload.audit_result -eq 'Failure'
                ) {
                    return [PSCustomObject]@{
                        Path = $BatchPath
                        LineNumber = $LineNumber
                        EventRecordID = [UInt64]$Record.payload.event_record_id
                        EventID = [int]$Record.payload.event_id
                        AuditResult = [string]$Record.payload.audit_result
                        ObjectName = [string]$Record.payload.object_name
                        AccessMask = [string]$Record.payload.access_mask
                    }
                }
            }
            catch {
                continue
            }
        }
    }

    return $null
}

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - GOVERNED FILE ACTIVITY MATRIX'
Write-Host "Governed root: $GovernedRoot"
Write-Host "Test root:     $TestRoot"
Write-Host "Run ID:        $RunID"
Write-Host '============================================================'

try {
    # Create / modify / read.
    $CreatePath = Join-Path $TestRoot "create-$RunID.txt"
    'FI Gate 1 create' | Set-Content -LiteralPath $CreatePath -Encoding ASCII
    Add-TrackedName -Path $CreatePath
    Add-OperationResult -Name 'Create' -Status 'Executed' -Path $CreatePath

    'FI Gate 1 modify' | Add-Content -LiteralPath $CreatePath -Encoding ASCII
    Add-OperationResult -Name 'ModifyWrite' -Status 'Executed' -Path $CreatePath

    $null = Get-Content -LiteralPath $CreatePath -Raw
    Add-OperationResult -Name 'SuccessfulRead' -Status 'Executed' -Path $CreatePath

    # Denied read and denied write using an explicit deny for only the current SID.
    $DeniedPath = Join-Path $TestRoot "denied-$RunID.txt"
    'FI Gate 1 denied access target' | Set-Content -LiteralPath $DeniedPath -Encoding ASCII
    Add-TrackedName -Path $DeniedPath

    # Include the SACL whenever this test reads/rewrites the file security
    # descriptor. A DACL-only Get-Acl/Set-Acl round trip can otherwise discard
    # inherited audit ACEs and make the later denied-access audit probes invalid.
    $DeniedOriginal = Get-Acl -LiteralPath $DeniedPath -Audit
    $DeniedOriginalSddl = $DeniedOriginal.Sddl
    $AuditSection = [Security.AccessControl.AccessControlSections]::Audit
    $DeniedOriginalAuditSddl = $DeniedOriginal.GetSecurityDescriptorSddlForm($AuditSection)
    $CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $DeniedRights = (
        [Security.AccessControl.FileSystemRights]::ReadData -bor
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData
    )
    $DenyRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $CurrentSid,
        $DeniedRights,
        [Security.AccessControl.AccessControlType]::Deny
    )

    $DeniedAcl = Get-Acl -LiteralPath $DeniedPath -Audit
    $DeniedAcl.AddAccessRule($DenyRule) | Out-Null
    Set-Acl -LiteralPath $DeniedPath -AclObject $DeniedAcl

    $DeniedApplied = Get-Acl -LiteralPath $DeniedPath -Audit
    $DeniedAppliedAuditSddl = $DeniedApplied.GetSecurityDescriptorSddlForm($AuditSection)
    if ($DeniedAppliedAuditSddl -ne $DeniedOriginalAuditSddl) {
        throw 'Denied-access setup changed the target SACL. Refusing to run an invalid failure-audit probe.'
    }

    $DeniedReadSecurityBefore = [UInt64]0
    $DeniedReadSecurityAfter = [UInt64]0
    $DeniedWriteSecurityBefore = [UInt64]0
    $DeniedWriteSecurityAfter = [UInt64]0

    try {
        $DeniedReadSecurityBefore = Get-FiGate1LatestSecurityRecordID
        try {
            $null = Get-Content -LiteralPath $DeniedPath -Raw -ErrorAction Stop
            Add-OperationResult -Name 'DeniedRead' -Status 'UnexpectedSuccess' -Path $DeniedPath
        }
        catch {
            Add-OperationResult -Name 'DeniedRead' -Status 'ExpectedDenied' -Path $DeniedPath -Detail $_.Exception.Message
        }

        $DeniedReadAuditWait = Wait-FiGate1DeniedFailureEvent `
            -AfterRecordID $DeniedReadSecurityBefore `
            -ObjectPath $DeniedPath `
            -SubjectSID $CurrentSid.Value `
            -RequiredAccessBits ([UInt64]1)
        $DeniedReadFailure = $DeniedReadAuditWait.FailureEvent
        $DeniedReadSecurityAfter = [UInt64]$DeniedReadAuditWait.LastSecurityRecordID

        $DeniedWriteSecurityBefore = Get-FiGate1LatestSecurityRecordID
        $DeniedWriteNativeProbe = Invoke-FiGate1NativeDeniedWrite -Path $DeniedPath
        switch ($DeniedWriteNativeProbe.Opened) {
            $true {
                Add-OperationResult -Name 'DeniedWrite' -Status 'UnexpectedSuccess' -Path $DeniedPath -Detail 'CreateFileW(FILE_WRITE_DATA) unexpectedly opened the denied object.'
            }
            $false {
                if ($DeniedWriteNativeProbe.Win32Error -eq 5) {
                    Add-OperationResult -Name 'DeniedWrite' -Status 'ExpectedDenied' -Path $DeniedPath -Detail 'CreateFileW(FILE_WRITE_DATA) returned ERROR_ACCESS_DENIED (5).'
                }
                else {
                    Add-OperationResult -Name 'DeniedWrite' -Status 'UnexpectedFailure' -Path $DeniedPath -Detail "CreateFileW(FILE_WRITE_DATA) returned Win32 error $($DeniedWriteNativeProbe.Win32Error), expected ERROR_ACCESS_DENIED (5)."
                }
            }
        }

        $DeniedWriteAuditWait = Wait-FiGate1DeniedFailureEvent `
            -AfterRecordID $DeniedWriteSecurityBefore `
            -ObjectPath $DeniedPath `
            -SubjectSID $CurrentSid.Value `
            -RequiredAccessBits ([UInt64]2)
        $DeniedWriteFailure = $DeniedWriteAuditWait.FailureEvent
        $DeniedWriteSecurityAfter = [UInt64]$DeniedWriteAuditWait.LastSecurityRecordID
    }
    finally {
        $DeniedRestore = Get-Acl -LiteralPath $DeniedPath -Audit
        $DeniedRestore.SetSecurityDescriptorSddlForm($DeniedOriginalSddl)
        Set-Acl -LiteralPath $DeniedPath -AclObject $DeniedRestore
    }

    # Rename.
    $RenameSource = Join-Path $TestRoot "rename-source-$RunID.txt"
    $RenameTarget = Join-Path $TestRoot "rename-target-$RunID.txt"
    'FI Gate 1 rename' | Set-Content -LiteralPath $RenameSource -Encoding ASCII
    Add-TrackedName -Path $RenameSource
    Add-TrackedName -Path $RenameTarget
    Rename-Item -LiteralPath $RenameSource -NewName ([IO.Path]::GetFileName($RenameTarget))
    Add-OperationResult -Name 'Rename' -Status 'Executed' -Path $RenameTarget

    # Move within the governed root.
    $MoveDirectory = Join-Path $TestRoot 'moved'
    New-Item -Path $MoveDirectory -ItemType Directory -Force | Out-Null
    $MoveSource = Join-Path $TestRoot "move-source-$RunID.txt"
    $MoveTarget = Join-Path $MoveDirectory "move-target-$RunID.txt"
    'FI Gate 1 move' | Set-Content -LiteralPath $MoveSource -Encoding ASCII
    Add-TrackedName -Path $MoveSource
    Add-TrackedName -Path $MoveTarget
    Move-Item -LiteralPath $MoveSource -Destination $MoveTarget
    Add-OperationResult -Name 'Move' -Status 'Executed' -Path $MoveTarget

    # Hard link.
    $HardTarget = Join-Path $TestRoot "hard-target-$RunID.txt"
    $HardLink = Join-Path $TestRoot "hard-link-$RunID.txt"
    'FI Gate 1 hard link' | Set-Content -LiteralPath $HardTarget -Encoding ASCII
    Add-TrackedName -Path $HardTarget
    Add-TrackedName -Path $HardLink
    $HardResult = Invoke-FiGate110AHardLinkCreate -LinkPath $HardLink -TargetPath $HardTarget

    if ($HardResult.ExitCode -eq 0 -and (Test-Path -LiteralPath $HardLink -PathType Leaf)) {
        Add-OperationResult -Name 'HardLinkCreate' -Status 'Executed' -Path $HardLink
    }
    else {
        Add-OperationResult -Name 'HardLinkCreate' -Status 'Failed' -Path $HardLink -Detail $HardResult.Output
    }

    # DACL/security change and restore.
    $AclPath = Join-Path $TestRoot "acl-$RunID.txt"
    'FI Gate 1 ACL target' | Set-Content -LiteralPath $AclPath -Encoding ASCII
    Add-TrackedName -Path $AclPath
    $AclOriginal = Get-Acl -LiteralPath $AclPath -Audit
    $AclOriginalSddl = $AclOriginal.Sddl
    $UsersSid = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-545'
    $ReadRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $UsersSid,
        [Security.AccessControl.FileSystemRights]::ReadData,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $AclChanged = Get-Acl -LiteralPath $AclPath -Audit
    $AclChanged.AddAccessRule($ReadRule) | Out-Null
    Set-Acl -LiteralPath $AclPath -AclObject $AclChanged
    try {
        Add-OperationResult -Name 'ACLChange' -Status 'Executed' -Path $AclPath
    }
    finally {
        $AclRestore = Get-Acl -LiteralPath $AclPath -Audit
        $AclRestore.SetSecurityDescriptorSddlForm($AclOriginalSddl)
        Set-Acl -LiteralPath $AclPath -AclObject $AclRestore
    }

    # Ownership change and restore.
    $OwnerPath = Join-Path $TestRoot "owner-$RunID.txt"
    'FI Gate 1 owner target' | Set-Content -LiteralPath $OwnerPath -Encoding ASCII
    Add-TrackedName -Path $OwnerPath
    $OwnerOriginal = Get-Acl -LiteralPath $OwnerPath -Audit
    $OwnerOriginalSddl = $OwnerOriginal.Sddl
    $OwnerChanged = Get-Acl -LiteralPath $OwnerPath -Audit
    $CurrentIdentityName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $OwnerTargetName = if ($OwnerOriginal.Owner -ieq 'BUILTIN\Administrators') {
        $CurrentIdentityName
    } else {
        'BUILTIN\Administrators'
    }
    $OwnerAccount = New-Object -TypeName Security.Principal.NTAccount -ArgumentList $OwnerTargetName
    $OwnerChanged.SetOwner($OwnerAccount)
    Set-Acl -LiteralPath $OwnerPath -AclObject $OwnerChanged
    try {
        Add-OperationResult -Name 'OwnershipChange' -Status 'Executed' -Path $OwnerPath -Detail "Owner target=$OwnerTargetName"
    }
    finally {
        $OwnerRestore = Get-Acl -LiteralPath $OwnerPath -Audit
        $OwnerRestore.SetSecurityDescriptorSddlForm($OwnerOriginalSddl)
        Set-Acl -LiteralPath $OwnerPath -AclObject $OwnerRestore
    }

    # SACL/auditing change and restore. This may depend on the administrator token.
    $SaclPath = Join-Path $TestRoot "sacl-$RunID.txt"
    'FI Gate 1 SACL target' | Set-Content -LiteralPath $SaclPath -Encoding ASCII
    Add-TrackedName -Path $SaclPath

    if ($SkipSACLChange) {
        Add-OperationResult -Name 'SACLChange' -Status 'Skipped' -Path $SaclPath -Detail '-SkipSACLChange was supplied.'
    }
    else {
        $SaclApplied = $false
        try {
            $SaclOriginal = Get-Acl -LiteralPath $SaclPath -Audit
            $SaclOriginalSddl = $SaclOriginal.Sddl
            $AuditRule = New-Object -TypeName Security.AccessControl.FileSystemAuditRule -ArgumentList @(
                $CurrentSid,
                [Security.AccessControl.FileSystemRights]::ReadData,
                [Security.AccessControl.AuditFlags]::Success
            )
            $SaclChanged = Get-Acl -LiteralPath $SaclPath -Audit
            $SaclChanged.AddAuditRule($AuditRule) | Out-Null
            Set-Acl -LiteralPath $SaclPath -AclObject $SaclChanged
            $SaclApplied = $true
            Add-OperationResult -Name 'SACLChange' -Status 'Executed' -Path $SaclPath
        }
        catch {
            if ($SaclApplied) { throw }
            Add-OperationResult -Name 'SACLChange' -Status 'Unavailable' -Path $SaclPath -Detail $_.Exception.Message
        }
        finally {
            if ($SaclApplied) {
                $SaclRestore = Get-Acl -LiteralPath $SaclPath -Audit
                $SaclRestore.SetSecurityDescriptorSddlForm($SaclOriginalSddl)
                Set-Acl -LiteralPath $SaclPath -AclObject $SaclRestore
            }
        }
    }

    # Local UNC/SMB activity if an existing share exposes this governed root.
    try {
        $RootFull = [IO.Path]::GetFullPath($GovernedRoot).TrimEnd('\')
        $Shares = @(
            Get-SmbShare -ErrorAction Stop |
                Where-Object {
                    $_.Path -and
                    -not $_.Special
                } |
                Sort-Object { $_.Path.Length } -Descending
        )

        $SelectedShare = $null

        foreach ($Share in $Shares) {
            $ShareFull = [IO.Path]::GetFullPath($Share.Path).TrimEnd('\')

            if (
                $RootFull -ieq $ShareFull -or
                $RootFull.StartsWith($ShareFull + '\', [StringComparison]::OrdinalIgnoreCase)
            ) {
                $SelectedShare = $Share
                break
            }
        }

        if ($null -eq $SelectedShare) {
            Add-OperationResult -Name 'LocalSMB' -Status 'NotApplicable' -Detail 'No existing non-special SMB share exposes the governed root.'
        }
        else {
            $ShareFull = [IO.Path]::GetFullPath($SelectedShare.Path).TrimEnd('\')
            $RelativeRoot = $RootFull.Substring($ShareFull.Length).TrimStart('\')
            $UNCBase = "\\localhost\$($SelectedShare.Name)"

            if ($RelativeRoot) {
                $UNCBase = Join-Path $UNCBase $RelativeRoot
            }

            $UNCActivityDir = Join-Path $UNCBase ([IO.Path]::GetFileName($TestRoot))
            $UNCPath = Join-Path $UNCActivityDir "local-smb-$RunID.txt"
            Add-TrackedName -Path $UNCPath
            'FI Gate 1 local SMB' | Set-Content -LiteralPath $UNCPath -Encoding ASCII
            $null = Get-Content -LiteralPath $UNCPath -Raw
            'FI Gate 1 local SMB modify' | Add-Content -LiteralPath $UNCPath -Encoding ASCII
            Remove-Item -LiteralPath $UNCPath -Force
            Add-OperationResult -Name 'LocalSMB' -Status 'Executed' -Path $UNCPath -Detail "Share=$($SelectedShare.Name)"
        }
    }
    catch {
        Add-OperationResult -Name 'LocalSMB' -Status 'Unavailable' -Detail $_.Exception.Message
    }

    # Delete.
    $DeletePath = Join-Path $TestRoot "delete-$RunID.txt"
    'FI Gate 1 delete' | Set-Content -LiteralPath $DeletePath -Encoding ASCII
    Add-TrackedName -Path $DeletePath
    Remove-Item -LiteralPath $DeletePath -Force
    Add-OperationResult -Name 'Delete' -Status 'Executed' -Path $DeletePath

    # Fence FI collection strictly after the completed workload. The service may
    # already have a configured collection in flight when the last workload
    # operation finishes. Waiting for only one later completed record could
    # therefore accept a collection that began before the workload boundary.
    # Requiring two completed collections after the workload timestamp makes
    # the second unambiguously start after the first post-boundary completion.
    $WorkloadFinishedUTC = [DateTime]::UtcNow

    Write-Host ''
    Write-Host '[INFO] Waiting for the first configured FI collection completion after the activity matrix...'
    $CollectionFenceFirst = Wait-FiGate110AConfiguredCollectionAfterTime `
        -AfterUTC $WorkloadFinishedUTC `
        -TimeoutSeconds $CollectionTimeoutSeconds

    $Collection = $null
    $CollectionFenceFirstUTC = $null

    if ($null -ne $CollectionFenceFirst) {
        $CollectionFenceFirstUTC = [DateTime]::Parse(
            [string]$CollectionFenceFirst.observed_at,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()

        Write-Host '[INFO] Waiting for one additional configured FI collection so the accepted cycle is fully post-workload...'
        $Collection = Wait-FiGate110AConfiguredCollectionAfterTime `
            -AfterUTC $CollectionFenceFirstUTC `
            -TimeoutSeconds $CollectionTimeoutSeconds
    }

    if ($null -eq $CollectionFenceFirst) {
        Add-OperationResult -Name 'FIConfiguredCollection' -Status 'Timeout' -Detail "No first post-workload collection completion within $CollectionTimeoutSeconds seconds."
    }
    elseif ($null -eq $Collection) {
        Add-OperationResult -Name 'FIConfiguredCollection' -Status 'Timeout' -Detail "The first post-workload collection completed, but no second collection completed within $CollectionTimeoutSeconds seconds; a fully post-workload cycle was not proven."
    }
    else {
        Add-OperationResult -Name 'FIConfiguredCollection' -Status 'Observed' -Detail ($Collection | ConvertTo-Json -Compress -Depth 6)
    }

    $RecentBatchFiles = @(
        Get-FiGate110ARecentFinalizedBatches `
            -SinceUTC ($StartedUTC.AddMinutes(-1))
    )
    Write-Host "[INFO] 10A recent finalized batches selected for spool correlation: $($RecentBatchFiles.Count)."

    $SecurityEvents = @(
        Get-FiGate1SecurityEvents `
            -AfterRecordID $SecurityBefore `
            -PathContains ([IO.Path]::GetFileName($TestRoot))
    )

    $EventSummary = @(
        $SecurityEvents |
            Group-Object EventID |
            Sort-Object Name |
            ForEach-Object {
                [PSCustomObject]@{
                    EventID = [int]$_.Name
                    Count = $_.Count
                }
            }
    )

    if ($null -eq $DeniedReadFailure) {
        Add-OperationResult -Name 'DeniedReadAudit' -Status 'Missing' -Path $DeniedPath -Detail "No matching 4656 Audit Failure record was observed within the bounded $($DeniedReadAuditWait.TimeoutSeconds)-second poll."
    }
    else {
        Add-OperationResult -Name 'DeniedReadAudit' -Status 'Observed' -Path $DeniedPath -Detail "EventRecordID=$($DeniedReadFailure.EventRecordID); AccessMask=$($DeniedReadFailure.AccessMask)"
    }

    if ($null -eq $DeniedWriteFailure) {
        Add-OperationResult -Name 'DeniedWriteAudit' -Status 'Missing' -Path $DeniedPath -Detail "No matching 4656 Audit Failure with FILE_WRITE_DATA was observed within the bounded $($DeniedWriteAuditWait.TimeoutSeconds)-second poll."
    }
    else {
        Add-OperationResult -Name 'DeniedWriteAudit' -Status 'Observed' -Path $DeniedPath -Detail "EventRecordID=$($DeniedWriteFailure.EventRecordID); AccessMask=$($DeniedWriteFailure.AccessMask)"
    }

    $DeniedReadSpool = $null
    if ($null -ne $DeniedReadFailure) {
        $DeniedReadSpool = Find-FiGate1SpoolSecurityEvent -EventRecordID $DeniedReadFailure.EventRecordID -BatchFiles $RecentBatchFiles
    }
    if ($null -eq $DeniedReadSpool) {
        Add-OperationResult -Name 'DeniedReadFISpool' -Status 'Missing' -Path $DeniedPath -Detail 'The exact denied-read Windows Security event was not found as a finalized FI WindowsSecurityEvent record.'
    }
    else {
        Add-OperationResult -Name 'DeniedReadFISpool' -Status 'Observed' -Path $DeniedPath -Detail "EventRecordID=$($DeniedReadSpool.EventRecordID); Spool=$($DeniedReadSpool.Path):$($DeniedReadSpool.LineNumber)"
    }

    $DeniedWriteSpool = $null
    if ($null -ne $DeniedWriteFailure) {
        $DeniedWriteSpool = Find-FiGate1SpoolSecurityEvent -EventRecordID $DeniedWriteFailure.EventRecordID -BatchFiles $RecentBatchFiles
    }
    if ($null -eq $DeniedWriteSpool) {
        Add-OperationResult -Name 'DeniedWriteFISpool' -Status 'Missing' -Path $DeniedPath -Detail 'The exact denied-write Windows Security event was not found as a finalized FI WindowsSecurityEvent record.'
    }
    else {
        Add-OperationResult -Name 'DeniedWriteFISpool' -Status 'Observed' -Path $DeniedPath -Detail "EventRecordID=$($DeniedWriteSpool.EventRecordID); Spool=$($DeniedWriteSpool.Path):$($DeniedWriteSpool.LineNumber)"
    }

    $SpoolMatches = New-Object System.Collections.Generic.List[object]

    foreach ($Name in @($TrackedNames | Select-Object -Unique)) {
        $Matches = @(
            Find-FiGate110ARecentSpoolFilename `
                -FileName $Name `
                -BatchFiles $RecentBatchFiles
        )

        $SpoolMatches.Add([PSCustomObject]@{
            FileName = $Name
            MatchCount = $Matches.Count
        })
    }

    $SACLCurrentStateRecord = $null
    $SACLFileName = [IO.Path]::GetFileName($SaclPath)
    $SACLFileNameUTF16LEBase64URL = Convert-FiGate110AUTF16LEBase64URL -Value $SACLFileName
    $SACLCurrentStateMatches = @(
        Find-FiGate110ARecentSpoolToken `
            -Token $SACLFileNameUTF16LEBase64URL `
            -BatchFiles $RecentBatchFiles
    )
    foreach ($Match in $SACLCurrentStateMatches) {
        try {
            $Record = $Match.Record
            $HasExactUSNFileName = $false
            foreach ($Change in @($Record.payload.changes)) {
                if ([string]$Change.file_name_utf16le_base64url -ceq $SACLFileNameUTF16LEBase64URL) {
                    $HasExactUSNFileName = $true
                    break
                }
            }
            if (
                $Record.record_kind -eq 'USNObjectObservation' -and
                $Record.payload.status -eq 'Observed' -and
                $HasExactUSNFileName -and
                $null -ne $Record.payload.ntfs_observation -and
                $Record.payload.ntfs_observation.sacl.state -eq 'Present' -and
                $Record.payload.ntfs_observation.sacl.data_format -ne 'NotKnown'
            ) {
                $SACLCurrentStateRecord = [PSCustomObject]@{
                    Path = $Match.Path
                    LineNumber = $Match.LineNumber
                    FileReferenceNumber = [string]$Record.payload.file_identity.file_reference_number
                    SequenceNumber = [string]$Record.payload.file_identity.sequence_number
                    State = [string]$Record.payload.ntfs_observation.sacl.state
                    DataFormat = [string]$Record.payload.ntfs_observation.sacl.data_format
                    ObservationStatus = [string]$Record.payload.ntfs_observation.observation_status
                }
                break
            }
        }
        catch {
            continue
        }
    }

    if ($null -eq $SACLCurrentStateRecord) {
        Add-OperationResult -Name 'SACLCurrentState' -Status 'Missing' -Path $SaclPath -Detail 'No FI USN object observation with readable current SACL state was found.'
    }
    else {
        Add-OperationResult -Name 'SACLCurrentState' -Status 'Observed' -Path $SaclPath -Detail "State=$($SACLCurrentStateRecord.State); DataFormat=$($SACLCurrentStateRecord.DataFormat); ObservationStatus=$($SACLCurrentStateRecord.ObservationStatus)"
    }

    $SpoolAfter = Get-FiGate110ABoundedSpoolSnapshot
    $ExpectedStatus = @{
        Create = 'Executed'
        ModifyWrite = 'Executed'
        SuccessfulRead = 'Executed'
        DeniedRead = 'ExpectedDenied'
        DeniedReadAudit = 'Observed'
        DeniedReadFISpool = 'Observed'
        DeniedWrite = 'ExpectedDenied'
        DeniedWriteAudit = 'Observed'
        DeniedWriteFISpool = 'Observed'
        Rename = 'Executed'
        Move = 'Executed'
        HardLinkCreate = 'Executed'
        ACLChange = 'Executed'
        OwnershipChange = 'Executed'
        SACLCurrentState = 'Observed'
        Delete = 'Executed'
        FIConfiguredCollection = 'Observed'
    }
    $ExecutionIssues = @(
        foreach ($ExpectedName in $ExpectedStatus.Keys) {
            $Observed = @($Operations | Where-Object { $_.Name -eq $ExpectedName } | Select-Object -Last 1)
            if ($Observed.Count -eq 0 -or $Observed[0].Status -ne $ExpectedStatus[$ExpectedName]) {
                [PSCustomObject]@{
                    Name = $ExpectedName
                    Expected = $ExpectedStatus[$ExpectedName]
                    Observed = if ($Observed.Count) { $Observed[0].Status } else { 'Missing' }
                }
            }
        }
    )
    $FinishedUTC = [DateTime]::UtcNow
    $Report = [PSCustomObject]@{
        RecordKind = 'FIGate1ActivityMatrix'
        RunID = $RunID
        Host = $env:COMPUTERNAME
        GovernedRoot = $GovernedRoot
        TestRoot = $TestRoot
        StartedUTC = $StartedUTC.ToString('o')
        FinishedUTC = $FinishedUTC.ToString('o')
        CollectionFence = [PSCustomObject]@{
            CollectionAtScriptStart = $CollectionAtScriptStart
            WorkloadFinishedUTC = $WorkloadFinishedUTC.ToString('o')
            FirstCompletionUTC = if ($null -ne $CollectionFenceFirstUTC) { $CollectionFenceFirstUTC.ToString('o') } else { '' }
            FirstCompletion = $CollectionFenceFirst
            AcceptedFullyPostWorkloadCollection = $Collection
        }
        SecurityRecordIDBefore = $SecurityBefore
        Operations = $Operations.ToArray()
        WorkloadExecutionPass = ($ExecutionIssues.Count -eq 0)
        WorkloadExecutionIssues = $ExecutionIssues
        SecurityEventSummary = $EventSummary
        SecurityEvents = $SecurityEvents
        SpoolBefore = $SpoolBefore
        SpoolAfter = $SpoolAfter
        SpoolTrackedNameMatches = $SpoolMatches.ToArray()
        DeniedAccessValidation = [PSCustomObject]@{
            ReadRecordIDBefore = $DeniedReadSecurityBefore
            ReadRecordIDAfter = $DeniedReadSecurityAfter
            ReadAuditWait = $DeniedReadAuditWait
            ReadFailureEvent = $DeniedReadFailure
            ReadFISpoolRecord = $DeniedReadSpool
            WriteRecordIDBefore = $DeniedWriteSecurityBefore
            WriteRecordIDAfter = $DeniedWriteSecurityAfter
            WriteAuditWait = $DeniedWriteAuditWait
            WriteNativeProbe = $DeniedWriteNativeProbe
            WriteFailureEvent = $DeniedWriteFailure
            WriteFISpoolRecord = $DeniedWriteSpool
            SACLBeforeProbe = $DeniedOriginalAuditSddl
            SACLAfterDenyApplied = $DeniedAppliedAuditSddl
        }
        SACLCurrentStateValidation = $SACLCurrentStateRecord
        RemoteSMB = 'Run 10B-RemoteClient-SMB-Activity.ps1 from a separate client to complete true remote SMB coverage.'
    }

    $ReportPath = Join-Path $ResultDirectory "gate1-activity-$($env:COMPUTERNAME)-$RunID.json"
    Write-FiGate1Json -InputObject $Report -Path $ReportPath

    Write-Host ''
    Write-Host '=== ACTIVITY MATRIX SUMMARY ==='
    $Operations | Format-Table Name,Status,Path -AutoSize

    Write-Host ''
    Write-Host '=== SECURITY EVENT SUMMARY ==='

    if ($EventSummary.Count -eq 0) {
        Write-Host '[INFO] No selected Security events matched the test-root name. Treat this as a coverage/configuration finding, not proof of no activity.'
    }
    else {
        $EventSummary | Format-Table EventID,Count -AutoSize
    }

    Write-Host ''
    Write-Host "[INFO] Report: $ReportPath"
    if ($ExecutionIssues.Count -gt 0) {
        throw "Local Gate 1 activity workload recorded $($ExecutionIssues.Count) core execution issue(s). Review: $ReportPath"
    }
    Write-Host '[PASS] Local Gate 1 activity workload completed. Review the report for event/FI preservation semantics.'
}
finally {
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $TestRoot -PathType Container)) {
        try {
            Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Host "[INFO] Test-root cleanup could not complete: $($_.Exception.Message)"
        }
    }
    elseif ($KeepArtifacts) {
        Write-Host "[INFO] Test artifacts retained: $TestRoot"
    }
}
