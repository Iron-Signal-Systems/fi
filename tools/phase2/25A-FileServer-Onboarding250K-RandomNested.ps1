# FI Phase 2 - 250,000-file randomized nested onboarding / transport campaign
# Windows Server 2016 / Windows PowerShell 5.1
#
# LOCAL/LAB VALIDATION TOOLING ONLY.
#
# Purpose:
#   - Build exactly 250,000 real files under Y:\FI-Lab.
#   - Use a reproducible, irregular directory tree up to 15 levels deep.
#   - Use a realistic skewed file-size distribution targeting ~394 GiB for the
#     default seed (well inside the requested 250-500 GiB range).
#   - Start FI from a clean onboarding checkpoint/state.
#   - Keep the real Phase 2 sender/receiver path active during onboarding.
#   - Capture CPU, RAM, Y: logical I/O/latency/queue, network throughput,
#     FI process resource use, sender resource use, and local queue growth every
#     five seconds while also printing those measurements live.
#   - Mutate one file during the initial baseline to validate anchored catch-up.
#   - Continue five-second telemetry after collection completion until the
#     source/generation transport path is quiet (or a bounded drain timeout).
#
# Independent post-checkpoint USN concurrency was already validated separately
# on 2026-09-19 and is intentionally not mixed into this initial-onboarding run.
#
# Safety:
#   - Hard-gated to ISS-FS-01 and exact deployed executable hashes.
#   - Preserves the existing Y:\FI-Lab root security descriptor (including SACL)
#     and restores it on the new root.
#   - Stops FI before removing the disposable lab dataset.
#   - Waits for published spool manifests to drain before stopping the sender.
#   - Archives the prior FI state/spool rather than deleting them.
#   - Does NOT modify Git, GitHub, FI configuration, service accounts, services,
#     certificate stores, or the receiver.
#
# IMPORTANT:
#   Y:\FI-Lab is treated as a disposable lab dataset and is removed/rebuilt.

[CmdletBinding()]
param(
    [int]$BaselineMutationAfterMinutes = 10,
    [int]$SpoolDrainTimeoutMinutes = 30
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ---------------------------------------------------------------------------
# Fixed lab contract
# ---------------------------------------------------------------------------

$ExpectedServer = 'ISS-FS-01'

$ExpectedFIHash =
    '781C4D0A940F9C247EF8DAF4D944D6C439FB22513FAEB84289692DB39013A7F7'

$ExpectedUSNHash =
    '82C261FD082630B7455654E5FF98C5B39E529BD1AA94019D96EB1B5B805AF92A'

$ExpectedSenderHash =
    'EBAD839B348DD969EECCFD80C44915015C4E30A8A4D41114D8EBC13C267753C6'

$CollectorService = 'FICollector'
$USNService       = 'FIUSNReader'
$SenderTask       = 'FI-GMSA-Sender-V2-Drain'

$CollectorExe = 'C:\Program Files\FI\fi.exe'
$USNExe       = 'C:\Program Files\FI\fi-usn.exe'
$SenderExe    = 'C:\Program Files\FI\fi-sender.exe'

$ConfiguredRoot  = 'C:\FI-Lab'
$ConfiguredState = 'C:\ProgramData\FI\state'
$ConfiguredSpool = 'C:\ProgramData\FI\spool'

$YRoot  = 'Y:\FI-Lab'
$YBase  = 'Y:\FI-Gate1'
$YState = Join-Path $YBase 'state'
$YSpool = Join-Path $YBase 'spool'

$SenderStage = 'C:\ProgramData\FI\transport-v2-drain\stage'

$ReceiverAddress = '192.168.1.119'
$ReceiverPort    = 8443

$ArchiveBase = 'Y:\FI-Archive'

$ResultsBase =
    'C:\ProgramData\FI\phase2-results\onboarding250k-random-nested'

$FlagDir = 'C:\FI-Test'

$TargetFiles      = 250000L
$DirectoryTarget  = 20000
$MaximumDepth     = 15
$GeneratorWorkers = 4
$GeneratorSeed    = [UInt64]7966157670060267791  # 0x6E8D7A31C4B2190F

$StartReserveGiB    = 8
$RecoveryReserveGiB = 8
$MinimumMarginGiB   = 64

$SampleSeconds = 5

$Run = 'onboarding250k-random-nested-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$ResultRoot = Join-Path $ResultsBase $Run
$SamplesPath = Join-Path $ResultRoot 'samples-5s.csv'
$OperationsPath = Join-Path $ResultRoot 'operations.csv'
$SummaryPath = Join-Path $ResultRoot 'summary.json'
$DatasetPath = Join-Path $ResultRoot 'dataset.json'
$Mutation1Path = Join-Path $ResultRoot 'mutation-baseline.json'
$TranscriptPath = Join-Path $ResultRoot 'console.txt'
$RootSddlPath = Join-Path $ResultRoot 'prior-root-sddl.txt'
$RuntimeTailPath = Join-Path $ResultRoot 'service-runtime-tail.jsonl'

$RunningFlag  = Join-Path $FlagDir 'onboarding250k-running.flag'
$CompleteFlag = Join-Path $FlagDir 'onboarding250k-complete.flag'
$FailedFlag   = Join-Path $FlagDir 'onboarding250k-failed.flag'

$StartReserve    = Join-Path $YBase 'phase2-250k-start-reserve.bin'
$RecoveryReserve = Join-Path $YBase 'phase2-250k-recovery-reserve.bin'

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

function Inv {
    param(
        [double]$Value,
        [string]$Format = 'F3'
    )

    return $Value.ToString(
        $Format,
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-ExactHash {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required executable missing: $Path"
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Remove-TreeOrJunction {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $item = Get-Item -LiteralPath $Path -Force

    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        cmd.exe /c "rmdir `"$Path`""
        if ($LASTEXITCODE -ne 0) {
            throw "Failed removing junction: $Path"
        }
        return
    }

    cmd.exe /c "rmdir /s /q `"$Path`""
    if ($LASTEXITCODE -ne 0) {
        throw "Failed removing directory tree: $Path"
    }
}

function New-Junction {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Link,

        [Parameter(Mandatory=$true)]
        [string]$Target
    )

    if (Test-Path -LiteralPath $Link) {
        throw "Refusing to replace existing path as a junction: $Link"
    }

    cmd.exe /c "mklink /J `"$Link`" `"$Target`"" | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Failed creating junction $Link -> $Target"
    }
}

function Stop-FI {
    Stop-Service $CollectorService -Force -ErrorAction SilentlyContinue
    Stop-Service $USNService -Force -ErrorAction SilentlyContinue

    $deadline = (Get-Date).AddSeconds(45)

    do {
        Start-Sleep -Milliseconds 250

        $svc = Get-Service $CollectorService,$USNService
    }
    until (
        -not ($svc | Where-Object Status -ne 'Stopped') -or
        (Get-Date) -ge $deadline
    )

    if ($svc | Where-Object Status -ne 'Stopped') {
        throw 'FI services did not stop cleanly.'
    }
}

function Stop-Sender {
    $task = Get-ScheduledTask -TaskName $SenderTask -ErrorAction Stop

    if ($task.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $SenderTask
    }

    $deadline = (Get-Date).AddSeconds(45)

    do {
        Start-Sleep -Milliseconds 250

        $sender =
            Get-Process -Name 'fi-sender' -ErrorAction SilentlyContinue
    }
    until (
        -not $sender -or
        (Get-Date) -ge $deadline
    )

    if ($sender) {
        throw 'fi-sender did not exit after scheduled-task stop.'
    }
}

function Start-Sender {
    Start-ScheduledTask -TaskName $SenderTask

    $deadline = (Get-Date).AddSeconds(30)

    do {
        Start-Sleep -Milliseconds 250

        $sender =
            Get-Process -Name 'fi-sender' -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    until (
        $sender -or
        (Get-Date) -ge $deadline
    )

    if (-not $sender) {
        throw 'fi-sender did not appear after starting scheduled task.'
    }
}

function Get-PublishedManifestCount {
    if (-not (Test-Path -LiteralPath $YSpool)) {
        return 0L
    }

    return @(
        Get-ChildItem `
            -LiteralPath $YSpool `
            -File `
            -Recurse `
            -Filter '*.manifest.json' `
            -ErrorAction SilentlyContinue
    ).Count
}

function Wait-PublishedSpoolDrain {
    param(
        [int]$TimeoutMinutes
    )

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $quietSince = $null

    while ($true) {
        $count = Get-PublishedManifestCount
        $now = Get-Date

        if ($count -eq 0) {
            if (-not $quietSince) {
                $quietSince = $now
            }

            if (($now - $quietSince).TotalSeconds -ge 30) {
                return
            }
        }
        else {
            $quietSince = $null
        }

        Write-Host (
            '[DRAIN] published spool manifests={0:N0}' -f $count
        )

        if ($now -ge $deadline) {
            throw "Published source spool did not drain within $TimeoutMinutes minutes."
        }

        Start-Sleep -Seconds 5
    }
}

function Get-ProcSnap {
    param(
        [Parameter(Mandatory=$true)]
        [System.Diagnostics.Process]$Process
    )

    $Process.Refresh()

    [PSCustomObject]@{
        Id         = $Process.Id
        CPUSeconds = [double]$Process.TotalProcessorTime.TotalSeconds
        WSBytes    = [Int64]$Process.WorkingSet64
        Private    = [Int64]$Process.PrivateMemorySize64
    }
}

function Get-NamedProcess {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $p =
        Get-Process -Name $Name -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $p) {
        return $null
    }

    return [System.Diagnostics.Process]::GetProcessById($p.Id)
}

function Get-SpoolSummary {
    if (-not (Test-Path -LiteralPath $YSpool)) {
        return [PSCustomObject]@{
            Files     = 0L
            Bytes     = 0L
            Manifests = 0L
        }
    }

    $files =
        @(
            Get-ChildItem `
                -LiteralPath $YSpool `
                -File `
                -Recurse `
                -ErrorAction SilentlyContinue
        )

    $bytes = 0L

    foreach ($f in $files) {
        $bytes += [Int64]$f.Length
    }

    [PSCustomObject]@{
        Files     = [Int64]$files.Count
        Bytes     = [Int64]$bytes
        Manifests = [Int64]@(
            $files |
            Where-Object Name -Like '*.manifest.json'
        ).Count
    }
}

function Get-StageSummary {
    if (-not (Test-Path -LiteralPath $SenderStage)) {
        return [PSCustomObject]@{
            Files = 0L
            Bytes = 0L
        }
    }

    $files =
        @(
            Get-ChildItem `
                -LiteralPath $SenderStage `
                -File `
                -Recurse `
                -ErrorAction SilentlyContinue
        )

    $bytes = 0L

    foreach ($f in $files) {
        $bytes += [Int64]$f.Length
    }

    [PSCustomObject]@{
        Files = [Int64]$files.Count
        Bytes = [Int64]$bytes
    }
}

function Get-ServiceRuntimeRecords {
    $runtime = Join-Path $YState 'service-runtime.jsonl'

    if (-not (Test-Path -LiteralPath $runtime)) {
        return @()
    }

    $rows = @()

    try {
        foreach ($line in [System.IO.File]::ReadLines($runtime)) {
            try {
                $rows += ($line | ConvertFrom-Json -ErrorAction Stop)
            }
            catch {
            }
        }
    }
    catch {
    }

    return @($rows)
}

function Get-FirstConfiguredComplete {
    return @(
        Get-ServiceRuntimeRecords |
        Where-Object {
            $_.record_kind -eq 'ConfiguredCollection' -and
            $_.outcome -eq 'Complete'
        }
    ) |
    Select-Object -First 1
}

function Get-USNCompleteAfter {
    param(
        [Parameter(Mandatory=$true)]
        [DateTimeOffset]$After
    )

    foreach ($r in (Get-ServiceRuntimeRecords)) {
        if (
            $r.record_kind -eq 'USNCatchUp' -and
            $r.outcome -eq 'Complete'
        ) {
            try {
                $t = [DateTimeOffset]::Parse([string]$r.observed_at)

                if ($t -gt $After) {
                    return $r
                }
            }
            catch {
            }
        }
    }

    return $null
}

function Get-OperationRows {
    $rows = @()

    foreach (
        $file in
        Get-ChildItem `
            -LiteralPath $YState `
            -File `
            -Filter '*-operations.jsonl' `
            -ErrorAction SilentlyContinue
    ) {
        $entries = @()

        try {
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                try {
                    $entries +=
                        ($line | ConvertFrom-Json -ErrorAction Stop)
                }
                catch {
                }
            }
        }
        catch {
            continue
        }

        foreach ($group in ($entries | Group-Object operation_id)) {
            $started =
                $group.Group |
                Where-Object event -eq 'Started' |
                Select-Object -First 1

            $finished =
                $group.Group |
                Where-Object event -eq 'Finished' |
                Select-Object -First 1

            if (-not $started -or -not $finished) {
                continue
            }

            $s = [DateTimeOffset]::Parse(
                [string]$started.started_at
            )

            $f = [DateTimeOffset]::Parse(
                [string]$finished.finished_at
            )

            $rows +=
                [PSCustomObject]@{
                    Journal     = $file.Name
                    Kind        = [string]$started.kind
                    StartedUTC  = $s.ToString('o')
                    FinishedUTC = $f.ToString('o')
                    DurationSec = [Math]::Round(
                        ($f - $s).TotalSeconds,
                        3
                    )
                    Outcome     = [string]$finished.outcome
                    Reason      = [string]$finished.reason_code
                }
        }
    }

    return @(
        $rows |
        Sort-Object StartedUTC
    )
}

function Get-MaxCheckpointNextUSN {
    $max = [UInt64]0

    foreach (
        $file in
        Get-ChildItem `
            -LiteralPath $YState `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue
    ) {
        if ($file.Extension -notin @('.json','.checkpoint')) {
            continue
        }

        try {
            $text = [IO.File]::ReadAllText($file.FullName)

            foreach (
                $m in
                [regex]::Matches(
                    $text,
                    '"next_usn"\s*:\s*"?([0-9]+)"?',
                    [Text.RegularExpressions.RegexOptions]::IgnoreCase
                )
            ) {
                $v = [UInt64]$m.Groups[1].Value

                if ($v -gt $max) {
                    $max = $v
                }
            }
        }
        catch {
        }
    }

    return $max
}

function Get-ReceiverConnectionCount {
    try {
        return @(
            Get-NetTCPConnection `
                -RemoteAddress $ReceiverAddress `
                -RemotePort $ReceiverPort `
                -State Established `
                -ErrorAction SilentlyContinue
        ).Count
    }
    catch {
        return 0
    }
}

# ---------------------------------------------------------------------------
# Native CPU/RAM and host-network snapshots
# ---------------------------------------------------------------------------

if (-not ('FIPhase2NativeMetrics' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class FIPhase2NativeMetrics
{
    [StructLayout(LayoutKind.Sequential)]
    public struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetSystemTimes(
        out FILETIME idleTime,
        out FILETIME kernelTime,
        out FILETIME userTime
    );

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);

    public static long ToInt64(FILETIME ft)
    {
        return ((long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    }
}
'@
}

function Get-NativeCPU {
    $idle = New-Object FIPhase2NativeMetrics+FILETIME
    $kernel = New-Object FIPhase2NativeMetrics+FILETIME
    $user = New-Object FIPhase2NativeMetrics+FILETIME

    if (
        -not
        [FIPhase2NativeMetrics]::GetSystemTimes(
            [ref]$idle,
            [ref]$kernel,
            [ref]$user
        )
    ) {
        throw 'GetSystemTimes failed.'
    }

    [PSCustomObject]@{
        Idle   = [FIPhase2NativeMetrics]::ToInt64($idle)
        Kernel = [FIPhase2NativeMetrics]::ToInt64($kernel)
        User   = [FIPhase2NativeMetrics]::ToInt64($user)
    }
}

function Get-NativeMemory {
    $m = New-Object FIPhase2NativeMetrics+MEMORYSTATUSEX
    $m.dwLength = [Runtime.InteropServices.Marshal]::SizeOf($m)

    if (
        -not
        [FIPhase2NativeMetrics]::GlobalMemoryStatusEx([ref]$m)
    ) {
        throw 'GlobalMemoryStatusEx failed.'
    }

    [PSCustomObject]@{
        LoadPct       = [double]$m.dwMemoryLoad
        TotalPhys     = [UInt64]$m.ullTotalPhys
        AvailablePhys = [UInt64]$m.ullAvailPhys
    }
}

function Get-NetworkSnapshot {
    [UInt64]$rx = 0
    [UInt64]$tx = 0
    [UInt64]$inErr = 0
    [UInt64]$outErr = 0
    [UInt64]$inDiscard = 0
    [UInt64]$outDiscard = 0
    [UInt64]$linkBits = 0

    $active = @()

    foreach (
        $nic in
        [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
    ) {
        if (
            $nic.NetworkInterfaceType -eq
                [Net.NetworkInformation.NetworkInterfaceType]::Loopback -or
            $nic.OperationalStatus -ne
                [Net.NetworkInformation.OperationalStatus]::Up
        ) {
            continue
        }

        try {
            $stats = $nic.GetIPv4Statistics()

            $rx += [UInt64]$stats.BytesReceived
            $tx += [UInt64]$stats.BytesSent
            $inErr += [UInt64]$stats.IncomingPacketsWithErrors
            $outErr += [UInt64]$stats.OutgoingPacketsWithErrors
            $inDiscard += [UInt64]$stats.IncomingPacketsDiscarded
            $outDiscard += [UInt64]$stats.OutgoingPacketsDiscarded

            if ($nic.Speed -gt 0) {
                $linkBits += [UInt64]$nic.Speed
            }

            $active +=
                [PSCustomObject]@{
                    Name     = $nic.Name
                    SpeedBps = [Int64]$nic.Speed
                }
        }
        catch {
        }
    }

    [PSCustomObject]@{
        RxBytes       = $rx
        TxBytes       = $tx
        InErrors      = $inErr
        OutErrors     = $outErr
        InDiscards    = $inDiscard
        OutDiscards   = $outDiscard
        LinkBits      = $linkBits
        Active        = $active
    }
}

function Get-YDiskSample {
    $set =
        Get-Counter -Counter @(
            '\LogicalDisk(Y:)\Disk Read Bytes/sec',
            '\LogicalDisk(Y:)\Disk Write Bytes/sec',
            '\LogicalDisk(Y:)\Avg. Disk sec/Read',
            '\LogicalDisk(Y:)\Avg. Disk sec/Write',
            '\LogicalDisk(Y:)\Current Disk Queue Length'
        ) `
        -SampleInterval 1 `
        -MaxSamples 1 `
        -ErrorAction Stop

    $values = @{}

    foreach ($c in $set.CounterSamples) {
        $path = [string]$c.Path

        if ($path -match '\\disk read bytes/sec$') {
            $values.ReadBytesSec = [double]$c.CookedValue
        }
        elseif ($path -match '\\disk write bytes/sec$') {
            $values.WriteBytesSec = [double]$c.CookedValue
        }
        elseif ($path -match '\\avg\. disk sec/read$') {
            $values.ReadSec = [double]$c.CookedValue
        }
        elseif ($path -match '\\avg\. disk sec/write$') {
            $values.WriteSec = [double]$c.CookedValue
        }
        elseif ($path -match '\\current disk queue length$') {
            $values.Queue = [double]$c.CookedValue
        }
    }

    [PSCustomObject]@{
        ReadBytesSec =
            $(if ($values.ContainsKey('ReadBytesSec')) {
                $values.ReadBytesSec
            }
            else {
                0.0
            })

        WriteBytesSec =
            $(if ($values.ContainsKey('WriteBytesSec')) {
                $values.WriteBytesSec
            }
            else {
                0.0
            })

        ReadMs =
            $(if ($values.ContainsKey('ReadSec')) {
                $values.ReadSec * 1000.0
            }
            else {
                0.0
            })

        WriteMs =
            $(if ($values.ContainsKey('WriteSec')) {
                $values.WriteSec * 1000.0
            }
            else {
                0.0
            })

        Queue =
            $(if ($values.ContainsKey('Queue')) {
                $values.Queue
            }
            else {
                0.0
            })
    }
}

# ---------------------------------------------------------------------------
# Deterministic randomized nested dataset generator
# ---------------------------------------------------------------------------

if (-not ('FI250KRandomNestedV1' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

public static class FI250KRandomNestedV1
{
    private static long _createdFiles;
    private static long _createdBytes;
    private static int _diskFull;
    private static int _stop;
    private static long _nextFile;
    private static string _lastError = "";
    private static byte[] _pool;
    private static Task[] _tasks;

    private static string[] _directories;
    private static int[] _depths;
    private static bool[] _hasChild;
    private static int[] _activeLeaves;
    private static int[] _hotLeaves;
    private static long[] _dirDepthHistogram = new long[16];
    private static long[] _fileDepthHistogram = new long[16];
    private static long[] _sizeBandHistogram = new long[5];

    public static long CreatedFiles { get { return Interlocked.Read(ref _createdFiles); } }
    public static long CreatedBytes { get { return Interlocked.Read(ref _createdBytes); } }
    public static bool DiskFull { get { return Volatile.Read(ref _diskFull) != 0; } }
    public static string LastError { get { return _lastError; } }

    public static bool IsRunning
    {
        get
        {
            Task[] tasks = _tasks;

            if (tasks == null)
                return false;

            for (int i = 0; i < tasks.Length; i++)
            {
                if (!tasks[i].IsCompleted)
                    return true;
            }

            return false;
        }
    }

    private static ulong Mix(ulong z)
    {
        z += 0x9E3779B97F4A7C15UL;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }

    private static int Range(ulong x, int min, int max)
    {
        ulong span = (ulong)((long)max - (long)min + 1L);
        return min + (int)(x % span);
    }

    public static int SizeBandFor(long index, ulong seed)
    {
        ulong x = Mix(((ulong)index) ^ seed);
        ulong bucket = x % 1000UL;

        if (bucket < 50UL) return 0;
        if (bucket < 550UL) return 1;
        if (bucket < 850UL) return 2;
        if (bucket < 970UL) return 3;
        return 4;
    }

    public static int SizeFor(long index, ulong seed)
    {
        ulong x = Mix(((ulong)index) ^ seed);
        ulong y = Mix(x + 0xD1B54A32D192ED03UL);

        switch (SizeBandFor(index, seed))
        {
            case 0:
                return Range(y, 0, 16 * 1024);

            case 1:
                return Range(y, 16 * 1024, 256 * 1024);

            case 2:
                return Range(y, 256 * 1024, 2 * 1024 * 1024);

            case 3:
                return Range(y, 2 * 1024 * 1024, 8 * 1024 * 1024);

            default:
                return Range(y, 8 * 1024 * 1024, 32 * 1024 * 1024);
        }
    }

    public static long PlannedBytes(long targetFiles, ulong seed)
    {
        long total = 0;

        for (long i = 0; i < targetFiles; i++)
            total += SizeFor(i, seed);

        return total;
    }

    private static int DepthFor(int index, ulong seed)
    {
        if (index < 15)
            return index + 1;

        ulong x = Mix(((ulong)index) + seed) % 1000UL;

        if (x < 40UL) return 1;
        if (x < 110UL) return 2;
        if (x < 230UL) return 3;
        if (x < 370UL) return 4;
        if (x < 510UL) return 5;
        if (x < 640UL) return 6;
        if (x < 750UL) return 7;
        if (x < 835UL) return 8;
        if (x < 895UL) return 9;
        if (x < 935UL) return 10;
        if (x < 960UL) return 11;
        if (x < 977UL) return 12;
        if (x < 988UL) return 13;
        if (x < 995UL) return 14;
        return 15;
    }

    public static void BuildDirectories(
        string root,
        int directoryCount,
        ulong seed)
    {
        if (directoryCount < 15)
            throw new ArgumentException("directoryCount must be at least 15");

        _directories = new string[directoryCount];
        _depths = new int[directoryCount];
        _hasChild = new bool[directoryCount];
        _dirDepthHistogram = new long[16];

        List<int>[] byDepth = new List<int>[16];

        for (int d = 0; d <= 15; d++)
            byDepth[d] = new List<int>();

        for (int i = 0; i < directoryCount; i++)
        {
            int depth = DepthFor(i, seed);

            int parent = -1;

            if (depth > 1)
            {
                List<int> parents = byDepth[depth - 1];

                if (parents.Count == 0)
                    throw new InvalidOperationException(
                        "no parent directory available for requested depth"
                    );

                ulong choice = Mix(
                    ((ulong)i) ^
                    seed ^
                    0xA0761D6478BD642FUL
                );

                parent = parents[(int)(choice % (ulong)parents.Count)];
            }

            string name = string.Format(
                "d{0:D2}{1:X4}",
                depth,
                i & 0xffff
            );

            string path =
                parent < 0
                    ? Path.Combine(root, name)
                    : Path.Combine(_directories[parent], name);

            Directory.CreateDirectory(path);

            _directories[i] = path;
            _depths[i] = depth;
            _dirDepthHistogram[depth]++;

            if (parent >= 0)
                _hasChild[parent] = true;

            byDepth[depth].Add(i);
        }

        List<int> usable = new List<int>();
        List<int> hot = new List<int>();

        for (int i = 0; i < directoryCount; i++)
        {
            if (_hasChild[i])
                continue;

            ulong x = Mix(
                ((ulong)i) ^
                seed ^
                0xE7037ED1A0B428DBUL
            );

            // Roughly five percent of leaves remain intentionally empty.
            if ((x % 20UL) == 0UL)
                continue;

            usable.Add(i);
        }

        if (usable.Count == 0)
            throw new InvalidOperationException("no usable leaf directories");

        int hotCount = Math.Max(1, usable.Count / 5);

        for (int i = 0; i < hotCount; i++)
            hot.Add(usable[i]);

        _activeLeaves = usable.ToArray();
        _hotLeaves = hot.ToArray();
    }

    private static int DirectoryForFile(long index, ulong seed)
    {
        if (_activeLeaves == null || _activeLeaves.Length == 0)
            throw new InvalidOperationException("directory plan not built");

        // Force both mutation candidates into depth-15 leaves when possible.
        if (index == 0 || index == 1)
        {
            for (int i = 0; i < _activeLeaves.Length; i++)
            {
                int d = _activeLeaves[i];

                if (_depths[d] == 15)
                    return d;
            }
        }

        ulong x = Mix(
            ((ulong)index) ^
            seed ^
            0x8EBC6AF09C88C6E3UL
        );

        // 65% of files land in the "hot" 20% of usable leaves.
        if ((x % 1000UL) < 650UL)
            return _hotLeaves[(int)(x % (ulong)_hotLeaves.Length)];

        return _activeLeaves[(int)(x % (ulong)_activeLeaves.Length)];
    }

    private static string FileNameFor(long index, ulong seed)
    {
        if (index == 0)
            return "mutation-baseline.bin";

        if (index == 1)
            return "mutation-post-checkpoint.bin";

        ulong x = Mix(
            ((ulong)index) ^
            seed ^
            0x589965CC75374CC3UL
        );

        return string.Format(
            "f{0:X6}_{1:X4}.dat",
            index,
            x & 0xffffUL
        );
    }

    public static string PathForFile(
        string root,
        long index,
        ulong seed)
    {
        if (_directories == null)
            throw new InvalidOperationException("directory plan not built");

        int directory = DirectoryForFile(index, seed);

        return Path.Combine(
            _directories[directory],
            FileNameFor(index, seed)
        );
    }

    public static int DepthForFile(long index, ulong seed)
    {
        int directory = DirectoryForFile(index, seed);
        return _depths[directory];
    }

    private static bool IsDiskFullException(IOException ex)
    {
        int code = Marshal.GetHRForException(ex) & 0xffff;
        return code == 112 || code == 39;
    }

    private static void FillHeader(byte[] header, long index, ulong seed)
    {
        ulong x = Mix(
            ((ulong)index) ^
            seed ^
            0xA5A5A5A5A5A5A5A5UL
        );

        for (int i = 0; i < header.Length; i++)
        {
            x = Mix(x + (ulong)i);
            header[i] = (byte)x;
        }
    }

    private static void Worker(
        string root,
        long targetFiles,
        ulong seed)
    {
        byte[] header = new byte[4096];

        while (Volatile.Read(ref _stop) == 0)
        {
            long index = Interlocked.Increment(ref _nextFile) - 1L;

            if (index >= targetFiles)
                return;

            int size = SizeFor(index, seed);
            int band = SizeBandFor(index, seed);
            int depth = DepthForFile(index, seed);
            string path = PathForFile(root, index, seed);

            try
            {
                using (
                    FileStream stream =
                        new FileStream(
                            path,
                            FileMode.CreateNew,
                            FileAccess.Write,
                            FileShare.Read,
                            1024 * 1024,
                            FileOptions.SequentialScan
                        )
                )
                {
                    if (size > 0)
                    {
                        FillHeader(header, index, seed);

                        int first = Math.Min(size, header.Length);
                        stream.Write(header, 0, first);

                        int remaining = size - first;

                        int offset =
                            (int)(
                                ((index * 4099L) & 0x7fffffffL) %
                                (_pool.Length - 4096)
                            );

                        while (remaining > 0)
                        {
                            int available = _pool.Length - offset;

                            int count =
                                Math.Min(
                                    remaining,
                                    Math.Min(
                                        available,
                                        1024 * 1024
                                    )
                                );

                            stream.Write(_pool, offset, count);

                            remaining -= count;
                            offset += count;

                            if (offset >= _pool.Length)
                                offset = 0;
                        }
                    }
                }

                Interlocked.Increment(ref _createdFiles);
                Interlocked.Add(ref _createdBytes, size);
                Interlocked.Increment(ref _fileDepthHistogram[depth]);
                Interlocked.Increment(ref _sizeBandHistogram[band]);
            }
            catch (IOException ex)
            {
                if (IsDiskFullException(ex))
                {
                    Volatile.Write(ref _diskFull, 1);
                    _lastError = ex.Message;

                    try
                    {
                        if (File.Exists(path))
                            File.Delete(path);
                    }
                    catch
                    {
                    }
                }
                else
                {
                    _lastError = ex.ToString();
                }

                Volatile.Write(ref _stop, 1);
                return;
            }
            catch (Exception ex)
            {
                _lastError = ex.ToString();
                Volatile.Write(ref _stop, 1);
                return;
            }
        }
    }

    public static void Start(
        string root,
        long targetFiles,
        int workers,
        ulong seed)
    {
        if (_directories == null)
            throw new InvalidOperationException("BuildDirectories must run first");

        _createdFiles = 0;
        _createdBytes = 0;
        _diskFull = 0;
        _stop = 0;
        _nextFile = 0;
        _lastError = "";
        _fileDepthHistogram = new long[16];
        _sizeBandHistogram = new long[5];

        _pool = new byte[64 * 1024 * 1024];
        new Random(1357911).NextBytes(_pool);

        _tasks = new Task[workers];

        for (int i = 0; i < workers; i++)
        {
            _tasks[i] =
                Task.Factory.StartNew(
                    delegate
                    {
                        Worker(
                            root,
                            targetFiles,
                            seed
                        );
                    },
                    TaskCreationOptions.LongRunning
                );
        }
    }

    public static void Wait()
    {
        Task[] tasks = _tasks;

        if (tasks != null)
            Task.WaitAll(tasks);
    }

    public static long[] DirectoryDepthHistogram()
    {
        return (long[])_dirDepthHistogram.Clone();
    }

    public static long[] FileDepthHistogram()
    {
        return (long[])_fileDepthHistogram.Clone();
    }

    public static long[] SizeBandHistogram()
    {
        return (long[])_sizeBandHistogram.Clone();
    }
}
'@
}

function Convert-Histogram {
    param(
        [long[]]$Values,
        [int]$Start,
        [int]$End
    )

    $o = [ordered]@{}

    for ($i = $Start; $i -le $End; $i++) {
        $o[[string]$i] = [Int64]$Values[$i]
    }

    return $o
}

function Invoke-FileMutation {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string]$Suffix,

        [Parameter(Mandatory=$true)]
        [string]$Marker
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Mutation target missing: $Path"
    }

    $beforeItem = Get-Item -LiteralPath $Path
    $beforeHash =
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash

    $beforeFsutil =
        (& fsutil.exe usn readdata $Path 2>&1 | Out-String)

    $directory = Split-Path -Parent $Path
    $stem = [IO.Path]::GetFileNameWithoutExtension($Path)
    $ext = [IO.Path]::GetExtension($Path)

    $newPath =
        Join-Path $directory ($stem + $Suffix + $ext)

    if (Test-Path -LiteralPath $newPath) {
        throw "Mutation destination already exists: $newPath"
    }

    Rename-Item -LiteralPath $Path -NewName ([IO.Path]::GetFileName($newPath))

    $bytes = [Text.Encoding]::UTF8.GetBytes(
        "`r`n$Marker`r`n"
    )

    $stream =
        New-Object IO.FileStream(
            $newPath,
            [IO.FileMode]::Append,
            [IO.FileAccess]::Write,
            [IO.FileShare]::Read
        )

    try {
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    $completed = [DateTimeOffset]::UtcNow
    $afterItem = Get-Item -LiteralPath $newPath
    $afterHash =
        (Get-FileHash -LiteralPath $newPath -Algorithm SHA256).Hash

    $afterFsutil =
        (& fsutil.exe usn readdata $newPath 2>&1 | Out-String)

    [UInt64]$usn = 0

    $m =
        [regex]::Match(
            $afterFsutil,
            '(?im)^\s*Usn\s*:\s*0x([0-9a-f]+)\s*$'
        )

    if ($m.Success) {
        $usn =
            [Convert]::ToUInt64(
                $m.Groups[1].Value,
                16
            )
    }

    return [PSCustomObject]@{
        old_path             = $Path
        new_path             = $newPath
        completed_utc        = $completed.ToString('o')
        usn                   = $usn
        before_length        = [Int64]$beforeItem.Length
        after_length         = [Int64]$afterItem.Length
        before_sha256        = $beforeHash
        after_sha256         = $afterHash
        before_creation_utc  = $beforeItem.CreationTimeUtc.ToString('o')
        after_creation_utc   = $afterItem.CreationTimeUtc.ToString('o')
        after_last_write_utc = $afterItem.LastWriteTimeUtc.ToString('o')
        fsutil_before        = $beforeFsutil.Trim()
        fsutil_after         = $afterFsutil.Trim()
    }
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

if ($env:COMPUTERNAME -ne $ExpectedServer) {
    throw "Wrong host: $env:COMPUTERNAME"
}

if (-not (Test-Path 'Y:\')) {
    throw 'Y: does not exist.'
}

$fiHash = Get-ExactHash $CollectorExe
$usnHash = Get-ExactHash $USNExe
$senderHash = Get-ExactHash $SenderExe

if ($fiHash -ne $ExpectedFIHash) {
    throw "Unexpected fi.exe SHA256: $fiHash"
}

if ($usnHash -ne $ExpectedUSNHash) {
    throw "Unexpected fi-usn.exe SHA256: $usnHash"
}

if ($senderHash -ne $ExpectedSenderHash) {
    throw "Unexpected fi-sender.exe SHA256: $senderHash"
}

$collectorSvc =
    Get-CimInstance Win32_Service -Filter "Name='$CollectorService'"

$usnSvc =
    Get-CimInstance Win32_Service -Filter "Name='$USNService'"

if ($collectorSvc.StartName -ne 'ISS\gFI-FS01$') {
    throw "Unexpected FICollector identity: $($collectorSvc.StartName)"
}

if ($usnSvc.StartName -ne 'ISS\gFI-USN-FS01$') {
    throw "Unexpected FIUSNReader identity: $($usnSvc.StartName)"
}

$null = Get-ScheduledTask -TaskName $SenderTask -ErrorAction Stop

if (-not (Test-Path -LiteralPath $YRoot)) {
    throw "Expected disposable lab root does not exist: $YRoot"
}

# Read the complete current security descriptor, including the SACL, before any
# destructive action. Refuse to proceed if this cannot be done.
$priorAcl = Get-Acl -LiteralPath $YRoot -Audit -ErrorAction Stop
$priorRootSddl = $priorAcl.Sddl

New-Item -ItemType Directory -Path $ResultRoot -Force | Out-Null
New-Item -ItemType Directory -Path $FlagDir -Force | Out-Null
New-Item -ItemType Directory -Path $ArchiveBase -Force | Out-Null

[IO.File]::WriteAllText(
    $RootSddlPath,
    $priorRootSddl,
    (New-Object Text.UTF8Encoding($false))
)

Remove-Item $RunningFlag,$CompleteFlag,$FailedFlag -Force -ErrorAction SilentlyContinue

$plannedBytes =
    [FI250KRandomNestedV1]::PlannedBytes(
        $TargetFiles,
        $GeneratorSeed
    )

$plannedGiB = [double]$plannedBytes / 1GB

$drive = New-Object IO.DriveInfo('Y')
$initialFreeGiB = [double]$drive.AvailableFreeSpace / 1GB
$totalGiB = [double]$drive.TotalSize / 1GB

$requiredFreeGiB =
    $plannedGiB +
    $StartReserveGiB +
    $RecoveryReserveGiB +
    $MinimumMarginGiB

if ($initialFreeGiB -lt $requiredFreeGiB) {
    throw (
        'Insufficient free space. Planned dataset={0:N3} GiB, ' +
        'required free including reserves/margin={1:N3} GiB, actual={2:N3} GiB.' -f
        $plannedGiB,
        $requiredFreeGiB,
        $initialFreeGiB
    )
}

# Prove the existing metric paths before taking down FI.
$null = Get-NativeCPU
$null = Get-NativeMemory
$null = Get-YDiskSample
$netPreflight = Get-NetworkSnapshot

if ($netPreflight.Active.Count -eq 0) {
    throw 'No active non-loopback network interfaces were found.'
}

$transcriptStarted = $false

try {
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
    $transcriptStarted = $true
}
catch {
}

try {
    Write-Host '=== FI PHASE 2 - 250K RANDOM NESTED ONBOARDING ==='
    Write-Host "Run                    : $Run"
    Write-Host "FI SHA256              : $fiHash"
    Write-Host "FIUSNReader SHA256     : $usnHash"
    Write-Host "Sender SHA256          : $senderHash"
    Write-Host ('Y: total                : {0:N3} GiB' -f $totalGiB)
    Write-Host ('Y: initial free         : {0:N3} GiB' -f $initialFreeGiB)
    Write-Host ('Planned dataset         : {0:N3} GiB' -f $plannedGiB)
    Write-Host "Files                   : 250,000"
    Write-Host "Directory target        : $DirectoryTarget"
    Write-Host "Maximum depth           : $MaximumDepth"
    Write-Host "Sample/live interval    : $SampleSeconds sec"
    Write-Host "Receiver                : ${ReceiverAddress}:$ReceiverPort"
    Write-Host ''
    Write-Host 'Active network interfaces:'

    $netPreflight.Active |
        Format-Table Name,@{
            N='LinkGbps'
            E={[Math]::Round($_.SpeedBps / 1GB,3)}
        } -AutoSize

    Write-Host ''
    Write-Host '=== STOPPING FI; DRAINING PUBLISHED SOURCE CUSTODY ==='

    Stop-FI

    # Leave the sender running long enough to retire already-published source
    # batches before we rotate the old source state/spool out of the active path.
    Wait-PublishedSpoolDrain -TimeoutMinutes $SpoolDrainTimeoutMinutes

    Stop-Sender

    Write-Host 'Published source spool drained and sender stopped.'
    Write-Host ''

    # -----------------------------------------------------------------------
    # Rotate old lab runtime state and rebuild clean onboarding paths
    # -----------------------------------------------------------------------

    $archive =
        Join-Path $ArchiveBase (
            'pre-250k-' +
            (Get-Date -Format 'yyyyMMdd-HHmmss')
        )

    New-Item -ItemType Directory -Path $archive -Force | Out-Null

    foreach ($link in @(
        $ConfiguredRoot,
        $ConfiguredState,
        $ConfiguredSpool
    )) {
        Remove-TreeOrJunction $link
    }

    if (Test-Path -LiteralPath $YState) {
        Move-Item `
            -LiteralPath $YState `
            -Destination (Join-Path $archive 'state')
    }

    if (Test-Path -LiteralPath $YSpool) {
        Move-Item `
            -LiteralPath $YSpool `
            -Destination (Join-Path $archive 'spool')
    }

    # The old 100K/working lab tree is disposable and its accepted measurements
    # are already preserved. Delete only the exact expected lab root.
    Remove-TreeOrJunction $YRoot

    Remove-Item `
        $StartReserve,$RecoveryReserve `
        -Force `
        -ErrorAction SilentlyContinue

    New-Item -ItemType Directory -Path $YRoot,$YState,$YSpool -Force |
        Out-Null

    # Restore the previous root's exact owner/group/DACL/SACL.
    $newAcl = Get-Acl -LiteralPath $YRoot -Audit

    $newAcl.SetSecurityDescriptorSddlForm(
        $priorRootSddl,
        [Security.AccessControl.AccessControlSections]::All
    )

    Set-Acl -LiteralPath $YRoot -AclObject $newAcl

    # Re-establish the known source runtime ACLs.
    & icacls.exe $YState `
        /grant 'ISS\gFI-FS01$:(OI)(CI)M' `
        /grant 'ISS\gFI-USN-FS01$:(OI)(CI)M' |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw 'Failed setting FI state ACL.'
    }

    & icacls.exe $YSpool `
        /grant 'ISS\gFI-FS01$:(OI)(CI)M' |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw 'Failed setting FI spool ACL.'
    }

    New-Junction $ConfiguredRoot $YRoot
    New-Junction $ConfiguredState $YState
    New-Junction $ConfiguredSpool $YSpool

    # Verify the root SDDL survived the rebuild.
    $restoredAcl = Get-Acl -LiteralPath $YRoot -Audit

    if ($restoredAcl.Sddl -ne $priorRootSddl) {
        throw 'Rebuilt Y:\FI-Lab security descriptor does not match the preserved SDDL.'
    }

    Write-Host "Prior FI state/spool archived at: $archive"
    Write-Host 'Y:\FI-Lab owner/DACL/SACL restored exactly.'
    Write-Host ''

    # -----------------------------------------------------------------------
    # Real disk reserves
    # -----------------------------------------------------------------------

    Write-Host (
        'Creating {0}-GiB start and {1}-GiB emergency reserve files...' -f
        $StartReserveGiB,
        $RecoveryReserveGiB
    )

    & fsutil.exe file createnew `
        $StartReserve `
        ([Int64]$StartReserveGiB * 1GB) |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw 'Failed creating start reserve.'
    }

    & fsutil.exe file createnew `
        $RecoveryReserve `
        ([Int64]$RecoveryReserveGiB * 1GB) |
        Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw 'Failed creating recovery reserve.'
    }

    # -----------------------------------------------------------------------
    # Dataset build
    # -----------------------------------------------------------------------

    Write-Host ''
    Write-Host '=== BUILDING RANDOMIZED NESTED DIRECTORY PLAN ==='

    $dirStart = [DateTimeOffset]::UtcNow

    [FI250KRandomNestedV1]::BuildDirectories(
        $YRoot,
        $DirectoryTarget,
        $GeneratorSeed
    )

    $dirElapsed =
        ([DateTimeOffset]::UtcNow - $dirStart).TotalSeconds

    Write-Host (
        'Directory plan complete in {0:N3} sec.' -f
        $dirElapsed
    )

    $baselineCandidate =
        [FI250KRandomNestedV1]::PathForFile(
            $YRoot,
            0,
            $GeneratorSeed
        )

    $postCheckpointCandidate =
        [FI250KRandomNestedV1]::PathForFile(
            $YRoot,
            1,
            $GeneratorSeed
        )

    Write-Host ''
    Write-Host '=== GENERATING 250,000 FILES ==='
    Write-Host (
        'Expected bytes: {0:N0} ({1:N3} GiB)' -f
        $plannedBytes,
        $plannedGiB
    )

    $datasetStart = [DateTimeOffset]::UtcNow

    [FI250KRandomNestedV1]::Start(
        $YRoot,
        $TargetFiles,
        $GeneratorWorkers,
        $GeneratorSeed
    )

    $lastDatasetBytes = 0L
    $lastDatasetTime = $datasetStart

    while ([FI250KRandomNestedV1]::IsRunning) {
        Start-Sleep -Seconds 5

        $now = [DateTimeOffset]::UtcNow
        $createdFiles = [FI250KRandomNestedV1]::CreatedFiles
        $createdBytes = [FI250KRandomNestedV1]::CreatedBytes
        $deltaSec = ($now - $lastDatasetTime).TotalSeconds
        $deltaBytes = $createdBytes - $lastDatasetBytes
        $rateMiBs =
            $(if ($deltaSec -gt 0) {
                ($deltaBytes / 1MB) / $deltaSec
            }
            else {
                0.0
            })

        $drive = New-Object IO.DriveInfo('Y')

        Write-Host (
            '[DATASET] files={0,9:N0}/{1:N0} data={2,8:N2}GiB rate={3,7:N1}MiB/s free={4,8:N2}GiB' -f
            $createdFiles,
            $TargetFiles,
            ($createdBytes / 1GB),
            $rateMiBs,
            ($drive.AvailableFreeSpace / 1GB)
        )

        $lastDatasetBytes = $createdBytes
        $lastDatasetTime = $now
    }

    [FI250KRandomNestedV1]::Wait()

    $datasetEnd = [DateTimeOffset]::UtcNow
    $datasetElapsed = ($datasetEnd - $datasetStart).TotalSeconds

    $createdFiles = [FI250KRandomNestedV1]::CreatedFiles
    $createdBytes = [FI250KRandomNestedV1]::CreatedBytes

    if ([FI250KRandomNestedV1]::DiskFull) {
        throw (
            'Dataset generator hit disk full: ' +
            [FI250KRandomNestedV1]::LastError
        )
    }

    if (-not [string]::IsNullOrWhiteSpace(
        [FI250KRandomNestedV1]::LastError
    )) {
        throw (
            'Dataset generator failed: ' +
            [FI250KRandomNestedV1]::LastError
        )
    }

    if ($createdFiles -ne $TargetFiles) {
        throw "Dataset created $createdFiles files; expected $TargetFiles."
    }

    if ($createdBytes -ne $plannedBytes) {
        throw "Dataset byte count $createdBytes does not match planned $plannedBytes."
    }

    Write-Host ''
    Write-Host '=== VERIFYING DATASET FROM NTFS ENUMERATION ==='

    $verifyFiles = 0L
    $verifyBytes = 0L

    foreach (
        $file in
        [IO.Directory]::EnumerateFiles(
            $YRoot,
            '*',
            [IO.SearchOption]::AllDirectories
        )
    ) {
        $info = New-Object IO.FileInfo($file)
        $verifyFiles++
        $verifyBytes += [Int64]$info.Length
    }

    if ($verifyFiles -ne $TargetFiles) {
        throw "NTFS verification found $verifyFiles files; expected $TargetFiles."
    }

    if ($verifyBytes -ne $plannedBytes) {
        throw "NTFS verification found $verifyBytes bytes; expected $plannedBytes."
    }

    $dirHistogram =
        Convert-Histogram `
            -Values ([FI250KRandomNestedV1]::DirectoryDepthHistogram()) `
            -Start 1 `
            -End 15

    $fileDepthHistogram =
        Convert-Histogram `
            -Values ([FI250KRandomNestedV1]::FileDepthHistogram()) `
            -Start 1 `
            -End 15

    $sizeBands = [FI250KRandomNestedV1]::SizeBandHistogram()

    $datasetSummary = [ordered]@{
        generator_version = 'fi-250k-random-nested/1.0'
        seed = [string]$GeneratorSeed
        target_files = $TargetFiles
        actual_files = $verifyFiles
        exact_bytes = $verifyBytes
        gib = [Math]::Round($verifyBytes / 1GB,3)
        directory_target = $DirectoryTarget
        maximum_depth = $MaximumDepth
        directory_depth_histogram = $dirHistogram
        file_depth_histogram = $fileDepthHistogram
        size_bands = [ordered]@{
            '0-16KiB' = [Int64]$sizeBands[0]
            '16KiB-256KiB' = [Int64]$sizeBands[1]
            '256KiB-2MiB' = [Int64]$sizeBands[2]
            '2MiB-8MiB' = [Int64]$sizeBands[3]
            '8MiB-32MiB' = [Int64]$sizeBands[4]
        }
        generation_started_utc = $datasetStart.ToString('o')
        generation_finished_utc = $datasetEnd.ToString('o')
        generation_elapsed_sec = [Math]::Round($datasetElapsed,3)
        baseline_mutation_candidate = $baselineCandidate
        post_checkpoint_mutation_candidate = $postCheckpointCandidate
    }

    $datasetSummary |
        ConvertTo-Json -Depth 8 |
        Set-Content $DatasetPath -Encoding UTF8

    Write-Host (
        'Dataset verified: {0:N0} files / {1:N3} GiB / depth 1..15.' -f
        $verifyFiles,
        ($verifyBytes / 1GB)
    )

    Write-Host ''
    Write-Host "*** Releasing $StartReserveGiB GiB start reserve before FI starts ***"

    Remove-Item -LiteralPath $StartReserve -Force

    $drive = New-Object IO.DriveInfo('Y')
    $fiStartFreeGiB = [double]$drive.AvailableFreeSpace / 1GB

    Write-Host ('Y: free at FI start: {0:N3} GiB' -f $fiStartFreeGiB)
    Write-Host "Emergency reserve held: $RecoveryReserveGiB GiB"
    Write-Host ''

    # -----------------------------------------------------------------------
    # Start sender and FI
    # -----------------------------------------------------------------------

    Start-Sender

    $stageStart = Get-StageSummary
    $spoolStart = Get-SpoolSummary

    $logicalCPUs =
        (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

    $measureStart = [DateTimeOffset]::UtcNow

    Set-Content `
        $RunningFlag `
        -Encoding ASCII `
        -Value (
            "RUN=$Run`r`n" +
            "STARTING_UTC=$($measureStart.ToString('o'))`r`n" +
            "SAMPLES=$SamplesPath"
        )

    Write-Host '=== STARTING FI INITIAL ONBOARDING ==='

    Start-Service $USNService
    Start-Service $CollectorService

    $processDeadline = (Get-Date).AddSeconds(30)
    $fiProc = $null
    $usnProc = $null

    do {
        Start-Sleep -Milliseconds 200
        $fiProc = Get-NamedProcess 'fi'
        $usnProc = Get-NamedProcess 'fi-usn'
    }
    until (
        ($fiProc -and $usnProc) -or
        (Get-Date) -ge $processDeadline
    )

    if (-not $fiProc -or -not $usnProc) {
        throw 'FI processes did not appear.'
    }

    $senderProc = Get-NamedProcess 'fi-sender'

    $prevFI = Get-ProcSnap $fiProc
    $prevUSN = Get-ProcSnap $usnProc

    $prevSender =
        $(if ($senderProc) {
            Get-ProcSnap $senderProc
        }
        else {
            $null
        })

    $prevCPU = Get-NativeCPU
    $prevNet = Get-NetworkSnapshot
    $netStart = $prevNet
    $prevTime = [DateTimeOffset]::UtcNow

    $fiStartCPU = $prevFI.CPUSeconds
    $usnStartCPU = $prevUSN.CPUSeconds
    $senderStartCPU =
        $(if ($prevSender) {
            $prevSender.CPUSeconds
        }
        else {
            0.0
        })

    $peakHostCPU = 0.0
    $peakFIHost = 0.0
    $peakUSNHost = 0.0
    $peakSenderHost = 0.0
    $peakCombinedFIHost = 0.0

    $peakFIWS = $prevFI.WSBytes / 1MB
    $peakUSNWS = $prevUSN.WSBytes / 1MB
    $peakSenderWS =
        $(if ($prevSender) {
            $prevSender.WSBytes / 1MB
        }
        else {
            0.0
        })

    $peakCombinedFIWS =
        $peakFIWS +
        $peakUSNWS +
        $peakSenderWS

    $minAvailableMiB = [double]::MaxValue
    $peakMemoryLoadPct = 0.0

    $peakYReadMiBs = 0.0
    $peakYWriteMiBs = 0.0
    $peakYReadMs = 0.0
    $peakYWriteMs = 0.0
    $peakYQueue = 0.0

    $peakNetRxMiBs = 0.0
    $peakNetTxMiBs = 0.0
    $peakNetTotalMiBs = 0.0
    $peakNetLinkPct = 0.0
    $netRxIntegratedBytes = 0.0
    $netTxIntegratedBytes = 0.0

    $sampleNumber = 0L
    $phase = 'BASELINE'
    $firstConfiguredComplete = $null
    $mutation1 = $null
    $mutation1Done = $false
    [UInt64]$checkpointAfterBaseline = 0

    $drainComplete = $false
    $drainTimedOut = $false
    $drainQuietSince = $null
    $drainDeadline = $null
    $lastStageSignature = $null

    $utf8 = New-Object Text.UTF8Encoding($false)

    $writer =
        New-Object IO.StreamWriter(
            $SamplesPath,
            $false,
            $utf8
        )

    $writer.WriteLine(
        'UTC,ElapsedSec,Phase,YFreeGiB,' +
        'HostCPU_Pct,HostMemoryLoadPct,HostAvailableMiB,' +
        'YRead_MiBs,YWrite_MiBs,YRead_ms,YWrite_ms,YQueue,' +
        'NetRx_MiBs,NetTx_MiBs,NetTotal_MiBs,NetApproxLinkPct,' +
        'NetInErrors,NetOutErrors,NetInDiscards,NetOutDiscards,' +
        'FI_CPU_HostPct,USN_CPU_HostPct,Sender_CPU_HostPct,CombinedFI_CPU_HostPct,' +
        'FI_WS_MiB,USN_WS_MiB,Sender_WS_MiB,CombinedFI_WS_MiB,' +
        'ReceiverTCPEstablished,SpoolFiles,SpoolMiB,SpoolManifests,StageFiles,StageMiB'
    )

    $nextQueueSample = [DateTimeOffset]::UtcNow
    $spoolNow = $spoolStart
    $stageNow = $stageStart
    $receiverConnections = 0

    try {
        # ---------------------------------------------------------------
        # Initial configured collection / baseline, followed by a bounded
        # transport-drain observation period. The same 5-second resource
        # telemetry remains active through both phases.
        # ---------------------------------------------------------------

        while (-not $drainComplete) {
            $cycleStart = [DateTimeOffset]::UtcNow

            if ($SampleSeconds -gt 1) {
                Start-Sleep -Seconds ($SampleSeconds - 1)
            }

            $disk = Get-YDiskSample
            $now = [DateTimeOffset]::UtcNow
            $wall = ($now - $prevTime).TotalSeconds

            if ($fiProc.HasExited -or $usnProc.HasExited) {
                throw 'An FI process exited during onboarding.'
            }

            $fi = Get-ProcSnap $fiProc
            $usn = Get-ProcSnap $usnProc

            $currentSenderProc = Get-NamedProcess 'fi-sender'
            $sender = $null

            if ($currentSenderProc) {
                $sender = Get-ProcSnap $currentSenderProc
            }

            $cpu = Get-NativeCPU
            $mem = Get-NativeMemory
            $net = Get-NetworkSnapshot

            $idleDelta = [double]($cpu.Idle - $prevCPU.Idle)
            $kernelDelta = [double]($cpu.Kernel - $prevCPU.Kernel)
            $userDelta = [double]($cpu.User - $prevCPU.User)
            $totalDelta = $kernelDelta + $userDelta

            $hostCPUPct = 0.0

            if ($totalDelta -gt 0) {
                $hostCPUPct =
                    (1.0 - ($idleDelta / $totalDelta)) * 100.0
            }

            if ($hostCPUPct -lt 0) { $hostCPUPct = 0.0 }
            if ($hostCPUPct -gt 100) { $hostCPUPct = 100.0 }

            $fiHostPct =
                ((($fi.CPUSeconds - $prevFI.CPUSeconds) / $wall) * 100.0) /
                $logicalCPUs

            $usnHostPct =
                ((($usn.CPUSeconds - $prevUSN.CPUSeconds) / $wall) * 100.0) /
                $logicalCPUs

            $senderHostPct = 0.0

            if (
                $sender -and
                $prevSender -and
                $sender.Id -eq $prevSender.Id
            ) {
                $senderHostPct =
                    ((($sender.CPUSeconds - $prevSender.CPUSeconds) / $wall) * 100.0) /
                    $logicalCPUs
            }

            $combinedFIHostPct =
                $fiHostPct +
                $usnHostPct +
                $senderHostPct

            $fiWS = $fi.WSBytes / 1MB
            $usnWS = $usn.WSBytes / 1MB
            $senderWS =
                $(if ($sender) {
                    $sender.WSBytes / 1MB
                }
                else {
                    0.0
                })

            $combinedFIWS = $fiWS + $usnWS + $senderWS

            $availableMiB = [double]$mem.AvailablePhys / 1MB
            $memoryLoadPct = [double]$mem.LoadPct

            $drive = New-Object IO.DriveInfo('Y')
            $yFreeGiB = [double]$drive.AvailableFreeSpace / 1GB

            $yReadMiBs = $disk.ReadBytesSec / 1MB
            $yWriteMiBs = $disk.WriteBytesSec / 1MB

            $netRxBytes = 0.0
            $netTxBytes = 0.0

            if ($net.RxBytes -ge $prevNet.RxBytes) {
                $netRxBytes =
                    [double]($net.RxBytes - $prevNet.RxBytes)
            }

            if ($net.TxBytes -ge $prevNet.TxBytes) {
                $netTxBytes =
                    [double]($net.TxBytes - $prevNet.TxBytes)
            }

            $netRxMiBs =
                $(if ($wall -gt 0) {
                    ($netRxBytes / 1MB) / $wall
                }
                else {
                    0.0
                })

            $netTxMiBs =
                $(if ($wall -gt 0) {
                    ($netTxBytes / 1MB) / $wall
                }
                else {
                    0.0
                })

            $netTotalMiBs = $netRxMiBs + $netTxMiBs

            $netLinkPct = 0.0

            if ($net.LinkBits -gt 0) {
                $netLinkPct =
                    (($netTotalMiBs * 1MB * 8.0) / $net.LinkBits) * 100.0
            }

            $netRxIntegratedBytes += $netRxBytes
            $netTxIntegratedBytes += $netTxBytes

            $peakHostCPU = [Math]::Max($peakHostCPU,$hostCPUPct)
            $peakFIHost = [Math]::Max($peakFIHost,$fiHostPct)
            $peakUSNHost = [Math]::Max($peakUSNHost,$usnHostPct)
            $peakSenderHost = [Math]::Max($peakSenderHost,$senderHostPct)
            $peakCombinedFIHost =
                [Math]::Max($peakCombinedFIHost,$combinedFIHostPct)

            $peakFIWS = [Math]::Max($peakFIWS,$fiWS)
            $peakUSNWS = [Math]::Max($peakUSNWS,$usnWS)
            $peakSenderWS = [Math]::Max($peakSenderWS,$senderWS)
            $peakCombinedFIWS =
                [Math]::Max($peakCombinedFIWS,$combinedFIWS)

            $minAvailableMiB =
                [Math]::Min($minAvailableMiB,$availableMiB)

            $peakMemoryLoadPct =
                [Math]::Max($peakMemoryLoadPct,$memoryLoadPct)

            $peakYReadMiBs =
                [Math]::Max($peakYReadMiBs,$yReadMiBs)

            $peakYWriteMiBs =
                [Math]::Max($peakYWriteMiBs,$yWriteMiBs)

            $peakYReadMs =
                [Math]::Max($peakYReadMs,$disk.ReadMs)

            $peakYWriteMs =
                [Math]::Max($peakYWriteMs,$disk.WriteMs)

            $peakYQueue =
                [Math]::Max($peakYQueue,$disk.Queue)

            $peakNetRxMiBs =
                [Math]::Max($peakNetRxMiBs,$netRxMiBs)

            $peakNetTxMiBs =
                [Math]::Max($peakNetTxMiBs,$netTxMiBs)

            $peakNetTotalMiBs =
                [Math]::Max($peakNetTotalMiBs,$netTotalMiBs)

            $peakNetLinkPct =
                [Math]::Max($peakNetLinkPct,$netLinkPct)

            $queueUpdated = $false

            if ($now -ge $nextQueueSample) {
                $spoolNow = Get-SpoolSummary
                $stageNow = Get-StageSummary
                $receiverConnections = Get-ReceiverConnectionCount
                $nextQueueSample = $now.AddSeconds(30)
                $queueUpdated = $true
            }

            $elapsed = ($now - $measureStart).TotalSeconds

            $writer.WriteLine([string]::Join(',',@(
                $now.ToString('o'),
                (Inv $elapsed 'F3'),
                $phase,
                (Inv $yFreeGiB 'F3'),
                (Inv $hostCPUPct 'F2'),
                (Inv $memoryLoadPct 'F2'),
                (Inv $availableMiB 'F2'),
                (Inv $yReadMiBs 'F3'),
                (Inv $yWriteMiBs 'F3'),
                (Inv $disk.ReadMs 'F3'),
                (Inv $disk.WriteMs 'F3'),
                (Inv $disk.Queue 'F3'),
                (Inv $netRxMiBs 'F3'),
                (Inv $netTxMiBs 'F3'),
                (Inv $netTotalMiBs 'F3'),
                (Inv $netLinkPct 'F3'),
                $net.InErrors,
                $net.OutErrors,
                $net.InDiscards,
                $net.OutDiscards,
                (Inv $fiHostPct 'F2'),
                (Inv $usnHostPct 'F2'),
                (Inv $senderHostPct 'F2'),
                (Inv $combinedFIHostPct 'F2'),
                (Inv $fiWS 'F2'),
                (Inv $usnWS 'F2'),
                (Inv $senderWS 'F2'),
                (Inv $combinedFIWS 'F2'),
                $receiverConnections,
                $spoolNow.Files,
                (Inv ($spoolNow.Bytes / 1MB) 'F3'),
                $spoolNow.Manifests,
                $stageNow.Files,
                (Inv ($stageNow.Bytes / 1MB) 'F3')
            )))

            $writer.Flush()

            # Live status every five seconds. This is intentionally useful by
            # itself and not dependent on the final report.
            Write-Host (
                '[{0:hh\:mm\:ss}] {1,-10} | CPU host={2,5:N1}% FI={3,5:N1}% usn={4,4:N1}% snd={5,4:N1}% | ' +
                'RAM FI={6,6:N1}MiB avail={7,7:N0}MiB | ' +
                'Y R/W={8,6:N1}/{9,6:N1}MiB/s lat={10,6:N1}/{11,6:N1}ms Q={12,5:N1} | ' +
                'NET rx/tx={13,6:N2}/{14,6:N2}MiB/s link~{15,5:N2}% | spool={16,5:N0}m stage={17,7:N1}MiB' -f
                ([TimeSpan]::FromSeconds($elapsed)),
                $phase,
                $hostCPUPct,
                $fiHostPct,
                $usnHostPct,
                $senderHostPct,
                $combinedFIWS,
                $availableMiB,
                $yReadMiBs,
                $yWriteMiBs,
                $disk.ReadMs,
                $disk.WriteMs,
                $disk.Queue,
                $netRxMiBs,
                $netTxMiBs,
                $netLinkPct,
                $spoolNow.Manifests,
                ($stageNow.Bytes / 1MB)
            )

            if (
                $phase -eq 'BASELINE' -and
                -not $mutation1Done -and
                $elapsed -ge ($BaselineMutationAfterMinutes * 60)
            ) {
                Write-Host ''
                Write-Host '*** BASELINE MUTATION: RENAME + APPEND + FLUSH ***'

                $mutation1 =
                    Invoke-FileMutation `
                        -Path $baselineCandidate `
                        -Suffix '-BASELINE-CHANGED' `
                        -Marker (
                            'FI 250K baseline mutation ' +
                            [DateTimeOffset]::UtcNow.ToString('o')
                        )

                $mutation1 |
                    ConvertTo-Json -Depth 6 |
                    Set-Content $Mutation1Path -Encoding UTF8

                $mutation1Done = $true

                Write-Host "Mutation USN : $($mutation1.usn)"
                Write-Host "New path     : $($mutation1.new_path)"
                Write-Host "New SHA256   : $($mutation1.after_sha256)"
                Write-Host ''
            }

            $configuredNow = Get-FirstConfiguredComplete

            if (
                -not $firstConfiguredComplete -and
                $configuredNow
            ) {
                $firstConfiguredComplete = $configuredNow
                $phase = 'DRAIN'
                $drainDeadline =
                    $now.AddMinutes($SpoolDrainTimeoutMinutes)
                $nextQueueSample = $now

                Write-Host ''
                Write-Host (
                    '*** FIRST CONFIGURED COLLECTION COMPLETE at {0} ***' -f
                    $firstConfiguredComplete.observed_at
                )

                $checkpointAfterBaseline = Get-MaxCheckpointNextUSN

                if ($mutation1 -and $mutation1.usn -gt 0) {
                    if (
                        $checkpointAfterBaseline -le
                        [UInt64]$mutation1.usn
                    ) {
                        throw (
                            "Accepted USN checkpoint $checkpointAfterBaseline did not pass " +
                            "baseline mutation USN $($mutation1.usn)."
                        )
                    }

                    Write-Host (
                        'Baseline catch-up checkpoint proof: {0} > mutation USN {1}' -f
                        $checkpointAfterBaseline,
                        $mutation1.usn
                    )
                }

                Write-Host (
                    'Continuing 5-second telemetry while source/generation transport drains.'
                )
                Write-Host ''
            }

            if (
                $phase -eq 'DRAIN' -and
                $queueUpdated
            ) {
                $stageSignature =
                    ('{0}:{1}' -f $stageNow.Files,$stageNow.Bytes)

                if (
                    $spoolNow.Manifests -eq 0 -and
                    $stageSignature -eq $lastStageSignature
                ) {
                    if (-not $drainQuietSince) {
                        $drainQuietSince = $now
                    }
                    elseif (
                        ($now - $drainQuietSince).TotalSeconds -ge 60
                    ) {
                        $drainComplete = $true

                        Write-Host ''
                        Write-Host (
                            '*** TRANSPORT DRAIN QUIET: spool manifests=0; stage stable for >=60 sec ***'
                        )
                    }
                }
                else {
                    $drainQuietSince = $null
                }

                $lastStageSignature = $stageSignature

                if (
                    -not $drainComplete -and
                    $drainDeadline -and
                    $now -ge $drainDeadline
                ) {
                    $drainTimedOut = $true
                    $drainComplete = $true

                    Write-Warning (
                        "Transport drain did not become quiet within $SpoolDrainTimeoutMinutes minutes after collection completion."
                    )
                }
            }

            $sampleNumber++
            $prevFI = $fi
            $prevUSN = $usn
            $prevSender = $sender
            $prevCPU = $cpu
            $prevNet = $net
            $prevTime = $now
        }
    }
    finally {
        $writer.Flush()
        $writer.Dispose()
    }

    # -----------------------------------------------------------------------
    # Final local state/report
    # -----------------------------------------------------------------------

    $measureEnd = [DateTimeOffset]::UtcNow

    $finalFI = Get-NamedProcess 'fi'
    $finalUSN = Get-NamedProcess 'fi-usn'
    $finalSender = Get-NamedProcess 'fi-sender'

    $fiCPUUsed =
        $(if ($finalFI) {
            (Get-ProcSnap $finalFI).CPUSeconds - $fiStartCPU
        }
        else {
            0.0
        })

    $usnCPUUsed =
        $(if ($finalUSN) {
            (Get-ProcSnap $finalUSN).CPUSeconds - $usnStartCPU
        }
        else {
            0.0
        })

    $senderCPUUsed =
        $(if ($finalSender) {
            [Math]::Max(
                0.0,
                (Get-ProcSnap $finalSender).CPUSeconds - $senderStartCPU
            )
        }
        else {
            0.0
        })

    $operations = Get-OperationRows

    $operations |
        Export-Csv $OperationsPath -NoTypeInformation

    $spoolFinal = Get-SpoolSummary
    $stageFinal = Get-StageSummary

    $runtime = Join-Path $YState 'service-runtime.jsonl'

    if (Test-Path -LiteralPath $runtime) {
        Get-Content $runtime -Tail 100 |
            Set-Content $RuntimeTailPath -Encoding UTF8
    }

    $finalNet = Get-NetworkSnapshot

    $netInErrorDelta =
        $(if ($finalNet.InErrors -ge $netStart.InErrors) {
            $finalNet.InErrors - $netStart.InErrors
        }
        else {
            0
        })

    $netOutErrorDelta =
        $(if ($finalNet.OutErrors -ge $netStart.OutErrors) {
            $finalNet.OutErrors - $netStart.OutErrors
        }
        else {
            0
        })

    $netInDiscardDelta =
        $(if ($finalNet.InDiscards -ge $netStart.InDiscards) {
            $finalNet.InDiscards - $netStart.InDiscards
        }
        else {
            0
        })

    $netOutDiscardDelta =
        $(if ($finalNet.OutDiscards -ge $netStart.OutDiscards) {
            $finalNet.OutDiscards - $netStart.OutDiscards
        }
        else {
            0
        })

    $services = Get-Service $CollectorService,$USNService
    $servicesRunning =
        -not ($services | Where-Object Status -ne 'Running')

    $senderTaskState =
        (Get-ScheduledTask -TaskName $SenderTask).State.ToString()

    $drive = New-Object IO.DriveInfo('Y')

    $baselineCheckpointPassedMutation =
        $mutation1 -and
        (
            $mutation1.usn -eq 0 -or
            $checkpointAfterBaseline -gt [UInt64]$mutation1.usn
        )

    $pass =
        $servicesRunning -and
        $firstConfiguredComplete -ne $null -and
        $mutation1Done -and
        $baselineCheckpointPassedMutation -and
        -not $drainTimedOut

    $summary = [ordered]@{
        run = $Run

        executable_hashes = [ordered]@{
            fi = $fiHash
            fi_usn = $usnHash
            fi_sender = $senderHash
        }

        dataset = $datasetSummary

        initial_free_gib = [Math]::Round($initialFreeGiB,3)
        fi_start_free_gib = [Math]::Round($fiStartFreeGiB,3)
        final_free_gib =
            [Math]::Round(
                [double]$drive.AvailableFreeSpace / 1GB,
                3
            )

        measurement_started_utc = $measureStart.ToString('o')
        measurement_finished_utc = $measureEnd.ToString('o')
        measurement_elapsed_sec =
            [Math]::Round(
                ($measureEnd - $measureStart).TotalSeconds,
                3
            )

        first_configured_complete = $firstConfiguredComplete
        baseline_checkpoint_after = $checkpointAfterBaseline
        baseline_checkpoint_passed_mutation =
            $baselineCheckpointPassedMutation

        baseline_mutation = $mutation1

        transport_drain = [ordered]@{
            completed_quiet = (-not $drainTimedOut)
            timed_out = $drainTimedOut
            timeout_minutes = $SpoolDrainTimeoutMinutes
        }

        cpu = [ordered]@{
            peak_host_pct = [Math]::Round($peakHostCPU,2)
            peak_fi_pct_of_host = [Math]::Round($peakFIHost,2)
            peak_usn_pct_of_host = [Math]::Round($peakUSNHost,2)
            peak_sender_pct_of_host = [Math]::Round($peakSenderHost,2)
            peak_combined_fi_pct_of_host =
                [Math]::Round($peakCombinedFIHost,2)
            fi_cpu_sec = [Math]::Round($fiCPUUsed,3)
            usn_cpu_sec = [Math]::Round($usnCPUUsed,3)
            sender_cpu_sec = [Math]::Round($senderCPUUsed,3)
        }

        memory = [ordered]@{
            peak_fi_ws_mib = [Math]::Round($peakFIWS,2)
            peak_usn_ws_mib = [Math]::Round($peakUSNWS,2)
            peak_sender_ws_mib = [Math]::Round($peakSenderWS,2)
            peak_combined_fi_ws_mib =
                [Math]::Round($peakCombinedFIWS,2)
            peak_host_memory_load_pct =
                [Math]::Round($peakMemoryLoadPct,2)
            min_host_available_mib =
                [Math]::Round($minAvailableMiB,2)
        }

        disk_y = [ordered]@{
            peak_logical_read_mib_s =
                [Math]::Round($peakYReadMiBs,3)
            peak_logical_write_mib_s =
                [Math]::Round($peakYWriteMiBs,3)
            peak_read_latency_ms =
                [Math]::Round($peakYReadMs,3)
            peak_write_latency_ms =
                [Math]::Round($peakYWriteMs,3)
            peak_queue_length =
                [Math]::Round($peakYQueue,3)
        }

        network_host = [ordered]@{
            note =
                'Host-level active-interface counters; not claimed as FI-only traffic.'
            peak_rx_mib_s = [Math]::Round($peakNetRxMiBs,3)
            peak_tx_mib_s = [Math]::Round($peakNetTxMiBs,3)
            peak_total_mib_s = [Math]::Round($peakNetTotalMiBs,3)
            peak_approx_aggregate_link_pct =
                [Math]::Round($peakNetLinkPct,3)
            integrated_rx_gib =
                [Math]::Round($netRxIntegratedBytes / 1GB,3)
            integrated_tx_gib =
                [Math]::Round($netTxIntegratedBytes / 1GB,3)
            incoming_error_delta = $netInErrorDelta
            outgoing_error_delta = $netOutErrorDelta
            incoming_discard_delta = $netInDiscardDelta
            outgoing_discard_delta = $netOutDiscardDelta
            active_interfaces = $netStart.Active
            receiver_address = $ReceiverAddress
            receiver_port = $ReceiverPort
        }

        source_transport = [ordered]@{
            spool_start = $spoolStart
            spool_final = $spoolFinal
            stage_start = $stageStart
            stage_final = $stageFinal
            sender_task_state = $senderTaskState
        }

        archived_prior_runtime = $archive

        fi_collector_status =
            ($services |
                Where-Object Name -eq $CollectorService).Status.ToString()

        fi_usn_reader_status =
            ($services |
                Where-Object Name -eq $USNService).Status.ToString()

        pass = $pass
    }

    $summary |
        ConvertTo-Json -Depth 12 |
        Set-Content $SummaryPath -Encoding UTF8

    if (Test-Path -LiteralPath $RecoveryReserve) {
        Remove-Item `
            -LiteralPath $RecoveryReserve `
            -Force `
            -ErrorAction SilentlyContinue
    }

    Set-Content `
        $CompleteFlag `
        -Encoding ASCII `
        -Value (
            "RUN=$Run`r`n" +
            "PASS=$pass`r`n" +
            "FINISHED_UTC=$($measureEnd.ToString('o'))`r`n" +
            "RESULTS=$ResultRoot"
        )

    Write-Host ''
    Write-Host '=== FI PHASE 2 250K RESULT ==='
    Write-Host ('Dataset                    : {0:N0} files / {1:N3} GiB' -f $verifyFiles,($verifyBytes / 1GB))
    Write-Host ('Peak host CPU              : {0:N2} %' -f $peakHostCPU)
    Write-Host ('Peak FI+USN+sender CPU     : {0:N2} % of host' -f $peakCombinedFIHost)
    Write-Host ('Peak FI+USN+sender RAM     : {0:N2} MiB' -f $peakCombinedFIWS)
    Write-Host ('Min host available RAM     : {0:N2} MiB' -f $minAvailableMiB)
    Write-Host ('Peak Y: read/write         : {0:N3} / {1:N3} MiB/s' -f $peakYReadMiBs,$peakYWriteMiBs)
    Write-Host ('Peak Y: read/write latency : {0:N3} / {1:N3} ms' -f $peakYReadMs,$peakYWriteMs)
    Write-Host ('Peak Y: queue              : {0:N3}' -f $peakYQueue)
    Write-Host ('Peak NET rx/tx             : {0:N3} / {1:N3} MiB/s' -f $peakNetRxMiBs,$peakNetTxMiBs)
    Write-Host ('Integrated NET rx/tx       : {0:N3} / {1:N3} GiB' -f ($netRxIntegratedBytes/1GB),($netTxIntegratedBytes/1GB))
    Write-Host ('Network errors in/out      : {0} / {1}' -f $netInErrorDelta,$netOutErrorDelta)
    Write-Host ('Network discards in/out    : {0} / {1}' -f $netInDiscardDelta,$netOutDiscardDelta)
    Write-Host ''
    Write-Host "Baseline mutation USN      : $($mutation1.usn)"
    Write-Host "Checkpoint after baseline  : $checkpointAfterBaseline"
    Write-Host "Transport drain quiet      : $(-not $drainTimedOut)"
    Write-Host ''
    Write-Host "PASS                       : $pass"
    Write-Host "Results                    : $ResultRoot"
    Write-Host "5-second CSV               : $SamplesPath"
    Write-Host ''
    Write-Host 'Services remain running for review.'
}
catch {
    $message = $_.Exception.ToString()

    Set-Content `
        $FailedFlag `
        -Encoding UTF8 `
        -Value (
            "RUN=$Run`r`n" +
            "UTC=$([DateTimeOffset]::UtcNow.ToString('o'))`r`n" +
            "ERROR=$message"
        )

    Write-Host ''
    Write-Host '250K CAMPAIGN ABORTED:'
    Write-Host $message
    Write-Host "Results: $ResultRoot"
    throw
}
finally {
    if ($transcriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
        }
    }
}
