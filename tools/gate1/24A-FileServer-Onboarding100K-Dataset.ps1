# FI Gate 1 - 100,000 random-size onboarding stress on Y:
# Windows Server 2016 / PowerShell 5.1
#
# Goal:
#   - Target 100,000 actual files.
#   - Deterministic pseudo-random size per file: 4 KiB .. 2.5 MiB, uniform.
#   - Build dataset with FI stopped.
#   - Start FI against the completed/space-limited dataset and measure CPU/RAM/I/O.
#   - Shipper intentionally OFF.
#   - If Y: fills before 100,000 files, preserve that as a valid disk-exhaustion
#     finding, release controlled reserve space, and onboard whatever fit.
#
# Heavy data/state/spool live on Y:. Results live on C:.

$ErrorActionPreference = 'Stop'

$ExpectedServer = 'ISS-FS-01'
$ExpectedFIHash = '5C2A8FA07D9AF6F9762F7ED62975E6E6247CCF50325CF3B24211229596E90DB0'

$ConfiguredRoot  = 'C:\FI-Lab'
$ConfiguredState = 'C:\ProgramData\FI\state'
$ConfiguredSpool = 'C:\ProgramData\FI\spool'

$YRoot  = 'Y:\FI-Lab'
$YBase  = 'Y:\FI-Gate1'
$YState = Join-Path $YBase 'state'
$YSpool = Join-Path $YBase 'spool'

$StartReserve    = Join-Path $YBase 'start-reserve.bin'
$RecoveryReserve = Join-Path $YBase 'recovery-reserve.bin'
$Sentinel        = Join-Path $YBase 'watchdog-sentinel.bin'

$ResultsBase = 'C:\ProgramData\FI\gate1-results\onboarding100k-random'
$FlagDir = 'C:\FI-Test'
$RunningFlag  = Join-Path $FlagDir 'onboarding100k-y-running.flag'
$CompleteFlag = Join-Path $FlagDir 'onboarding100k-y-complete.flag'
$FailedFlag   = Join-Path $FlagDir 'onboarding100k-y-failed.flag'

$TargetFiles        = 100000L
$DirectoryCount     = 1000
$FilesPerDirectory  = 100
$MinFileBytes       = 4KB
$MaxFileBytes       = [int](2.5MB)
$GeneratorWorkers   = 4
$GeneratorSeed      = [UInt64]7955086146661276861
$StartReserveGiB    = 4
$RecoveryReserveGiB = 4
$FullHoldSeconds    = 60
$RecoveryWaitHours  = 8

$Run = 'onboarding100k-random-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$ResultRoot = Join-Path $ResultsBase $Run
$SamplesPath = Join-Path $ResultRoot 'samples.csv'
$OperationsPath = Join-Path $ResultRoot 'operations.csv'
$SummaryPath = Join-Path $ResultRoot 'summary.json'
$TranscriptPath = Join-Path $ResultRoot 'console.txt'

function Remove-TreeOrJunction {
    param([Parameter(Mandatory=$true)][string]$Path)

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
        [Parameter(Mandatory=$true)][string]$Link,
        [Parameter(Mandatory=$true)][string]$Target
    )

    cmd.exe /c "mklink /J `"$Link`" `"$Target`"" | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Failed creating junction $Link -> $Target"
    }
}

function Stop-FI {
    Stop-Service FICollector -Force -ErrorAction SilentlyContinue
    Stop-Service FIUSNReader -Force -ErrorAction SilentlyContinue

    $deadline = (Get-Date).AddSeconds(30)

    do {
        Start-Sleep -Milliseconds 250
        $svc = Get-Service FICollector,FIUSNReader
    }
    until (
        -not ($svc | Where-Object Status -ne 'Stopped') -or
        (Get-Date) -ge $deadline
    )

    if ($svc | Where-Object Status -ne 'Stopped') {
        throw 'FI services did not stop cleanly.'
    }
}

function New-PerfCounter {
    param(
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Counter,
        [string]$Instance = ''
    )

    if ([string]::IsNullOrWhiteSpace($Instance)) {
        return New-Object System.Diagnostics.PerformanceCounter -ArgumentList $Category,$Counter
    }

    return New-Object System.Diagnostics.PerformanceCounter -ArgumentList $Category,$Counter,$Instance
}

function Get-ProcSnap {
    param([Parameter(Mandatory=$true)][System.Diagnostics.Process]$Process)

    $Process.Refresh()

    [PSCustomObject]@{
        CPUSeconds = [double]$Process.TotalProcessorTime.TotalSeconds
        WSBytes    = [Int64]$Process.WorkingSet64
        Private    = [Int64]$Process.PrivateMemorySize64
    }
}

function Inv {
    param([double]$Value,[string]$Format='F3')

    return $Value.ToString(
        $Format,
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

function Get-ConfiguredCollections {
    $runtime = Join-Path $YState 'service-runtime.jsonl'

    if (-not (Test-Path -LiteralPath $runtime)) {
        return @()
    }

    $rows = @()

    try {
        foreach ($line in [System.IO.File]::ReadLines($runtime)) {
            try {
                $r = $line | ConvertFrom-Json -ErrorAction Stop

                if ($r.record_kind -eq 'ConfiguredCollection') {
                    $rows += $r
                }
            }
            catch {
            }
        }
    }
    catch {
    }

    return @($rows)
}

function Get-OperationRows {
    $rows = @()

    foreach ($file in Get-ChildItem "$YState\*-operations.jsonl" -File -ErrorAction SilentlyContinue) {
        $entries = @()

        try {
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                try {
                    $entries += ($line | ConvertFrom-Json -ErrorAction Stop)
                }
                catch {
                }
            }
        }
        catch {
            continue
        }

        foreach ($group in ($entries | Group-Object operation_id)) {
            $started = $group.Group |
                Where-Object event -eq 'Started' |
                Select-Object -First 1

            $finished = $group.Group |
                Where-Object event -eq 'Finished' |
                Select-Object -First 1

            if (-not $started -or -not $finished) {
                continue
            }

            $s = [DateTimeOffset]::Parse([string]$started.started_at)
            $f = [DateTimeOffset]::Parse([string]$finished.finished_at)

            $rows += [PSCustomObject]@{
                Journal     = $file.Name
                Kind        = [string]$started.kind
                StartedUTC  = $s.ToString('o')
                FinishedUTC = $f.ToString('o')
                DurationSec = [Math]::Round(($f - $s).TotalSeconds,3)
                Outcome     = [string]$finished.outcome
                Reason      = [string]$finished.reason_code
            }
        }
    }

    return @($rows | Sort-Object StartedUTC)
}

if ($env:COMPUTERNAME -ne $ExpectedServer) {
    throw "Wrong host: $env:COMPUTERNAME"
}

if (-not (Test-Path 'Y:\')) {
    throw 'Y: does not exist.'
}

$hash = (Get-FileHash 'C:\Program Files\FI\fi.exe' -Algorithm SHA256).Hash

if ($hash -ne $ExpectedFIHash) {
    throw "Unexpected fi.exe SHA256: $hash"
}

if (Get-Process -Name 'fi-resilience-shippersim-v0.2.2-windows-amd64' -ErrorAction SilentlyContinue) {
    throw 'Shipper simulator is running. This onboarding pass requires it OFF.'
}

New-Item -ItemType Directory -Path $ResultRoot -Force | Out-Null
New-Item -ItemType Directory -Path $FlagDir -Force | Out-Null

Remove-Item $RunningFlag,$CompleteFlag,$FailedFlag -Force -ErrorAction SilentlyContinue

$transcriptStarted = $false

try {
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
    $transcriptStarted = $true
}
catch {
}

try {
    Write-Host '=== FI 100,000 RANDOM-SIZE Y: ONBOARDING TEST ==='
    Write-Host "Run          : $Run"
    Write-Host "FI SHA256    : $hash"
    Write-Host 'Target files : 100,000'
    Write-Host 'Sizes        : uniform random 4 KiB .. 2.5 MiB'
    Write-Host "Governed root: $YRoot"
    Write-Host "State        : $YState"
    Write-Host "Spool        : $YSpool"
    Write-Host 'Shipper      : OFF intentionally'
    Write-Host ''

    Write-Host '=== FLUSHING DISPOSABLE LAB/RUNTIME ==='
    Stop-FI

    Remove-TreeOrJunction $ConfiguredRoot
    Remove-TreeOrJunction $ConfiguredState
    Remove-TreeOrJunction $ConfiguredSpool

    Remove-TreeOrJunction $YRoot
    Remove-TreeOrJunction $YBase

    New-Item -ItemType Directory -Path $YRoot,$YState,$YSpool -Force | Out-Null

    & icacls.exe $YState `
        /grant 'ISS\gFI-FS01$:(OI)(CI)M' `
        /grant 'ISS\gFI-USN-FS01$:(OI)(CI)M' | Out-Null

    & icacls.exe $YSpool `
        /grant 'ISS\gFI-FS01$:(OI)(CI)M' | Out-Null

    & icacls.exe $YRoot `
        /grant 'ISS\gFI-FS01$:(OI)(CI)RX' | Out-Null

    New-Junction $ConfiguredRoot $YRoot
    New-Junction $ConfiguredState $YState
    New-Junction $ConfiguredSpool $YSpool

    [System.IO.File]::WriteAllBytes(
        $Sentinel,
        [byte[]](0x46,0x49,0x2D,0x31,0x30,0x30,0x4B)
    )

    if (-not ('FI100KRandomDataset' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

public static class FI100KRandomDataset
{
    private static long _createdFiles;
    private static long _createdBytes;
    private static int _diskFull;
    private static int _stop;
    private static int _nextDirectory;
    private static string _lastError = "";
    private static byte[] _pool;
    private static Task[] _tasks;

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

    public static int SizeFor(long index, int minBytes, int maxBytes, ulong seed)
    {
        ulong range = (ulong)(maxBytes - minBytes + 1);
        ulong x = Mix(((ulong)index) ^ seed);
        return minBytes + (int)(x % range);
    }

    public static long PlannedBytes(long targetFiles, int minBytes, int maxBytes, ulong seed)
    {
        long total = 0;

        for (long i = 0; i < targetFiles; i++)
        {
            total += SizeFor(i, minBytes, maxBytes, seed);
        }

        return total;
    }

    private static bool IsDiskFullException(IOException ex)
    {
        int code = Marshal.GetHRForException(ex) & 0xffff;
        return code == 112 || code == 39;
    }

    private static void FillHeader(byte[] header, long index)
    {
        ulong x = Mix((ulong)index + 0xA5A5A5A5UL);

        for (int i = 0; i < header.Length; i++)
        {
            x = Mix(x + (ulong)i);
            header[i] = (byte)x;
        }
    }

    private static void Worker(
        string root,
        long targetFiles,
        int directoryCount,
        int filesPerDirectory,
        int minBytes,
        int maxBytes,
        ulong seed)
    {
        byte[] header = new byte[4096];

        while (Volatile.Read(ref _stop) == 0)
        {
            int d = Interlocked.Increment(ref _nextDirectory) - 1;

            if (d >= directoryCount)
                return;

            string dir = Path.Combine(root, string.Format("D{0:D4}", d));

            try
            {
                Directory.CreateDirectory(dir);
            }
            catch (IOException ex)
            {
                if (IsDiskFullException(ex))
                {
                    Volatile.Write(ref _diskFull, 1);
                    _lastError = ex.Message;
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

            for (int f = 0; f < filesPerDirectory; f++)
            {
                if (Volatile.Read(ref _stop) != 0)
                    return;

                long index = (long)d * (long)filesPerDirectory + (long)f;

                if (index >= targetFiles)
                    return;

                int size = SizeFor(index, minBytes, maxBytes, seed);

                string path = Path.Combine(
                    dir,
                    string.Format("F{0:D6}.bin", index)
                );

                try
                {
                    using (FileStream stream = new FileStream(
                        path,
                        FileMode.CreateNew,
                        FileAccess.Write,
                        FileShare.Read,
                        1024 * 1024,
                        FileOptions.SequentialScan))
                    {
                        FillHeader(header, index);

                        int first = Math.Min(size, header.Length);
                        stream.Write(header, 0, first);

                        int remaining = size - first;
                        int offset = (int)((index * 4099L) % (_pool.Length - 4096));

                        while (remaining > 0)
                        {
                            int available = _pool.Length - offset;
                            int count = Math.Min(
                                remaining,
                                Math.Min(available, 1024 * 1024)
                            );

                            stream.Write(_pool, offset, count);
                            remaining -= count;

                            offset += count;

                            if (offset >= _pool.Length)
                                offset = 0;
                        }
                    }

                    Interlocked.Increment(ref _createdFiles);
                    Interlocked.Add(ref _createdBytes, size);
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
    }

    public static void Start(
        string root,
        long targetFiles,
        int directoryCount,
        int filesPerDirectory,
        int minBytes,
        int maxBytes,
        int workers,
        ulong seed)
    {
        _createdFiles = 0;
        _createdBytes = 0;
        _diskFull = 0;
        _stop = 0;
        _nextDirectory = 0;
        _lastError = "";

        _pool = new byte[64 * 1024 * 1024];
        new Random(1357911).NextBytes(_pool);

        _tasks = new Task[workers];

        for (int i = 0; i < workers; i++)
        {
            _tasks[i] = Task.Factory.StartNew(
                delegate
                {
                    Worker(
                        root,
                        targetFiles,
                        directoryCount,
                        filesPerDirectory,
                        minBytes,
                        maxBytes,
                        seed
                    );
                },
                TaskCreationOptions.LongRunning
            );
        }
    }

    public static void Stop()
    {
        Volatile.Write(ref _stop, 1);
    }

    public static void Wait()
    {
        Task[] tasks = _tasks;

        if (tasks != null)
            Task.WaitAll(tasks);
    }
}
'@
    }

    $drive = New-Object System.IO.DriveInfo('Y')
    $initialFreeGiB = [double]$drive.AvailableFreeSpace / 1GB
    $totalGiB = [double]$drive.TotalSize / 1GB

    [Int64]$plannedBytes = [FI100KRandomDataset]::PlannedBytes(
        $TargetFiles,
        $MinFileBytes,
        $MaxFileBytes,
        $GeneratorSeed
    )

    $plannedGiB = [double]$plannedBytes / 1GB

    Write-Host ('Y: total               : {0:N3} GiB' -f $totalGiB)
    Write-Host ('Y: free before reserves: {0:N3} GiB' -f $initialFreeGiB)
    Write-Host ('Exact 100K data plan    : {0:N3} GiB' -f $plannedGiB)
    Write-Host ''

    if ($initialFreeGiB -lt 12) {
        throw 'Y: has less than 12 GiB free; refusing to remove the recovery margin.'
    }

    Write-Host "Creating two $StartReserveGiB-GiB reserve files..."

    & fsutil.exe file createnew $StartReserve ([Int64]$StartReserveGiB * 1GB) | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to create start reserve.'
    }

    & fsutil.exe file createnew $RecoveryReserve ([Int64]$RecoveryReserveGiB * 1GB) | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to create recovery reserve.'
    }

    $afterReserve = New-Object System.IO.DriveInfo('Y')
    $afterReserveFreeGiB = [double]$afterReserve.AvailableFreeSpace / 1GB

    Write-Host ('Y: free after reserves : {0:N3} GiB' -f $afterReserveFreeGiB)
    Write-Host ''

    Write-Host '=== BUILDING RANDOM DATASET WITH FI STOPPED ==='
    Write-Host 'Target is 100,000 files. If Y: fills first, that is recorded and onboarding continues with what fit.'

    $datasetStart = [DateTimeOffset]::UtcNow

    [FI100KRandomDataset]::Start(
        $YRoot,
        $TargetFiles,
        $DirectoryCount,
        $FilesPerDirectory,
        $MinFileBytes,
        $MaxFileBytes,
        $GeneratorWorkers,
        $GeneratorSeed
    )

    $lastFiles = -1L
    $lastProgressUTC = [DateTimeOffset]::UtcNow

    while ([FI100KRandomDataset]::IsRunning) {
        Start-Sleep -Seconds 5

        $nowFiles = [FI100KRandomDataset]::CreatedFiles
        $nowBytes = [FI100KRandomDataset]::CreatedBytes

        if ($nowFiles -gt $lastFiles) {
            $lastFiles = $nowFiles
            $lastProgressUTC = [DateTimeOffset]::UtcNow
        }
        elseif (
            ([DateTimeOffset]::UtcNow - $lastProgressUTC).TotalSeconds -ge 60
        ) {
            [FI100KRandomDataset]::Stop()
            throw (
                'Dataset generator made no forward progress for 60 seconds. ' +
                "Files=$nowFiles Bytes=$nowBytes LastError=$([FI100KRandomDataset]::LastError)"
            )
        }

        $driveNow = New-Object System.IO.DriveInfo('Y')

        Write-Host (
            'DATASET files={0,7:N0}/{1:N0} data={2,8:N2}GiB free={3,8:N2}GiB' -f
            $nowFiles,
            $TargetFiles,
            ($nowBytes / 1GB),
            ($driveNow.AvailableFreeSpace / 1GB)
        )
    }

    [FI100KRandomDataset]::Wait()

    if (
        -not [FI100KRandomDataset]::DiskFull -and
        [FI100KRandomDataset]::CreatedFiles -lt $TargetFiles
    ) {
        throw (
            'Dataset generator stopped before target. ' +
            "Files=$([FI100KRandomDataset]::CreatedFiles) " +
            "LastError=$([FI100KRandomDataset]::LastError)"
        )
    }

    $datasetEnd = [DateTimeOffset]::UtcNow
    $datasetElapsed = ($datasetEnd - $datasetStart).TotalSeconds

    $createdFiles = [FI100KRandomDataset]::CreatedFiles
    $createdBytes = [FI100KRandomDataset]::CreatedBytes
    $datasetDiskFull = [FI100KRandomDataset]::DiskFull
    $datasetError = [FI100KRandomDataset]::LastError

    $drive = New-Object System.IO.DriveInfo('Y')
    $preStartFreeGiB = [double]$drive.AvailableFreeSpace / 1GB

    Write-Host ''
    Write-Host '=== DATASET BUILD RESULT ==='
    Write-Host ('Created files : {0:N0}' -f $createdFiles)
    Write-Host ('Created bytes : {0:N0}' -f $createdBytes)
    Write-Host ('Created GiB   : {0:N3}' -f ($createdBytes / 1GB))
    Write-Host ('Elapsed       : {0:N3} sec' -f $datasetElapsed)
    Write-Host "Disk full     : $datasetDiskFull"
    Write-Host ('Y: free now   : {0:N3} GiB' -f $preStartFreeGiB)

    if ($datasetDiskFull) {
        Write-Host "Disk-full detail: $datasetError"
    }

    Write-Host ''
    Write-Host "*** Releasing $StartReserveGiB GiB start reserve before FI starts ***"

    Remove-Item -LiteralPath $StartReserve -Force

    $drive = New-Object System.IO.DriveInfo('Y')
    $fiStartFreeGiB = [double]$drive.AvailableFreeSpace / 1GB

    Write-Host ('Y: free for FI startup: {0:N3} GiB' -f $fiStartFreeGiB)
    Write-Host "Emergency recovery reserve still held: $RecoveryReserveGiB GiB"
    Write-Host ''

    $logicalCPUs = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
    [Int64]$totalPhysicalBytes = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory

    $hostCPU = New-PerfCounter 'Processor' 'Percent Processor Time' '_Total'
    $availMB = New-PerfCounter 'Memory' 'Available MBytes'
    $committedPct = New-PerfCounter 'Memory' 'Percent Committed Bytes In Use'
    $pagesPerSec = New-PerfCounter 'Memory' 'Pages/sec'

    $yRead = New-PerfCounter 'LogicalDisk' 'Disk Read Bytes/sec' 'Y:'
    $yWrite = New-PerfCounter 'LogicalDisk' 'Disk Write Bytes/sec' 'Y:'
    $yReadLat = New-PerfCounter 'LogicalDisk' 'Avg. Disk sec/Read' 'Y:'
    $yWriteLat = New-PerfCounter 'LogicalDisk' 'Avg. Disk sec/Write' 'Y:'
    $yQueue = New-PerfCounter 'LogicalDisk' 'Current Disk Queue Length' 'Y:'

    $physRead = New-PerfCounter 'PhysicalDisk' 'Disk Read Bytes/sec' '_Total'
    $physWrite = New-PerfCounter 'PhysicalDisk' 'Disk Write Bytes/sec' '_Total'

    foreach ($pc in @(
        $hostCPU,$availMB,$committedPct,$pagesPerSec,
        $yRead,$yWrite,$yReadLat,$yWriteLat,$yQueue,
        $physRead,$physWrite
    )) {
        [void]$pc.NextValue()
    }

    Start-Sleep -Seconds 1

    $measureStart = [DateTimeOffset]::UtcNow

    Set-Content $RunningFlag -Value (
        "RUN=$Run`r`nSTARTING_UTC=$($measureStart.ToString('o'))"
    ) -Encoding ASCII

    Write-Host '=== STARTING FI ONBOARDING ==='

    Start-Service FIUSNReader
    Start-Service FICollector

    $processDeadline = (Get-Date).AddSeconds(20)
    $fiProc = $null
    $usnProc = $null

    do {
        Start-Sleep -Milliseconds 200

        $fiProc = Get-Process -Name 'fi' -ErrorAction SilentlyContinue |
            Select-Object -First 1

        $usnProc = Get-Process -Name 'fi-usn' -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    until (
        ($fiProc -and $usnProc) -or
        (Get-Date) -ge $processDeadline
    )

    if (-not $fiProc -or -not $usnProc) {
        throw 'FI processes did not appear.'
    }

    $fiProc = [System.Diagnostics.Process]::GetProcessById($fiProc.Id)
    $usnProc = [System.Diagnostics.Process]::GetProcessById($usnProc.Id)

    $prevFI = Get-ProcSnap $fiProc
    $prevUSN = Get-ProcSnap $usnProc
    $prevTime = [DateTimeOffset]::UtcNow

    $fiStartCPU = $prevFI.CPUSeconds
    $usnStartCPU = $prevUSN.CPUSeconds

    $peakHostCPU = 0.0
    $peakCombinedFIHost = 0.0
    $peakCombinedFIWS = ($prevFI.WSBytes + $prevUSN.WSBytes) / 1MB
    $peakCombinedFIPrivate = ($prevFI.Private + $prevUSN.Private) / 1MB

    $minAvailableMB = [double]::MaxValue
    $peakCommittedPct = 0.0
    $peakPagesPerSec = 0.0

    $peakYReadMBs = 0.0
    $peakYWriteMBs = 0.0
    $peakYReadMs = 0.0
    $peakYWriteMs = 0.0
    $peakYQueue = 0.0
    $peakPhysReadMBs = 0.0
    $peakPhysWriteMBs = 0.0

    $firstCollection = $null
    $recoveryCollection = $null
    $reserveReleased = $false
    $reserveReleaseUTC = $null
    $lowFreeSince = $null
    $sampleNumber = 0L
    $phase = 'ONBOARDING'

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($SamplesPath,$false,$utf8)

    $writer.WriteLine(
        'UTC,ElapsedSec,Phase,YFreeGiB,YFreePct,HostCPU_Pct,AvailableMB,CommittedPct,PagesPerSec,' +
        'YRead_MiBs,YWrite_MiBs,YRead_ms,YWrite_ms,YQueue,' +
        'PhysicalRead_MiBs,PhysicalWrite_MiBs,' +
        'FI_CPU_HostPct,USN_CPU_HostPct,CombinedFI_CPU_HostPct,' +
        'FI_WS_MiB,USN_WS_MiB,CombinedFI_WS_MiB,' +
        'FI_Private_MiB,USN_Private_MiB,CombinedFI_Private_MiB'
    )

    try {
        while ($true) {
            Start-Sleep -Seconds 1

            $now = [DateTimeOffset]::UtcNow
            $wall = ($now - $prevTime).TotalSeconds

            if ($fiProc.HasExited -or $usnProc.HasExited) {
                throw 'An FI process exited during onboarding.'
            }

            $fi = Get-ProcSnap $fiProc
            $usn = Get-ProcSnap $usnProc

            $fiRaw = (($fi.CPUSeconds - $prevFI.CPUSeconds) / $wall) * 100.0
            $usnRaw = (($usn.CPUSeconds - $prevUSN.CPUSeconds) / $wall) * 100.0

            $fiHostPct = $fiRaw / $logicalCPUs
            $usnHostPct = $usnRaw / $logicalCPUs
            $combinedFIHostPct = $fiHostPct + $usnHostPct

            $hostCPUPct = [double]$hostCPU.NextValue()
            $available = [double]$availMB.NextValue()
            $commitPct = [double]$committedPct.NextValue()
            $pages = [double]$pagesPerSec.NextValue()

            $yReadMBs = [double]$yRead.NextValue() / 1MB
            $yWriteMBs = [double]$yWrite.NextValue() / 1MB
            $yReadMs = [double]$yReadLat.NextValue() * 1000.0
            $yWriteMs = [double]$yWriteLat.NextValue() * 1000.0
            $yQueueNow = [double]$yQueue.NextValue()

            $physReadMBs = [double]$physRead.NextValue() / 1MB
            $physWriteMBs = [double]$physWrite.NextValue() / 1MB

            $fiWS = $fi.WSBytes / 1MB
            $usnWS = $usn.WSBytes / 1MB
            $combinedFIWS = $fiWS + $usnWS

            $fiPrivate = $fi.Private / 1MB
            $usnPrivate = $usn.Private / 1MB
            $combinedFIPrivate = $fiPrivate + $usnPrivate

            $drive = New-Object System.IO.DriveInfo('Y')
            $yFreeGiB = [double]$drive.AvailableFreeSpace / 1GB
            $yFreePct = ([double]$drive.AvailableFreeSpace / [double]$drive.TotalSize) * 100.0

            $peakHostCPU = [Math]::Max($peakHostCPU,$hostCPUPct)
            $peakCombinedFIHost = [Math]::Max($peakCombinedFIHost,$combinedFIHostPct)
            $peakCombinedFIWS = [Math]::Max($peakCombinedFIWS,$combinedFIWS)
            $peakCombinedFIPrivate = [Math]::Max($peakCombinedFIPrivate,$combinedFIPrivate)

            $minAvailableMB = [Math]::Min($minAvailableMB,$available)
            $peakCommittedPct = [Math]::Max($peakCommittedPct,$commitPct)
            $peakPagesPerSec = [Math]::Max($peakPagesPerSec,$pages)

            $peakYReadMBs = [Math]::Max($peakYReadMBs,$yReadMBs)
            $peakYWriteMBs = [Math]::Max($peakYWriteMBs,$yWriteMBs)
            $peakYReadMs = [Math]::Max($peakYReadMs,$yReadMs)
            $peakYWriteMs = [Math]::Max($peakYWriteMs,$yWriteMs)
            $peakYQueue = [Math]::Max($peakYQueue,$yQueueNow)

            $peakPhysReadMBs = [Math]::Max($peakPhysReadMBs,$physReadMBs)
            $peakPhysWriteMBs = [Math]::Max($peakPhysWriteMBs,$physWriteMBs)

            $elapsed = ($now - $measureStart).TotalSeconds

            $writer.WriteLine([string]::Join(',',@(
                $now.ToString('o'),
                (Inv $elapsed 'F3'),
                $phase,
                (Inv $yFreeGiB 'F3'),
                (Inv $yFreePct 'F3'),
                (Inv $hostCPUPct 'F2'),
                (Inv $available 'F2'),
                (Inv $commitPct 'F2'),
                (Inv $pages 'F2'),
                (Inv $yReadMBs 'F3'),
                (Inv $yWriteMBs 'F3'),
                (Inv $yReadMs 'F3'),
                (Inv $yWriteMs 'F3'),
                (Inv $yQueueNow 'F3'),
                (Inv $physReadMBs 'F3'),
                (Inv $physWriteMBs 'F3'),
                (Inv $fiHostPct 'F2'),
                (Inv $usnHostPct 'F2'),
                (Inv $combinedFIHostPct 'F2'),
                (Inv $fiWS 'F2'),
                (Inv $usnWS 'F2'),
                (Inv $combinedFIWS 'F2'),
                (Inv $fiPrivate 'F2'),
                (Inv $usnPrivate 'F2'),
                (Inv $combinedFIPrivate 'F2')
            )))

            if (($sampleNumber % 10) -eq 0) {
                $writer.Flush()

                Write-Host (
                    '[{0:hh\:mm\:ss}] {1,-10} free={2,7:N2}GiB | HOST={3,6:N2}% FI={4,6:N2}% RAM={5,7:N1}MiB | ' +
                    'Y R/W={6,7:N1}/{7,7:N1}MiB/s LAT={8,7:N1}/{9,7:N1}ms Q={10,6:N1}' -f
                    ([TimeSpan]::FromSeconds($elapsed)),
                    $phase,
                    $yFreeGiB,
                    $hostCPUPct,
                    $combinedFIHostPct,
                    $combinedFIWS,
                    $yReadMBs,
                    $yWriteMBs,
                    $yReadMs,
                    $yWriteMs,
                    $yQueueNow
                )

                $collections = @(Get-ConfiguredCollections)

                if (-not $firstCollection -and $collections.Count -gt 0) {
                    $firstCollection = $collections[0]

                    Write-Host ''
                    Write-Host "*** FIRST CONFIGURED COLLECTION FINALIZED: $($firstCollection.outcome) ***"
                    Write-Host ''

                    if ($firstCollection.outcome -eq 'Complete') {
                        $recoveryCollection = $firstCollection
                        break
                    }

                    $phase = 'FAIL-HOLD'
                }

                if ($firstCollection -and $firstCollection.outcome -ne 'Complete') {
                    if ($yFreeGiB -le 0.50) {
                        if (-not $lowFreeSince) {
                            $lowFreeSince = $now
                        }
                    }
                    else {
                        $lowFreeSince = $null
                    }

                    $shouldRelease =
                        -not $reserveReleased -and (
                            (
                                $lowFreeSince -and
                                ($now - $lowFreeSince).TotalSeconds -ge $FullHoldSeconds
                            ) -or
                            (
                                $firstCollection -and
                                ([DateTimeOffset]::Parse([string]$firstCollection.observed_at)) -lt $now.AddSeconds(-$FullHoldSeconds)
                            )
                        )

                    if ($shouldRelease) {
                        Write-Host ''
                        Write-Host "*** RELEASING $RecoveryReserveGiB GiB EMERGENCY RESERVE ***"

                        Remove-Item -LiteralPath $RecoveryReserve -Force -ErrorAction SilentlyContinue

                        $reserveReleased = $true
                        $reserveReleaseUTC = [DateTimeOffset]::UtcNow
                        $phase = 'RECOVERY'
                        Write-Host ''
                    }

                    if ($reserveReleased) {
                        $collections = @(Get-ConfiguredCollections)

                        foreach ($c in $collections) {
                            try {
                                $ct = [DateTimeOffset]::Parse([string]$c.observed_at)

                                if (
                                    $ct -gt $reserveReleaseUTC -and
                                    $c.outcome -eq 'Complete'
                                ) {
                                    $recoveryCollection = $c
                                    break
                                }
                            }
                            catch {
                            }
                        }

                        if ($recoveryCollection) {
                            break
                        }

                        if (
                            ([DateTimeOffset]::UtcNow - $reserveReleaseUTC).TotalHours -ge
                            $RecoveryWaitHours
                        ) {
                            break
                        }
                    }
                }
            }

            $sampleNumber++
            $prevFI = $fi
            $prevUSN = $usn
            $prevTime = $now
        }
    }
    finally {
        $writer.Flush()
        $writer.Dispose()
    }

    $measureEnd = [DateTimeOffset]::UtcNow

    $finalFI = Get-ProcSnap $fiProc
    $finalUSN = Get-ProcSnap $usnProc

    $fiCPUUsed = $finalFI.CPUSeconds - $fiStartCPU
    $usnCPUUsed = $finalUSN.CPUSeconds - $usnStartCPU

    $collections = @(Get-ConfiguredCollections)
    $operations = Get-OperationRows

    $operations |
        Export-Csv $OperationsPath -NoTypeInformation

    $completeCount = @($collections | Where-Object outcome -eq 'Complete').Count
    $partialCount = @($collections | Where-Object outcome -eq 'Partial').Count
    $failedCount = @($collections | Where-Object outcome -eq 'Failed').Count

    $services = Get-Service FICollector,FIUSNReader
    $servicesRunning = -not ($services | Where-Object Status -ne 'Running')

    $drive = New-Object System.IO.DriveInfo('Y')
    $finalFreeGiB = [double]$drive.AvailableFreeSpace / 1GB

    $pass =
        $servicesRunning -and
        $recoveryCollection -ne $null -and
        $recoveryCollection.outcome -eq 'Complete'

    $summary = [ordered]@{
        run                         = $Run
        fi_sha256                   = $hash

        target_files                = $TargetFiles
        planned_dataset_bytes       = $plannedBytes
        planned_dataset_gib         = [Math]::Round($plannedGiB,3)

        actual_files_created        = $createdFiles
        actual_dataset_bytes        = $createdBytes
        actual_dataset_gib          = [Math]::Round($createdBytes / 1GB,3)
        dataset_generation_sec      = [Math]::Round($datasetElapsed,3)
        dataset_hit_disk_full       = $datasetDiskFull
        dataset_disk_full_detail    = $datasetError

        y_total_gib                 = [Math]::Round($totalGiB,3)
        y_initial_free_gib          = [Math]::Round($initialFreeGiB,3)
        y_free_at_fi_start_gib      = [Math]::Round($fiStartFreeGiB,3)
        y_final_free_gib            = [Math]::Round($finalFreeGiB,3)

        first_collection_outcome    = $(if ($firstCollection) { $firstCollection.outcome } else { '' })
        recovery_reserve_released   = $reserveReleased
        post_release_complete       = $($recoveryCollection -ne $null)

        configured_complete_count   = $completeCount
        configured_partial_count    = $partialCount
        configured_failed_count     = $failedCount

        measurement_started_utc     = $measureStart.ToString('o')
        measurement_finished_utc    = $measureEnd.ToString('o')
        measurement_elapsed_sec     = [Math]::Round(($measureEnd - $measureStart).TotalSeconds,3)

        peak_host_cpu_pct           = [Math]::Round($peakHostCPU,2)
        combined_fi_cpu_sec         = [Math]::Round($fiCPUUsed + $usnCPUUsed,3)
        peak_combined_fi_cpu_pct    = [Math]::Round($peakCombinedFIHost,2)

        total_physical_memory_mib   = [Math]::Round($totalPhysicalBytes / 1MB,2)
        min_available_memory_mib    = [Math]::Round($minAvailableMB,2)
        peak_committed_pct          = [Math]::Round($peakCommittedPct,2)
        peak_pages_per_sec          = [Math]::Round($peakPagesPerSec,2)

        peak_combined_fi_ws_mib     = [Math]::Round($peakCombinedFIWS,2)
        peak_combined_fi_private_mib= [Math]::Round($peakCombinedFIPrivate,2)

        peak_y_read_mib_s           = [Math]::Round($peakYReadMBs,3)
        peak_y_write_mib_s          = [Math]::Round($peakYWriteMBs,3)
        peak_y_read_latency_ms      = [Math]::Round($peakYReadMs,3)
        peak_y_write_latency_ms     = [Math]::Round($peakYWriteMs,3)
        peak_y_queue_length         = [Math]::Round($peakYQueue,3)

        peak_host_physical_read_mib_s  = [Math]::Round($peakPhysReadMBs,3)
        peak_host_physical_write_mib_s = [Math]::Round($peakPhysWriteMBs,3)

        fi_collector_status         = ($services | Where-Object Name -eq 'FICollector').Status.ToString()
        fi_usn_reader_status        = ($services | Where-Object Name -eq 'FIUSNReader').Status.ToString()

        pass                        = $pass
    }

    $summary |
        ConvertTo-Json -Depth 6 |
        Set-Content $SummaryPath -Encoding UTF8

    if (Test-Path -LiteralPath $RecoveryReserve) {
        Remove-Item -LiteralPath $RecoveryReserve -Force -ErrorAction SilentlyContinue
    }

    Set-Content $CompleteFlag -Value (
        "RUN=$Run`r`nPASS=$pass`r`nFINISHED_UTC=$($measureEnd.ToString('o'))"
    ) -Encoding ASCII

    Write-Host ''
    Write-Host '=== 100K RANDOM ONBOARDING RESULT ==='
    Write-Host ('Target files             : {0:N0}' -f $TargetFiles)
    Write-Host ('Actual files created     : {0:N0}' -f $createdFiles)
    Write-Host ('Actual dataset           : {0:N3} GiB' -f ($createdBytes / 1GB))
    Write-Host "Dataset hit disk full    : $datasetDiskFull"
    Write-Host ''
    Write-Host "First collection outcome : $(if ($firstCollection) { $firstCollection.outcome } else { 'NONE' })"
    Write-Host "Recovery reserve released: $reserveReleased"
    Write-Host "Post/recovery Complete   : $($recoveryCollection -ne $null)"
    Write-Host ''
    Write-Host ('Peak host CPU            : {0:N2} %' -f $peakHostCPU)
    Write-Host ('Peak combined FI CPU     : {0:N2} % of host' -f $peakCombinedFIHost)
    Write-Host ('Combined FI CPU consumed : {0:N3} sec' -f ($fiCPUUsed + $usnCPUUsed))
    Write-Host ('Peak combined FI RAM     : {0:N2} MiB' -f $peakCombinedFIWS)
    Write-Host ('Minimum available RAM    : {0:N2} MiB' -f $minAvailableMB)
    Write-Host ''
    Write-Host ('Peak Y: read             : {0:N3} MiB/s' -f $peakYReadMBs)
    Write-Host ('Peak Y: write            : {0:N3} MiB/s' -f $peakYWriteMBs)
    Write-Host ('Peak Y: read latency     : {0:N3} ms' -f $peakYReadMs)
    Write-Host ('Peak Y: write latency    : {0:N3} ms' -f $peakYWriteMs)
    Write-Host ('Peak Y: queue            : {0:N3}' -f $peakYQueue)
    Write-Host ''
    Write-Host "Configured Complete      : $completeCount"
    Write-Host "Configured Partial       : $partialCount"
    Write-Host "Configured Failed        : $failedCount"
    Write-Host ''
    Write-Host '=== OPERATION TIMINGS ==='

    $operations |
        Format-Table Kind,DurationSec,Outcome,Reason -Auto

    Write-Host ''

    if ($pass) {
        Write-Host '100K RANDOM ONBOARDING TEST: PASS'
    }
    else {
        Write-Host '100K RANDOM ONBOARDING TEST: FINDING/FAIL'
    }

    Write-Host "Results: $ResultRoot"
    Write-Host ''
    $services | Format-Table Name,Status -Auto
    Write-Host ''
    Write-Host 'C:\FI-Lab, FI state, and FI spool remain junctioned to Y: for review.'
}
catch {
    $message = $_.Exception.Message

    Set-Content $FailedFlag -Value (
        "RUN=$Run`r`nERROR=$message`r`nUTC=$([DateTimeOffset]::UtcNow.ToString('o'))"
    ) -Encoding ASCII

    Set-Content $CompleteFlag -Value (
        "RUN=$Run`r`nOUTCOME=FAILED`r`nERROR=$message"
    ) -Encoding ASCII

    Write-Host ''
    Write-Host '100K RANDOM ONBOARDING TEST ABORTED:'
    Write-Host $message
    Write-Host "Results: $ResultRoot"
    throw
}
finally {
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
    }
}
