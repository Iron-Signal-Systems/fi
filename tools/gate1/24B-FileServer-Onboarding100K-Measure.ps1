# FI Gate 1 - resume 100,000 random-size onboarding after counter-preflight abort
# Windows Server 2016 / PowerShell 5.1
#
# IMPORTANT:
#   - DOES NOT delete or rebuild Y:\FI-Lab.
#   - Reuses the completed 100,000-file / 131,365,642,498-byte dataset.
#   - Reuses the existing Y: FI state/spool layout.
#   - Clears only prior test flag files.
#   - Uses native Windows APIs for host CPU/RAM.
#   - Uses Get-Counter ONLY for the Y: LogicalDisk counters already proven to work
#     on this host.
#
# Shipper remains OFF for this onboarding measurement.

$ErrorActionPreference = 'Stop'

$ExpectedServer = 'ISS-FS-01'
$ExpectedFIHash = '5C2A8FA07D9AF6F9762F7ED62975E6E6247CCF50325CF3B24211229596E90DB0'

$ExpectedFiles = 100000L
$ExpectedBytes = 131365642498L

$ConfiguredRoot  = 'C:\FI-Lab'
$ConfiguredState = 'C:\ProgramData\FI\state'
$ConfiguredSpool = 'C:\ProgramData\FI\spool'

$YRoot  = 'Y:\FI-Lab'
$YBase  = 'Y:\FI-Gate1'
$YState = Join-Path $YBase 'state'
$YSpool = Join-Path $YBase 'spool'
$RecoveryReserve = Join-Path $YBase 'recovery-reserve.bin'

$FlagDir = 'C:\FI-Test'
$RunningFlag  = Join-Path $FlagDir 'onboarding100k-y-running.flag'
$CompleteFlag = Join-Path $FlagDir 'onboarding100k-y-complete.flag'
$FailedFlag   = Join-Path $FlagDir 'onboarding100k-y-failed.flag'

$ResultsBase = 'C:\ProgramData\FI\gate1-results\onboarding100k-random'
$Run = 'onboarding100k-random-resume-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$ResultRoot = Join-Path $ResultsBase $Run
$SamplesPath = Join-Path $ResultRoot 'samples.csv'
$OperationsPath = Join-Path $ResultRoot 'operations.csv'
$SummaryPath = Join-Path $ResultRoot 'summary.json'
$TranscriptPath = Join-Path $ResultRoot 'console.txt'

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

function Get-ProcSnap {
    param([Parameter(Mandatory=$true)][System.Diagnostics.Process]$Process)

    $Process.Refresh()

    [PSCustomObject]@{
        CPUSeconds = [double]$Process.TotalProcessorTime.TotalSeconds
        WSBytes    = [Int64]$Process.WorkingSet64
        Private    = [Int64]$Process.PrivateMemorySize64
        PeakWS     = [Int64]$Process.PeakWorkingSet64
    }
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

function Get-SpoolSummary {
    [Int64]$files = 0
    [Int64]$bytes = 0
    [Int64]$manifests = 0
    [Int64]$records = 0
    [Int64]$manifestDataBytes = 0

    foreach ($file in Get-ChildItem $YSpool -File -ErrorAction SilentlyContinue) {
        $files++
        $bytes += [Int64]$file.Length

        if ($file.Name -notlike '*.manifest.json') {
            continue
        }

        $manifests++

        try {
            $m = Get-Content -LiteralPath $file.FullName -Raw |
                ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $m.record_count) {
                $records += [Int64]$m.record_count
            }

            if ($null -ne $m.data_bytes) {
                $manifestDataBytes += [Int64]$m.data_bytes
            }
        }
        catch {
        }
    }

    [PSCustomObject]@{
        Files             = $files
        Bytes             = $bytes
        Manifests         = $manifests
        Records           = $records
        ManifestDataBytes = $manifestDataBytes
    }
}

if (-not ('FINativeMetrics' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class FINativeMetrics
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
    $idle = New-Object FINativeMetrics+FILETIME
    $kernel = New-Object FINativeMetrics+FILETIME
    $user = New-Object FINativeMetrics+FILETIME

    if (-not [FINativeMetrics]::GetSystemTimes([ref]$idle,[ref]$kernel,[ref]$user)) {
        throw 'GetSystemTimes failed.'
    }

    [PSCustomObject]@{
        Idle   = [FINativeMetrics]::ToInt64($idle)
        Kernel = [FINativeMetrics]::ToInt64($kernel)
        User   = [FINativeMetrics]::ToInt64($user)
    }
}

function Get-NativeMemory {
    $m = New-Object FINativeMetrics+MEMORYSTATUSEX
    $m.dwLength = [Runtime.InteropServices.Marshal]::SizeOf($m)

    if (-not [FINativeMetrics]::GlobalMemoryStatusEx([ref]$m)) {
        throw 'GlobalMemoryStatusEx failed.'
    }

    [PSCustomObject]@{
        LoadPct       = [double]$m.dwMemoryLoad
        TotalPhys     = [UInt64]$m.ullTotalPhys
        AvailablePhys = [UInt64]$m.ullAvailPhys
        TotalPageFile = [UInt64]$m.ullTotalPageFile
        AvailPageFile = [UInt64]$m.ullAvailPageFile
    }
}

function Get-YDiskSample {
    $set = Get-Counter -Counter @(
        '\LogicalDisk(Y:)\Disk Read Bytes/sec',
        '\LogicalDisk(Y:)\Disk Write Bytes/sec',
        '\LogicalDisk(Y:)\Avg. Disk sec/Read',
        '\LogicalDisk(Y:)\Avg. Disk sec/Write',
        '\LogicalDisk(Y:)\Current Disk Queue Length'
    ) -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop

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
        ReadBytesSec  = $(if ($values.ContainsKey('ReadBytesSec')) { $values.ReadBytesSec } else { 0.0 })
        WriteBytesSec = $(if ($values.ContainsKey('WriteBytesSec')) { $values.WriteBytesSec } else { 0.0 })
        ReadMs        = $(if ($values.ContainsKey('ReadSec')) { $values.ReadSec * 1000.0 } else { 0.0 })
        WriteMs       = $(if ($values.ContainsKey('WriteSec')) { $values.WriteSec * 1000.0 } else { 0.0 })
        Queue         = $(if ($values.ContainsKey('Queue')) { $values.Queue } else { 0.0 })
    }
}

function Inv {
    param([double]$Value,[string]$Format='F3')

    return $Value.ToString(
        $Format,
        [System.Globalization.CultureInfo]::InvariantCulture
    )
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

$transcriptStarted = $false

try {
    Start-Transcript -Path $TranscriptPath -Force | Out-Null
    $transcriptStarted = $true
}
catch {
}

try {
    Write-Host '=== RESUME FI 100K RANDOM ONBOARDING ==='
    Write-Host "Run       : $Run"
    Write-Host "FI SHA256 : $hash"
    Write-Host ''

    Stop-FI

    Write-Host '=== VERIFYING EXISTING DATASET ==='

    $count = 0L
    $bytes = 0L

    foreach ($file in [System.IO.Directory]::EnumerateFiles(
        $YRoot,
        '*',
        [System.IO.SearchOption]::AllDirectories
    )) {
        $info = New-Object System.IO.FileInfo($file)
        $count++
        $bytes += [Int64]$info.Length
    }

    Write-Host ('Files : {0:N0}' -f $count)
    Write-Host ('Bytes : {0:N0}' -f $bytes)
    Write-Host ('GiB   : {0:N3}' -f ($bytes / 1GB))

    if ($count -ne $ExpectedFiles) {
        throw "Expected $ExpectedFiles files; found $count."
    }

    if ($bytes -ne $ExpectedBytes) {
        throw "Expected $ExpectedBytes bytes; found $bytes."
    }

    Write-Host 'Dataset verification: PASS'
    Write-Host ''

    foreach ($pair in @(
        @{ Link=$ConfiguredRoot;  Target=$YRoot  },
        @{ Link=$ConfiguredState; Target=$YState },
        @{ Link=$ConfiguredSpool; Target=$YSpool }
    )) {
        if (-not (Test-Path -LiteralPath $pair.Link)) {
            throw "Required FI path is missing: $($pair.Link)"
        }

        $item = Get-Item -LiteralPath $pair.Link -Force

        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
            throw "Expected junction, found normal path: $($pair.Link)"
        }
    }

    if (-not (Test-Path -LiteralPath $RecoveryReserve)) {
        Write-Warning '4-GiB emergency reserve is absent. Continuing because Y: has ample free space.'
    }

    $drive = New-Object System.IO.DriveInfo('Y')
    $freeGiB = [double]$drive.AvailableFreeSpace / 1GB

    Write-Host ('Y: free before FI start: {0:N3} GiB' -f $freeGiB)
    Write-Host ''

    Write-Host '=== COUNTER PREFLIGHT ==='

    $cpuPre = Get-NativeCPU
    $memPre = Get-NativeMemory
    $diskPre = Get-YDiskSample

    Write-Host 'Native host CPU API : PASS'
    Write-Host 'Native host RAM API : PASS'
    Write-Host 'Y: disk counters    : PASS'
    Write-Host ''

    Remove-Item $RunningFlag,$CompleteFlag,$FailedFlag -Force -ErrorAction SilentlyContinue

    $logicalCPUs = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

    $measureStart = [DateTimeOffset]::UtcNow

    Set-Content $RunningFlag -Value (
        "RUN=$Run`r`nSTARTING_UTC=$($measureStart.ToString('o'))"
    ) -Encoding ASCII

    Write-Host '=== STARTING FI ==='

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
    $prevCPU = Get-NativeCPU
    $prevTime = [DateTimeOffset]::UtcNow

    $fiStartCPU = $prevFI.CPUSeconds
    $usnStartCPU = $prevUSN.CPUSeconds

    $peakHostCPU = 0.0
    $peakCombinedFIHost = 0.0
    $peakCombinedFIWS = ($prevFI.WSBytes + $prevUSN.WSBytes) / 1MB
    $peakCombinedFIPrivate = ($prevFI.Private + $prevUSN.Private) / 1MB
    $minAvailableMiB = [double]::MaxValue
    $peakMemoryLoadPct = 0.0

    $peakYReadMiBs = 0.0
    $peakYWriteMiBs = 0.0
    $peakYReadMs = 0.0
    $peakYWriteMs = 0.0
    $peakYQueue = 0.0

    $sampleNumber = 0L
    $result = $null

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $writer = New-Object System.IO.StreamWriter($SamplesPath,$false,$utf8)

    $writer.WriteLine(
        'UTC,ElapsedSec,YFreeGiB,HostCPU_Pct,HostMemoryLoadPct,HostAvailableMiB,' +
        'YRead_MiBs,YWrite_MiBs,YRead_ms,YWrite_ms,YQueue,' +
        'FI_CPU_HostPct,USN_CPU_HostPct,CombinedFI_CPU_HostPct,' +
        'FI_WS_MiB,USN_WS_MiB,CombinedFI_WS_MiB,' +
        'FI_Private_MiB,USN_Private_MiB,CombinedFI_Private_MiB'
    )

    try {
        while (-not $result) {
            $disk = Get-YDiskSample
            $now = [DateTimeOffset]::UtcNow
            $wall = ($now - $prevTime).TotalSeconds

            if ($fiProc.HasExited -or $usnProc.HasExited) {
                throw 'An FI process exited during onboarding.'
            }

            $fi = Get-ProcSnap $fiProc
            $usn = Get-ProcSnap $usnProc
            $cpu = Get-NativeCPU
            $mem = Get-NativeMemory

            $idleDelta = [double]($cpu.Idle - $prevCPU.Idle)
            $kernelDelta = [double]($cpu.Kernel - $prevCPU.Kernel)
            $userDelta = [double]($cpu.User - $prevCPU.User)
            $totalDelta = $kernelDelta + $userDelta

            $hostCPUPct = 0.0

            if ($totalDelta -gt 0) {
                $hostCPUPct = (1.0 - ($idleDelta / $totalDelta)) * 100.0
            }

            if ($hostCPUPct -lt 0) { $hostCPUPct = 0.0 }
            if ($hostCPUPct -gt 100) { $hostCPUPct = 100.0 }

            $fiRaw = (($fi.CPUSeconds - $prevFI.CPUSeconds) / $wall) * 100.0
            $usnRaw = (($usn.CPUSeconds - $prevUSN.CPUSeconds) / $wall) * 100.0

            $fiHostPct = $fiRaw / $logicalCPUs
            $usnHostPct = $usnRaw / $logicalCPUs
            $combinedFIHostPct = $fiHostPct + $usnHostPct

            $fiWS = $fi.WSBytes / 1MB
            $usnWS = $usn.WSBytes / 1MB
            $combinedFIWS = $fiWS + $usnWS

            $fiPrivate = $fi.Private / 1MB
            $usnPrivate = $usn.Private / 1MB
            $combinedFIPrivate = $fiPrivate + $usnPrivate

            $availableMiB = [double]$mem.AvailablePhys / 1MB
            $memoryLoadPct = [double]$mem.LoadPct

            $drive = New-Object System.IO.DriveInfo('Y')
            $yFreeGiB = [double]$drive.AvailableFreeSpace / 1GB

            $yReadMiBs = $disk.ReadBytesSec / 1MB
            $yWriteMiBs = $disk.WriteBytesSec / 1MB

            $peakHostCPU = [Math]::Max($peakHostCPU,$hostCPUPct)
            $peakCombinedFIHost = [Math]::Max($peakCombinedFIHost,$combinedFIHostPct)
            $peakCombinedFIWS = [Math]::Max($peakCombinedFIWS,$combinedFIWS)
            $peakCombinedFIPrivate = [Math]::Max($peakCombinedFIPrivate,$combinedFIPrivate)
            $minAvailableMiB = [Math]::Min($minAvailableMiB,$availableMiB)
            $peakMemoryLoadPct = [Math]::Max($peakMemoryLoadPct,$memoryLoadPct)

            $peakYReadMiBs = [Math]::Max($peakYReadMiBs,$yReadMiBs)
            $peakYWriteMiBs = [Math]::Max($peakYWriteMiBs,$yWriteMiBs)
            $peakYReadMs = [Math]::Max($peakYReadMs,$disk.ReadMs)
            $peakYWriteMs = [Math]::Max($peakYWriteMs,$disk.WriteMs)
            $peakYQueue = [Math]::Max($peakYQueue,$disk.Queue)

            $elapsed = ($now - $measureStart).TotalSeconds

            $writer.WriteLine([string]::Join(',',@(
                $now.ToString('o'),
                (Inv $elapsed 'F3'),
                (Inv $yFreeGiB 'F3'),
                (Inv $hostCPUPct 'F2'),
                (Inv $memoryLoadPct 'F2'),
                (Inv $availableMiB 'F2'),
                (Inv $yReadMiBs 'F3'),
                (Inv $yWriteMiBs 'F3'),
                (Inv $disk.ReadMs 'F3'),
                (Inv $disk.WriteMs 'F3'),
                (Inv $disk.Queue 'F3'),
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
                    '[{0:hh\:mm\:ss}] HOST={1,6:N2}% FI={2,6:N2}% AVAIL={3,7:N0}MiB | ' +
                    'Y R/W={4,7:N1}/{5,7:N1}MiB/s LAT={6,7:N1}/{7,7:N1}ms Q={8,6:N1} | FI RAM={9,7:N1}MiB' -f
                    ([TimeSpan]::FromSeconds($elapsed)),
                    $hostCPUPct,
                    $combinedFIHostPct,
                    $availableMiB,
                    $yReadMiBs,
                    $yWriteMiBs,
                    $disk.ReadMs,
                    $disk.WriteMs,
                    $disk.Queue,
                    $combinedFIWS
                )

                $collections = @(Get-ConfiguredCollections)

                if ($collections.Count -gt 0) {
                    $result = $collections[0]
                }
            }

            $sampleNumber++
            $prevFI = $fi
            $prevUSN = $usn
            $prevCPU = $cpu
            $prevTime = $now
        }
    }
    finally {
        $writer.Flush()
        $writer.Dispose()
    }

    $measureEnd = [DateTimeOffset]::UtcNow
    $resultTime = [DateTimeOffset]::Parse([string]$result.observed_at)

    $finalFI = Get-ProcSnap $fiProc
    $finalUSN = Get-ProcSnap $usnProc

    $fiCPUUsed = $finalFI.CPUSeconds - $fiStartCPU
    $usnCPUUsed = $finalUSN.CPUSeconds - $usnStartCPU
    $combinedCPUUsed = $fiCPUUsed + $usnCPUUsed

    $operations = Get-OperationRows

    $operations |
        Export-Csv $OperationsPath -NoTypeInformation

    $spool = Get-SpoolSummary

    $services = Get-Service FICollector,FIUSNReader
    $servicesRunning = -not ($services | Where-Object Status -ne 'Running')

    $pass =
        $result.outcome -eq 'Complete' -and
        $servicesRunning

    $summary = [ordered]@{
        run                          = $Run
        fi_sha256                    = $hash

        dataset_files                = $count
        dataset_bytes                = $bytes
        dataset_gib                  = [Math]::Round($bytes / 1GB,3)

        measurement_started_utc      = $measureStart.ToString('o')
        collection_finished_utc      = $resultTime.ToString('o')
        collection_elapsed_sec       = [Math]::Round(($resultTime - $measureStart).TotalSeconds,3)
        collection_outcome           = $result.outcome

        peak_host_cpu_pct            = [Math]::Round($peakHostCPU,2)
        fi_cpu_consumed_sec          = [Math]::Round($fiCPUUsed,3)
        usn_cpu_consumed_sec         = [Math]::Round($usnCPUUsed,3)
        combined_fi_cpu_sec          = [Math]::Round($combinedCPUUsed,3)
        peak_combined_fi_cpu_pct     = [Math]::Round($peakCombinedFIHost,2)

        peak_combined_fi_ws_mib      = [Math]::Round($peakCombinedFIWS,2)
        peak_combined_fi_private_mib = [Math]::Round($peakCombinedFIPrivate,2)

        peak_host_memory_load_pct    = [Math]::Round($peakMemoryLoadPct,2)
        min_host_available_mib       = [Math]::Round($minAvailableMiB,2)

        peak_y_read_mib_s            = [Math]::Round($peakYReadMiBs,3)
        peak_y_write_mib_s           = [Math]::Round($peakYWriteMiBs,3)
        peak_y_read_latency_ms       = [Math]::Round($peakYReadMs,3)
        peak_y_write_latency_ms      = [Math]::Round($peakYWriteMs,3)
        peak_y_queue_length          = [Math]::Round($peakYQueue,3)

        spool_files                  = $spool.Files
        spool_bytes                  = $spool.Bytes
        spool_manifests              = $spool.Manifests
        spool_manifest_record_count  = $spool.Records
        spool_manifest_data_bytes    = $spool.ManifestDataBytes

        fi_collector_status          = ($services | Where-Object Name -eq 'FICollector').Status.ToString()
        fi_usn_reader_status         = ($services | Where-Object Name -eq 'FIUSNReader').Status.ToString()

        pass                         = $pass
    }

    $summary |
        ConvertTo-Json -Depth 6 |
        Set-Content $SummaryPath -Encoding UTF8

    if (Test-Path -LiteralPath $RecoveryReserve) {
        Remove-Item -LiteralPath $RecoveryReserve -Force -ErrorAction SilentlyContinue
    }

    Set-Content $CompleteFlag -Value (
        "RUN=$Run`r`nPASS=$pass`r`nOUTCOME=$($result.outcome)`r`nFINISHED_UTC=$($measureEnd.ToString('o'))"
    ) -Encoding ASCII

    Write-Host ''
    Write-Host '=== 100K RANDOM ONBOARDING RESULT ==='
    Write-Host "Outcome                    : $($result.outcome)"
    Write-Host ('Collection elapsed         : {0:N3} sec' -f (($resultTime - $measureStart).TotalSeconds))
    Write-Host ''
    Write-Host ('Peak host CPU              : {0:N2} %' -f $peakHostCPU)
    Write-Host ('Peak combined FI CPU       : {0:N2} % of host' -f $peakCombinedFIHost)
    Write-Host ('Combined FI CPU consumed   : {0:N3} sec' -f $combinedCPUUsed)
    Write-Host ''
    Write-Host ('Peak combined FI RAM       : {0:N2} MiB' -f $peakCombinedFIWS)
    Write-Host ('Min host available RAM     : {0:N2} MiB' -f $minAvailableMiB)
    Write-Host ('Peak host memory load      : {0:N2} %' -f $peakMemoryLoadPct)
    Write-Host ''
    Write-Host ('Peak Y: read               : {0:N3} MiB/s' -f $peakYReadMiBs)
    Write-Host ('Peak Y: write              : {0:N3} MiB/s' -f $peakYWriteMiBs)
    Write-Host ('Peak Y: read latency       : {0:N3} ms' -f $peakYReadMs)
    Write-Host ('Peak Y: write latency      : {0:N3} ms' -f $peakYWriteMs)
    Write-Host ('Peak Y: queue              : {0:N3}' -f $peakYQueue)
    Write-Host ''
    Write-Host ('Spool files                : {0:N0}' -f $spool.Files)
    Write-Host ('Spool bytes                : {0:N0}' -f $spool.Bytes)
    Write-Host ('Manifest record count      : {0:N0}' -f $spool.Records)
    Write-Host ''
    Write-Host '=== OPERATION TIMINGS ==='

    $operations |
        Format-Table Kind,DurationSec,Outcome,Reason -Auto

    Write-Host ''

    if ($pass) {
        Write-Host '100K RANDOM ONBOARDING RESUME: PASS'
    }
    else {
        Write-Host '100K RANDOM ONBOARDING RESUME: FINDING/FAIL'
    }

    Write-Host "Results: $ResultRoot"
    Write-Host ''
    $services | Format-Table Name,Status -Auto
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
    Write-Host '100K RANDOM ONBOARDING RESUME ABORTED:'
    Write-Host $message
    Write-Host "Results: $ResultRoot"
    throw
}
finally {
    if ($transcriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
    }
}
