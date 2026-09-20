# FI Phase 2 - independent live resource viewer
# RUN ON: ISS-FS-01 - Administrator PowerShell
#
# This does not read the campaign report and does not write a report.
# It independently samples the live host every five seconds until Ctrl-C.
#
# Displays:
#   host CPU / available RAM / memory load
#   FICollector / FIUSNReader / fi-sender CPU + working set
#   Y: logical read/write throughput, latency, queue
#   aggregate active-interface RX/TX throughput and approximate link utilization
#   receiver TCP connection count
#
# Host network counters include all host traffic and are not claimed as FI-only.

[CmdletBinding()]
param(
    [int]$IntervalSeconds = 5,
    [string]$ReceiverAddress = '192.168.1.119',
    [int]$ReceiverPort = 8443
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if ($env:COMPUTERNAME -ne 'ISS-FS-01') {
    throw "Wrong host: $env:COMPUTERNAME"
}

if (-not (Test-Path 'Y:\')) {
    throw 'Y: does not exist.'
}

if (-not ('FILiveNativeMetrics' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class FILiveNativeMetrics
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

function Get-CPU {
    $idle = New-Object FILiveNativeMetrics+FILETIME
    $kernel = New-Object FILiveNativeMetrics+FILETIME
    $user = New-Object FILiveNativeMetrics+FILETIME

    if (-not [FILiveNativeMetrics]::GetSystemTimes([ref]$idle,[ref]$kernel,[ref]$user)) {
        throw 'GetSystemTimes failed.'
    }

    [PSCustomObject]@{
        Idle = [FILiveNativeMetrics]::ToInt64($idle)
        Kernel = [FILiveNativeMetrics]::ToInt64($kernel)
        User = [FILiveNativeMetrics]::ToInt64($user)
    }
}

function Get-Memory {
    $m = New-Object FILiveNativeMetrics+MEMORYSTATUSEX
    $m.dwLength = [Runtime.InteropServices.Marshal]::SizeOf($m)

    if (-not [FILiveNativeMetrics]::GlobalMemoryStatusEx([ref]$m)) {
        throw 'GlobalMemoryStatusEx failed.'
    }

    [PSCustomObject]@{
        LoadPct = [double]$m.dwMemoryLoad
        AvailableMiB = [double]$m.ullAvailPhys / 1MB
    }
}

function Get-Network {
    [UInt64]$rx = 0
    [UInt64]$tx = 0
    [UInt64]$speed = 0

    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if (
            $nic.NetworkInterfaceType -eq [Net.NetworkInformation.NetworkInterfaceType]::Loopback -or
            $nic.OperationalStatus -ne [Net.NetworkInformation.OperationalStatus]::Up
        ) {
            continue
        }

        try {
            $s = $nic.GetIPv4Statistics()
            $rx += [UInt64]$s.BytesReceived
            $tx += [UInt64]$s.BytesSent

            if ($nic.Speed -gt 0) {
                $speed += [UInt64]$nic.Speed
            }
        }
        catch {
        }
    }

    [PSCustomObject]@{
        Rx = $rx
        Tx = $tx
        Speed = $speed
    }
}

function Get-Disk {
    $set = Get-Counter -Counter @(
        '\LogicalDisk(Y:)\Disk Read Bytes/sec',
        '\LogicalDisk(Y:)\Disk Write Bytes/sec',
        '\LogicalDisk(Y:)\Avg. Disk sec/Read',
        '\LogicalDisk(Y:)\Avg. Disk sec/Write',
        '\LogicalDisk(Y:)\Current Disk Queue Length'
    ) -SampleInterval 1 -MaxSamples 1

    $v = @{}

    foreach ($c in $set.CounterSamples) {
        $p = [string]$c.Path

        if ($p -match '\\disk read bytes/sec$') {
            $v.R = [double]$c.CookedValue
        }
        elseif ($p -match '\\disk write bytes/sec$') {
            $v.W = [double]$c.CookedValue
        }
        elseif ($p -match '\\avg\. disk sec/read$') {
            $v.RL = [double]$c.CookedValue * 1000
        }
        elseif ($p -match '\\avg\. disk sec/write$') {
            $v.WL = [double]$c.CookedValue * 1000
        }
        elseif ($p -match '\\current disk queue length$') {
            $v.Q = [double]$c.CookedValue
        }
    }

    [PSCustomObject]@{
        ReadMiBs = $(if ($v.ContainsKey('R')) {$v.R / 1MB} else {0.0})
        WriteMiBs = $(if ($v.ContainsKey('W')) {$v.W / 1MB} else {0.0})
        ReadMs = $(if ($v.ContainsKey('RL')) {$v.RL} else {0.0})
        WriteMs = $(if ($v.ContainsKey('WL')) {$v.WL} else {0.0})
        Queue = $(if ($v.ContainsKey('Q')) {$v.Q} else {0.0})
    }
}

function Get-P {
    param([string]$Name)

    $p = Get-Process -Name $Name -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $p) {
        return $null
    }

    $p.Refresh()

    [PSCustomObject]@{
        Id = $p.Id
        CPU = [double]$p.TotalProcessorTime.TotalSeconds
        WS = [double]$p.WorkingSet64 / 1MB
    }
}

function CpuPct($Now,$Prev,$Wall,$Logical) {
    if (-not $Now -or -not $Prev -or $Now.Id -ne $Prev.Id -or $Wall -le 0) {
        return 0.0
    }

    return ((($Now.CPU - $Prev.CPU) / $Wall) * 100.0) / $Logical
}

$logical = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
$prevCPU = Get-CPU
$prevNet = Get-Network
$prevFI = Get-P 'fi'
$prevUSN = Get-P 'fi-usn'
$prevSender = Get-P 'fi-sender'
$prevTime = [DateTimeOffset]::UtcNow

Write-Host 'FI LIVE 5-SECOND RESOURCE VIEWER - Ctrl-C to stop'
Write-Host 'Network is host-level aggregate traffic, not FI-only attribution.'
Write-Host ''

while ($true) {
    if ($IntervalSeconds -gt 1) {
        Start-Sleep -Seconds ($IntervalSeconds - 1)
    }

    $disk = Get-Disk
    $now = [DateTimeOffset]::UtcNow
    $wall = ($now - $prevTime).TotalSeconds

    $cpu = Get-CPU
    $mem = Get-Memory
    $net = Get-Network

    $idle = [double]($cpu.Idle - $prevCPU.Idle)
    $kernel = [double]($cpu.Kernel - $prevCPU.Kernel)
    $user = [double]($cpu.User - $prevCPU.User)
    $total = $kernel + $user

    $hostCPU = 0.0

    if ($total -gt 0) {
        $hostCPU = (1.0 - ($idle / $total)) * 100.0
    }

    if ($hostCPU -lt 0) {$hostCPU = 0}
    if ($hostCPU -gt 100) {$hostCPU = 100}

    $fi = Get-P 'fi'
    $usn = Get-P 'fi-usn'
    $sender = Get-P 'fi-sender'

    $fiCPU = CpuPct $fi $prevFI $wall $logical
    $usnCPU = CpuPct $usn $prevUSN $wall $logical
    $senderCPU = CpuPct $sender $prevSender $wall $logical

    $fiWS = $(if ($fi) {$fi.WS} else {0.0})
    $usnWS = $(if ($usn) {$usn.WS} else {0.0})
    $senderWS = $(if ($sender) {$sender.WS} else {0.0})

    $rx = 0.0
    $tx = 0.0

    if ($wall -gt 0 -and $net.Rx -ge $prevNet.Rx) {
        $rx = (($net.Rx - $prevNet.Rx) / 1MB) / $wall
    }

    if ($wall -gt 0 -and $net.Tx -ge $prevNet.Tx) {
        $tx = (($net.Tx - $prevNet.Tx) / 1MB) / $wall
    }

    $linkPct = 0.0

    if ($net.Speed -gt 0) {
        $linkPct = ((($rx + $tx) * 1MB * 8.0) / $net.Speed) * 100.0
    }

    $conn = 0

    try {
        $conn = @(
            Get-NetTCPConnection `
                -RemoteAddress $ReceiverAddress `
                -RemotePort $ReceiverPort `
                -State Established `
                -ErrorAction SilentlyContinue
        ).Count
    }
    catch {
    }

    $drive = New-Object IO.DriveInfo('Y')

    Write-Host (
        '{0:HH:mm:ss} | CPU host={1,5:N1}% fi={2,5:N1}% usn={3,4:N1}% snd={4,4:N1}% | ' +
        'RAM fi/usn/snd={5,5:N1}/{6,5:N1}/{7,5:N1}MiB avail={8,7:N0}MiB load={9,4:N0}% | ' +
        'Y R/W={10,6:N1}/{11,6:N1}MiB/s lat={12,6:N1}/{13,6:N1}ms Q={14,5:N1} free={15,7:N1}GiB | ' +
        'NET rx/tx={16,6:N2}/{17,6:N2}MiB/s link~{18,5:N2}% recvTCP={19}' -f
        $now.LocalDateTime,
        $hostCPU,
        $fiCPU,
        $usnCPU,
        $senderCPU,
        $fiWS,
        $usnWS,
        $senderWS,
        $mem.AvailableMiB,
        $mem.LoadPct,
        $disk.ReadMiBs,
        $disk.WriteMiBs,
        $disk.ReadMs,
        $disk.WriteMs,
        $disk.Queue,
        ($drive.AvailableFreeSpace / 1GB),
        $rx,
        $tx,
        $linkPct,
        $conn
    )

    $prevCPU = $cpu
    $prevNet = $net
    $prevFI = $fi
    $prevUSN = $usn
    $prevSender = $sender
    $prevTime = $now
}
