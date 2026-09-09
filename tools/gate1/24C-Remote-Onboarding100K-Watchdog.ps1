# FI Gate 1 - remote availability watchdog for 100K random Y: onboarding.
# Run on AdminBox before the server-side script.
# Read-only against Y: so an intentionally full Y: does not make the watchdog
# itself consume space.

$ErrorActionPreference = 'Stop'

$Server = 'ISS-FS-01'
$RunningFlag  = '\\ISS-FS-01\C$\FI-Test\onboarding100k-y-running.flag'
$CompleteFlag = '\\ISS-FS-01\C$\FI-Test\onboarding100k-y-complete.flag'
$Sentinel     = '\\ISS-FS-01\Y$\FI-Gate1\watchdog-sentinel.bin'

$Run = 'watchdog-100k-y-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
$ResultRoot = "C:\FI-Test\client-results\onboarding100k-random\$Run"
$CsvPath = Join-Path $ResultRoot 'watchdog.csv'
$SummaryPath = Join-Path $ResultRoot 'summary.json'

New-Item -ItemType Directory -Path $ResultRoot -Force | Out-Null

function Get-P95 {
    param([System.Collections.Generic.List[double]]$Values)

    if ($Values.Count -eq 0) {
        return 0.0
    }

    $arr = @($Values.ToArray() | Sort-Object)
    $idx = [Math]::Ceiling($arr.Count * 0.95) - 1

    if ($idx -lt 0) { $idx = 0 }
    if ($idx -ge $arr.Count) { $idx = $arr.Count - 1 }

    return [double]$arr[$idx]
}

Write-Host '=== FI 100K RANDOM Y: REMOTE WATCHDOG ==='
Write-Host "Server : $Server"
Write-Host "Results: $ResultRoot"
Write-Host ''
Write-Host 'Waiting for FI onboarding start flag...'

while (-not (Test-Path -LiteralPath $RunningFlag)) {
    Start-Sleep -Seconds 5
}

Write-Host 'FI onboarding started.'
Write-Host ''

$utf8 = New-Object System.Text.UTF8Encoding($false)
$writer = New-Object System.IO.StreamWriter($CsvPath,$false,$utf8)
$writer.WriteLine('UTC,PingOK,PingMs,SMBReadOK,SMBReadMs,WinRMChecked,WinRMOK,WinRMMs')

$pingValues = New-Object 'System.Collections.Generic.List[double]'
$smbValues = New-Object 'System.Collections.Generic.List[double]'
$winrmValues = New-Object 'System.Collections.Generic.List[double]'

$pingFailures = 0
$smbFailures = 0
$winrmFailures = 0
$smbOver1s = 0
$winrmOver5s = 0
$samples = 0
$start = [DateTimeOffset]::UtcNow

try {
    while ($true) {
        $now = [DateTimeOffset]::UtcNow

        $pingOK = $false
        $pingMs = -1.0

        try {
            $p = Test-Connection -ComputerName $Server -Count 1 -ErrorAction Stop |
                Select-Object -First 1

            $pingOK = $true
            $pingMs = [double]$p.ResponseTime
            [void]$pingValues.Add($pingMs)
        }
        catch {
            $pingFailures++
        }

        $smbOK = $false
        $smbMs = -1.0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $stream = [System.IO.File]::Open(
                $Sentinel,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite
            )

            try {
                [void]$stream.ReadByte()
            }
            finally {
                $stream.Dispose()
            }

            $smbOK = $true
        }
        catch {
        }
        finally {
            $sw.Stop()
            $smbMs = $sw.Elapsed.TotalMilliseconds
        }

        if ($smbOK) {
            [void]$smbValues.Add($smbMs)

            if ($smbMs -ge 1000.0) {
                $smbOver1s++
            }
        }
        else {
            $smbFailures++
        }

        $winrmChecked = (($samples % 6) -eq 0)
        $winrmOK = $false
        $winrmMs = -1.0

        if ($winrmChecked) {
            $ww = [System.Diagnostics.Stopwatch]::StartNew()

            try {
                Test-WSMan -ComputerName $Server -ErrorAction Stop | Out-Null
                $winrmOK = $true
            }
            catch {
            }
            finally {
                $ww.Stop()
                $winrmMs = $ww.Elapsed.TotalMilliseconds
            }

            if ($winrmOK) {
                [void]$winrmValues.Add($winrmMs)

                if ($winrmMs -ge 5000.0) {
                    $winrmOver5s++
                }
            }
            else {
                $winrmFailures++
            }
        }

        $writer.WriteLine([string]::Join(',',@(
            $now.ToString('o'),
            $pingOK,
            $pingMs.ToString('F3',[System.Globalization.CultureInfo]::InvariantCulture),
            $smbOK,
            $smbMs.ToString('F3',[System.Globalization.CultureInfo]::InvariantCulture),
            $winrmChecked,
            $winrmOK,
            $winrmMs.ToString('F3',[System.Globalization.CultureInfo]::InvariantCulture)
        )))
        $writer.Flush()

        Write-Host (
            '[{0:hh\:mm\:ss}] Ping={1} {2,7:N1}ms | Y: SMB={3} {4,8:N1}ms | WinRM={5} {6,8:N1}ms' -f
            ([TimeSpan]::FromSeconds(($now - $start).TotalSeconds)),
            $pingOK,
            $pingMs,
            $smbOK,
            $smbMs,
            $(if ($winrmChecked) { $winrmOK } else { 'skip' }),
            $winrmMs
        )

        $samples++

        if ($pingOK -and (Test-Path -LiteralPath $CompleteFlag)) {
            break
        }

        Start-Sleep -Seconds 10
    }
}
finally {
    $writer.Flush()
    $writer.Dispose()
}

$end = [DateTimeOffset]::UtcNow

$summary = [ordered]@{
    run                 = $Run
    server              = $Server
    started_utc         = $start.ToString('o')
    finished_utc        = $end.ToString('o')
    elapsed_sec         = [Math]::Round(($end - $start).TotalSeconds,3)
    samples             = $samples

    ping_failures       = $pingFailures
    ping_p95_ms         = [Math]::Round((Get-P95 $pingValues),3)
    ping_max_ms         = $(if ($pingValues.Count) { [Math]::Round(($pingValues | Measure-Object -Maximum).Maximum,3) } else { 0 })

    smb_failures        = $smbFailures
    smb_over_1s         = $smbOver1s
    smb_p95_ms          = [Math]::Round((Get-P95 $smbValues),3)
    smb_max_ms          = $(if ($smbValues.Count) { [Math]::Round(($smbValues | Measure-Object -Maximum).Maximum,3) } else { 0 })

    winrm_failures      = $winrmFailures
    winrm_over_5s       = $winrmOver5s
    winrm_p95_ms        = [Math]::Round((Get-P95 $winrmValues),3)
    winrm_max_ms        = $(if ($winrmValues.Count) { [Math]::Round(($winrmValues | Measure-Object -Maximum).Maximum,3) } else { 0 })

    availability_pass =
        ($pingFailures -eq 0 -and $smbFailures -eq 0 -and $winrmFailures -eq 0)
}

$summary |
    ConvertTo-Json -Depth 4 |
    Set-Content $SummaryPath -Encoding UTF8

Write-Host ''
Write-Host '=== REMOTE WATCHDOG RESULT ==='
Write-Host "Ping failures : $pingFailures"
Write-Host ('Ping p95/max  : {0:N3} / {1:N3} ms' -f $summary.ping_p95_ms,$summary.ping_max_ms)
Write-Host "Y: SMB failures: $smbFailures"
Write-Host ('Y: SMB p95/max : {0:N3} / {1:N3} ms' -f $summary.smb_p95_ms,$summary.smb_max_ms)
Write-Host "Y: SMB >=1 sec : $smbOver1s"
Write-Host "WinRM failures : $winrmFailures"
Write-Host ('WinRM p95/max : {0:N3} / {1:N3} ms' -f $summary.winrm_p95_ms,$summary.winrm_max_ms)
Write-Host "WinRM >=5 sec  : $winrmOver5s"
Write-Host ''

if ($summary.availability_pass) {
    Write-Host 'REMOTE AVAILABILITY WATCHDOG: PASS'
}
else {
    Write-Host 'REMOTE AVAILABILITY WATCHDOG: FINDING/FAIL'
}

Write-Host "Results: $ResultRoot"
