# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

param()

$CollectorService = "FICollector"
$HelperService = "FIUSNReader"

$ProbeExe = "C:\FI-Test\fi-collector-boundary-probe.exe"
$ResultFile = "C:\ProgramData\FI\state\collector-token-boundary-probe.json"
$RuntimePath = "C:\ProgramData\FI\state\service-runtime.jsonl"

$ProgramProbe = "C:\Program Files\FI\fi-collector-boundary-probe.tmp"
$StateProbe = "C:\ProgramData\FI\state\fi-collector-boundary-probe.tmp"
$SpoolProbe = "C:\ProgramData\FI\spool\fi-collector-boundary-probe.tmp"

$ExpectedCollectorBinPath = '"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m'

function Get-FILatestConfiguredCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $null
    }

    $Lines = Get-Content -LiteralPath $Path

    for ($Index = $Lines.Count - 1; $Index -ge 0; $Index--) {
        try {
            $Record = $Lines[$Index] | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            continue
        }

        if ($Record.record_kind -eq "ConfiguredCollection") {
            return $Record
        }
    }

    return $null
}

function Set-FIServicePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$PathName
    )

    $Service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop

    $Result = Invoke-CimMethod `
        -InputObject $Service `
        -MethodName Change `
        -Arguments @{
            PathName = $PathName
        }

    if ($Result.ReturnValue -ne 0) {
        throw "$Name PathName change failed. ReturnValue=$($Result.ReturnValue)"
    }
}

function Wait-FIFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$TimeoutSeconds = 30
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            return $true
        }

        Start-Sleep -Milliseconds 250
    }
    while ((Get-Date) -lt $Deadline)

    return $false
}

function Wait-FIFreshConfiguredCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$BeforeObservedAt = "",

        [int]$TimeoutSeconds = 120
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        $Current = Get-FILatestConfiguredCollection -Path $Path

        if (
            $Current -and
            [string]$Current.observed_at -ne $BeforeObservedAt
        ) {
            return $Current
        }

        Start-Sleep -Milliseconds 500
    }
    while ((Get-Date) -lt $Deadline)

    return $null
}

function Wait-FIPipe {
    param(
        [int]$TimeoutSeconds = 120
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        $Helper = Get-Service -Name $HelperService -ErrorAction Stop

        if ($Helper.Status -ne "Running") {
            throw "$HelperService stopped while waiting for the FI-USN pipe."
        }

        if (Test-Path '\\.\pipe\FI-USN') {
            return
        }

        Start-Sleep -Milliseconds 500
    }
    while ((Get-Date) -lt $Deadline)

    throw "FI-USN pipe was not observed within $TimeoutSeconds seconds."
}

function Wait-FIServiceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$State,

        [int]$TimeoutSeconds = 30
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        $Current = (Get-Service -Name $Name -ErrorAction Stop).Status.ToString()

        if ($Current -eq $State) {
            return
        }

        Start-Sleep -Milliseconds 250
    }
    while ((Get-Date) -lt $Deadline)

    throw "$Name did not reach $State within $TimeoutSeconds seconds."
}

if (-not (Test-Path -LiteralPath $ProbeExe -PathType Leaf)) {
    throw "Probe executable not found: $ProbeExe"
}

$CollectorConfig = Get-CimInstance Win32_Service -Filter "Name='$CollectorService'" -ErrorAction Stop
$OriginalCollectorBinPath = $CollectorConfig.PathName

if ($OriginalCollectorBinPath -ne $ExpectedCollectorBinPath) {
    Write-Host ""
    Write-Host "Expected:"
    Write-Host "  $ExpectedCollectorBinPath"
    Write-Host ""
    Write-Host "Observed:"
    Write-Host "  $OriginalCollectorBinPath"
    throw "FICollector binary path does not match the validated production value. No changes made."
}

$CollectorWasRunning = ((Get-Service -Name $CollectorService).Status -eq "Running")
$HelperWasRunning = ((Get-Service -Name $HelperService).Status -eq "Running")

if (-not $CollectorWasRunning -or -not $HelperWasRunning) {
    throw "FICollector and FIUSNReader must both be running before Test 08."
}

$BeforeRuntime = Get-FILatestConfiguredCollection -Path $RuntimePath
$BeforeRuntimeObserved = ""

if ($BeforeRuntime) {
    $BeforeRuntimeObserved = [string]$BeforeRuntime.observed_at
}

$ProbePassed = $false
$ProbeResult = $null

Write-Host ""
Write-Host "FI USN Verification - Test 08: Exact FICollector Service-Token Boundary"
Write-Host "Run on the FILE SERVER in elevated Windows PowerShell."
Write-Host ""
Write-Host "[INFO] Production FICollector PathName: $OriginalCollectorBinPath"

foreach ($Path in @($ResultFile, $ProgramProbe, $StateProbe, $SpoolProbe)) {
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

try {
    Write-Host ""
    Write-Host "=== STOP PRODUCTION SERVICES ==="

    Write-Host "[INFO] Stopping FICollector."
    Stop-Service -Name $CollectorService -ErrorAction Stop
    Wait-FIServiceState -Name $CollectorService -State "Stopped"
    Write-Host "[PASS] FICollector stopped."

    Write-Host "[INFO] Stopping FIUSNReader so executable access is tested without a sharing lock."
    Stop-Service -Name $HelperService -ErrorAction Stop
    Wait-FIServiceState -Name $HelperService -State "Stopped"
    Write-Host "[PASS] FIUSNReader stopped."

    Write-Host ""
    Write-Host "=== RUN COLLECTOR-TOKEN PROBE ==="

    Write-Host "[INFO] Temporarily pointing FICollector at the lab-only probe."
    Set-FIServicePath -Name $CollectorService -PathName $ProbeExe

    Write-Host "[INFO] Starting FICollector with the lab-only probe binary."
    $StartOutput = & sc.exe start $CollectorService 2>&1
    $StartExitCode = $LASTEXITCODE
    $StartOutput | ForEach-Object { Write-Host $_ }
    Write-Host "[INFO] sc.exe start exit code: $StartExitCode"

    if (-not (Wait-FIFile -Path $ResultFile -TimeoutSeconds 30)) {
        Write-Host ""
        sc.exe query $CollectorService
        throw "Probe result file was not created within 30 seconds."
    }

    Write-Host ""
    Write-Host "=== PROBE RESULT ==="

    $ProbeResult = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json

    Write-Host "[INFO] Version: $($ProbeResult.version)"
    Write-Host "[INFO] Observed at: $($ProbeResult.observed_at)"
    Write-Host "[INFO] Service name: $($ProbeResult.service_name)"
    Write-Host ""

    foreach ($Check in $ProbeResult.checks) {
        $Suffix = ""

        if ($Check.error_code) {
            $Suffix = " -- error $($Check.error_code): $($Check.error)"
        }
        elseif ($Check.error) {
            $Suffix = " -- $($Check.error)"
        }

        Write-Host "[$($Check.result)] $($Check.name)$Suffix"
    }

    Write-Host ""
    Write-Host "Overall: $($ProbeResult.overall)"
    Write-Host "Failure count: $($ProbeResult.failure_count)"

    if (
        $ProbeResult.overall -ne "PASS" -or
        [int]$ProbeResult.failure_count -ne 0
    ) {
        throw "FICollector exact service-token boundary probe reported failure."
    }

    $ProbePassed = $true
    Write-Host "[PASS] FICollector exact service-token boundary probe passed."
}
finally {
    Write-Host ""
    Write-Host "=== RESTORE PRODUCTION SERVICES ==="

    Stop-Service -Name $CollectorService -ErrorAction SilentlyContinue

    $CollectorStoppedDeadline = (Get-Date).AddSeconds(30)
    do {
        if ((Get-Service -Name $CollectorService).Status -eq "Stopped") {
            break
        }

        Start-Sleep -Milliseconds 250
    }
    while ((Get-Date) -lt $CollectorStoppedDeadline)

    Write-Host "[INFO] Restoring exact original FICollector PathName."
    Set-FIServicePath -Name $CollectorService -PathName $OriginalCollectorBinPath

    Write-Host "[INFO] Starting FIUSNReader."
    Start-Service -Name $HelperService -ErrorAction Stop
    Wait-FIServiceState -Name $HelperService -State "Running" -TimeoutSeconds 30
    Wait-FIPipe -TimeoutSeconds 120
    Write-Host "[PASS] FIUSNReader is running and the FI-USN pipe is present."

    Write-Host "[INFO] Starting production FICollector."
    Start-Service -Name $CollectorService -ErrorAction Stop
    Wait-FIServiceState -Name $CollectorService -State "Running" -TimeoutSeconds 30
    Write-Host "[PASS] Production FICollector is running."

    foreach ($Path in @($ProgramProbe, $StateProbe, $SpoolProbe)) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "=== RESTORED SERVICE CONFIG ==="
    sc.exe qc $CollectorService
    sc.exe qsidtype $CollectorService
    sc.exe qmanagedaccount $CollectorService

    Write-Host ""
    Get-Service -Name $CollectorService, $HelperService |
        Format-Table Name,Status -AutoSize
}

if (-not $ProbePassed) {
    Write-Host "[FAIL] TEST 08 FAILED."
    exit 1
}

Write-Host ""
Write-Host "=== WAIT FOR FRESH NORMAL COLLECTION ==="

$AfterRuntime = Wait-FIFreshConfiguredCollection `
    -Path $RuntimePath `
    -BeforeObservedAt $BeforeRuntimeObserved `
    -TimeoutSeconds 120

if (-not $AfterRuntime) {
    Write-Host "[FAIL] No fresh ConfiguredCollection was observed after production restore."
    exit 1
}

$AfterRuntime |
    ConvertTo-Json -Depth 8 |
    Write-Host

if ($AfterRuntime.outcome -ne "Complete") {
    Write-Host "[FAIL] Restored FICollector did not complete a normal collection."
    exit 1
}

Write-Host "[PASS] Restored production FICollector completed a fresh normal collection."
Write-Host "[PASS] TEST 08 PASSED."
exit 0
