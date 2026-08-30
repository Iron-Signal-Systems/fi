param()

$CollectorService = "FICollector"
$HelperService = "FIUSNReader"

$ProbeExe = "C:\FI-Test\fi-collector-boundary-probe.exe"
$ResultFile = "C:\ProgramData\FI\state\collector-token-boundary-probe.json"

$ProgramProbe = "C:\Program Files\FI\fi-collector-boundary-probe.tmp"
$StateProbe = "C:\ProgramData\FI\state\fi-collector-boundary-probe.tmp"
$SpoolProbe = "C:\ProgramData\FI\spool\fi-collector-boundary-probe.tmp"

$ExpectedCollectorBinPath = '"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m'

function Wait-FIServiceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$State,

        [int]$TimeoutSeconds = 20
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
    throw "FICollector binary path does not match the validated Server 2022 preflight value. No changes made."
}

Write-Host ""
Write-Host "FICollector exact service-token boundary probe - Windows Server 2022"
Write-Host "Host: $env:COMPUTERNAME"
Write-Host ""

foreach ($Path in @($ResultFile, $ProgramProbe, $StateProbe, $SpoolProbe)) {
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

$CollectorWasRunning = ((Get-Service -Name $CollectorService).Status -eq "Running")
$HelperWasRunning = ((Get-Service -Name $HelperService).Status -eq "Running")

try {
    if ($CollectorWasRunning) {
        Write-Host "[INFO] Stopping FICollector."
        Stop-Service -Name $CollectorService -ErrorAction Stop
        Wait-FIServiceState -Name $CollectorService -State "Stopped"
    }

    if ($HelperWasRunning) {
        Write-Host "[INFO] Stopping FIUSNReader so executable access is tested without a sharing lock."
        Stop-Service -Name $HelperService -ErrorAction Stop
        Wait-FIServiceState -Name $HelperService -State "Stopped"
    }

    Write-Host "[INFO] Temporarily pointing FICollector at the lab-only probe."
    Set-FIServicePath -Name $CollectorService -PathName $ProbeExe

    Write-Host "[INFO] Starting FICollector with the lab-only probe binary."
    Start-Service -Name $CollectorService -ErrorAction Stop

    Start-Sleep -Seconds 3

    if (-not (Test-Path -LiteralPath $ResultFile -PathType Leaf)) {
        Write-Host ""
        sc.exe query $CollectorService
        throw "Probe result file was not created."
    }

    Write-Host ""
    Write-Host "=== PROBE RESULT ==="
    $Result = Get-Content -LiteralPath $ResultFile -Raw | ConvertFrom-Json

    Write-Host "[INFO] Version: $($Result.version)"
    Write-Host "[INFO] Observed at: $($Result.observed_at)"
    Write-Host "[INFO] Service name: $($Result.service_name)"
    Write-Host ""

    foreach ($Check in $Result.checks) {
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
    Write-Host "Overall: $($Result.overall)"
    Write-Host "Failure count: $($Result.failure_count)"
}
finally {
    Write-Host ""
    Write-Host "=== RESTORE FICollector ==="

    Stop-Service -Name $CollectorService -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    Write-Host "[INFO] Restoring exact original FICollector PathName."
    Set-FIServicePath -Name $CollectorService -PathName $OriginalCollectorBinPath

    if ($HelperWasRunning) {
        Write-Host "[INFO] Restarting FIUSNReader."
        Start-Service -Name $HelperService -ErrorAction Stop
        Wait-FIServiceState -Name $HelperService -State "Running"
    }

    if ($CollectorWasRunning) {
        Write-Host "[INFO] Restarting FICollector."
        Start-Service -Name $CollectorService -ErrorAction Stop
        Wait-FIServiceState -Name $CollectorService -State "Running"
    }

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
        Format-Table Name, Status -AutoSize
}
