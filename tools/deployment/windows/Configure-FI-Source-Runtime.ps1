# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectedComputerName,

    [Parameter(Mandatory = $true)]
    [string]$CollectorAccount,

    [Parameter(Mandatory = $true)]
    [string]$USNReaderAccount,

    [Parameter(Mandatory = $true)]
    [string]$ObjReaderAccount,

    [Parameter(Mandatory = $true)]
    [string]$SenderAccount,

    [switch]$ConfirmChange
)

$ErrorActionPreference = 'Stop'

$CollectorService = 'FICollector'
$USNReaderService = 'FIUSNReader'
$ObjReaderService = 'FIObjReader'
$SenderService = 'FISender'

$CollectorPath = '"C:\Program Files\FI\fi.exe" -service'
$USNReaderPath = '"C:\Program Files\FI\fi-usn.exe"'
$ObjReaderPath = '"C:\Program Files\FI\fi-obj.exe"'
$SenderPath = '"C:\Program Files\FI\fi-sender.exe"'

$LegacySenderTask = 'FI-GMSA-Sender-V2-Drain'

function Assert-FIAdministrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object `
        Security.Principal.WindowsPrincipal `
        $Identity

    if (-not $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw 'FI Windows runtime configuration requires an elevated administrator session.'
    }
}

function Assert-FITargetComputer {
    if ($env:COMPUTERNAME -ine $ExpectedComputerName) {
        throw (
            "FI source-runtime deployment target mismatch. Expected " +
            "$ExpectedComputerName; running on $env:COMPUTERNAME."
        )
    }

    Write-Host "[PASS] Deployment target confirmed: $env:COMPUTERNAME"
}
function Assert-FIFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required FI file is missing: $Path"
    }
}

function Invoke-FISC {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $Output = @(
        & sc.exe @Arguments 2>&1 |
            ForEach-Object {
                $_.ToString()
            }
    )

    $ExitCode = $LASTEXITCODE

    if ($ExitCode -ne 0) {
        throw (
            "sc.exe {0} failed with exit code {1}: {2}" -f
            ($Arguments -join ' '),
            $ExitCode,
            ($Output -join ' ')
        )
    }

    return $Output
}

function Assert-FISenderRuntimeOwnership {
    param(
        [switch]$RequireServiceOwner
    )

    $Service = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$SenderService'" `
        -ErrorAction SilentlyContinue

    $ServiceProcessID = [UInt32]0

    if (
        $null -ne $Service -and
        $Service.State -eq 'Running'
    ) {
        $ServiceProcessID = [UInt32]$Service.ProcessId

        if ($ServiceProcessID -eq 0) {
            throw 'FISender reports Running without a service process ID.'
        }
    }

    $Processes = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                $_.Name -ieq 'fi-sender.exe'
            }
    )

    $ServiceProcesses = @(
        $Processes |
            Where-Object {
                $ServiceProcessID -ne 0 -and
                [UInt32]$_.ProcessId -eq $ServiceProcessID
            }
    )

    $UnexpectedProcesses = @(
        $Processes |
            Where-Object {
                $ServiceProcessID -eq 0 -or
                [UInt32]$_.ProcessId -ne $ServiceProcessID
            }
    )

    if ($UnexpectedProcesses.Count -ne 0) {
        $UnexpectedIDs = (
            $UnexpectedProcesses |
                ForEach-Object {
                    [string]$_.ProcessId
                }
        ) -join ', '

        throw (
            'Unexpected fi-sender.exe runtime owner detected. ' +
            "Process ID(s): $UnexpectedIDs"
        )
    }

    if (
        $ServiceProcessID -ne 0 -and
        $ServiceProcesses.Count -ne 1
    ) {
        throw (
            'FISender service/process ownership is inconsistent. ' +
            "SCM PID=$ServiceProcessID; matching processes=" +
            "$($ServiceProcesses.Count)."
        )
    }

    if (
        $RequireServiceOwner -and
        (
            $null -eq $Service -or
            $Service.State -ne 'Running' -or
            $ServiceProcesses.Count -ne 1
        )
    ) {
        throw 'FISender does not own exactly one running fi-sender.exe process.'
    }
}
function Assert-FIExistingServiceIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$StartName
    )

    $Existing = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$Name'" `
        -ErrorAction SilentlyContinue

    if (
        $null -ne $Existing -and
        $Existing.StartName -ine $StartName
    ) {
        throw (
            "$Name identity mismatch. Expected $StartName; " +
            "observed $($Existing.StartName). " +
            'Service identity changes require separate explicit review.'
        )
    }
}

function Set-FIManagedService {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [string]$PathName,

        [Parameter(Mandatory = $true)]
        [string]$StartName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('none', 'unrestricted')]
        [string]$SIDType
    )

    $Existing = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$Name'" `
        -ErrorAction SilentlyContinue

    if ($null -eq $Existing) {
        Write-Host "[INFO] Creating $Name."

        Invoke-FISC -Arguments @(
            'create',
            $Name,
            'binPath=',
            $PathName,
            'start=',
            'auto',
            'obj=',
            $StartName,
            'DisplayName=',
            $DisplayName
        ) | Out-Host

        Invoke-FISC -Arguments @(
            'managedaccount',
            $Name,
            'true'
        ) | Out-Host

        Invoke-FISC -Arguments @(
            'sidtype',
            $Name,
            $SIDType
        ) | Out-Host

        return
    }

    if ($Existing.StartName -ine $StartName) {
        throw (
            "$Name identity mismatch. Expected $StartName; " +
            "observed $($Existing.StartName). " +
            'Service identity changes require separate explicit review.'
        )
    }

    $ManagedText = (
        Invoke-FISC -Arguments @(
            'qmanagedaccount',
            $Name
        )
    ) -join "`n"

    $SIDText = (
        Invoke-FISC -Arguments @(
            'qsidtype',
            $Name
        )
    ) -join "`n"

    $ManagedCorrect = (
        $ManagedText -match
        'ACCOUNT MANAGED\s*:\s*TRUE'
    )

    $SIDCorrect = (
        $SIDText -match (
            'SERVICE_SID_TYPE\s*:\s*' +
            [regex]::Escape($SIDType)
        )
    )

    $ConfigurationCorrect = (
        $Existing.PathName -eq $PathName -and
        $Existing.StartMode -eq 'Auto' -and
        $Existing.DisplayName -eq $DisplayName
    )

    if (
        $ConfigurationCorrect -and
        $ManagedCorrect -and
        $SIDCorrect
    ) {
        Write-Host "[PASS] $Name already matches the lifecycle contract."
        return
    }

    if ($Existing.State -ne 'Stopped') {
        Write-Host "[INFO] Stopping $Name for lifecycle reconciliation."

        Stop-Service `
            -Name $Name `
            -ErrorAction Stop

        (Get-Service -Name $Name).WaitForStatus(
            'Stopped',
            [TimeSpan]::FromSeconds(30)
        )
    }

    if (-not $ConfigurationCorrect) {
        Write-Host "[INFO] Reconciling $Name service configuration."

        Invoke-FISC -Arguments @(
            'config',
            $Name,
            'binPath=',
            $PathName,
            'start=',
            'auto',
            'DisplayName=',
            $DisplayName
        ) | Out-Host
    }

    if (-not $ManagedCorrect) {
        Write-Host "[INFO] Enabling managed-account semantics for $Name."

        Invoke-FISC -Arguments @(
            'managedaccount',
            $Name,
            'true'
        ) | Out-Host
    }

    if (-not $SIDCorrect) {
        Write-Host "[INFO] Reconciling service SID type for $Name."

        Invoke-FISC -Arguments @(
            'sidtype',
            $Name,
            $SIDType
        ) | Out-Host
    }
}

function Test-FIServiceContract {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$PathName,

        [Parameter(Mandatory = $true)]
        [string]$StartName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('NONE', 'UNRESTRICTED')]
        [string]$SIDType
    )

    $Service = Get-CimInstance `
        Win32_Service `
        -Filter "Name='$Name'" `
        -ErrorAction Stop

    if ($Service.PathName -ne $PathName) {
        throw "$Name PathName mismatch. Observed: $($Service.PathName)"
    }

    if ($Service.StartMode -ne 'Auto') {
        throw "$Name is not configured for automatic startup."
    }

    if ($Service.StartName -ine $StartName) {
        throw "$Name identity mismatch. Observed: $($Service.StartName)"
    }

    $Managed = @(
        & sc.exe qmanagedaccount $Name 2>&1
    ) -join "`n"

    if ($Managed -notmatch 'ACCOUNT MANAGED\s*:\s*TRUE') {
        throw "$Name is not configured as a managed-account service."
    }

    $ObservedSIDType = @(
        & sc.exe qsidtype $Name 2>&1
    ) -join "`n"

    if (
        $ObservedSIDType -notmatch (
            'SERVICE_SID_TYPE\s*:\s*' +
            [regex]::Escape($SIDType)
        )
    ) {
        throw "$Name service SID type is not $SIDType."
    }
}

function Wait-FIServiceRunning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [int]$TimeoutSeconds = 30
    )

    $Service = Get-Service `
        -Name $Name `
        -ErrorAction Stop

    if ($Service.Status -ne 'Running') {
        Start-Service `
            -Name $Name `
            -ErrorAction Stop
    }

    (Get-Service -Name $Name).WaitForStatus(
        'Running',
        [TimeSpan]::FromSeconds($TimeoutSeconds)
    )
}

Assert-FIAdministrator
Assert-FITargetComputer

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI WINDOWS SOURCE RUNTIME LIFECYCLE'
Write-Host '============================================================'
Write-Host ''

Assert-FIFile 'C:\Program Files\FI\fi.exe'
Assert-FIFile 'C:\Program Files\FI\fi-usn.exe'
Assert-FIFile 'C:\Program Files\FI\fi-obj.exe'
Assert-FIFile 'C:\Program Files\FI\fi-sender.exe'
Assert-FIFile 'C:\ProgramData\FI\config\fi.conf'
Assert-FIFile 'C:\ProgramData\FI\config\fi-transport-trust.conf'

Write-Host '[PASS] Required FI binaries and configuration files are present.'

Assert-FIExistingServiceIdentity `
    -Name $CollectorService `
    -StartName $CollectorAccount

Assert-FIExistingServiceIdentity `
    -Name $USNReaderService `
    -StartName $USNReaderAccount

Assert-FIExistingServiceIdentity `
    -Name $ObjReaderService `
    -StartName $ObjReaderAccount

Assert-FIExistingServiceIdentity `
    -Name $SenderService `
    -StartName $SenderAccount

Write-Host '[PASS] Existing FI service identities match the requested security boundary.'

if (-not $ConfirmChange) {
    Write-Host ''
    Write-Host '[INFO] Validation-only run complete.'
    Write-Host '[INFO] Re-run with -ConfirmChange to reconcile the production runtime.'
    exit 0
}

Write-Host ''
Write-Host '===== RETIRE LEGACY SENDER OWNER ====='

$Task = Get-ScheduledTask `
    -TaskName $LegacySenderTask `
    -ErrorAction SilentlyContinue

if (
    $null -ne $Task -and
    $Task.State -eq 'Running'
) {
    throw (
        "Legacy sender task $LegacySenderTask is currently running. " +
        'FI will not forcibly terminate an active sender during lifecycle migration.'
    )
}

Assert-FISenderRuntimeOwnership

if ($null -ne $Task) {
    Write-Host "[PASS] Legacy sender task is quiescent: $LegacySenderTask"
}
else {
    Write-Host "[INFO] Legacy sender task is not present."
}

Write-Host ''
Write-Host '===== RECONCILE SERVICES ====='

Set-FIManagedService `
    -Name $USNReaderService `
    -DisplayName 'FIUSNReader' `
    -PathName $USNReaderPath `
    -StartName $USNReaderAccount `
    -SIDType 'none'

Set-FIManagedService `
    -Name $ObjReaderService `
    -DisplayName 'FI Object Reader' `
    -PathName $ObjReaderPath `
    -StartName $ObjReaderAccount `
    -SIDType 'none'

Set-FIManagedService `
    -Name $CollectorService `
    -DisplayName 'FI Collector' `
    -PathName $CollectorPath `
    -StartName $CollectorAccount `
    -SIDType 'unrestricted'

Set-FIManagedService `
    -Name $SenderService `
    -DisplayName 'FI Sender' `
    -PathName $SenderPath `
    -StartName $SenderAccount `
    -SIDType 'none'

Write-Host ''
Write-Host '===== START SERVICES ====='

Wait-FIServiceRunning $USNReaderService
Wait-FIServiceRunning $ObjReaderService
Wait-FIServiceRunning $CollectorService

Write-Host ''
Write-Host '===== TRANSFER SENDER LIFECYCLE OWNERSHIP ====='

$Task = Get-ScheduledTask `
    -TaskName $LegacySenderTask `
    -ErrorAction SilentlyContinue

if (
    $null -ne $Task -and
    $Task.State -eq 'Running'
) {
    throw (
        "Legacy sender task $LegacySenderTask became active during migration. " +
        'FISender will not be started.'
    )
}

Assert-FISenderRuntimeOwnership

if ($null -ne $Task) {
    Disable-ScheduledTask `
        -TaskName $LegacySenderTask `
        -ErrorAction Stop |
        Out-Null

    Write-Host "[PASS] Legacy sender task disabled: $LegacySenderTask"
}

Wait-FIServiceRunning $SenderService

Write-Host ''
Write-Host '===== VERIFY SERVICE CONTRACT ====='

Test-FIServiceContract `
    -Name $CollectorService `
    -PathName $CollectorPath `
    -StartName $CollectorAccount `
    -SIDType 'UNRESTRICTED'

Test-FIServiceContract `
    -Name $USNReaderService `
    -PathName $USNReaderPath `
    -StartName $USNReaderAccount `
    -SIDType 'NONE'

Test-FIServiceContract `
    -Name $ObjReaderService `
    -PathName $ObjReaderPath `
    -StartName $ObjReaderAccount `
    -SIDType 'NONE'

Test-FIServiceContract `
    -Name $SenderService `
    -PathName $SenderPath `
    -StartName $SenderAccount `
    -SIDType 'NONE'

if (-not (Test-Path '\\.\pipe\FI-USN')) {
    throw 'FI-USN broker pipe is not present.'
}

if (-not (Test-Path '\\.\pipe\FI-OBJ')) {
    throw 'FI-OBJ broker pipe is not present.'
}

$Task = Get-ScheduledTask `
    -TaskName $LegacySenderTask `
    -ErrorAction SilentlyContinue

if (
    $null -ne $Task -and
    $Task.Settings.Enabled
) {
    throw 'Legacy FI sender task remained enabled.'
}

Assert-FISenderRuntimeOwnership -RequireServiceOwner

Write-Host ''
Write-Host '[PASS] FI Windows source runtime lifecycle is reconciled.'
Write-Host '[PASS] FICollector is Automatic and Running.'
Write-Host '[PASS] FIUSNReader is Automatic and Running.'
Write-Host '[PASS] FIObjReader is Automatic, Running, and managed-account enabled.'
Write-Host '[PASS] FISender is Automatic and Running.'
Write-Host '[PASS] Legacy scheduled-task sender is not an active runtime owner.'
Write-Host '[PASS] FI-USN and FI-OBJ broker pipes are present.'
