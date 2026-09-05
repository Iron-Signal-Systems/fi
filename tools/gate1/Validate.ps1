# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Server,

    [Parameter(Mandatory = $true)]
    [string]$Save,

    [string]$Version = '',

    [ValidateSet('Full','RemoteSMB')]
    [string]$StartAt = 'Full',

    [string]$ContainmentProbePath = '',

    [switch]$SkipContainment,
    [switch]$SkipRecovery,
    [switch]$SkipRemoteSMB,
    [switch]$Force,
    [switch]$RequireCleanRepository
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (
    $PSVersionTable.PSEdition -ne 'Desktop' -or
    $PSVersionTable.PSVersion.Major -ne 5 -or
    $PSVersionTable.PSVersion.Minor -lt 1
) {
    throw ("FI Gate 1 validation requires Windows PowerShell 5.1 (Desktop). Observed edition={0}, version={1}. Run with powershell.exe, not pwsh.exe." -f $PSVersionTable.PSEdition,$PSVersionTable.PSVersion)
}

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ToolsRoot = Split-Path -Parent $Here
$RepoRoot = Split-Path -Parent $ToolsRoot
$ProfilePath = Join-Path $Here 'validation-profiles.psd1'
$Local10B = Join-Path $Here '10B-RemoteClient-SMB-Activity.ps1'
$RunID = [Guid]::NewGuid().ToString('N').Substring(0,12)

if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) {
    throw "Validator profile file not found: $ProfilePath"
}
if (-not (Test-Path -LiteralPath $Local10B -PathType Leaf)) {
    throw "Gate 1 10B script not found: $Local10B"
}

if ($Version -and @('2016','2019','2022','2025') -notcontains $Version) {
    throw "Unsupported -Version value '$Version'. Accepted values: 2016, 2019, 2022, 2025."
}

$Profiles = Import-PowerShellDataFile -LiteralPath $ProfilePath
$ExpectedCollectorHash = [string]$Profiles.Artifact.CollectorSHA256
$ExpectedHelperHash = [string]$Profiles.Artifact.HelperSHA256

$Save = [IO.Path]::GetFullPath($Save)
$SummaryPath = Join-Path $Save 'validation-summary.txt'
$ReportPath = Join-Path $Save 'validation-report.json'
$StatePath = Join-Path $Save 'resolved-system-state.json'
$HashPath = Join-Path $Save 'SHA256SUMS.txt'
$LogsPath = Join-Path $Save 'logs'
$RawPath = Join-Path $Save 'raw'
$ServerRawPath = Join-Path $RawPath 'server'
$ClientRawPath = Join-Path $RawPath 'client'
$ToolsSavePath = Join-Path $Save 'tools'
$TranscriptPath = Join-Path $LogsPath 'validation-transcript.txt'
$GoStdoutPath = Join-Path $LogsPath 'containment-probe-build.stdout.txt'
$GoStderrPath = Join-Path $LogsPath 'containment-probe-build.stderr.txt'

if (Test-Path -LiteralPath $ReportPath -PathType Leaf) {
    if (-not $Force) {
        throw "A validation report already exists at $ReportPath. Use a new -Save directory or -Force."
    }

    foreach ($GeneratedPath in @(
        $SummaryPath,
        $ReportPath,
        $StatePath,
        $HashPath,
        $LogsPath,
        $RawPath,
        $ToolsSavePath
    )) {
        Remove-Item -LiteralPath $GeneratedPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($Directory in @($Save,$LogsPath,$RawPath,$ServerRawPath,$ClientRawPath,$ToolsSavePath)) {
    New-Item -Path $Directory -ItemType Directory -Force | Out-Null
}

$Steps = New-Object System.Collections.Generic.List[object]
$TemporaryChanges = New-Object System.Collections.Generic.List[object]
$ValidationError = ''
$OverallStatus = 'FAIL'
$Session = $null
$RemoteState = $null
$Profile = $null
$ProbeLocal = $null
$ProbeHash = ''
$BoundaryProbeLocal = $null
$BoundaryProbeHash = ''
$RepoHead = ''
$RepoStatus = @()
$StartedUTC = [DateTime]::UtcNow
$TranscriptStarted = $false
$script:ArtifactsSaved = $false

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host '============================================================'
    Write-Host $Text
    Write-Host '============================================================'
}

function Add-StepResult {
    param(
        [string]$Name,
        [string]$Status,
        [DateTime]$Started,
        [string]$Detail = ''
    )

    $Finished = [DateTime]::UtcNow
    $Steps.Add([PSCustomObject]@{
        Name = $Name
        Status = $Status
        StartedUTC = $Started.ToString('o')
        FinishedUTC = $Finished.ToString('o')
        DurationSeconds = [Math]::Round(($Finished - $Started).TotalSeconds,3)
        Detail = $Detail
    })
}

function Invoke-ValidationStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    Write-Host ''
    Write-Host "[RUN ] $Name"
    $Started = [DateTime]::UtcNow

    try {
        # Preserve the success-output stream as one continuous PowerShell pipeline.
        # Formatting commands such as Format-Table emit a coordinated sequence of
        # formatting records; sending those records to Out-Host one at a time can
        # corrupt the formatting stream under Windows PowerShell 5.1.
        $StepOutput = @()
        & $Action | Tee-Object -Variable StepOutput | Out-Host

        $Detail = ''
        # Tee-Object assigns a scalar when the action emits exactly one success
        # object. Normalize to an array before Count/index operations so this
        # remains valid under Windows PowerShell 5.1 with StrictMode enabled.
        $CapturedStepOutput = @($StepOutput)
        if ($CapturedStepOutput.Count -gt 0) {
            $LastOutput = $CapturedStepOutput[$CapturedStepOutput.Count - 1]
            if ($null -ne $LastOutput) {
                $Detail = [string]$LastOutput
            }
        }

        Add-StepResult -Name $Name -Status 'PASS' -Started $Started -Detail ([string]$Detail)
        Write-Host "[PASS] $Name"
    }
    catch {
        $Detail = $_.Exception.Message
        Add-StepResult -Name $Name -Status 'FAIL' -Started $Started -Detail $Detail

        Write-Host "[FAIL] $Name - $Detail"
        Write-Host ("[FAIL] Exception type: {0}" -f $_.Exception.GetType().FullName)
        if ($_.InvocationInfo) {
            Write-Host ("[FAIL] Script: {0}; line: {1}; column: {2}" -f $_.InvocationInfo.ScriptName,$_.InvocationInfo.ScriptLineNumber,$_.InvocationInfo.OffsetInLine)
            if (-not [string]::IsNullOrWhiteSpace([string]$_.InvocationInfo.Line)) {
                Write-Host ("[FAIL] Line text: {0}" -f ([string]$_.InvocationInfo.Line).Trim())
            }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$_.ScriptStackTrace)) {
            Write-Host "[FAIL] Script stack trace:"
            Write-Host ([string]$_.ScriptStackTrace)
        }
        throw
    }
}

function Test-TcpPortFast {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        [Parameter(Mandatory = $true)]
        [int]$Port,
        [int]$TimeoutMilliseconds = 2000
    )

    $Client = New-Object System.Net.Sockets.TcpClient
    try {
        $Async = $Client.BeginConnect($ComputerName,$Port,$null,$null)
        if (-not $Async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds,$false)) {
            return $false
        }
        try {
            $Client.EndConnect($Async)
        }
        catch {
            return $false
        }
        return $Client.Connected
    }
    finally {
        $Client.Close()
        $Client.Dispose()
    }
}

function Get-ControllerSourceAddress {
    param([Parameter(Mandatory = $true)][string]$Target)

    $TargetAddress = Resolve-DnsName -Name $Target -Type A -ErrorAction Stop |
        Select-Object -First 1 -ExpandProperty IPAddress

    $Socket = New-Object System.Net.Sockets.Socket -ArgumentList @(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Dgram,
        [System.Net.Sockets.ProtocolType]::Udp
    )
    try {
        $Socket.Connect($TargetAddress,9)
        return ([System.Net.IPEndPoint]$Socket.LocalEndPoint).Address.IPAddressToString
    }
    finally {
        $Socket.Close()
        $Socket.Dispose()
    }
}

function Invoke-RemotePowerShellFile {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string[]]$Arguments = @(),
        [string]$CapturePath = '',
        [int]$TimeoutSeconds = 900
    )

    $Job = Invoke-Command -Session $PSSession -AsJob -ArgumentList @($Path,$Arguments,$CapturePath) -ScriptBlock {
        param($Path,$Arguments,$CapturePath)

        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Required validator script not found: $Path"
        }

        $NativeArguments = @(
            '-NoLogo',
            '-NoProfile',
            '-ExecutionPolicy','Bypass',
            '-File',$Path
        ) + $Arguments

        if ($CapturePath) {
            $CaptureDirectory = Split-Path -Parent $CapturePath
            New-Item -Path $CaptureDirectory -ItemType Directory -Force | Out-Null
            & powershell.exe @NativeArguments 2>&1 | Tee-Object -FilePath $CapturePath
        }
        else {
            & powershell.exe @NativeArguments 2>&1
        }

        $Code = $LASTEXITCODE
        if ($Code -ne 0) {
            throw "Child PowerShell script returned exit code ${Code}: $Path"
        }
    }

    # IMPORTANT: Do not call Receive-Job while the remoting job is still active.
    # On Windows PowerShell 5.1, Receive-Job against a remoting job can block the
    # supervising thread long enough to defeat both heartbeat and timeout logic.
    # Wait-Job -Timeout 1 keeps supervision bounded; collect child output only
    # after the job has entered a terminal state.
    $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $NextHeartbeatSeconds = 10
    try {
        while ($true) {
            $null = Wait-Job -Job $Job -Timeout 1
            $State = [string]$Job.State
            $Elapsed = [int]$Stopwatch.Elapsed.TotalSeconds

            if ($State -notin @('NotStarted','Running','Blocked')) {
                break
            }

            if ($Elapsed -ge $TimeoutSeconds) {
                Stop-Job -Job $Job -ErrorAction SilentlyContinue
                throw "Remote test exceeded ${TimeoutSeconds}s: $Path"
            }

            if ($Elapsed -ge $NextHeartbeatSeconds) {
                $Remaining = [Math]::Max(0,$TimeoutSeconds - $Elapsed)
                Write-Host "[INFO] Remote test $([IO.Path]::GetFileName($Path)): ${Elapsed}s elapsed / ${TimeoutSeconds}s timeout; ${Remaining}s remaining; job_state=$State."
                while ($NextHeartbeatSeconds -le $Elapsed) {
                    $NextHeartbeatSeconds += 10
                }
            }
        }

        # The job is now terminal. Receiving its buffered output cannot stall the
        # active-job supervision path or extend the declared wall-clock timeout.
        @(Receive-Job -Job $Job -ErrorAction SilentlyContinue) | ForEach-Object { $_ }

        if ($Job.State -ne 'Completed') {
            $Reason = ''
            if ($Job.ChildJobs.Count -gt 0 -and $null -ne $Job.ChildJobs[0].JobStateInfo.Reason) {
                $Reason = [string]$Job.ChildJobs[0].JobStateInfo.Reason.Message
            }
            if (-not $Reason) { $Reason = "Remote job ended in state $($Job.State)." }
            throw $Reason
        }
    }
    finally {
        $Stopwatch.Stop()
        Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue
    }
}

function Get-RemoteAuditSetting {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [string]$Subcategory
    )

    return [int](Invoke-Command -Session $PSSession -ArgumentList $Subcategory -ScriptBlock {
        param($Subcategory)
        $Output = @(& auditpol.exe /get "/subcategory:$Subcategory" 2>&1 | ForEach-Object { $_.ToString() })
        $Line = $Output | Where-Object { $_ -match [regex]::Escape($Subcategory) } | Select-Object -Last 1
        if (-not $Line) {
            throw "Could not read Advanced Audit Policy subcategory: $Subcategory"
        }
        if ($Line -match '(?i)Success\s+and\s+Failure') { return 3 }
        if ($Line -match '(?i)No\s+Auditing') { return 0 }
        if ($Line -match '(?i)Success') { return 1 }
        if ($Line -match '(?i)Failure') { return 2 }
        throw "Unrecognized Advanced Audit Policy state for ${Subcategory}: $Line"
    })
}

function Set-RemoteAuditSetting {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [string]$Subcategory,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0,3)]
        [int]$Setting
    )

    Invoke-Command -Session $PSSession -ArgumentList @($Subcategory,$Setting) -ScriptBlock {
        param($Subcategory,$Setting)

        $Success = 'disable'
        $Failure = 'disable'
        switch ($Setting) {
            1 { $Success = 'enable' }
            2 { $Failure = 'enable' }
            3 { $Success = 'enable'; $Failure = 'enable' }
        }

        & auditpol.exe /set "/subcategory:$Subcategory" "/success:$Success" "/failure:$Failure" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "auditpol.exe failed setting $Subcategory to value $Setting."
        }
    }
}



function Invoke-FiLocalProcessWithHeartbeat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,
        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,
        [Parameter(Mandatory = $true)]
        [string]$StderrPath,
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [ValidateRange(10,1800)]
        [int]$TimeoutSeconds = 300
    )

    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $FilePath
    $StartInfo.Arguments = $Arguments
    $StartInfo.WorkingDirectory = $WorkingDirectory
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $StartInfo

    try {
        if (-not $Process.Start()) {
            throw "Could not start ${Label}."
        }

        $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        $StderrTask = $Process.StandardError.ReadToEndAsync()
        $Started = Get-Date
        $NextHeartbeat = $Started.AddSeconds(10)

        while (-not $Process.HasExited) {
            $Now = Get-Date
            $Elapsed = [int](($Now - $Started).TotalSeconds)

            if ($Elapsed -ge $TimeoutSeconds) {
                try { $Process.Kill() } catch { }
                [void]$Process.WaitForExit(10000)
                throw "${Label} exceeded ${TimeoutSeconds}s and was terminated."
            }

            if ($Now -ge $NextHeartbeat) {
                $Remaining = [Math]::Max(0, $TimeoutSeconds - $Elapsed)
                Write-Host "[INFO] ${Label}: ${Elapsed}s elapsed / ${TimeoutSeconds}s timeout; ${Remaining}s remaining."
                $NextHeartbeat = $Now.AddSeconds(10)
            }

            Start-Sleep -Milliseconds 250
        }

        $Process.WaitForExit()
        $Process.Refresh()
        $StdoutText = [string]$StdoutTask.GetAwaiter().GetResult()
        $StderrText = [string]$StderrTask.GetAwaiter().GetResult()

        [IO.File]::WriteAllText(
            $StdoutPath,
            $StdoutText,
            (New-Object System.Text.UTF8Encoding($false))
        )
        [IO.File]::WriteAllText(
            $StderrPath,
            $StderrText,
            (New-Object System.Text.UTF8Encoding($false))
        )

        return [PSCustomObject]@{
            ExitCode = [int]$Process.ExitCode
            Stdout = $StdoutText
            Stderr = $StderrText
        }
    }
    finally {
        try {
            if ($Process -and -not $Process.HasExited) {
                $Process.Kill()
                [void]$Process.WaitForExit(5000)
            }
        }
        catch { }
        if ($Process) { $Process.Dispose() }
    }
}

function Build-CollectorBoundaryProbe {
    $Source = Join-Path $RepoRoot 'go\cmd\collectorboundaryprobe\main_windows.go'
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Collector boundary probe source is missing: $Source"
    }

    $Go = Get-Command go.exe -ErrorAction SilentlyContinue
    if ($null -eq $Go) { $Go = Get-Command go -ErrorAction SilentlyContinue }
    if ($null -eq $Go) { throw 'Go is required to build the collector service-token boundary probe.' }

    $Output = Join-Path $ToolsSavePath 'fi-collector-boundary-probe.exe'
    $Stdout = Join-Path $LogsPath 'collector-boundary-probe-build.stdout.txt'
    $Stderr = Join-Path $LogsPath 'collector-boundary-probe-build.stderr.txt'
    Remove-Item -LiteralPath $Output,$Stdout,$Stderr -Force -ErrorAction SilentlyContinue

    Write-Host "[INFO] Building collector boundary probe from $Source"
    $ArgumentText = 'build -trimpath -o "{0}" ./cmd/collectorboundaryprobe' -f $Output
    $Build = Invoke-FiLocalProcessWithHeartbeat `
        -FilePath $Go.Source `
        -Arguments $ArgumentText `
        -WorkingDirectory (Join-Path $RepoRoot 'go') `
        -StdoutPath $Stdout `
        -StderrPath $Stderr `
        -Label 'Collector boundary probe build'

    if ($Build.ExitCode -ne 0) {
        $BuildError = ([string]$Build.Stderr).Trim()
        throw "Collector boundary probe build failed with exit code $($Build.ExitCode). $BuildError"
    }
    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) { throw "Collector boundary probe output is missing: $Output" }
    return $Output
}

function Invoke-CollectorBoundaryCheck {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [string]$ProbePath,
        [Parameter(Mandatory = $true)]
        [string]$RemoteTest08,
        [Parameter(Mandatory = $true)]
        [string]$RemoteResultDirectory
    )

    $RemoteProbeDirectory = 'C:\FI-Test'
    $RemoteProbe = 'C:\FI-Test\fi-collector-boundary-probe.exe'
    $DirectoryExisted = [bool](Invoke-Command -Session $PSSession -ArgumentList $RemoteProbeDirectory -ScriptBlock {
        param($RemoteProbeDirectory)
        return (Test-Path -LiteralPath $RemoteProbeDirectory -PathType Container)
    })

    try {
        Invoke-Command -Session $PSSession -ArgumentList $RemoteProbeDirectory -ScriptBlock {
            param($RemoteProbeDirectory)
            New-Item -Path $RemoteProbeDirectory -ItemType Directory -Force | Out-Null
        }
        Copy-Item -LiteralPath $ProbePath -Destination $RemoteProbe -ToSession $PSSession -Force
        $TemporaryChanges.Add([PSCustomObject]@{ Name='Collector boundary probe'; Action="Staged $RemoteProbe"; Restored=$false })

        Invoke-RemotePowerShellFile -PSSession $PSSession -Path $RemoteTest08 -CapturePath (Join-Path $RemoteResultDirectory '08-output.txt')

        Invoke-Command -Session $PSSession -ArgumentList $RemoteResultDirectory -ScriptBlock {
            param($RemoteResultDirectory)
            $ProbeResult = 'C:\ProgramData\FI\state\collector-token-boundary-probe.json'
            if (-not (Test-Path -LiteralPath $ProbeResult -PathType Leaf)) {
                throw "Test 08 passed but its probe result is missing: $ProbeResult"
            }
            Copy-Item -LiteralPath $ProbeResult -Destination (Join-Path $RemoteResultDirectory 'collector-token-boundary-probe.json') -Force
            Remove-Item -LiteralPath $ProbeResult -Force -ErrorAction SilentlyContinue
        }
    }
    finally {
        Invoke-Command -Session $PSSession -ArgumentList @($RemoteProbe,$RemoteProbeDirectory,$DirectoryExisted) -ScriptBlock {
            param($RemoteProbe,$RemoteProbeDirectory,$DirectoryExisted)
            Remove-Item -LiteralPath $RemoteProbe -Force -ErrorAction SilentlyContinue
            if (-not $DirectoryExisted -and (Test-Path -LiteralPath $RemoteProbeDirectory -PathType Container)) {
                $Children = @(Get-ChildItem -LiteralPath $RemoteProbeDirectory -Force -ErrorAction SilentlyContinue)
                if ($Children.Count -eq 0) { Remove-Item -LiteralPath $RemoteProbeDirectory -Force -ErrorAction SilentlyContinue }
            }
        }
        $Change = $TemporaryChanges | Where-Object { $_.Name -eq 'Collector boundary probe' } | Select-Object -Last 1
        if ($null -ne $Change) { $Change.Restored = $true }
    }
}

function Build-ContainmentProbe {
    param([string]$RequestedPath = '')

    if ($RequestedPath) {
        $Resolved = (Resolve-Path -LiteralPath $RequestedPath -ErrorAction Stop).Path
        return $Resolved
    }

    $Source = Join-Path $RepoRoot 'go\cmd\containmentclientprobe\main_windows.go'
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Generic containment probe source is missing: $Source"
    }

    $Go = Get-Command go.exe -ErrorAction SilentlyContinue
    if ($null -eq $Go) {
        $Go = Get-Command go -ErrorAction SilentlyContinue
    }
    if ($null -eq $Go) {
        throw 'Go is required to build the Gate 1 containment probe. Supply -ContainmentProbePath to use a reviewed prebuilt probe.'
    }

    $Output = Join-Path $ToolsSavePath 'fi-gate1-containment-probe.exe'
    Remove-Item -LiteralPath $Output -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $GoStdoutPath,$GoStderrPath -Force -ErrorAction SilentlyContinue

    Write-Host "[INFO] Building containment probe from $Source"
    $ArgumentText = 'build -trimpath -o "{0}" ./cmd/containmentclientprobe' -f $Output
    $Build = Invoke-FiLocalProcessWithHeartbeat `
        -FilePath $Go.Source `
        -Arguments $ArgumentText `
        -WorkingDirectory (Join-Path $RepoRoot 'go') `
        -StdoutPath $GoStdoutPath `
        -StderrPath $GoStderrPath `
        -Label 'Containment probe build'

    if ($Build.ExitCode -ne 0) {
        $BuildError = ([string]$Build.Stderr).Trim()
        throw "Containment probe build failed with exit code $($Build.ExitCode). $BuildError"
    }
    if (-not (Test-Path -LiteralPath $Output -PathType Leaf)) {
        throw "Containment probe build returned success but output is missing: $Output"
    }

    return $Output
}

function Invoke-ProductionContainmentCheck {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [string]$ProbePath,
        [Parameter(Mandatory = $true)]
        [string]$GovernedRoot,
        [Parameter(Mandatory = $true)]
        [string]$RemoteResultDirectory
    )

    $RemoteProbe = "C:\ProgramData\FI\state\gate1-containment-probe-$RunID.exe"
    Copy-Item -LiteralPath $ProbePath -Destination $RemoteProbe -ToSession $PSSession -Force

    $Result = Invoke-Command -Session $PSSession -ArgumentList @($RemoteProbe,$GovernedRoot,$RemoteResultDirectory) -ScriptBlock {
        param($RemoteProbe,$GovernedRoot,$RemoteResultDirectory)

        $InputPath = 'C:\ProgramData\FI\state\gate1-containment-input.json'
        $ResultPath = 'C:\ProgramData\FI\state\gate1-containment-result.json'
        $ErrorPath = 'C:\ProgramData\FI\state\gate1-containment-error.txt'
        $ServiceName = 'FICollector'

        function Wait-VisibleServiceState {
            param([string]$Name,[string]$State,[int]$TimeoutSeconds = 15)
            $Started = Get-Date
            $NextHeartbeat = $Started.AddSeconds(10)
            while ((Get-Date) -lt $Started.AddSeconds($TimeoutSeconds)) {
                $Current = (Get-Service -Name $Name -ErrorAction Stop).Status.ToString()
                if ($Current -eq $State) { return }
                $Now = Get-Date
                if ($Now -ge $NextHeartbeat) {
                    $Elapsed = [int](($Now - $Started).TotalSeconds)
                    $Remaining = [Math]::Max(0,$TimeoutSeconds - $Elapsed)
                    Write-Host "[INFO] Service ${Name}: ${Elapsed}s elapsed / ${TimeoutSeconds}s timeout; ${Remaining}s remaining; waiting for $State; current=$Current."
                    $NextHeartbeat = $NextHeartbeat.AddSeconds(10)
                }
                Start-Sleep -Milliseconds 250
            }
            throw "Service $Name did not reach $State within $TimeoutSeconds seconds."
        }

        $OriginalService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        $OriginalPath = [string]$OriginalService.PathName
        $OriginalStatus = (Get-Service $ServiceName -ErrorAction Stop).Status.ToString()
        $Target = Get-ChildItem -LiteralPath 'C:\Windows\System32\LogFiles\WMI\RtBackup' -Filter '*.etl' -File -ErrorAction Stop |
            Select-Object -First 1

        if ($null -eq $Target) {
            throw 'No protected RtBackup ETL target was available for production containment validation.'
        }

        $FileIDOutput = @(& fsutil.exe file queryfileid $Target.FullName 2>&1 | ForEach-Object { $_.ToString() }) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw "fsutil file queryfileid failed for $($Target.FullName): $FileIDOutput"
        }
        $Match = [regex]::Match($FileIDOutput,'0x([0-9A-Fa-f]{32}|[0-9A-Fa-f]{16})')
        if (-not $Match.Success) {
            throw "Could not parse NTFS file ID for $($Target.FullName): $FileIDOutput"
        }

        $Hex = $Match.Groups[1].Value.PadLeft(32,'0')
        $Low64 = $Hex.Substring(16,16)
        $SequenceHex = $Low64.Substring(0,4)
        $FRNHex = $Low64.Substring(4,12)
        $Sequence = [Convert]::ToUInt64($SequenceHex,16)
        $FRN = [Convert]::ToUInt64($FRNHex,16)

        $ProbeInputJson = [PSCustomObject]@{
            file_reference_number = [string]$FRN
            governed_root = $GovernedRoot
            sequence_number = [string]$Sequence
            target_description = $Target.FullName
        } | ConvertTo-Json -Depth 4

        # Windows PowerShell 5.1 `Set-Content -Encoding UTF8` writes a UTF-8 BOM.
        # The Go JSON decoder intentionally expects JSON to begin with JSON data,
        # so write probe input explicitly as UTF-8 without BOM.
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($InputPath, $ProbeInputJson, $Utf8NoBom)

        Remove-Item -LiteralPath $ResultPath,$ErrorPath -Force -ErrorAction SilentlyContinue

        try {
            if ((Get-Service $ServiceName).Status -ne 'Stopped') {
                Stop-Service $ServiceName -Force -ErrorAction Stop
                Wait-VisibleServiceState -Name $ServiceName -State 'Stopped' -TimeoutSeconds 15
            }

            $Current = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
            $Change = Invoke-CimMethod -InputObject $Current -MethodName Change -Arguments @{ PathName = ('"{0}"' -f $RemoteProbe) }
            if ([int]$Change.ReturnValue -ne 0) {
                throw "Could not point FICollector at containment probe. Win32_Service.Change returned $($Change.ReturnValue)."
            }

            & sc.exe start $ServiceName | Out-Null

            $Started = Get-Date
            $TimeoutSeconds = 45
            $NextHeartbeat = $Started.AddSeconds(10)
            while ((Get-Date) -lt $Started.AddSeconds($TimeoutSeconds)) {
                if (Test-Path -LiteralPath $ResultPath -PathType Leaf) {
                    break
                }
                if (Test-Path -LiteralPath $ErrorPath -PathType Leaf) {
                    $ProbeError = Get-Content -LiteralPath $ErrorPath -Raw
                    throw "Containment probe failed: $ProbeError"
                }
                $Now = Get-Date
                if ($Now -ge $NextHeartbeat) {
                    $Elapsed = [int](($Now - $Started).TotalSeconds)
                    $Remaining = [Math]::Max(0,$TimeoutSeconds - $Elapsed)
                    Write-Host "[INFO] Production containment: ${Elapsed}s elapsed / ${TimeoutSeconds}s timeout; ${Remaining}s remaining; waiting for broker result."
                    $NextHeartbeat = $NextHeartbeat.AddSeconds(10)
                }
                Start-Sleep -Seconds 1
            }

            if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
                throw 'Production containment probe did not produce a result within 45 seconds.'
            }

            $ProbeResult = Get-Content -LiteralPath $ResultPath -Raw | ConvertFrom-Json
            if ($ProbeResult.broker_result -ne 'Outside') {
                throw "Expected protected outside target to resolve Outside; observed $($ProbeResult.broker_result)."
            }

            New-Item -Path $RemoteResultDirectory -ItemType Directory -Force | Out-Null
            $SavedResult = Join-Path $RemoteResultDirectory 'production-containment.json'
            Copy-Item -LiteralPath $ResultPath -Destination $SavedResult -Force

            return [PSCustomObject]@{
                BrokerResult = [string]$ProbeResult.broker_result
                FileReferenceNumber = [string]$ProbeResult.file_reference_number
                SequenceNumber = [string]$ProbeResult.sequence_number
                Target = [string]$ProbeResult.target_description
                SavedResult = $SavedResult
            }
        }
        finally {
            try {
                if ((Get-Service $ServiceName -ErrorAction SilentlyContinue).Status -ne 'Stopped') {
                    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
                    Wait-VisibleServiceState -Name $ServiceName -State 'Stopped' -TimeoutSeconds 15
                }
                $Current = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
                $Restore = Invoke-CimMethod -InputObject $Current -MethodName Change -Arguments @{ PathName = $OriginalPath }
                if ([int]$Restore.ReturnValue -ne 0) {
                    throw "FICollector PathName restoration failed with code $($Restore.ReturnValue)."
                }
                if ($OriginalStatus -eq 'Running') {
                    Start-Service $ServiceName -ErrorAction Stop
                    Wait-VisibleServiceState -Name $ServiceName -State 'Running' -TimeoutSeconds 15
                }
            }
            finally {
                Remove-Item -LiteralPath $RemoteProbe,$InputPath,$ResultPath,$ErrorPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return $Result
}

function Invoke-LocalActivityWithPrerequisites {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [string]$Remote10A,
        [Parameter(Mandatory = $true)]
        [string]$GovernedRoot,
        [Parameter(Mandatory = $true)]
        [string]$RemoteResultDirectory
    )

    $OriginalAudit = Get-RemoteAuditSetting -PSSession $PSSession -Subcategory 'File System'
    $AuditChanged = $false
    $AuditRuleAdded = $false
    $AuditSID = ''

    try {
        if ($OriginalAudit -ne 3) {
            Write-Host "[INFO] Temporarily enabling File System Success/Failure auditing; original setting value=$OriginalAudit."
            Set-RemoteAuditSetting -PSSession $PSSession -Subcategory 'File System' -Setting 3
            $AuditChanged = $true
            $TemporaryChanges.Add([PSCustomObject]@{ Name='File System audit policy'; Action='Temporarily set Success and Failure'; Restored=$false })
        }

        $SACLResult = Invoke-Command -Session $PSSession -ArgumentList $GovernedRoot -ScriptBlock {
            param($GovernedRoot)

            $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $SID = $Identity.User
            $RequiredRights = (
                [Security.AccessControl.FileSystemRights]::ReadData -bor
                [Security.AccessControl.FileSystemRights]::WriteData -bor
                [Security.AccessControl.FileSystemRights]::AppendData
            )
            $RequiredInheritance = (
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            )

            $Acl = Get-Acl -LiteralPath $GovernedRoot -Audit -ErrorAction Stop
            $Existing = @($Acl.Audit | Where-Object {
                try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $SID.Value } catch { $false }
            })

            $Adequate = $false
            foreach ($Rule in $Existing) {
                $HasRights = (([int]$Rule.FileSystemRights -band [int]$RequiredRights) -eq [int]$RequiredRights)
                $HasFailure = (($Rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Failure) -ne 0)
                $HasContainer = (($Rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0)
                $HasObject = (($Rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0)
                if ($HasRights -and $HasFailure -and $HasContainer -and $HasObject) {
                    $Adequate = $true
                    break
                }
            }

            if ($Adequate) {
                return [PSCustomObject]@{ Added=$false; SID=$SID.Value }
            }

            $Rule = New-Object -TypeName Security.AccessControl.FileSystemAuditRule -ArgumentList @(
                $SID,
                $RequiredRights,
                $RequiredInheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AuditFlags]::Failure
            )
            $Acl.AddAuditRule($Rule)
            Set-Acl -LiteralPath $GovernedRoot -AclObject $Acl -ErrorAction Stop
            return [PSCustomObject]@{ Added=$true; SID=$SID.Value }
        }

        $AuditRuleAdded = [bool]$SACLResult.Added
        $AuditSID = [string]$SACLResult.SID
        if ($AuditRuleAdded) {
            Write-Host "[INFO] Added temporary governed-root failure audit ACE for $AuditSID."
            $TemporaryChanges.Add([PSCustomObject]@{ Name='Governed-root failure audit ACE'; Action="Added for $AuditSID"; Restored=$false })
        }
        else {
            Write-Host '[INFO] Governed root already had adequate failure-audit coverage for the validator identity.'
        }

        Invoke-RemotePowerShellFile -PSSession $PSSession -Path $Remote10A -Arguments @(
            '-GovernedRoot',$GovernedRoot,
            '-ResultDirectory',$RemoteResultDirectory,
            '-CollectionTimeoutSeconds','180',
            '-ConfirmWorkload'
        ) -CapturePath (Join-Path $RemoteResultDirectory '10A-output.txt')
    }
    finally {
        $RestoreErrors = New-Object System.Collections.Generic.List[string]

        if ($AuditRuleAdded) {
            try {
                Invoke-Command -Session $PSSession -ArgumentList @($GovernedRoot,$AuditSID) -ScriptBlock {
                    param($GovernedRoot,$AuditSID)
                    $SID = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList $AuditSID
                    $Rights = (
                        [Security.AccessControl.FileSystemRights]::ReadData -bor
                        [Security.AccessControl.FileSystemRights]::WriteData -bor
                        [Security.AccessControl.FileSystemRights]::AppendData
                    )
                    $Inheritance = (
                        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                        [Security.AccessControl.InheritanceFlags]::ObjectInherit
                    )
                    $Rule = New-Object -TypeName Security.AccessControl.FileSystemAuditRule -ArgumentList @(
                        $SID,
                        $Rights,
                        $Inheritance,
                        [Security.AccessControl.PropagationFlags]::None,
                        [Security.AccessControl.AuditFlags]::Failure
                    )
                    $Acl = Get-Acl -LiteralPath $GovernedRoot -Audit -ErrorAction Stop
                    $Acl.RemoveAuditRuleSpecific($Rule)
                    Set-Acl -LiteralPath $GovernedRoot -AclObject $Acl -ErrorAction Stop

                    $Verify = Get-Acl -LiteralPath $GovernedRoot -Audit -ErrorAction Stop
                    $StillPresent = @($Verify.Audit | Where-Object {
                        $SameSID = $false
                        try { $SameSID = ($_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq $SID.Value) } catch { }
                        $SameRights = (([int]$_.FileSystemRights -band [int]$Rights) -eq [int]$Rights)
                        $SameFailure = (($_.AuditFlags -band [Security.AccessControl.AuditFlags]::Failure) -ne 0)
                        $SameContainer = (($_.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0)
                        $SameObject = (($_.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0)
                        $SameSID -and $SameRights -and $SameFailure -and $SameContainer -and $SameObject -and (-not $_.IsInherited)
                    })
                    if ($StillPresent.Count -ne 0) {
                        throw 'Temporary governed-root failure audit ACE is still present after removal.'
                    }
                }
                $Change = $TemporaryChanges | Where-Object { $_.Name -eq 'Governed-root failure audit ACE' } | Select-Object -Last 1
                if ($null -ne $Change) { $Change.Restored = $true }
                Write-Host '[PASS] Temporary governed-root failure audit ACE removed.'
            }
            catch {
                $RestoreErrors.Add("Governed-root failure audit ACE restoration: $($_.Exception.Message)")
            }
        }

        if ($AuditChanged) {
            try {
                Set-RemoteAuditSetting -PSSession $PSSession -Subcategory 'File System' -Setting $OriginalAudit
                $RestoredAudit = Get-RemoteAuditSetting -PSSession $PSSession -Subcategory 'File System'
                if ($RestoredAudit -ne $OriginalAudit) {
                    throw "Expected audit setting $OriginalAudit after restoration; observed $RestoredAudit."
                }
                $Change = $TemporaryChanges | Where-Object { $_.Name -eq 'File System audit policy' } | Select-Object -Last 1
                if ($null -ne $Change) { $Change.Restored = $true }
                Write-Host "[PASS] File System audit policy restored to setting value $OriginalAudit."
            }
            catch {
                $RestoreErrors.Add("File System audit policy restoration: $($_.Exception.Message)")
            }
        }

        if ($RestoreErrors.Count -ne 0) {
            throw ($RestoreErrors -join ' | ')
        }
    }
}

function Wait-ForConfiguredCollectionAfter {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [DateTime]$AfterUTC,
        [int]$TimeoutSeconds = 180
    )

    $Started = [DateTime]::UtcNow
    $NextHeartbeat = $Started.AddSeconds(10)

    while ([DateTime]::UtcNow -lt $Started.AddSeconds($TimeoutSeconds)) {
        $Record = Invoke-Command -Session $PSSession -ArgumentList $AfterUTC -ScriptBlock {
            param($AfterUTC)
            $Path = 'C:\ProgramData\FI\state\service-runtime.jsonl'
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
            $Lines = @(Get-Content -LiteralPath $Path -Tail 512 -ErrorAction Stop)
            for ($Index = $Lines.Count - 1; $Index -ge 0; $Index--) {
                try { $Current = $Lines[$Index] | ConvertFrom-Json } catch { continue }
                if ($Current.record_kind -ne 'ConfiguredCollection') { continue }
                try {
                    $Observed = [DateTime]::Parse(
                        [string]$Current.observed_at,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind
                    ).ToUniversalTime()
                }
                catch { continue }
                if ($Observed -gt $AfterUTC.ToUniversalTime()) { return $Current }
            }
            return $null
        }

        if ($null -ne $Record) { return $Record }

        $Now = [DateTime]::UtcNow
        if ($Now -ge $NextHeartbeat) {
            $Elapsed = [int](($Now - $Started).TotalSeconds)
            $Remaining = [Math]::Max(0,$TimeoutSeconds - $Elapsed)
            Write-Host "[INFO] Post-workload collection: ${Elapsed}s elapsed / ${TimeoutSeconds}s timeout; ${Remaining}s remaining."
            $NextHeartbeat = $NextHeartbeat.AddSeconds(10)
        }
        Start-Sleep -Seconds 2
    }

    return $null
}

function Invoke-RemoteSMBValidation {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [string]$Target,
        [Parameter(Mandatory = $true)]
        [string]$GovernedRoot,
        [Parameter(Mandatory = $true)]
        [string]$Remote10C,
        [Parameter(Mandatory = $true)]
        [string]$RemoteResultDirectory
    )

    $ControllerIP = Get-ControllerSourceAddress -Target $Target
    $Baseline445 = Test-TcpPortFast -ComputerName $Target -Port 445
    $FirewallRuleName = "FI-Gate1-Validator-SMB-$RunID"
    $FirewallAdded = $false
    $OriginalDetailedFileShare = Get-RemoteAuditSetting -PSSession $PSSession -Subcategory 'Detailed File Share'
    $AuditChanged = $false

    if ($GovernedRoot -notmatch '^(?<drive>[A-Za-z]):\\(?<rest>.*)$') {
        throw "True remote SMB validation currently requires a local drive-letter governed root. Observed: $GovernedRoot"
    }
    $Drive = $Matches.drive.ToUpperInvariant()
    $Rest = $Matches.rest
    $UNCPath = "\\$Target\$Drive`$"
    if ($Rest) { $UNCPath += "\$Rest" }

    try {
        Write-Host "[INFO] TCP/445 baseline reachable: $Baseline445"

        if ($OriginalDetailedFileShare -ne 3) {
            Write-Host "[INFO] Temporarily enabling Detailed File Share Success/Failure auditing; original setting value=$OriginalDetailedFileShare."
            Set-RemoteAuditSetting -PSSession $PSSession -Subcategory 'Detailed File Share' -Setting 3
            $AuditChanged = $true
            $TemporaryChanges.Add([PSCustomObject]@{ Name='Detailed File Share audit policy'; Action='Temporarily set Success and Failure'; Restored=$false })
        }

        if (-not $Baseline445) {
            $NetworkCategory = Invoke-Command -Session $PSSession -ScriptBlock {
                $Profile = Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -ne 'Disconnected' } | Select-Object -First 1
                if ($null -eq $Profile) { return '' }
                return [string]$Profile.NetworkCategory
            }
            if ($NetworkCategory -ne 'DomainAuthenticated') {
                throw "TCP/445 is blocked and the target is not on a DomainAuthenticated profile. Refusing to create a broader temporary SMB rule. Observed profile: $NetworkCategory"
            }

            Invoke-Command -Session $PSSession -ArgumentList @($FirewallRuleName,$ControllerIP) -ScriptBlock {
                param($RuleName,$ControllerIP)
                if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) {
                    throw "Temporary firewall rule already exists: $RuleName"
                }
                New-NetFirewallRule -Name $RuleName -DisplayName $RuleName -Description 'Temporary FI Gate 1 validator true-remote SMB rule.' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 -RemoteAddress $ControllerIP -Profile Domain -Enabled True | Out-Null
            }
            $FirewallAdded = $true
            $TemporaryChanges.Add([PSCustomObject]@{ Name='Temporary SMB firewall rule'; Action="Allow TCP/445 from $ControllerIP only"; Restored=$false })

            $Started = Get-Date
            $Timeout = 30
            $NextHeartbeat = $Started.AddSeconds(10)
            $Opened = $false
            while ((Get-Date) -lt $Started.AddSeconds($Timeout)) {
                if (Test-TcpPortFast -ComputerName $Target -Port 445) { $Opened = $true; break }
                $Now = Get-Date
                if ($Now -ge $NextHeartbeat) {
                    $Elapsed = [int](($Now - $Started).TotalSeconds)
                    $Remaining = [Math]::Max(0,$Timeout - $Elapsed)
                    Write-Host "[INFO] Waiting for TCP/445: ${Elapsed}s elapsed / ${Timeout}s timeout; ${Remaining}s remaining."
                    $NextHeartbeat = $NextHeartbeat.AddSeconds(10)
                }
                Start-Sleep -Seconds 2
            }
            if (-not $Opened) { throw 'TCP/445 did not become reachable after the temporary scoped firewall rule.' }
        }

        if (-not (Test-Path -LiteralPath $UNCPath -PathType Container)) {
            throw "Governed root is not reachable through administrative SMB path: $UNCPath"
        }

        $WorkloadStarted = [DateTime]::UtcNow
        & $Local10B -UNCPath $UNCPath -ResultDirectory $ClientRawPath -ConfirmWorkload

        $ClientReportFile = Get-ChildItem -LiteralPath $ClientRawPath -Filter 'gate1-remote-smb-*.json' -File |
            Where-Object { $_.LastWriteTimeUtc -ge $WorkloadStarted.AddMinutes(-1) } |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($null -eq $ClientReportFile) { throw '10B did not produce a client report.' }

        $ClientReport = Get-Content -LiteralPath $ClientReportFile.FullName -Raw | ConvertFrom-Json
        $RemoteRunID = [string]$ClientReport.RunID
        $FinishedUTC = [DateTime]::Parse(
            [string]$ClientReport.FinishedUTC,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()

        $Collection = Wait-ForConfiguredCollectionAfter -PSSession $PSSession -AfterUTC $FinishedUTC -TimeoutSeconds 180
        if ($null -eq $Collection) { throw 'No post-SMB configured collection was observed within 180 seconds.' }
        if ([string]$Collection.outcome -ne 'Complete') {
            throw "Post-SMB configured collection was not Complete. Outcome=$($Collection.outcome)"
        }

        Invoke-RemotePowerShellFile -PSSession $PSSession -Path $Remote10C -Arguments @(
            '-RunID',$RemoteRunID,
            '-LookbackMinutes','60',
            '-MaxEvents','20000',
            '-ResultDirectory',$RemoteResultDirectory
        ) -CapturePath (Join-Path $RemoteResultDirectory '10C-output.txt')

        $CorrelationPath = Invoke-Command -Session $PSSession -ArgumentList @($RemoteResultDirectory,$RemoteRunID) -ScriptBlock {
            param($RemoteResultDirectory,$RemoteRunID)
            $Expected = Join-Path $RemoteResultDirectory "gate1-remote-smb-correlation-$($env:COMPUTERNAME)-$($RemoteRunID.ToLowerInvariant()).json"
            if (-not (Test-Path -LiteralPath $Expected -PathType Leaf)) { throw "10C report missing: $Expected" }
            return $Expected
        }

        $CorrelationLocal = Join-Path $ServerRawPath ([IO.Path]::GetFileName([string]$CorrelationPath))
        Copy-Item -FromSession $PSSession -LiteralPath ([string]$CorrelationPath) -Destination $CorrelationLocal -Force
        $Correlation = Get-Content -LiteralPath $CorrelationLocal -Raw | ConvertFrom-Json

        if ([bool]$Correlation.SecurityQueryMayBeTruncated) { throw '10C Security query may be truncated.' }
        if ([int]$Correlation.Event5145Count -lt 1) { throw 'No matching true-remote Event ID 5145 was observed.' }
        if ([int]$Correlation.SpoolMatchTotal -lt 1) { throw 'No matching FI spool activity was observed.' }

        return "RunID=$RemoteRunID; Event5145=$($Correlation.Event5145Count); SpoolMatches=$($Correlation.SpoolMatchTotal); baseline445=$Baseline445"
    }
    finally {
        $RestoreErrors = New-Object System.Collections.Generic.List[string]

        if ($FirewallAdded) {
            try {
                Invoke-Command -Session $PSSession -ArgumentList $FirewallRuleName -ScriptBlock {
                    param($RuleName)
                    if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) {
                        Remove-NetFirewallRule -Name $RuleName -ErrorAction Stop
                    }
                    if (Get-NetFirewallRule -Name $RuleName -ErrorAction SilentlyContinue) {
                        throw "Temporary firewall rule still exists: $RuleName"
                    }
                }

                $Started = Get-Date
                $Timeout = 30
                $NextHeartbeat = $Started.AddSeconds(10)
                $Restored = $false
                while ((Get-Date) -lt $Started.AddSeconds($Timeout)) {
                    $Current = Test-TcpPortFast -ComputerName $Target -Port 445
                    if ($Current -eq $Baseline445) { $Restored = $true; break }
                    $Now = Get-Date
                    if ($Now -ge $NextHeartbeat) {
                        $Elapsed = [int](($Now - $Started).TotalSeconds)
                        $Remaining = [Math]::Max(0,$Timeout - $Elapsed)
                        Write-Host "[INFO] Restoring TCP/445 baseline: ${Elapsed}s elapsed / ${Timeout}s timeout; ${Remaining}s remaining."
                        $NextHeartbeat = $NextHeartbeat.AddSeconds(10)
                    }
                    Start-Sleep -Seconds 2
                }
                if (-not $Restored) { throw "TCP/445 did not return to baseline state $Baseline445 after temporary rule removal." }

                $Change = $TemporaryChanges | Where-Object { $_.Name -eq 'Temporary SMB firewall rule' } | Select-Object -Last 1
                if ($null -ne $Change) { $Change.Restored = $true }
                Write-Host "[PASS] TCP/445 returned to baseline state: $Baseline445"
            }
            catch {
                $RestoreErrors.Add("Temporary SMB firewall restoration: $($_.Exception.Message)")
            }
        }

        if ($AuditChanged) {
            try {
                Set-RemoteAuditSetting -PSSession $PSSession -Subcategory 'Detailed File Share' -Setting $OriginalDetailedFileShare
                $RestoredAudit = Get-RemoteAuditSetting -PSSession $PSSession -Subcategory 'Detailed File Share'
                if ($RestoredAudit -ne $OriginalDetailedFileShare) {
                    throw "Expected audit setting $OriginalDetailedFileShare after restoration; observed $RestoredAudit."
                }
                $Change = $TemporaryChanges | Where-Object { $_.Name -eq 'Detailed File Share audit policy' } | Select-Object -Last 1
                if ($null -ne $Change) { $Change.Restored = $true }
                Write-Host "[PASS] Detailed File Share audit policy restored to setting value $OriginalDetailedFileShare."
            }
            catch {
                $RestoreErrors.Add("Detailed File Share audit policy restoration: $($_.Exception.Message)")
            }
        }

        if ($RestoreErrors.Count -ne 0) {
            throw ($RestoreErrors -join ' | ')
        }
    }
}

function Save-RemoteResultFiles {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,
        [Parameter(Mandatory = $true)]
        [string]$RemoteResultDirectory
    )

    $Files = @(Invoke-Command -Session $PSSession -ArgumentList $RemoteResultDirectory -ScriptBlock {
        param($RemoteResultDirectory)
        if (-not (Test-Path -LiteralPath $RemoteResultDirectory -PathType Container)) { return @() }
        $Root = $RemoteResultDirectory.TrimEnd('\') + '\'
        Get-ChildItem -LiteralPath $RemoteResultDirectory -File -Recurse | ForEach-Object {
            [PSCustomObject]@{
                FullName = $_.FullName
                RelativePath = $_.FullName.Substring($Root.Length)
            }
        }
    })

    foreach ($File in $Files) {
        $Destination = Join-Path $ServerRawPath ([string]$File.RelativePath)
        New-Item -Path (Split-Path -Parent $Destination) -ItemType Directory -Force | Out-Null
        Write-Host "[INFO] Saving server artifact: $($File.RelativePath)"
        Copy-Item -FromSession $PSSession -LiteralPath ([string]$File.FullName) -Destination $Destination -Force
    }
}

function Write-SHA256Manifest {
    $Lines = New-Object System.Collections.Generic.List[string]
    $Files = Get-ChildItem -LiteralPath $Save -File -Recurse | Where-Object { $_.FullName -ne $HashPath } | Sort-Object FullName
    foreach ($File in $Files) {
        $Hash = (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $Relative = $File.FullName.Substring($Save.Length).TrimStart('\')
        $Lines.Add("$Hash  $Relative")
    }
    $Lines | Set-Content -LiteralPath $HashPath -Encoding ASCII
}

try {
    Start-Transcript -LiteralPath $TranscriptPath -Force | Out-Null
    $TranscriptStarted = $true

    Write-Section 'FI GATE 1 VALIDATOR'
    Write-Host "Server: $Server"
    Write-Host "Save:   $Save"
    Write-Host "Run ID: $RunID"
    Write-Host "Mode:   $StartAt"
    Write-Host ''
    Write-Host 'The validator discovers FI configuration and service identities from the target.'
    Write-Host 'Temporary test prerequisites are restored before the run completes.'
    Write-Host 'No Git commit, push, branch, PR, or repository setting is changed.'

    Invoke-ValidationStep -Name 'Repository and validator preflight' -Action {
        if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot '.git') -PathType Container)) {
            throw "Validator must run from an FI Git working tree. Repository root: $RepoRoot"
        }
        Push-Location $RepoRoot
        try {
            $script:RepoHead = (git rev-parse HEAD).Trim()
            if ($LASTEXITCODE -ne 0) { throw 'git rev-parse HEAD failed.' }
            $script:RepoStatus = @(git status --porcelain)
            if ($RequireCleanRepository -and $script:RepoStatus.Count -ne 0) {
                throw 'Repository working tree is not clean and -RequireCleanRepository was supplied.'
            }
        }
        finally {
            Pop-Location
        }

        if ($StartAt -eq 'Full') {
            $script:BoundaryProbeLocal = Build-CollectorBoundaryProbe
            $script:BoundaryProbeHash = (Get-FileHash -LiteralPath $script:BoundaryProbeLocal -Algorithm SHA256).Hash.ToUpperInvariant()

            if (-not $SkipContainment) {
                $script:ProbeLocal = Build-ContainmentProbe -RequestedPath $ContainmentProbePath
                $script:ProbeHash = (Get-FileHash -LiteralPath $script:ProbeLocal -Algorithm SHA256).Hash.ToUpperInvariant()
            }
        }

        "HEAD=$script:RepoHead; dirty_paths=$($script:RepoStatus.Count); start_at=$StartAt; boundary_probe_sha256=$script:BoundaryProbeHash; containment_probe_sha256=$script:ProbeHash"
    }

    Invoke-ValidationStep -Name 'Connect and discover target configuration' -Action {
        $SessionOption = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 240000
        $script:Session = New-PSSession -ComputerName $Server -SessionOption $SessionOption -ErrorAction Stop

        $script:RemoteState = Invoke-Command -Session $script:Session -ScriptBlock {
            $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $ConfigPath = 'C:\ProgramData\FI\config\fi.conf'
            if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "FI config not found: $ConfigPath" }
            $ConfigRaw = Get-Content -LiteralPath $ConfigPath -Raw
            $Roots = New-Object System.Collections.Generic.List[string]
            foreach ($Line in ($ConfigRaw -split "`r?`n")) {
                $Match = [regex]::Match($Line,'^\s*governed_root\s*:\s*(.+?)\s*$')
                if ($Match.Success -and $Match.Groups[1].Value.Trim()) { $Roots.Add($Match.Groups[1].Value.Trim()) }
            }
            if ($Roots.Count -ne 1) { throw "Validator currently requires exactly one governed_root; observed $($Roots.Count)." }

            function Resolve-ServiceBinaryPath {
                param([string]$PathName)
                $Match = [regex]::Match($PathName,'^\s*"([^"]+\.exe)"','IgnoreCase')
                if (-not $Match.Success) { $Match = [regex]::Match($PathName,'^\s*([^\s]+\.exe)','IgnoreCase') }
                if (-not $Match.Success) { throw "Could not resolve executable from service PathName: $PathName" }
                return $Match.Groups[1].Value
            }

            $Collector = Get-CimInstance Win32_Service -Filter "Name='FICollector'" -ErrorAction Stop
            $Helper = Get-CimInstance Win32_Service -Filter "Name='FIUSNReader'" -ErrorAction Stop
            $CollectorBinary = Resolve-ServiceBinaryPath -PathName ([string]$Collector.PathName)
            $HelperBinary = Resolve-ServiceBinaryPath -PathName ([string]$Helper.PathName)
            if (-not (Test-Path -LiteralPath $CollectorBinary -PathType Leaf)) { throw "Collector binary missing: $CollectorBinary" }
            if (-not (Test-Path -LiteralPath $HelperBinary -PathType Leaf)) { throw "Helper binary missing: $HelperBinary" }

            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                WindowsCaption = [string]$OS.Caption
                WindowsVersion = [string]$OS.Version
                WindowsBuild = [string]$OS.BuildNumber
                ConfigPath = $ConfigPath
                ConfigSHA256 = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash.ToUpperInvariant()
                GovernedRoot = [string]$Roots[0]
                CollectorAccount = [string]$Collector.StartName
                CollectorPathName = [string]$Collector.PathName
                CollectorBinary = $CollectorBinary
                CollectorSHA256 = (Get-FileHash -LiteralPath $CollectorBinary -Algorithm SHA256).Hash.ToUpperInvariant()
                CollectorState = [string]$Collector.State
                CollectorStartMode = [string]$Collector.StartMode
                HelperAccount = [string]$Helper.StartName
                HelperPathName = [string]$Helper.PathName
                HelperBinary = $HelperBinary
                HelperSHA256 = (Get-FileHash -LiteralPath $HelperBinary -Algorithm SHA256).Hash.ToUpperInvariant()
                HelperState = [string]$Helper.State
                HelperStartMode = [string]$Helper.StartMode
                PipePresent = [bool](Test-Path '\\.\pipe\FI-USN')
            }
        }

        if (-not $Profiles.Builds.ContainsKey([string]$script:RemoteState.WindowsBuild)) {
            throw "Uncharacterized Windows build $($script:RemoteState.WindowsBuild)."
        }
        $script:Profile = $Profiles.Builds[[string]$script:RemoteState.WindowsBuild]
        if ($Version -and ([string]$script:Profile.Version -ne $Version)) {
            throw "-Version $Version does not match detected release $($script:Profile.Version) / build $($script:RemoteState.WindowsBuild)."
        }
        if ([string]$script:RemoteState.CollectorSHA256 -ne $ExpectedCollectorHash) {
            throw "Collector SHA256 mismatch. Expected $ExpectedCollectorHash; observed $($script:RemoteState.CollectorSHA256)."
        }
        if ([string]$script:RemoteState.HelperSHA256 -ne $ExpectedHelperHash) {
            throw "Helper SHA256 mismatch. Expected $ExpectedHelperHash; observed $($script:RemoteState.HelperSHA256)."
        }
        if ([string]$script:RemoteState.CollectorAccount -ieq [string]$script:RemoteState.HelperAccount) {
            throw "Collector and helper use the same identity: $($script:RemoteState.CollectorAccount)"
        }
        if ([string]$script:RemoteState.CollectorState -ne 'Running') { throw 'FICollector is not Running.' }
        if ([string]$script:RemoteState.HelperState -ne 'Running') { throw 'FIUSNReader is not Running.' }
        if (-not [bool]$script:RemoteState.PipePresent) { throw 'FI-USN pipe is not present.' }

        $script:RemoteState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $StatePath -Encoding UTF8
        "$($script:Profile.Release) build $($script:RemoteState.WindowsBuild); root=$($script:RemoteState.GovernedRoot); collector=$($script:RemoteState.CollectorAccount); helper=$($script:RemoteState.HelperAccount)"
    }

    Write-Section 'DISCOVERED TARGET'
    Write-Host "Target:          $($RemoteState.ComputerName)"
    Write-Host "Release:         $($Profile.Release)"
    Write-Host "Build:           $($RemoteState.WindowsBuild)"
    Write-Host "Governed root:   $($RemoteState.GovernedRoot)"
    Write-Host "Collector gMSA:  $($RemoteState.CollectorAccount)"
    Write-Host "Helper gMSA:     $($RemoteState.HelperAccount)"
    Write-Host "Collector hash:  $($RemoteState.CollectorSHA256)"
    Write-Host "Helper hash:     $($RemoteState.HelperSHA256)"

    Invoke-ValidationStep -Name 'Stage current Gate 1 test kit' -Action {
        $RemoteBase = "C:\ProgramData\FI\gate1-validator\$RunID"
        $RemoteRepo = Join-Path $RemoteBase 'repo'
        $RemoteToolsRoot = Join-Path $RemoteRepo 'tools'
        $RemoteResults = "C:\ProgramData\FI\gate1-results\validator-$RunID"

        Invoke-Command -Session $Session -ArgumentList @($RemoteToolsRoot,$RemoteResults) -ScriptBlock {
            param($RemoteToolsRoot,$RemoteResults)
            New-Item -Path $RemoteToolsRoot -ItemType Directory -Force | Out-Null
            New-Item -Path $RemoteResults -ItemType Directory -Force | Out-Null
        }

        Copy-Item -LiteralPath (Join-Path $RepoRoot 'tools\gate1') -Destination $RemoteToolsRoot -ToSession $Session -Recurse -Force
        Copy-Item -LiteralPath (Join-Path $RepoRoot 'tools\scripts') -Destination $RemoteToolsRoot -ToSession $Session -Recurse -Force

        Set-Variable -Name RemoteBase -Value $RemoteBase -Scope Script
        Set-Variable -Name RemoteRepo -Value $RemoteRepo -Scope Script
        Set-Variable -Name RemoteResults -Value $RemoteResults -Scope Script
        Set-Variable -Name RemoteGate1 -Value (Join-Path $RemoteToolsRoot 'gate1') -Scope Script
        Set-Variable -Name RemoteScripts -Value (Join-Path $RemoteToolsRoot 'scripts') -Scope Script
        "remote_results=$RemoteResults"
    }

    if ($StartAt -eq 'Full') {
            Invoke-ValidationStep -Name 'Exact deployment and service boundary' -Action {
                Invoke-RemotePowerShellFile -PSSession $Session -Path (Join-Path $script:RemoteGate1 '11-FileServer-Deployment-Acceptance.ps1') -Arguments @(
                    '-GovernedRoot',[string]$RemoteState.GovernedRoot,
                    '-ResultDirectory',$script:RemoteResults
                ) -CapturePath (Join-Path $script:RemoteResults '11-output.txt')

                Invoke-CollectorBoundaryCheck -PSSession $Session -ProbePath $script:BoundaryProbeLocal -RemoteTest08 (Join-Path $script:RemoteScripts '08-FileServer-Collector-Boundary.ps1') -RemoteResultDirectory $script:RemoteResults
                "deployment acceptance + common current Test 08; boundary_probe_sha256=$script:BoundaryProbeHash"
            }

            $ProtectedContainmentApplicable = @('2022','2025') -contains [string]$Profile.Version
            if ($SkipContainment) {
                $Now = [DateTime]::UtcNow
                Add-StepResult -Name 'Production protected-object containment' -Status 'SKIP' -Started $Now -Detail 'Skipped by -SkipContainment.'
                Write-Host '[SKIP] Production protected-object containment - skipped by -SkipContainment.'
            }
            elseif (-not $ProtectedContainmentApplicable) {
                $Now = [DateTime]::UtcNow
                $Detail = "Not applicable to $($Profile.Release) build $($RemoteState.WindowsBuild); the protected RtBackup production containment acceptance is release-specific to Server 2022/2025."
                Add-StepResult -Name 'Production protected-object containment' -Status 'SKIP' -Started $Now -Detail $Detail
                Write-Host "[SKIP] Production protected-object containment - $Detail"
            }
            else {
                Invoke-ValidationStep -Name 'Production protected-object containment' -Action {
                    $Containment = Invoke-ProductionContainmentCheck -PSSession $Session -ProbePath $script:ProbeLocal -GovernedRoot ([string]$RemoteState.GovernedRoot) -RemoteResultDirectory $script:RemoteResults
                    "result=$($Containment.BrokerResult); FRN=$($Containment.FileReferenceNumber); sequence=$($Containment.SequenceNumber); probe_sha256=$script:ProbeHash"
                }
            }

            Invoke-ValidationStep -Name 'Local governed activity and Security/FI correlation' -Action {
                Invoke-LocalActivityWithPrerequisites -PSSession $Session -Remote10A (Join-Path $script:RemoteGate1 '10A-FileServer-Activity-Matrix.ps1') -GovernedRoot ([string]$RemoteState.GovernedRoot) -RemoteResultDirectory $script:RemoteResults
                '10A complete; temporary audit prerequisites restored'
            }

            if (-not $SkipRecovery) {
                Invoke-ValidationStep -Name 'Collector restart and USN catch-up' -Action {
                    Invoke-RemotePowerShellFile -PSSession $Session -Path (Join-Path $script:RemoteGate1 '12A-FileServer-Collector-Restart-Recovery.ps1') -Arguments @(
                        '-GovernedRoot',[string]$RemoteState.GovernedRoot,
                        '-ResultDirectory',$script:RemoteResults,
                        '-ConfirmDisruptive'
                    ) -CapturePath (Join-Path $script:RemoteResults '12A-output.txt')
                    'collector restart/catch-up passed'
                }

                Invoke-ValidationStep -Name 'Helper outage, checkpoint freeze, and catch-up' -Action {
                    Invoke-RemotePowerShellFile -PSSession $Session -Path (Join-Path $script:RemoteScripts '04-FileServer-Failure-Recovery.ps1') -Arguments @(
                        '-GovernedRoot',[string]$RemoteState.GovernedRoot,
                        '-ConfirmDisruptive'
                    ) -CapturePath (Join-Path $script:RemoteResults '04-helper-outage-output.txt')
                    'helper outage/freeze/catch-up passed'
                }
            }
            else {
                foreach ($Name in @('Collector restart and USN catch-up','Helper outage, checkpoint freeze, and catch-up')) {
                    $Now = [DateTime]::UtcNow
                    Add-StepResult -Name $Name -Status 'SKIP' -Started $Now -Detail 'Skipped by -SkipRecovery.'
                    Write-Host "[SKIP] $Name"
                }
            }

    }
    else {
        foreach ($ResumeSkip in @(
            'Exact deployment and service boundary',
            'Production protected-object containment',
            'Local governed activity and Security/FI correlation',
            'Collector restart and USN catch-up',
            'Helper outage, checkpoint freeze, and catch-up'
        )) {
            $Now = [DateTime]::UtcNow
            Add-StepResult -Name $ResumeSkip -Status 'SKIP' -Started $Now -Detail 'Resume mode: not re-executed in this run.'
            Write-Host "[SKIP] $ResumeSkip - resume mode"
        }
    }

    if (-not $SkipRemoteSMB) {
        Invoke-ValidationStep -Name 'True remote SMB and server-side correlation' -Action {
            Invoke-RemoteSMBValidation -PSSession $Session -Target $Server -GovernedRoot ([string]$RemoteState.GovernedRoot) -Remote10C (Join-Path $script:RemoteGate1 '10C-FileServer-Remote-SMB-Correlation.ps1') -RemoteResultDirectory $script:RemoteResults
        }
    }
    else {
        $Now = [DateTime]::UtcNow
        Add-StepResult -Name 'True remote SMB and server-side correlation' -Status 'SKIP' -Started $Now -Detail 'Skipped by -SkipRemoteSMB.'
        Write-Host '[SKIP] True remote SMB and server-side correlation'
    }

    Invoke-ValidationStep -Name 'Final exact state and artifact collection' -Action {
        $Final = Invoke-Command -Session $Session -ArgumentList @(
            $ExpectedCollectorHash,
            $ExpectedHelperHash,
            [string]$RemoteState.CollectorPathName,
            [string]$RemoteState.HelperPathName,
            [string]$RemoteState.CollectorAccount,
            [string]$RemoteState.HelperAccount,
            [string]$RemoteState.ConfigSHA256
        ) -ScriptBlock {
            param(
                $ExpectedCollectorHash,
                $ExpectedHelperHash,
                $ExpectedCollectorPathName,
                $ExpectedHelperPathName,
                $ExpectedCollectorAccount,
                $ExpectedHelperAccount,
                $ExpectedConfigSHA256
            )
            $Collector = Get-CimInstance Win32_Service -Filter "Name='FICollector'" -ErrorAction Stop
            $Helper = Get-CimInstance Win32_Service -Filter "Name='FIUSNReader'" -ErrorAction Stop

            function Resolve-ServiceBinaryPath {
                param([string]$PathName)
                $Match = [regex]::Match($PathName,'^\s*"([^"]+\.exe)"','IgnoreCase')
                if (-not $Match.Success) { $Match = [regex]::Match($PathName,'^\s*([^\s]+\.exe)','IgnoreCase') }
                if (-not $Match.Success) { throw "Could not resolve service executable: $PathName" }
                return $Match.Groups[1].Value
            }

            $CollectorBinary = Resolve-ServiceBinaryPath -PathName ([string]$Collector.PathName)
            $HelperBinary = Resolve-ServiceBinaryPath -PathName ([string]$Helper.PathName)
            $CollectorHash = (Get-FileHash -LiteralPath $CollectorBinary -Algorithm SHA256).Hash.ToUpperInvariant()
            $HelperHash = (Get-FileHash -LiteralPath $HelperBinary -Algorithm SHA256).Hash.ToUpperInvariant()

            $ConfigSHA256 = (Get-FileHash -LiteralPath 'C:\ProgramData\FI\config\fi.conf' -Algorithm SHA256).Hash.ToUpperInvariant()

            [PSCustomObject]@{
                CollectorSHA256 = $CollectorHash
                HelperSHA256 = $HelperHash
                CollectorState = [string]$Collector.State
                HelperState = [string]$Helper.State
                CollectorPathName = [string]$Collector.PathName
                HelperPathName = [string]$Helper.PathName
                CollectorAccount = [string]$Collector.StartName
                HelperAccount = [string]$Helper.StartName
                ConfigSHA256 = $ConfigSHA256
                PipePresent = [bool](Test-Path '\\.\pipe\FI-USN')
                HashesMatch = ($CollectorHash -eq $ExpectedCollectorHash -and $HelperHash -eq $ExpectedHelperHash)
                ServiceConfigurationMatch = (
                    [string]$Collector.PathName -eq $ExpectedCollectorPathName -and
                    [string]$Helper.PathName -eq $ExpectedHelperPathName -and
                    [string]$Collector.StartName -eq $ExpectedCollectorAccount -and
                    [string]$Helper.StartName -eq $ExpectedHelperAccount
                )
                ConfigUnchanged = ($ConfigSHA256 -eq $ExpectedConfigSHA256)
            }
        }

        if (-not [bool]$Final.HashesMatch) { throw 'Final FI executable hashes do not match the exact Gate 1 pair.' }
        if (-not [bool]$Final.ServiceConfigurationMatch) { throw 'Final FI service PathName or service identity differs from the discovered pre-test state.' }
        if (-not [bool]$Final.ConfigUnchanged) { throw 'FI config changed during validation.' }
        if ([string]$Final.CollectorState -ne 'Running') { throw 'FICollector is not Running in final state.' }
        if ([string]$Final.HelperState -ne 'Running') { throw 'FIUSNReader is not Running in final state.' }
        if (-not [bool]$Final.PipePresent) { throw 'FI-USN pipe is missing in final state.' }

        Save-RemoteResultFiles -PSSession $Session -RemoteResultDirectory $script:RemoteResults
        $script:ArtifactsSaved = $true
        'exact hashes/config/service identities/PathName unchanged; services Running; pipe present; raw artifacts saved'
    }

    $Unrestored = @($TemporaryChanges | Where-Object { -not $_.Restored })
    if ($Unrestored.Count -ne 0) {
        throw "One or more temporary validator changes were not restored: $(($Unrestored.Name) -join ', ')"
    }

    if ($StartAt -eq 'Full') {
        $OverallStatus = 'PASS'
    }
    else {
        $OverallStatus = 'PASS_PARTIAL'
    }
}
catch {
    $ValidationError = $_.Exception.Message
    $OverallStatus = 'FAIL'
    Write-Host ''
    Write-Host "[FAIL] VALIDATION STOPPED: $ValidationError"
}
finally {
    if ($null -ne $Session) {
        try {
            if (
                -not $script:ArtifactsSaved -and
                (Get-Variable -Name RemoteResults -Scope Script -ErrorAction SilentlyContinue)
            ) {
                Save-RemoteResultFiles -PSSession $Session -RemoteResultDirectory $script:RemoteResults
            }
        }
        catch {
            Write-Host "[INFO] Partial server-artifact collection warning: $($_.Exception.Message)"
        }

        try {
            if (Get-Variable -Name RemoteBase -Scope Script -ErrorAction SilentlyContinue) {
                Invoke-Command -Session $Session -ArgumentList $script:RemoteBase -ScriptBlock {
                    param($RemoteBase)
                    Remove-Item -LiteralPath $RemoteBase -Recurse -Force -ErrorAction SilentlyContinue
                } -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch {
            Write-Host "[INFO] Remote validator staging cleanup warning: $($_.Exception.Message)"
        }
        Remove-PSSession $Session -ErrorAction SilentlyContinue
    }

    $FinishedUTC = [DateTime]::UtcNow
    $Report = [PSCustomObject]@{
        RecordKind = 'FIGate1UnifiedValidation'
        SchemaVersion = 1
        RunID = $RunID
        OverallStatus = $OverallStatus
        Error = $ValidationError
        StartedUTC = $StartedUTC.ToString('o')
        FinishedUTC = $FinishedUTC.ToString('o')
        DurationSeconds = [Math]::Round(($FinishedUTC - $StartedUTC).TotalSeconds,3)
        Controller = $env:COMPUTERNAME
        Target = $Server
        RequestedVersion = $Version
        RunMode = $StartAt
        DetectedRelease = if ($null -ne $Profile) { [string]$Profile.Release } else { '' }
        DetectedBuild = if ($null -ne $RemoteState) { [string]$RemoteState.WindowsBuild } else { '' }
        GovernedRoot = if ($null -ne $RemoteState) { [string]$RemoteState.GovernedRoot } else { '' }
        CollectorAccount = if ($null -ne $RemoteState) { [string]$RemoteState.CollectorAccount } else { '' }
        HelperAccount = if ($null -ne $RemoteState) { [string]$RemoteState.HelperAccount } else { '' }
        ExpectedCollectorSHA256 = $ExpectedCollectorHash
        ExpectedHelperSHA256 = $ExpectedHelperHash
        ObservedCollectorSHA256 = if ($null -ne $RemoteState) { [string]$RemoteState.CollectorSHA256 } else { '' }
        ObservedHelperSHA256 = if ($null -ne $RemoteState) { [string]$RemoteState.HelperSHA256 } else { '' }
        ContainmentProbeSHA256 = $ProbeHash
        CollectorBoundaryProbeSHA256 = $BoundaryProbeHash
        RepositoryHEAD = $RepoHead
        RepositoryDirtyPathCount = @($RepoStatus).Count
        RepositoryStatus = @($RepoStatus)
        TemporaryChanges = $TemporaryChanges.ToArray()
        TemporaryChangesRestored = (@($TemporaryChanges | Where-Object { -not $_.Restored }).Count -eq 0)
        Steps = $Steps.ToArray()
        SaveDirectory = $Save
    }
    $Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

    $SummaryLines = New-Object System.Collections.Generic.List[string]
    $SummaryLines.Add('FI GATE 1 VALIDATION SUMMARY')
    $SummaryLines.Add('')
    $SummaryLines.Add("Overall:         $OverallStatus")
    $SummaryLines.Add("Target:          $Server")
    if ($null -ne $Profile) { $SummaryLines.Add("Release:         $($Profile.Release)") }
    if ($null -ne $RemoteState) {
        $SummaryLines.Add("Build:           $($RemoteState.WindowsBuild)")
        $SummaryLines.Add("Governed root:   $($RemoteState.GovernedRoot)")
        $SummaryLines.Add("Collector gMSA:  $($RemoteState.CollectorAccount)")
        $SummaryLines.Add("Helper gMSA:     $($RemoteState.HelperAccount)")
    }
    $SummaryLines.Add("Repository HEAD: $RepoHead")
    $SummaryLines.Add("Run ID:          $RunID")
    $SummaryLines.Add("Run mode:        $StartAt")
    $SummaryLines.Add('')
    $SummaryLines.Add('Steps:')
    foreach ($Step in $Steps) {
        $SummaryLines.Add(('{0,-52} {1,-5} {2,8:N1}s  {3}' -f $Step.Name,$Step.Status,[double]$Step.DurationSeconds,$Step.Detail))
    }
    if ($ValidationError) {
        $SummaryLines.Add('')
        $SummaryLines.Add("Error: $ValidationError")
    }
    $SummaryLines.Add('')
    $SummaryLines.Add("Temporary changes restored: $($Report.TemporaryChangesRestored)")
    $SummaryLines.Add("JSON report: $ReportPath")
    $SummaryLines | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

    Write-Section "VALIDATION RESULT: $OverallStatus"
    $Steps | Select-Object Name,Status,DurationSeconds,Detail | Format-Table -AutoSize
    Write-Host ''
    Write-Host "Summary: $SummaryPath"
    Write-Host "Report:  $ReportPath"
    Write-Host "Raw:     $RawPath"

    if ($TranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
    }

    try { Write-SHA256Manifest } catch { Write-Host "[INFO] SHA256 manifest warning: $($_.Exception.Message)" }
}

if (@('PASS','PASS_PARTIAL') -notcontains $OverallStatus) {
    exit 1
}
exit 0
