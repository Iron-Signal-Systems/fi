[CmdletBinding()]
param(
    [switch]$ConfirmSweep
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Common-Server2019-Sweep.ps1')

Assert-FI2019Controller

$Session = $null
$RunStartedUTC = [DateTime]::UtcNow
$SummaryPath = ''

try {
    $Session = New-FI2019Session
    $Preflight = Get-FI2019RemotePreflight -Session $Session

    Write-Host ''
    Write-Host '============================================================'
    Write-Host 'FI CANDIDATE #4 - SERVER 2019 SWEEP'
    Write-Host 'PRE-FLIGHT'
    Write-Host '============================================================'
    Write-Host "Controller:            $env:COMPUTERNAME"
    Write-Host "Target:                $($Preflight.Host)"
    Write-Host "OS:                    $($Preflight.OS)"
    Write-Host "Build:                 $($Preflight.Build)"
    Write-Host "Domain:                $($Preflight.Domain)"
    Write-Host "Secure channel:        $($Preflight.SecureChannel)"
    Write-Host "Governed root:         $($FI2019.GovernedRoot)"
    Write-Host "Collector gMSA admin:  $($Preflight.CollectorIsAdmin)"
    Write-Host "Helper gMSA admin:     $($Preflight.HelperIsAdmin)"
    Write-Host "Installed collector:   $($Preflight.InstalledCollectorSHA256)"
    Write-Host "Installed helper:      $($Preflight.InstalledHelperSHA256)"
    Write-Host "Collector Gate1:  $($Preflight.InstalledCollectorMatchesGate1)"
    Write-Host "Helper Gate1:     $($Preflight.InstalledHelperMatchesGate1)"
    Write-Host ''

    if (-not $ConfirmSweep) {
        Write-Host '[PASS] Read-only Server 2019 pre-flight passed.'
        Write-Host '[INFO] No server changes were made.'
        Write-Host '[INFO] Re-run with -ConfirmSweep to deploy exact Gate 1 build and execute the bounded acceptance sweep.'
        return
    }

    Write-Host '=== STAGE EXACT CANDIDATE #4 + CURRENT GATE 1 TOOLS ==='

    Invoke-Command -Session $Session -ArgumentList $FI2019.RemoteWorkRoot -ScriptBlock {
        param($WorkRoot)
        if (Test-Path -LiteralPath $WorkRoot) {
            Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction Stop
        }
        New-Item -Path $WorkRoot -ItemType Directory -Force | Out-Null
    }

    Copy-Item -ToSession $Session -LiteralPath $FI2019.LocalCollector -Destination $FI2019.RemoteCollector -Force
    Copy-Item -ToSession $Session -LiteralPath $FI2019.LocalHelper -Destination $FI2019.RemoteHelper -Force
    Copy-Item -ToSession $Session -LiteralPath (Join-Path $FI2019.RepoRoot 'tools') -Destination $FI2019.RemoteWorkRoot -Recurse -Force

    $Staged = Invoke-Command -Session $Session -ArgumentList @(
        $FI2019.RemoteCollector,$FI2019.RemoteHelper,
        $FI2019.CollectorSHA256,$FI2019.HelperSHA256
    ) -ScriptBlock {
        param($Collector,$Helper,$CollectorHash,$HelperHash)
        $C = (Get-FileHash -LiteralPath $Collector -Algorithm SHA256).Hash.ToUpperInvariant()
        $H = (Get-FileHash -LiteralPath $Helper -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($C -ne $CollectorHash) { throw "Remote staged collector hash mismatch: $C" }
        if ($H -ne $HelperHash) { throw "Remote staged helper hash mismatch: $H" }
        [PSCustomObject]@{CollectorSHA256=$C;HelperSHA256=$H}
    }

    Write-Host "[PASS] Remote collector SHA256: $($Staged.CollectorSHA256)"
    Write-Host "[PASS] Remote helper SHA256:    $($Staged.HelperSHA256)"

    Write-Host ''
    Write-Host '=== DEPLOY / REDEPLOY EXACT CANDIDATE #4 ==='
    Invoke-Command -Session $Session -ArgumentList @(
        $FI2019.RemoteToolsRoot,
        $FI2019.RemoteCollector,
        $FI2019.CollectorSHA256,
        $FI2019.RemoteHelper,
        $FI2019.HelperSHA256,
        $FI2019.CollectorAccount,
        $FI2019.HelperAccount,
        $FI2019.GovernedRoot
    ) -ScriptBlock {
        param($Tools,$Collector,$CollectorHash,$Helper,$HelperHash,$CollectorAccount,$HelperAccount,$GovernedRoot)

        $Deploy = Join-Path $Tools 'gate1\09-FileServer-Deploy-Test-Pair.ps1'
        & $Deploy `
            -CollectorCandidate $Collector `
            -CollectorSHA256 $CollectorHash `
            -HelperCandidate $Helper `
            -HelperSHA256 $HelperHash `
            -CollectorAccount $CollectorAccount `
            -HelperAccount $HelperAccount `
            -GovernedRoot $GovernedRoot `
            -ReplaceExistingFilesAndConfig `
            -ReconfigureExistingServices `
            -ConfirmDeploy
    }

    Write-Host ''
    Write-Host '=== ONE BOUNDED SERVER-SIDE ACCEPTANCE SWEEP ==='
    Write-Host '[INFO] Includes deployment boundary, local activity/Security/ReadSACL,'
    Write-Host '[INFO] baseline measurement, collector restart, helper outage/catch-up,'
    Write-Host '[INFO] and operation/resource summary. Stress/lab fault tests are NOT repeated.'

    Invoke-Command -Session $Session -ArgumentList @(
        $FI2019.RemoteToolsRoot,
        $FI2019.GovernedRoot,
        $FI2019.RemoteResultDirectory
    ) -ScriptBlock {
        param($Tools,$GovernedRoot,$ResultDirectory)

        $Runner = Join-Path $Tools 'gate1\Invoke-FIGate1-Readiness.ps1'
        & $Runner `
            -GovernedRoot $GovernedRoot `
            -ResultDirectory $ResultDirectory `
            -IncludeCollectorBoundary `
            -IncludeLocalActivity `
            -IncludePerformanceBaseline `
            -StopCollectorForPerformance `
            -IncludeCollectorRestart `
            -IncludeHelperOutage
    }

    Write-Host ''
    Write-Host '=== CANDIDATE #4 CONTENT-PREFIX CUSTODY CHECK ==='

    $Acceptance = Invoke-Command -Session $Session -ArgumentList @(
        $FI2019.RemoteResultDirectory
    ) -ScriptBlock {
        param($ResultDirectory)

        Set-StrictMode -Version 2.0
        $ErrorActionPreference = 'Stop'

        $ActivityFile = Get-ChildItem -LiteralPath $ResultDirectory -Filter 'gate1-activity-*.json' -File |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($null -eq $ActivityFile) {
            throw 'No 10A activity report was found after the sweep.'
        }

        $Activity = [IO.File]::ReadAllText($ActivityFile.FullName) | ConvertFrom-Json
        if (-not [bool]$Activity.WorkloadExecutionPass) {
            throw "Latest 10A activity report is not a PASS: $($ActivityFile.FullName)"
        }
        if ($null -eq $Activity.SACLCurrentStateValidation) {
            throw '10A did not preserve a live SACL current-state validation record.'
        }
        if ([string]$Activity.SACLCurrentStateValidation.State -ne 'Present') {
            throw "10A SACL current-state validation was not Present: $($Activity.SACLCurrentStateValidation.State)"
        }

        $RunID = [string]$Activity.RunID
        $FileName = "create-$RunID.txt"
        $FileNameBytes = [Text.Encoding]::Unicode.GetBytes($FileName)
        $FileNameToken = [Convert]::ToBase64String($FileNameBytes).TrimEnd('=').Replace('+','-').Replace('/','_')

        $ExpectedPrefixBytes = [Text.Encoding]::ASCII.GetBytes('FI Gate 1 create')
        if ($ExpectedPrefixBytes.Length -ne 16) {
            throw 'Internal acceptance error: expected prefix marker is not exactly 16 bytes.'
        }
        $ExpectedPrefix = [Convert]::ToBase64String($ExpectedPrefixBytes).TrimEnd('=').Replace('+','-').Replace('/','_')

        $Since = [DateTime]::Parse(
            [string]$Activity.StartedUTC,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime().AddMinutes(-1)

        $Spool = 'C:\ProgramData\FI\spool'
        $Directory = New-Object System.IO.DirectoryInfo -ArgumentList $Spool
        $BatchFiles = @(
            $Directory.EnumerateFiles('batch-*.jsonl',[IO.SearchOption]::TopDirectoryOnly) |
                Where-Object { $_.LastWriteTimeUtc -ge $Since } |
                Sort-Object LastWriteTimeUtc
        )
        if ($BatchFiles.Count -gt 1000) {
            throw "Content-prefix check exceeded the 1000 recent-batch bound: $($BatchFiles.Count)"
        }

        $Stopwatch = [Diagnostics.Stopwatch]::StartNew()
        $NextHeartbeat = 15
        $LinesRead = 0
        $Found = $null

        foreach ($File in $BatchFiles) {
            $LineNumber = 0
            foreach ($Line in [IO.File]::ReadLines($File.FullName)) {
                $LineNumber++
                $LinesRead++

                if ($LinesRead -gt 100000) {
                    throw 'Content-prefix check exceeded the 100000-line bound.'
                }
                if ($Stopwatch.Elapsed.TotalSeconds -ge 30) {
                    throw "Content-prefix check exceeded 30 seconds after $LinesRead lines."
                }
                if ($Stopwatch.Elapsed.TotalSeconds -ge $NextHeartbeat) {
                    Write-Host "[INFO] Content-prefix check: $LinesRead lines scanned; $([int]$Stopwatch.Elapsed.TotalSeconds)s elapsed."
                    $NextHeartbeat += 15
                }
                if (-not $Line.Contains($FileNameToken)) { continue }

                try {
                    $Record = $Line | ConvertFrom-Json
                    if ([string]$Record.record_kind -ne 'USNObjectObservation') { continue }
                    if ([string]$Record.payload.status -ne 'Observed') { continue }

                    $ExactName = $false
                    foreach ($Change in @($Record.payload.changes)) {
                        if ([string]$Change.file_name_utf16le_base64url -ceq $FileNameToken) {
                            $ExactName = $true
                            break
                        }
                    }
                    if (-not $ExactName) { continue }

                    $Prefix = $Record.payload.ntfs_observation.content_prefix
                    if ($null -eq $Prefix) { continue }
                    if (
                        [string]$Prefix.state -eq 'Present' -and
                        [string]$Prefix.bytes_observed -eq '16' -and
                        [string]$Prefix.prefix_base64url -ceq $ExpectedPrefix
                    ) {
                        $Found = [PSCustomObject]@{
                            SpoolPath = $File.FullName
                            LineNumber = $LineNumber
                            FileName = $FileName
                            State = [string]$Prefix.state
                            BytesObserved = [string]$Prefix.bytes_observed
                            PrefixBase64URL = [string]$Prefix.prefix_base64url
                            ExpectedPrefixBase64URL = $ExpectedPrefix
                        }
                        break
                    }
                }
                catch {
                    continue
                }
            }
            if ($null -ne $Found) { break }
        }

        if ($null -eq $Found) {
            throw "No exact Gate 1 build content-prefix record was found for $FileName."
        }

        $ReadinessFile = Get-ChildItem -LiteralPath $ResultDirectory -Filter 'gate1-readiness-*.json' -File |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($null -eq $ReadinessFile) {
            throw 'No readiness summary was found after the sweep.'
        }

        $Readiness = [IO.File]::ReadAllText($ReadinessFile.FullName) | ConvertFrom-Json
        $BadSteps = @($Readiness.Steps | Where-Object { $_.Status -ne 'PASS' })
        if ($BadSteps.Count -ne 0) {
            throw "Readiness summary contains $($BadSteps.Count) non-PASS step(s)."
        }

        [PSCustomObject]@{
            ActivityReport = $ActivityFile.FullName
            ActivityRunID = $RunID
            ActivityPass = [bool]$Activity.WorkloadExecutionPass
            ReadSACLState = [string]$Activity.SACLCurrentStateValidation.State
            ReadSACLDataFormat = [string]$Activity.SACLCurrentStateValidation.DataFormat
            ContentPrefix = $Found
            ReadinessReport = $ReadinessFile.FullName
            ReadinessSteps = $Readiness.Steps
            FICollector = (Get-Service FICollector).Status.ToString()
            FIUSNReader = (Get-Service FIUSNReader).Status.ToString()
            InstalledCollectorSHA256 = (Get-FileHash 'C:\Program Files\FI\fi.exe' -Algorithm SHA256).Hash.ToUpperInvariant()
            InstalledHelperSHA256 = (Get-FileHash 'C:\Program Files\FI\fi-usn.exe' -Algorithm SHA256).Hash.ToUpperInvariant()
        }
    }

    if ($Acceptance.InstalledCollectorSHA256 -ne $FI2019.CollectorSHA256) {
        throw 'Post-sweep installed collector hash is not Gate 1 build.'
    }
    if ($Acceptance.InstalledHelperSHA256 -ne $FI2019.HelperSHA256) {
        throw 'Post-sweep installed helper hash is not Gate 1 build.'
    }
    if ($Acceptance.FICollector -ne 'Running' -or $Acceptance.FIUSNReader -ne 'Running') {
        throw "FI services are not both running after the sweep. Collector=$($Acceptance.FICollector) Helper=$($Acceptance.FIUSNReader)"
    }

    Write-Host "[PASS] 10A local activity/security matrix: $($Acceptance.ActivityRunID)"
    Write-Host "[PASS] Gate 1 build ReadSACL state: $($Acceptance.ReadSACLState) / $($Acceptance.ReadSACLDataFormat)"
    Write-Host "[PASS] Gate 1 build content prefix exact 16-byte custody: $($Acceptance.ContentPrefix.PrefixBase64URL)"
    Write-Host "[PASS] FICollector and FIUSNReader are running."

    $Summary = [ordered]@{
        RecordKind = 'FIGate1Server2019Sweep'
        Host = $FI2019.TargetHost
        Build = $FI2019.ExpectedBuild
        RepositoryCommit = $FI2019.ExpectedRepoCommit
        StartedUTC = $RunStartedUTC.ToString('o')
        FinishedUTC = [DateTime]::UtcNow.ToString('o')
        OverallStatus = 'PASS'
        ArtifactIdentity = 'PASS'
        DeploymentBoundary = 'PASS'
        USNQueryRead = 'PASS'
        FileIDReobservation = 'PASS'
        ReadSACL = 'PASS'
        SecuritySourceCheckpoint = 'PASS'
        ContentPrefixCustody = 'PASS'
        LocalActivity = 'PASS'
        RestartHelperCatchup = 'PASS'
        NormalConfiguredCollection = 'PASS'
        PerformanceBaseline = 'PASS'
        ProtectedContainmentBasis = 'Server 2019 build 17763 was previously characterized; this sweep revalidates exact Gate 1 artifact identity, File-ID re-observation, and the current broker/runtime on the same exact build.'
        ActivityReport = $Acceptance.ActivityReport
        ReadinessReport = $Acceptance.ReadinessReport
        ContentPrefix = $Acceptance.ContentPrefix
        InstalledCollectorSHA256 = $Acceptance.InstalledCollectorSHA256
        InstalledHelperSHA256 = $Acceptance.InstalledHelperSHA256
        Remaining = @(
            'True remote SMB pass',
            'Passive Before/During/After 12D around a separately controlled LDAPS fault'
        )
    }

    $SummaryName = "server2019-sweep-summary-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')).json"
    $SummaryPath = Join-Path $FI2019.LocalResultDirectory $SummaryName
    $Summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $SummaryPath -Encoding UTF8

    Write-Host ''
    Write-Host '============================================================'
    Write-Host '[PASS] SERVER 2019 CORE SWEEP COMPLETE'
    Write-Host '============================================================'
    Write-Host "Summary: $SummaryPath"
    Write-Host 'Remaining: true remote SMB + passive 12D Before/During/After.'
}
finally {
    if ($null -ne $Session) {
        try {
            Copy-FI2019ChangedRemoteResults -Session $Session -SinceUTC $RunStartedUTC
        }
        catch {
            Write-Host "[INFO] Result copy-back did not complete: $($_.Exception.Message)"
        }
        Remove-PSSession $Session -ErrorAction SilentlyContinue
    }
}
