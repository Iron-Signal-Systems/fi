# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

$ErrorActionPreference = 'Stop'

$Server = 'ISS-FS-25'
$ExpectedBuild = '26100'

$CollectorAccount = 'ISS\gFI-FS25$'
$HelperAccount = 'ISS\gFI-USN-FS25$'

$CollectorLocal = 'C:\FI-Test\fi-2025-candidate.exe'
$HelperLocal = 'C:\FI-Test\fi-usn-2025-candidate.exe'

$CollectorExpectedSHA256 = 'CE58D165636F132ABC60902D242D9262BE1A422C18107B937629C98D255E1926'
$HelperExpectedSHA256 = '22F90B3976D2B69FB5FD8DC4B137B1DAA08767A72AAED92A6E0D0FE462810217'

$CollectorService = 'FICollector'
$HelperService = 'FIUSNReader'

$CollectorRemote = 'C:\Program Files\FI\fi.exe'
$HelperRemote = 'C:\Program Files\FI\fi-usn.exe'

$ProgramDir = 'C:\Program Files\FI'
$ProgramDataDir = 'C:\ProgramData\FI'
$ConfigDir = 'C:\ProgramData\FI\config'
$ConfigFile = 'C:\ProgramData\FI\config\fi.conf'
$StateDir = 'C:\ProgramData\FI\state'
$SpoolDir = 'C:\ProgramData\FI\spool'

$GovernedRoot = 'C:\FI-Test\governed-2025'
$StagingDir = 'C:\FI-Test\production-staging'
$CollectorStaged = "$StagingDir\fi.exe"
$HelperStaged = "$StagingDir\fi-usn.exe"

$CollectorPathName = '"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m'
$HelperPathName = '"C:\Program Files\FI\fi-usn.exe"'

function Get-LocalSHA256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required local candidate is missing: $Path"
    }

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

Write-Host ""
Write-Host "============================================================"
Write-Host "FI SERVER 2025 - INSTALL PRODUCTION PAIR"
Write-Host "Target: $Server"
Write-Host "Build:  $ExpectedBuild"
Write-Host "============================================================"

Write-Host ""
Write-Host "=== VERIFY LOCAL CANDIDATES ==="

$CollectorLocalSHA256 = Get-LocalSHA256 -Path $CollectorLocal
$HelperLocalSHA256 = Get-LocalSHA256 -Path $HelperLocal

Write-Host "[INFO] Collector SHA256: $CollectorLocalSHA256"
Write-Host "[INFO] Helper SHA256:    $HelperLocalSHA256"

if ($CollectorLocalSHA256 -ne $CollectorExpectedSHA256) {
    throw "Collector candidate hash mismatch. Expected $CollectorExpectedSHA256."
}

if ($HelperLocalSHA256 -ne $HelperExpectedSHA256) {
    throw "Helper candidate hash mismatch. Expected $HelperExpectedSHA256."
}

Write-Host "[PASS] Local candidate hashes match the reviewed Server 2025 binaries."

$Session = New-PSSession -ComputerName $Server

try {
    Write-Host ""
    Write-Host "=== TARGET PREFLIGHT ==="

    Invoke-Command -Session $Session -ScriptBlock {
        param(
            $ExpectedBuild,
            $CollectorService,
            $HelperService,
            $CollectorAccount,
            $HelperAccount,
            $CollectorRemote,
            $HelperRemote,
            $ConfigFile,
            $GovernedRoot,
            $CollectorExpectedSHA256,
            $HelperExpectedSHA256,
            $StagingDir
        )

        $OS = Get-CimInstance Win32_OperatingSystem

        Write-Host "[INFO] Host:    $env:COMPUTERNAME"
        Write-Host "[INFO] Caption: $($OS.Caption)"
        Write-Host "[INFO] Version: $($OS.Version)"
        Write-Host "[INFO] Build:   $($OS.BuildNumber)"

        if ($env:COMPUTERNAME -ine 'ISS-FS-25') {
            throw "Expected ISS-FS-25. No deployment changes made."
        }

        if ($OS.BuildNumber -ne $ExpectedBuild) {
            throw "Expected build $ExpectedBuild. Observed $($OS.BuildNumber)."
        }

        $Administrators = @(net.exe localgroup Administrators)

        if (($Administrators -join "`n") -match [regex]::Escape('gFI-FS25$')) {
            throw "$CollectorAccount is unexpectedly a local Administrator."
        }

        if (($Administrators -join "`n") -notmatch [regex]::Escape('gFI-USN-FS25$')) {
            throw "$HelperAccount is not a local Administrator."
        }

        if (Test-Path -LiteralPath $CollectorRemote -PathType Leaf) {
            $Hash = (
                Get-FileHash -LiteralPath $CollectorRemote -Algorithm SHA256
            ).Hash.ToUpperInvariant()

            if ($Hash -ne $CollectorExpectedSHA256) {
                throw "Existing $CollectorRemote does not match the reviewed collector candidate."
            }

            Write-Host "[INFO] Existing production collector matches reviewed hash."
        }

        if (Test-Path -LiteralPath $HelperRemote -PathType Leaf) {
            $Hash = (
                Get-FileHash -LiteralPath $HelperRemote -Algorithm SHA256
            ).Hash.ToUpperInvariant()

            if ($Hash -ne $HelperExpectedSHA256) {
                throw "Existing $HelperRemote does not match the reviewed helper candidate."
            }

            Write-Host "[INFO] Existing production helper matches reviewed hash."
        }

        if (Test-Path -LiteralPath $ConfigFile -PathType Leaf) {
            $ExpectedConfig = @(
                'version_id: 1.0'
                "governed_root: $GovernedRoot"
            )

            $ObservedConfig = @(
                Get-Content -LiteralPath $ConfigFile
            )

            if (($ObservedConfig -join "`n") -ne ($ExpectedConfig -join "`n")) {
                throw "Existing FI config does not match the Server 2025 acceptance config."
            }

            Write-Host "[INFO] Existing FI config matches the Server 2025 acceptance config."
        }

        foreach ($ServiceName in @($CollectorService, $HelperService)) {
            $Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

            if ($null -ne $Existing) {
                Write-Host "[INFO] Existing service detected: $ServiceName"
            }
        }

        New-Item -Path $StagingDir -ItemType Directory -Force | Out-Null

        Write-Host "[PASS] Target preflight passed."
    } -ArgumentList `
        $ExpectedBuild,
        $CollectorService,
        $HelperService,
        $CollectorAccount,
        $HelperAccount,
        $CollectorRemote,
        $HelperRemote,
        $ConfigFile,
        $GovernedRoot,
        $CollectorExpectedSHA256,
        $HelperExpectedSHA256,
        $StagingDir

    Write-Host ""
    Write-Host "=== COPY CANDIDATES TO TARGET STAGING ==="

    Copy-Item `
        -LiteralPath $CollectorLocal `
        -Destination $CollectorStaged `
        -ToSession $Session `
        -Force

    Copy-Item `
        -LiteralPath $HelperLocal `
        -Destination $HelperStaged `
        -ToSession $Session `
        -Force

    Invoke-Command -Session $Session -ScriptBlock {
        param(
            $CollectorStaged,
            $HelperStaged,
            $CollectorExpectedSHA256,
            $HelperExpectedSHA256
        )

        $CollectorHash = (
            Get-FileHash -LiteralPath $CollectorStaged -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        $HelperHash = (
            Get-FileHash -LiteralPath $HelperStaged -Algorithm SHA256
        ).Hash.ToUpperInvariant()

        Write-Host "[INFO] Staged collector SHA256: $CollectorHash"
        Write-Host "[INFO] Staged helper SHA256:    $HelperHash"

        if ($CollectorHash -ne $CollectorExpectedSHA256) {
            throw 'Staged collector hash mismatch.'
        }

        if ($HelperHash -ne $HelperExpectedSHA256) {
            throw 'Staged helper hash mismatch.'
        }

        Write-Host "[PASS] Target staging hashes match."
    } -ArgumentList `
        $CollectorStaged,
        $HelperStaged,
        $CollectorExpectedSHA256,
        $HelperExpectedSHA256

    Write-Host ""
    Write-Host "=== INSTALL / RESUME PRODUCTION PAIR ==="

    Invoke-Command -Session $Session -ScriptBlock {
        param(
            $CollectorAccount,
            $HelperAccount,
            $CollectorService,
            $HelperService,
            $CollectorRemote,
            $HelperRemote,
            $CollectorStaged,
            $HelperStaged,
            $ProgramDir,
            $ProgramDataDir,
            $ConfigDir,
            $ConfigFile,
            $StateDir,
            $SpoolDir,
            $GovernedRoot,
            $CollectorPathName,
            $HelperPathName,
            $CollectorExpectedSHA256,
            $HelperExpectedSHA256
        )

        function Invoke-FIIcacls {
            param(
                [Parameter(Mandatory = $true)]
                [string[]]$Arguments,

                [Parameter(Mandatory = $true)]
                [string]$Description
            )

            $Output = @(
                & icacls.exe @Arguments 2>&1 |
                    ForEach-Object {
                        $_.ToString()
                    }
            )

            $ExitCode = $LASTEXITCODE

            $Output | ForEach-Object {
                Write-Host $_
            }

            if ($ExitCode -ne 0) {
                throw "$Description failed. icacls exit code: $ExitCode"
            }

            Write-Host "[PASS] $Description"
        }

        function New-Or-Verify-FIService {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Name,

                [Parameter(Mandatory = $true)]
                [string]$DisplayName,

                [Parameter(Mandatory = $true)]
                [string]$PathName,

                [Parameter(Mandatory = $true)]
                [string]$BootstrapPath,

                [Parameter(Mandatory = $true)]
                [string]$StartName
            )

            $Existing = Get-CimInstance `
                Win32_Service `
                -Filter "Name='$Name'" `
                -ErrorAction SilentlyContinue

            if ($null -eq $Existing) {
                Write-Host "[INFO] Creating $Name against no-space staging path."

                $CreateOutput = @(
                    & sc.exe create $Name `
                        binPath= $BootstrapPath `
                        start= auto `
                        obj= $StartName `
                        DisplayName= $DisplayName 2>&1
                )

                $CreateExitCode = $LASTEXITCODE

                $CreateOutput | ForEach-Object {
                    Write-Host $_
                }

                if ($CreateExitCode -ne 0) {
                    throw "$Name bootstrap service creation failed. sc.exe exit code: $CreateExitCode"
                }

                & sc.exe managedaccount $Name true | Out-Host

                if ($LASTEXITCODE -ne 0) {
                    throw "Could not mark $Name as a managed-account service."
                }

                $Existing = Get-CimInstance `
                    Win32_Service `
                    -Filter "Name='$Name'" `
                    -ErrorAction Stop

                Write-Host "[INFO] Setting exact production PathName through Win32_Service.Change."

                $ChangeResult = Invoke-CimMethod `
                    -InputObject $Existing `
                    -MethodName Change `
                    -Arguments @{
                        PathName = $PathName
                    }

                if ($ChangeResult.ReturnValue -ne 0) {
                    throw "$Name production PathName change failed. ReturnValue=$($ChangeResult.ReturnValue)"
                }

                $Existing = Get-CimInstance `
                    Win32_Service `
                    -Filter "Name='$Name'" `
                    -ErrorAction Stop
            }
            else {
                Write-Host "[INFO] $Name already exists; verifying exact configuration."
            }

            if ($Existing.PathName -ne $PathName) {
                throw "$Name PathName mismatch.`nExpected: $PathName`nObserved: $($Existing.PathName)"
            }

            if ($Existing.StartName -ine $StartName) {
                throw "$Name StartName mismatch. Expected $StartName, observed $($Existing.StartName)."
            }

            $Managed = @(
                & sc.exe qmanagedaccount $Name
            ) -join "`n"

            if ($Managed -notmatch 'ACCOUNT MANAGED\s*:\s*TRUE') {
                throw "$Name exists but is not configured as a managed-account service."
            }

            Write-Host "[PASS] $Name configuration matches."
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
                $Current = (
                    Get-Service -Name $Name -ErrorAction Stop
                ).Status.ToString()

                if ($Current -eq $State) {
                    return
                }

                Start-Sleep -Milliseconds 250
            }
            while ((Get-Date) -lt $Deadline)

            throw "$Name did not reach $State within $TimeoutSeconds seconds."
        }

        Write-Host ""
        Write-Host "--- DIRECTORIES ---"

        New-Item `
            -Path $ProgramDir,$ProgramDataDir,$ConfigDir,$StateDir,$SpoolDir,$GovernedRoot `
            -ItemType Directory `
            -Force |
            Out-Null

        Write-Host ""
        Write-Host "--- PROGRAM ACL ---"

        Invoke-FIIcacls `
            -Arguments @(
                $ProgramDir,
                '/inheritance:r'
            ) `
            -Description 'Removed inherited ACLs from the FI program directory.'

        Invoke-FIIcacls `
            -Arguments @(
                $ProgramDir,
                '/grant:r',
                'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
                'BUILTIN\Administrators:(OI)(CI)(F)',
                "${CollectorAccount}:(OI)(CI)(RX)",
                "${HelperAccount}:(OI)(CI)(RX)"
            ) `
            -Description 'Applied the FI program-directory ACL boundary.'

        if (Test-Path -LiteralPath $CollectorRemote -PathType Leaf) {
            $InstalledCollectorHash = (
                Get-FileHash -LiteralPath $CollectorRemote -Algorithm SHA256
            ).Hash.ToUpperInvariant()

            Write-Host "[INFO] Existing installed collector SHA256: $InstalledCollectorHash"

            if ($InstalledCollectorHash -ne $CollectorExpectedSHA256) {
                throw 'Existing installed collector does not match the reviewed candidate. Refusing replacement during acceptance.'
            }

            Write-Host "[PASS] Existing production collector already matches the reviewed candidate; copy skipped."
        }
        else {
            Copy-Item `
                -LiteralPath $CollectorStaged `
                -Destination $CollectorRemote

            $InstalledCollectorHash = (
                Get-FileHash -LiteralPath $CollectorRemote -Algorithm SHA256
            ).Hash.ToUpperInvariant()

            if ($InstalledCollectorHash -ne $CollectorExpectedSHA256) {
                throw 'Newly installed collector hash mismatch.'
            }

            Write-Host "[PASS] Production collector installed with the reviewed hash."
        }

        if (Test-Path -LiteralPath $HelperRemote -PathType Leaf) {
            $InstalledHelperHash = (
                Get-FileHash -LiteralPath $HelperRemote -Algorithm SHA256
            ).Hash.ToUpperInvariant()

            Write-Host "[INFO] Existing installed helper SHA256: $InstalledHelperHash"

            if ($InstalledHelperHash -ne $HelperExpectedSHA256) {
                throw 'Existing installed helper does not match the reviewed candidate. Refusing replacement during acceptance.'
            }

            Write-Host "[PASS] Existing production helper already matches the reviewed candidate; copy skipped."
        }
        else {
            Copy-Item `
                -LiteralPath $HelperStaged `
                -Destination $HelperRemote

            $InstalledHelperHash = (
                Get-FileHash -LiteralPath $HelperRemote -Algorithm SHA256
            ).Hash.ToUpperInvariant()

            if ($InstalledHelperHash -ne $HelperExpectedSHA256) {
                throw 'Newly installed helper hash mismatch.'
            }

            Write-Host "[PASS] Production helper installed with the reviewed hash."
        }

        Write-Host "[PASS] Production binaries match the reviewed candidates."

        Write-Host ""
        Write-Host "--- CONFIG ACL / CONFIG ---"

        Invoke-FIIcacls `
            -Arguments @(
                $ConfigDir,
                '/inheritance:r'
            ) `
            -Description 'Removed inherited ACLs from the FI config directory.'

        Invoke-FIIcacls `
            -Arguments @(
                $ConfigDir,
                '/grant:r',
                'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
                'BUILTIN\Administrators:(OI)(CI)(F)',
                "${CollectorAccount}:(OI)(CI)(RX)",
                "${HelperAccount}:(OI)(CI)(RX)"
            ) `
            -Description 'Applied the administrator-controlled FI config ACL.'

        @(
            'version_id: 1.0'
            "governed_root: $GovernedRoot"
        ) |
            Set-Content `
                -LiteralPath $ConfigFile `
                -Encoding ASCII

        Write-Host "[PASS] FI config is present."
        Get-Content -LiteralPath $ConfigFile

        Write-Host ""
        Write-Host "--- STATE / SPOOL ACLS ---"

        foreach ($Target in @($StateDir, $SpoolDir)) {
            Invoke-FIIcacls `
                -Arguments @(
                    $Target,
                    '/inheritance:r'
                ) `
                -Description "Removed inherited ACLs from $Target."

            Invoke-FIIcacls `
                -Arguments @(
                    $Target,
                    '/grant:r',
                    'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
                    'BUILTIN\Administrators:(OI)(CI)(F)',
                    "${CollectorAccount}:(OI)(CI)(M)"
                ) `
                -Description "Applied the FI collector data ACL to $Target."
        }

        Write-Host ""
        Write-Host "--- GOVERNED ROOT ACL ---"

        Invoke-FIIcacls `
            -Arguments @(
                'C:\FI-Test',
                '/grant',
                "${CollectorAccount}:(RX)"
            ) `
            -Description 'Granted FICollector traversal to C:\FI-Test.'

        Invoke-FIIcacls `
            -Arguments @(
                $GovernedRoot,
                '/inheritance:r'
            ) `
            -Description 'Removed inherited ACLs from the Server 2025 acceptance governed root.'

        Invoke-FIIcacls `
            -Arguments @(
                $GovernedRoot,
                '/grant:r',
                'NT AUTHORITY\SYSTEM:(OI)(CI)(F)',
                'BUILTIN\Administrators:(OI)(CI)(F)',
                "${CollectorAccount}:(OI)(CI)(RX)",
                "${HelperAccount}:(OI)(CI)(RX)"
            ) `
            -Description 'Applied the governed-root acceptance ACL.'

        $ControlFile = Join-Path $GovernedRoot 'acceptance-control.txt'

        if (-not (Test-Path -LiteralPath $ControlFile -PathType Leaf)) {
            @(
                'FI Server 2025 production-pair acceptance control.'
                "Created: $([DateTime]::UtcNow.ToString('o'))"
            ) |
                Set-Content `
                    -LiteralPath $ControlFile `
                    -Encoding ASCII
        }

        Write-Host "[PASS] Acceptance control file is present: $ControlFile"

        Write-Host ""
        Write-Host "--- EVENT LOG READERS ---"

        $EventLogReaders = @(
            net.exe localgroup 'Event Log Readers'
        )

        if (
            ($EventLogReaders -join "`n") -notmatch
            [regex]::Escape('gFI-FS25$')
        ) {
            net.exe localgroup 'Event Log Readers' $CollectorAccount /add | Out-Host

            if ($LASTEXITCODE -ne 0) {
                throw "Could not add $CollectorAccount to Event Log Readers."
            }
        }

        Write-Host "[PASS] FICollector gMSA is in Event Log Readers."

        Write-Host ""
        Write-Host "--- CREATE / VERIFY SERVICES ---"

        New-Or-Verify-FIService `
            -Name $CollectorService `
            -DisplayName 'FI Collector' `
            -PathName $CollectorPathName `
            -BootstrapPath $CollectorStaged `
            -StartName $CollectorAccount

        & sc.exe sidtype $CollectorService unrestricted | Out-Host

        if ($LASTEXITCODE -ne 0) {
            throw 'Could not set FICollector service SID type to UNRESTRICTED.'
        }

        New-Or-Verify-FIService `
            -Name $HelperService `
            -DisplayName 'FI USN Reader' `
            -PathName $HelperPathName `
            -BootstrapPath $HelperStaged `
            -StartName $HelperAccount

        Write-Host "[PASS] Production service configuration is present."

        Write-Host ""
        Write-Host "--- SERVICE CONFIGURATION ---"

        & sc.exe qc $CollectorService | Out-Host
        & sc.exe qmanagedaccount $CollectorService | Out-Host
        & sc.exe qsidtype $CollectorService | Out-Host

        & sc.exe qc $HelperService | Out-Host
        & sc.exe qmanagedaccount $HelperService | Out-Host

        Write-Host ""
        Write-Host "--- START HELPER ---"

        $HelperState = (
            Get-Service -Name $HelperService -ErrorAction Stop
        ).Status.ToString()

        if ($HelperState -ne 'Running') {
            Start-Service -Name $HelperService -ErrorAction Stop
        }

        Wait-FIServiceState -Name $HelperService -State 'Running'

        $PipeDeadline = (Get-Date).AddSeconds(120)
        $PipeObserved = $false

        while ((Get-Date) -lt $PipeDeadline) {
            $CurrentHelperState = (
                Get-Service -Name $HelperService -ErrorAction Stop
            ).Status.ToString()

            if ($CurrentHelperState -ne 'Running') {
                throw "FIUSNReader left Running state while waiting for the FI-USN pipe. Current state: $CurrentHelperState"
            }

            if (Test-Path '\\.\pipe\FI-USN') {
                $PipeObserved = $true
                break
            }

            Start-Sleep -Milliseconds 500
        }

        if (-not $PipeObserved) {
            throw 'FIUSNReader remained Running but the local FI-USN pipe was not observed within 120 seconds.'
        }

        Write-Host "[PASS] FIUSNReader remained running and the FI-USN pipe was observed."

        Write-Host ""
        Write-Host "--- START COLLECTOR ---"

        $CollectorState = (
            Get-Service -Name $CollectorService -ErrorAction Stop
        ).Status.ToString()

        if ($CollectorState -ne 'Running') {
            Start-Service -Name $CollectorService -ErrorAction Stop
        }

        Wait-FIServiceState -Name $CollectorService -State 'Running'

        Write-Host "[PASS] FICollector is running."

        Write-Host ""
        Write-Host "--- WAIT FOR ACTUAL CONFIGURED COLLECTION ---"

        $RuntimeLog = Join-Path $StateDir 'service-runtime.jsonl'
        $CollectionDeadline = (Get-Date).AddSeconds(120)
        $ConfiguredCollection = $null

        while (
            $null -eq $ConfiguredCollection -and
            (Get-Date) -lt $CollectionDeadline
        ) {
            if (Test-Path -LiteralPath $RuntimeLog -PathType Leaf) {
                $Records = @(
                    Get-Content -LiteralPath $RuntimeLog |
                        ForEach-Object {
                            if (-not [string]::IsNullOrWhiteSpace($_)) {
                                $_ | ConvertFrom-Json
                            }
                        }
                )

                $CollectionMatches = @(
                    $Records |
                        Where-Object {
                            $_.record_kind -eq 'ConfiguredCollection'
                        } |
                        Select-Object -Last 1
                )

                if ($CollectionMatches.Count -gt 0) {
                    $ConfiguredCollection = $CollectionMatches[0]
                    break
                }
            }

            Start-Sleep -Seconds 1
        }

        if ($null -eq $ConfiguredCollection) {
            throw 'No ConfiguredCollection service-runtime record was observed within the acceptance window.'
        }

        Write-Host "[INFO] ConfiguredCollection:"
        $ConfiguredCollection |
            ConvertTo-Json -Depth 8 |
            Write-Host

        if ($ConfiguredCollection.outcome -eq 'Failed') {
            throw "First ConfiguredCollection failed: $($ConfiguredCollection.error)"
        }

        Write-Host "[PASS] An actual configured collection cycle completed without Failed outcome."

        Write-Host ""
        Write-Host "--- FINAL SERVICE STATE ---"

        Get-Service -Name $CollectorService,$HelperService |
            Format-Table Name,Status -AutoSize

        Write-Host ""
        Write-Host "--- FINAL IDENTITY BOUNDARY ---"

        net.exe localgroup Administrators | Out-Host

        $AdminOutput = @(
            net.exe localgroup Administrators
        ) -join "`n"

        if ($AdminOutput -match [regex]::Escape('gFI-FS25$')) {
            throw 'FICollector gMSA became a local Administrator.'
        }

        if ($AdminOutput -notmatch [regex]::Escape('gFI-USN-FS25$')) {
            throw 'FIUSNReader gMSA is no longer a local Administrator.'
        }

        Write-Host "[PASS] Split-privilege local Administrator boundary is correct."

        Write-Host ""
        Write-Host "--- FI ACLS ---"

        icacls.exe $ProgramDir | Out-Host
        icacls.exe $ConfigDir | Out-Host
        icacls.exe $ConfigFile | Out-Host
        icacls.exe $StateDir | Out-Host
        icacls.exe $SpoolDir | Out-Host
        icacls.exe $GovernedRoot | Out-Host

        Write-Host ""
        Write-Host "--- CHECKPOINT / STATE FILES ---"

        Get-ChildItem `
            -LiteralPath $StateDir `
            -File `
            -Force |
            Sort-Object Name |
            Select-Object Name,Length,LastWriteTime |
            Format-Table -AutoSize

        Write-Host ""
        Write-Host "[PASS] Server 2025 production pair installed and first configured cycle observed."
        Write-Host "[INFO] Characterization services were intentionally left untouched for now."
        Write-Host "[INFO] Do not commit the Server 2025 changes until production acceptance is complete."
    } -ArgumentList `
        $CollectorAccount,
        $HelperAccount,
        $CollectorService,
        $HelperService,
        $CollectorRemote,
        $HelperRemote,
        $CollectorStaged,
        $HelperStaged,
        $ProgramDir,
        $ProgramDataDir,
        $ConfigDir,
        $ConfigFile,
        $StateDir,
        $SpoolDir,
        $GovernedRoot,
        $CollectorPathName,
        $HelperPathName,
        $CollectorExpectedSHA256,
        $HelperExpectedSHA256
}
finally {
    if ($null -ne $Session) {
        Remove-PSSession $Session
    }
}
