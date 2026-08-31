# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# FI USN customer verification common functions.
# Windows PowerShell 5.1 / Windows Server 2016 compatible.

$ErrorActionPreference = "Stop"

function Write-FiPass {
    param([string]$Message)
    Write-Host "[PASS] $Message"
}

function Write-FiFail {
    param([string]$Message)
    Write-Host "[FAIL] $Message"
}

function Write-FiInfo {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Get-FiConfiguredRoots {
    param(
        [string]$ConfigPath = "C:\ProgramData\FI\config\fi.conf"
    )

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "FI config not found: $ConfigPath"
    }

    $Roots = @()

    foreach ($Line in Get-Content -LiteralPath $ConfigPath) {
        $RootMatch = [regex]::Match(
            $Line,
            '^\s*governed_root\s*:\s*(.+?)\s*$'
        )

        if ($RootMatch.Success) {
            $Value = $RootMatch.Groups[1].Value.Trim()

            if ($Value) {
                $Roots += $Value
            }
        }
    }

    if ($Roots.Count -eq 0) {
        throw "No governed_root entries found in $ConfigPath"
    }

    return $Roots
}

function ConvertFrom-FiBase64Url {
    param([string]$Value)

    $Base64 = $Value.Replace('-', '+').Replace('_', '/')

    switch ($Base64.Length % 4) {
        0 { }
        2 { $Base64 += '==' }
        3 { $Base64 += '=' }
        default { throw "Invalid base64url length." }
    }

    return [Convert]::FromBase64String($Base64)
}

function ConvertTo-FiUTF16LEBase64Url {
    param([string]$Value)

    return [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($Value)
    ).TrimEnd('=').Replace('+','-').Replace('/','_')
}

function Get-FiCheckpointPath {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GovernedRoot,

        [string]$StatePath = "C:\ProgramData\FI\state"
    )

    $CheckpointMatches = @()

    foreach ($File in Get-ChildItem -LiteralPath $StatePath -Filter "root-*-usn.json" -File -ErrorAction Stop) {
        try {
            $Checkpoint = Get-Content -LiteralPath $File.FullName -Raw | ConvertFrom-Json
            $Encoded = $Checkpoint.governed_root.requested_path_utf16le_base64url

            if (-not $Encoded) {
                continue
            }

            $Bytes = ConvertFrom-FiBase64Url -Value $Encoded
            $RequestedPath = [Text.Encoding]::Unicode.GetString($Bytes)

            if ($RequestedPath.TrimEnd('\') -ieq $GovernedRoot.TrimEnd('\')) {
                $CheckpointMatches += $File.FullName
            }
        }
        catch {
            # Ignore unrelated or malformed files during discovery.
        }
    }

    if ($CheckpointMatches.Count -eq 0) {
        throw "No USN checkpoint found for governed root: $GovernedRoot"
    }

    if ($CheckpointMatches.Count -gt 1) {
        throw "More than one USN checkpoint matched governed root: $GovernedRoot"
    }

    return $CheckpointMatches[0]
}

function Get-FiCheckpoint {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CheckpointPath
    )

    return Get-Content -LiteralPath $CheckpointPath -Raw | ConvertFrom-Json
}

function Get-FiIcaclsAudit {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [switch]$Recurse
    )

    $Arguments = @($Path)

    if ($Recurse) {
        $Arguments += "/T"
        $Arguments += "/C"
    }

    $Output = @(
        & icacls.exe @Arguments 2>&1 |
            ForEach-Object { $_.ToString() }
    )

    $ExitCode = $LASTEXITCODE

    $AccessDenied = @(
        $Output |
            Select-String -SimpleMatch "Access is denied"
    )

    $FailureSummaries = @(
        $Output |
            Select-String -Pattern 'Failed processing\s+[1-9][0-9]*\s+files?'
    )

    $HasProblems = (
        $ExitCode -ne 0 -or
        $AccessDenied.Count -gt 0 -or
        $FailureSummaries.Count -gt 0
    )

    return [PSCustomObject]@{
        Path = $Path
        Recurse = [bool]$Recurse
        ExitCode = $ExitCode
        Output = $Output
        AccessDenied = $AccessDenied
        FailureSummaries = $FailureSummaries
        HasProblems = $HasProblems
    }
}

function Get-FiLatestConfiguredCollection {
    param(
        [string]$RuntimePath = "C:\ProgramData\FI\state\service-runtime.jsonl"
    )

    if (-not (Test-Path -LiteralPath $RuntimePath)) {
        throw "FI service runtime log not found: $RuntimePath"
    }

    $Last = Get-Content -LiteralPath $RuntimePath |
        Select-String -SimpleMatch '"record_kind":"ConfiguredCollection"' |
        Select-Object -Last 1

    if (-not $Last) {
        return $null
    }

    return $Last.Line | ConvertFrom-Json
}

function Find-FiSpoolFilename {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FileName,

        [string]$SpoolPath = "C:\ProgramData\FI\spool",

        [int]$NewestFiles = 40
    )

    $Encoded = ConvertTo-FiUTF16LEBase64Url -Value $FileName

    $SpoolMatches = Get-ChildItem -LiteralPath $SpoolPath -Filter "*.jsonl" -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $NewestFiles |
        Select-String -Pattern $Encoded -SimpleMatch

    return $SpoolMatches
}

function Wait-FiSpoolFilename {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FileName,

        [string]$SpoolPath = "C:\ProgramData\FI\spool",

        [int]$NewestFiles = 60,

        [int]$TimeoutSeconds = 60
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        $SpoolMatches = @(
            Find-FiSpoolFilename `
                -FileName $FileName `
                -SpoolPath $SpoolPath `
                -NewestFiles $NewestFiles
        )

        if ($SpoolMatches.Count -gt 0) {
            return $SpoolMatches
        }

        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $Deadline)

    return @()
}

function Wait-FiCheckpointAdvance {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CheckpointPath,

        [Parameter(Mandatory=$true)]
        [UInt64]$BeforeUSN,

        [int]$TimeoutSeconds = 60
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        Start-Sleep -Seconds 2

        $Current = Get-FiCheckpoint -CheckpointPath $CheckpointPath
        $CurrentUSN = [UInt64]$Current.next_usn

        if ($CurrentUSN -gt $BeforeUSN) {
            return $Current
        }
    } while ((Get-Date) -lt $Deadline)

    return $null
}

function Wait-FiCheckpointStable {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CheckpointPath,

        [Parameter(Mandatory=$true)]
        [UInt64]$ExpectedUSN,

        [int]$Seconds = 35
    )

    Start-Sleep -Seconds $Seconds

    $Current = Get-FiCheckpoint -CheckpointPath $CheckpointPath
    return ([UInt64]$Current.next_usn -eq $ExpectedUSN)
}

function Test-FiServiceRunning {
    param([string]$Name)

    $Service = Get-Service -Name $Name -ErrorAction Stop
    return ($Service.Status -eq "Running")
}

function Get-FiServiceInfo {
    param([string]$Name)

    return Get-CimInstance Win32_Service -Filter "Name='$Name'"
}
