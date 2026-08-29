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
        if ($Line -match '^\s*governed_root\s*:\s*(.+?)\s*$') {
            $Value = $Matches[1].Trim()
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

    $Matches = @()

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
                $Matches += $File.FullName
            }
        }
        catch {
            # Ignore unrelated or malformed files during discovery.
        }
    }

    if ($Matches.Count -eq 0) {
        throw "No USN checkpoint found for governed root: $GovernedRoot"
    }

    if ($Matches.Count -gt 1) {
        throw "More than one USN checkpoint matched governed root: $GovernedRoot"
    }

    return $Matches[0]
}

function Get-FiCheckpoint {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CheckpointPath
    )

    return Get-Content -LiteralPath $CheckpointPath -Raw | ConvertFrom-Json
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

function Find-FiSpoolFilename {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FileName,

        [string]$SpoolPath = "C:\ProgramData\FI\spool",

        [int]$NewestFiles = 40
    )

    $Encoded = ConvertTo-FiUTF16LEBase64Url -Value $FileName

    $Matches = Get-ChildItem -LiteralPath $SpoolPath -Filter "*.jsonl" -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First $NewestFiles |
        Select-String -Pattern $Encoded -SimpleMatch

    return $Matches
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
        $Matches = @(Find-FiSpoolFilename -FileName $FileName -SpoolPath $SpoolPath -NewestFiles $NewestFiles)

        if ($Matches.Count -gt 0) {
            return $Matches
        }

        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $Deadline)

    return @()
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
