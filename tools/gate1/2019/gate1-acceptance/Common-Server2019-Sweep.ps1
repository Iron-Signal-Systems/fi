Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'FI-Server2019-Config.ps1')

function Assert-FI2019Controller {
    if ($env:COMPUTERNAME -ine $FI2019.ControllerHost) {
        throw "This package is pinned to controller $($FI2019.ControllerHost). Current host: $env:COMPUTERNAME"
    }

    foreach ($Path in @($FI2019.RepoRoot,$FI2019.LocalCollector,$FI2019.LocalHelper)) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Required local path is missing: $Path"
        }
    }

    Push-Location $FI2019.RepoRoot
    try {
        $Head = (& git rev-parse HEAD).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'git rev-parse HEAD failed.' }
        if ($Head -ne $FI2019.ExpectedRepoCommit) {
            throw "Repository HEAD mismatch. Expected $($FI2019.ExpectedRepoCommit); observed $Head"
        }

        $Status = @(& git status --porcelain)
        if ($LASTEXITCODE -ne 0) { throw 'git status --porcelain failed.' }
        if ($Status.Count -ne 0) {
            throw 'Repository working tree is not clean. Refusing to stage Gate 1 tooling from an ambiguous tree.'
        }
    }
    finally {
        Pop-Location
    }

    $CollectorHash = (Get-FileHash -LiteralPath $FI2019.LocalCollector -Algorithm SHA256).Hash.ToUpperInvariant()
    $HelperHash = (Get-FileHash -LiteralPath $FI2019.LocalHelper -Algorithm SHA256).Hash.ToUpperInvariant()

    if ($CollectorHash -ne $FI2019.CollectorSHA256) {
        throw "Collector SHA256 mismatch. Expected $($FI2019.CollectorSHA256); observed $CollectorHash"
    }
    if ($HelperHash -ne $FI2019.HelperSHA256) {
        throw "Helper SHA256 mismatch. Expected $($FI2019.HelperSHA256); observed $HelperHash"
    }

    New-Item -Path $FI2019.LocalResultDirectory -ItemType Directory -Force | Out-Null
}

function New-FI2019Session {
    $Option = New-PSSessionOption -OpenTimeout 30000
    return New-PSSession -ComputerName $FI2019.TargetHost -SessionOption $Option -ErrorAction Stop
}

function Get-FI2019RemotePreflight {
    param([Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session)

    return Invoke-Command -Session $Session -ArgumentList @(
        $FI2019.TargetHost,
        $FI2019.ExpectedBuild,
        $FI2019.GovernedRoot,
        $FI2019.CollectorAccount,
        $FI2019.HelperAccount,
        $FI2019.CollectorSHA256,
        $FI2019.HelperSHA256
    ) -ScriptBlock {
        param(
            $ExpectedHost,$ExpectedBuild,$GovernedRoot,
            $CollectorAccount,$HelperAccount,
            $CollectorHash,$HelperHash
        )

        Set-StrictMode -Version 2.0
        $ErrorActionPreference = 'Stop'

        $OS = Get-CimInstance Win32_OperatingSystem
        $Computer = Get-CimInstance Win32_ComputerSystem
        $Admins = (@(& net.exe localgroup Administrators 2>&1) -join "`n")

        $CollectorService = Get-CimInstance Win32_Service -Filter "Name='FICollector'" -ErrorAction SilentlyContinue
        $HelperService = Get-CimInstance Win32_Service -Filter "Name='FIUSNReader'" -ErrorAction SilentlyContinue

        $InstalledCollector = 'C:\Program Files\FI\fi.exe'
        $InstalledHelper = 'C:\Program Files\FI\fi-usn.exe'
        $InstalledCollectorHash = ''
        $InstalledHelperHash = ''

        if (Test-Path -LiteralPath $InstalledCollector -PathType Leaf) {
            $InstalledCollectorHash = (Get-FileHash -LiteralPath $InstalledCollector -Algorithm SHA256).Hash.ToUpperInvariant()
        }
        if (Test-Path -LiteralPath $InstalledHelper -PathType Leaf) {
            $InstalledHelperHash = (Get-FileHash -LiteralPath $InstalledHelper -Algorithm SHA256).Hash.ToUpperInvariant()
        }

        $ConfigText = ''
        if (Test-Path -LiteralPath 'C:\ProgramData\FI\config\fi.conf' -PathType Leaf) {
            $ConfigText = (@(Get-Content -LiteralPath 'C:\ProgramData\FI\config\fi.conf') -join "`n")
        }

        $Shares = @()
        try {
            $RootFull = [IO.Path]::GetFullPath($GovernedRoot).TrimEnd('\')
            $Shares = @(
                Get-SmbShare -ErrorAction Stop |
                    Where-Object { $_.Path } |
                    ForEach-Object {
                        [PSCustomObject]@{
                            Name = $_.Name
                            Path = $_.Path
                            Special = [bool]$_.Special
                        }
                    }
            )
        }
        catch {
            $Shares = @()
        }

        $SecureChannel = $false
        try { $SecureChannel = [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { $SecureChannel = $false }

        $Result = [PSCustomObject]@{
            Host = $env:COMPUTERNAME
            Domain = $Computer.Domain
            PartOfDomain = [bool]$Computer.PartOfDomain
            OS = $OS.Caption
            Version = $OS.Version
            Build = [string]$OS.BuildNumber
            PowerShell = $PSVersionTable.PSVersion.ToString()
            SecureChannel = $SecureChannel
            GovernedRootExists = [bool](Test-Path -LiteralPath $GovernedRoot -PathType Container)
            CollectorIsAdmin = ($Admins -match ('(?im)^\s*' + [regex]::Escape($CollectorAccount) + '\s*$'))
            HelperIsAdmin = ($Admins -match ('(?im)^\s*' + [regex]::Escape($HelperAccount) + '\s*$'))
            CollectorService = $CollectorService
            HelperService = $HelperService
            InstalledCollectorSHA256 = $InstalledCollectorHash
            InstalledHelperSHA256 = $InstalledHelperHash
            InstalledCollectorMatchesGate1 = ($InstalledCollectorHash -eq $CollectorHash)
            InstalledHelperMatchesGate1 = ($InstalledHelperHash -eq $HelperHash)
            Config = $ConfigText
            Shares = $Shares
        }

        if ($Result.Host -ine $ExpectedHost) { throw "Wrong target host. Expected $ExpectedHost; observed $($Result.Host)" }
        if ($Result.Build -ne $ExpectedBuild) { throw "Wrong Windows build. Expected $ExpectedBuild; observed $($Result.Build)" }
        if (-not $Result.PartOfDomain) { throw 'Target is not domain joined.' }
        if (-not $Result.SecureChannel) { throw 'Target domain secure channel is not healthy.' }
        if (-not $Result.GovernedRootExists) { throw "Governed root does not exist: $GovernedRoot" }
        if ($Result.CollectorIsAdmin) { throw "$CollectorAccount is unexpectedly a local Administrator." }
        if (-not $Result.HelperIsAdmin) { throw "$HelperAccount is not a local Administrator." }

        return $Result
    }
}

function Copy-FI2019ChangedRemoteResults {
    param(
        [Parameter(Mandatory=$true)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory=$true)][DateTime]$SinceUTC,
        [string]$Destination = ''
    )

    if ([string]::IsNullOrWhiteSpace($Destination)) {
        $Destination = Join-Path $FI2019.LocalResultDirectory 'server'
    }

    New-Item -Path $Destination -ItemType Directory -Force | Out-Null

    $RemoteFiles = @(
        Invoke-Command -Session $Session -ArgumentList @(
            $FI2019.RemoteResultDirectory,
            $SinceUTC.ToUniversalTime()
        ) -ScriptBlock {
            param($Root,$Since)
            if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return }
            $Files = @(
                Get-ChildItem -LiteralPath $Root -File -Recurse -ErrorAction Stop |
                    Where-Object { $_.LastWriteTimeUtc -ge $Since } |
                    Sort-Object LastWriteTimeUtc
            )
            if ($Files.Count -gt 200) {
                throw "Refusing to copy more than 200 Gate 1 result files created since $Since."
            }
            $Files | Select-Object FullName
        }
    )

    foreach ($RemoteFile in $RemoteFiles) {
        if ($null -eq $RemoteFile -or [string]::IsNullOrWhiteSpace([string]$RemoteFile.FullName)) { continue }
        $Relative = [string]$RemoteFile.FullName
        $Prefix = $FI2019.RemoteResultDirectory.TrimEnd('\') + '\'
        if ($Relative.StartsWith($Prefix,[StringComparison]::OrdinalIgnoreCase)) {
            $Relative = $Relative.Substring($Prefix.Length)
        }
        else {
            $Relative = [IO.Path]::GetFileName($Relative)
        }

        $LocalPath = Join-Path $Destination $Relative
        $LocalParent = Split-Path -Parent $LocalPath
        if ($LocalParent) { New-Item -Path $LocalParent -ItemType Directory -Force | Out-Null }

        Copy-Item -FromSession $Session -LiteralPath $RemoteFile.FullName -Destination $LocalPath -Force
    }
}
