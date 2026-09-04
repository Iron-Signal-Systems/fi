# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

# FI Gate 1 acceptance common functions.
# Windows PowerShell 5.1 / Windows Server 2016 compatible.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Gate1Directory = Split-Path -Parent $MyInvocation.MyCommand.Path
$CommonVerification = Join-Path (Split-Path -Parent $Gate1Directory) 'scripts\Common.ps1'

if (-not (Test-Path -LiteralPath $CommonVerification -PathType Leaf)) {
    throw "FI verification Common.ps1 was not found: $CommonVerification"
}

. $CommonVerification

function Assert-FiGate1Administrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $Identity

    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This Gate 1 test must run from elevated Windows PowerShell.'
    }
}

function Get-FiGate1SingleGovernedRoot {
    param(
        [string]$GovernedRoot = '',
        [string]$ConfigPath = 'C:\ProgramData\FI\config\fi.conf'
    )

    if ($GovernedRoot) {
        return $GovernedRoot.TrimEnd('\')
    }

    $Roots = @(Get-FiConfiguredRoots -ConfigPath $ConfigPath)

    if ($Roots.Count -ne 1) {
        throw "Exactly one governed root is required when -GovernedRoot is omitted. Config contains $($Roots.Count)."
    }

    return $Roots[0].TrimEnd('\')
}

function Get-FiGate1ConfiguredCollectionCount {
    param(
        [string]$RuntimePath = 'C:\ProgramData\FI\state\service-runtime.jsonl'
    )

    if (-not (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) {
        return 0
    }

    return [int](
        Get-Content -LiteralPath $RuntimePath |
            Select-String -SimpleMatch '"record_kind":"ConfiguredCollection"' |
            Measure-Object
    ).Count
}

function Wait-FiGate1ConfiguredCollectionAfter {
    param(
        [Parameter(Mandatory = $true)]
        [int]$BeforeCount,

        [string]$RuntimePath = 'C:\ProgramData\FI\state\service-runtime.jsonl',

        [int]$TimeoutSeconds = 180
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    do {
        $Count = Get-FiGate1ConfiguredCollectionCount -RuntimePath $RuntimePath

        if ($Count -gt $BeforeCount) {
            return Get-FiLatestConfiguredCollection -RuntimePath $RuntimePath
        }

        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $Deadline)

    return $null
}

function Get-FiGate1LatestSecurityRecordID {
    try {
        $Event = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop

        if ($null -eq $Event) {
            return [UInt64]0
        }

        return [UInt64]$Event.RecordId
    }
    catch {
        return [UInt64]0
    }
}

function Get-FiGate1SecurityEvents {
    param(
        [Parameter(Mandatory = $true)]
        [UInt64]$AfterRecordID,

        [string]$PathContains = '',

        [int[]]$EventIDs = @(4656,4663,4660,4664,4670,4907,5145,1102,4719),

        [int]$MaxEvents = 10000
    )

    $Results = New-Object System.Collections.Generic.List[object]

    try {
        $Events = Get-WinEvent `
            -FilterHashtable @{
                LogName = 'Security'
                Id = $EventIDs
            } `
            -MaxEvents $MaxEvents `
            -ErrorAction Stop
    }
    catch {
        return @()
    }

    foreach ($Event in $Events) {
        if ([UInt64]$Event.RecordId -le $AfterRecordID) {
            break
        }

        $Xml = $Event.ToXml()

        if ($PathContains -and $Xml -notlike "*$PathContains*") {
            continue
        }

        $Results.Add([PSCustomObject]@{
            TimeCreated = $Event.TimeCreated
            EventRecordID = [UInt64]$Event.RecordId
            EventID = [int]$Event.Id
            Provider = $Event.ProviderName
            MachineName = $Event.MachineName
            XML = $Xml
        })
    }

    return $Results.ToArray()
}

function Get-FiGate1SpoolSnapshot {
    param(
        [string]$SpoolPath = 'C:\ProgramData\FI\spool'
    )

    if (-not (Test-Path -LiteralPath $SpoolPath -PathType Container)) {
        return [PSCustomObject]@{
            Exists = $false
            FileCount = 0
            Bytes = [UInt64]0
            JsonlCount = 0
            ManifestCount = 0
        }
    }

    $FileCount = 0
    $JsonlCount = 0
    $ManifestCount = 0
    $Bytes = [UInt64]0

    Get-ChildItem -LiteralPath $SpoolPath -File -Recurse -Force -ErrorAction Stop | ForEach-Object {
        $FileCount++
        $Bytes += [UInt64]$_.Length
        if ($_.Extension -ieq '.jsonl') { $JsonlCount++ }
        if ($_.Name -like '*.manifest.json') { $ManifestCount++ }
    }

    return [PSCustomObject]@{
        Exists = $true
        FileCount = $FileCount
        Bytes = $Bytes
        JsonlCount = $JsonlCount
        ManifestCount = $ManifestCount
    }
}

function Get-FiGate1FreeBytes {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $Root = [IO.Path]::GetPathRoot($Item.FullName)
    $DriveName = $Root.TrimEnd('\').TrimEnd(':')
    $Drive = Get-PSDrive -Name $DriveName -ErrorAction Stop

    return [UInt64]$Drive.Free
}

function New-FiGate1ResultDirectory {
    param(
        [string]$ResultDirectory = 'C:\ProgramData\FI\gate1-results'
    )

    New-Item -Path $ResultDirectory -ItemType Directory -Force | Out-Null

    # Gate 1 reports can contain paths, identities, service configuration, and
    # raw selected Security-event XML. Protect new report files from inheriting
    # ordinary-user read access. This changes only the result-directory root;
    # it does not recursively rewrite an arbitrary caller-selected tree.
    $Acl = New-Object -TypeName Security.AccessControl.DirectorySecurity
    $Acl.SetAccessRuleProtection($true,$false)
    foreach ($Spec in @(
        @('S-1-5-18',[Security.AccessControl.FileSystemRights]::FullControl),
        @('S-1-5-32-544',[Security.AccessControl.FileSystemRights]::FullControl)
    )) {
        $SID = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList ([string]$Spec[0])
        $Rule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $SID,
            $Spec[1],
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $Acl.AddAccessRule($Rule) | Out-Null
    }
    Set-Acl -LiteralPath $ResultDirectory -AclObject $Acl
    return $ResultDirectory
}

function Write-FiGate1Json {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $InputObject |
        ConvertTo-Json -Depth 12 |
        Set-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-FiGate1PowerShellFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string[]]$Arguments = @()
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required FI script was not found: $Path"
    }

    $Output = @(
        & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $Path @Arguments 2>&1 |
            ForEach-Object { $_.ToString() }
    )
    $ExitCode = $LASTEXITCODE
    $Output | ForEach-Object { Write-Host $_ }

    return [PSCustomObject]@{
        Path = $Path
        ExitCode = $ExitCode
        Output = $Output
    }
}

function Get-FiGate1TestRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GovernedRoot,

        [string]$Name = '_fi_gate1'
    )

    $TestRoot = Join-Path $GovernedRoot $Name
    New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null
    return $TestRoot
}

function Test-FiGate1RootLooksNonProduction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GovernedRoot
    )

    return (
        $GovernedRoot -match '(?i)\\FI-Test(\\|$)' -or
        $GovernedRoot -match '(?i)\\FI-Lab(\\|$)' -or
        $GovernedRoot -match '(?i)\\Lab(\\|$)' -or
        $GovernedRoot -match '(?i)\\Test(\\|$)'
    )
}


function Get-FiGate1CollectorProcessSnapshot {
    $Service = Get-CimInstance Win32_Service -Filter "Name='FICollector'" -ErrorAction Stop

    if ([UInt32]$Service.ProcessId -eq 0) {
        return $null
    }

    $Process = Get-CimInstance Win32_Process -Filter "ProcessId=$($Service.ProcessId)" -ErrorAction Stop

    return [PSCustomObject]@{
        ProcessID = [UInt32]$Process.ProcessId
        ReadOperationCount = [UInt64]$Process.ReadOperationCount
        WriteOperationCount = [UInt64]$Process.WriteOperationCount
        OtherOperationCount = [UInt64]$Process.OtherOperationCount
        ReadTransferCount = [UInt64]$Process.ReadTransferCount
        WriteTransferCount = [UInt64]$Process.WriteTransferCount
        OtherTransferCount = [UInt64]$Process.OtherTransferCount
        KernelModeTime100ns = [UInt64]$Process.KernelModeTime
        UserModeTime100ns = [UInt64]$Process.UserModeTime
        WorkingSetBytes = [UInt64]$Process.WorkingSetSize
        PageFileUsageKB = [UInt64]$Process.PageFileUsage
        ObservedUTC = [DateTime]::UtcNow.ToString('o')
    }
}

function Get-FiGate1UnsignedDelta {
    param([UInt64]$After,[UInt64]$Before)
    if ($After -lt $Before) { return [UInt64]0 }
    return [UInt64]($After - $Before)
}
