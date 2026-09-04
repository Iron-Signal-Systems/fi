# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UNCPath,

    [string]$ResultDirectory = "$env:TEMP\FI-Gate1",

    [switch]$KeepArtifacts,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmWorkload
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if (-not $ConfirmWorkload) { throw '-ConfirmWorkload is required because this script creates/modifies/deletes test data.' }

if ($UNCPath -notmatch '^\\\\[^\\]+\\[^\\]+') {
    throw '-UNCPath must be a UNC path such as \\FILESERVER\Share\GovernedFolder.'
}

if (-not (Test-Path -LiteralPath $UNCPath -PathType Container)) {
    throw "UNC path is not reachable as a directory: $UNCPath"
}

New-Item -Path $ResultDirectory -ItemType Directory -Force | Out-Null

$RunID = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$TestRoot = Join-Path $UNCPath "_fi_gate1_remote_$RunID"
$StartedUTC = [DateTime]::UtcNow
$Operations = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param([string]$Name,[string]$Status,[string]$Path = '',[string]$Detail = '')
    $Operations.Add([PSCustomObject]@{
        Name = $Name
        Status = $Status
        Path = $Path
        Detail = $Detail
        ObservedUTC = [DateTime]::UtcNow.ToString('o')
    })
}

Write-Host ''
Write-Host '============================================================'
Write-Host 'FI GATE 1 - TRUE REMOTE SMB ACTIVITY'
Write-Host "Client:   $env:COMPUTERNAME"
Write-Host "UNC path: $UNCPath"
Write-Host "Run ID:   $RunID"
Write-Host '============================================================'

try {
    New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null

    $File = Join-Path $TestRoot "remote-smb-$RunID.txt"
    'FI Gate 1 remote SMB create' | Set-Content -LiteralPath $File -Encoding ASCII
    Add-Result -Name 'RemoteSMBCreate' -Status 'Executed' -Path $File

    $null = Get-Content -LiteralPath $File -Raw
    Add-Result -Name 'RemoteSMBRead' -Status 'Executed' -Path $File

    'FI Gate 1 remote SMB modify' | Add-Content -LiteralPath $File -Encoding ASCII
    Add-Result -Name 'RemoteSMBModify' -Status 'Executed' -Path $File

    $Renamed = Join-Path $TestRoot "remote-smb-renamed-$RunID.txt"
    Rename-Item -LiteralPath $File -NewName ([IO.Path]::GetFileName($Renamed))
    Add-Result -Name 'RemoteSMBRename' -Status 'Executed' -Path $Renamed

    Remove-Item -LiteralPath $Renamed -Force
    Add-Result -Name 'RemoteSMBDelete' -Status 'Executed' -Path $Renamed

    $Report = [PSCustomObject]@{
        RecordKind = 'FIGate1RemoteSMBActivity'
        RunID = $RunID
        ClientHost = $env:COMPUTERNAME
        ClientUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        UNCPath = $UNCPath
        TestRoot = $TestRoot
        StartedUTC = $StartedUTC.ToString('o')
        FinishedUTC = [DateTime]::UtcNow.ToString('o')
        Operations = $Operations.ToArray()
        ServerReview = 'On the FI file server, confirm 5145 and applicable NTFS events preserve the true remote source and that FI spools the governed-file activity without collapsing share and NTFS outcomes.'
    }

    $ReportPath = Join-Path $ResultDirectory "gate1-remote-smb-$($env:COMPUTERNAME)-$RunID.json"
    $Report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ReportPath -Encoding UTF8

    $Operations | Format-Table Name,Status,Path -AutoSize
    Write-Host "[PASS] Remote SMB workload completed. Report: $ReportPath"
    Write-Host "[INFO] Run the FI file-server collection/inspection after this workload and correlate on RunID: $RunID"
}
finally {
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $TestRoot -PathType Container)) {
        Remove-Item -LiteralPath $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
