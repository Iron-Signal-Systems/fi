# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this source code is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RuntimeIdentity,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ProgramDataRoot = (Join-Path $env:ProgramData 'FI')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Sid {
    param([Parameter(Mandatory = $true)][string]$Identity)
    $account = [System.Security.Principal.NTAccount]::new($Identity)
    $resolved = $account.Translate([System.Security.Principal.SecurityIdentifier])
    return [System.Security.Principal.SecurityIdentifier]$resolved
}

function New-ExpectedRule {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$Sid,
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags
    )

    return [System.Security.AccessControl.FileSystemAccessRule]::new(
        $Sid,
        $Rights,
        $InheritanceFlags,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
}

function Test-DirectoryDacl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.SecurityIdentifier]$RuntimeSid,
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemRights]$RuntimeRights,
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.InheritanceFlags]$RuntimeInheritance
    )

    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $inheritChildren = [System.Security.AccessControl.InheritanceFlags]([int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit)

    $expected = @(
        (New-ExpectedRule -Sid $systemSid -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl) -InheritanceFlags $inheritChildren)
        (New-ExpectedRule -Sid $administratorsSid -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl) -InheritanceFlags $inheritChildren)
        (New-ExpectedRule -Sid $RuntimeSid -Rights $RuntimeRights -InheritanceFlags $RuntimeInheritance)
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [pscustomobject]@{
            Path = $Path
            Exists = $false
            Protected = $false
            ExactRules = $false
            Compliant = $false
            Problem = 'DirectoryMissing'
        }
    }

    $acl = Get-Acl -LiteralPath $Path
    $actual = @($acl.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    ))

    $exactRules = $actual.Count -eq $expected.Count
    if ($exactRules) {
        foreach ($wanted in $expected) {
            $matches = @($actual | Where-Object {
                $_.IdentityReference.Value -eq $wanted.IdentityReference.Value -and
                [int64]$_.FileSystemRights -eq [int64]$wanted.FileSystemRights -and
                $_.InheritanceFlags -eq $wanted.InheritanceFlags -and
                $_.PropagationFlags -eq $wanted.PropagationFlags -and
                $_.AccessControlType -eq $wanted.AccessControlType -and
                -not $_.IsInherited
            })
            if ($matches.Count -ne 1) {
                $exactRules = $false
                break
            }
        }
    }

    $protected = [bool]$acl.AreAccessRulesProtected
    $problem = 'DaclMismatch'
    if ($protected -and $exactRules) {
        $problem = ''
    }
    return [pscustomobject]@{
        Path = $Path
        Exists = $true
        Protected = $protected
        ExactRules = $exactRules
        Compliant = ($protected -and $exactRules)
        Problem = $problem
    }
}

if ([string]::IsNullOrWhiteSpace($env:ProgramData)) {
    throw 'ProgramData is not set.'
}

$runtimeSid = Resolve-Sid -Identity $RuntimeIdentity
$fiRoot = [System.IO.Path]::GetFullPath($ProgramDataRoot)
$configPath = Join-Path $fiRoot 'config'
$statePath = Join-Path $fiRoot 'state'
$spoolPath = Join-Path $fiRoot 'spool'
$none = [System.Security.AccessControl.InheritanceFlags]::None
$inheritChildren = [System.Security.AccessControl.InheritanceFlags]([int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit)

$results = @(
    (Test-DirectoryDacl -Path $fiRoot -RuntimeSid $runtimeSid -RuntimeRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) -RuntimeInheritance $none)
    (Test-DirectoryDacl -Path $configPath -RuntimeSid $runtimeSid -RuntimeRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) -RuntimeInheritance $inheritChildren)
    (Test-DirectoryDacl -Path $statePath -RuntimeSid $runtimeSid -RuntimeRights ([System.Security.AccessControl.FileSystemRights]::Modify) -RuntimeInheritance $inheritChildren)
    (Test-DirectoryDacl -Path $spoolPath -RuntimeSid $runtimeSid -RuntimeRights ([System.Security.AccessControl.FileSystemRights]::Modify) -RuntimeInheritance $inheritChildren)
)

$results | Format-Table -AutoSize

$compliant = @($results | Where-Object { -not $_.Compliant }).Count -eq 0
Write-Host ''
Write-Host ('FI local runtime DACL compliant: {0}' -f $compliant)

if (-not $compliant) {
    exit 1
}
