# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this source code is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
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

function Assert-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $administrator = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($administrator)) {
        throw 'Set-FILocalStateAcl.ps1 must be run from an elevated Windows PowerShell session.'
    }
}

function Resolve-Sid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    $account = [System.Security.Principal.NTAccount]::new($Identity)
    $resolved = $account.Translate([System.Security.Principal.SecurityIdentifier])
    return [System.Security.Principal.SecurityIdentifier]$resolved
}

function New-AllowRule {
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

function Set-ExactDirectoryDacl {
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

    $acl = Get-Acl -LiteralPath $Path

    # FI-owned runtime directories use protected DACLs. Remove inherited access
    # and every existing explicit access rule, then install only the identities
    # required for operating-system administration and FI runtime access.
    $acl.SetAccessRuleProtection($true, $false)
    $existingRules = @($acl.GetAccessRules(
        $true,
        $false,
        [System.Security.Principal.SecurityIdentifier]
    ))
    foreach ($rule in $existingRules) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }

    [void]$acl.AddAccessRule((New-AllowRule `
        -Sid $systemSid `
        -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl) `
        -InheritanceFlags $inheritChildren))
    [void]$acl.AddAccessRule((New-AllowRule `
        -Sid $administratorsSid `
        -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl) `
        -InheritanceFlags $inheritChildren))
    [void]$acl.AddAccessRule((New-AllowRule `
        -Sid $RuntimeSid `
        -Rights $RuntimeRights `
        -InheritanceFlags $RuntimeInheritance))

    if ($PSCmdlet.ShouldProcess($Path, 'Replace FI-owned directory DACL')) {
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

if ([string]::IsNullOrWhiteSpace($env:ProgramData)) {
    throw 'ProgramData is not set.'
}

Assert-Administrator
$runtimeSid = Resolve-Sid -Identity $RuntimeIdentity

$fiRoot = [System.IO.Path]::GetFullPath($ProgramDataRoot)
$configPath = Join-Path $fiRoot 'config'
$statePath = Join-Path $fiRoot 'state'
$spoolPath = Join-Path $fiRoot 'spool'

foreach ($path in @($fiRoot, $configPath, $statePath, $spoolPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($path, 'Create FI-owned directory')) {
            [void](New-Item -ItemType Directory -Path $path -Force)
        }
    }
}

$none = [System.Security.AccessControl.InheritanceFlags]::None
$inheritChildren = [System.Security.AccessControl.InheritanceFlags]([int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit)

# The FI root grants the runtime identity traverse/read only on that directory.
# Each owned child receives its own protected DACL below.
Set-ExactDirectoryDacl `
    -Path $fiRoot `
    -RuntimeSid $runtimeSid `
    -RuntimeRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) `
    -RuntimeInheritance $none

# Configuration is runtime-readable but not runtime-writable.
Set-ExactDirectoryDacl `
    -Path $configPath `
    -RuntimeSid $runtimeSid `
    -RuntimeRights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute) `
    -RuntimeInheritance $inheritChildren

# Checkpoints, operation/resource journals, supporting-SID state, temporary state
# files, spool batches, and manifests require runtime create/update/replace.
foreach ($path in @($statePath, $spoolPath)) {
    Set-ExactDirectoryDacl `
        -Path $path `
        -RuntimeSid $runtimeSid `
        -RuntimeRights ([System.Security.AccessControl.FileSystemRights]::Modify) `
        -RuntimeInheritance $inheritChildren
}

Write-Host ''
Write-Host 'FI local runtime DACL provisioning complete.'
Write-Host ('Runtime identity : {0}' -f $RuntimeIdentity)
Write-Host ('Runtime SID      : {0}' -f $runtimeSid.Value)
Write-Host ('FI root          : {0}' -f $fiRoot)
Write-Host ('Config           : {0}  (ReadAndExecute)' -f $configPath)
Write-Host ('State            : {0}  (Modify)' -f $statePath)
Write-Host ('Spool            : {0}  (Modify)' -f $spoolPath)
