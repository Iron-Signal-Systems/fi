# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Use of this script is governed by the File Intelligence (FI)
# Source Review License, Version 1.0, found in the repository root LICENSE file.

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ChangeMask = 0x000D0156
$ReadMask = 0x00000001

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this example from an elevated Windows PowerShell window.'
}

$expectedChangeInheritance =
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit

$expectedReadInheritance =
    [Security.AccessControl.InheritanceFlags]::ObjectInherit

$expectedAudit =
    [Security.AccessControl.AuditFlags]::Success -bor
    [Security.AccessControl.AuditFlags]::Failure

foreach ($requestedPath in $Path) {
    $resolved = (Resolve-Path -LiteralPath $requestedPath).ProviderPath
    $acl = Get-Acl -LiteralPath $resolved -Audit

    $removedChange = 0
    $removedRead = 0

    foreach ($rule in @($acl.GetAuditRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    ))) {
        if ($rule.IsInherited) {
            continue
        }

        $sid = $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value

        if ($sid -ne 'S-1-1-0') {
            continue
        }

        $mask = [int]$rule.FileSystemRights

        $exactChange =
            $mask -eq $ChangeMask -and
            $rule.InheritanceFlags -eq $expectedChangeInheritance -and
            $rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None -and
            $rule.AuditFlags -eq $expectedAudit

        $exactRead =
            $mask -eq $ReadMask -and
            $rule.InheritanceFlags -eq $expectedReadInheritance -and
            $rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::InheritOnly -and
            $rule.AuditFlags -eq $expectedAudit

        if ($exactChange) {
            if ($PSCmdlet.ShouldProcess(
                $resolved,
                'Remove exact FI example change-audit ACE'
            )) {
                [void]$acl.RemoveAuditRuleSpecific($rule)
                $removedChange++
            }
            continue
        }

        if ($exactRead) {
            if ($PSCmdlet.ShouldProcess(
                $resolved,
                'Remove exact FI example read-audit ACE'
            )) {
                [void]$acl.RemoveAuditRuleSpecific($rule)
                $removedRead++
            }
        }
    }

    if (($removedChange + $removedRead) -gt 0) {
        Set-Acl -LiteralPath $resolved -AclObject $acl
    }

    Write-Host "Exact explicit FI change rules removed from $resolved : $removedChange"
    Write-Host "Exact explicit FI read rules removed from $resolved   : $removedRead"
}

Write-Warning 'Global advanced audit-policy settings and SCENoApplyLegacyAuditPolicy were NOT changed. Manage those through GPO or the system policy owner.'
