[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$RecommendedMask = 0x000D0156

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this example from an elevated PowerShell window.'
}

foreach ($requestedPath in $Path) {
    $resolved = (Resolve-Path -LiteralPath $requestedPath).ProviderPath
    $acl = Get-Acl -LiteralPath $resolved -Audit
    $removed = 0

    foreach ($rule in @($acl.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        if ($rule.IsInherited) { continue }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $mask = [int]$rule.FileSystemRights
        $exactRights = ($mask -eq $RecommendedMask)
        $exactInheritance = ($rule.InheritanceFlags -eq ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit))
        $exactPropagation = ($rule.PropagationFlags -eq [Security.AccessControl.PropagationFlags]::None)
        $exactAudit = ($rule.AuditFlags -eq ([Security.AccessControl.AuditFlags]::Success -bor [Security.AccessControl.AuditFlags]::Failure))

        if ($sid -eq 'S-1-1-0' -and $exactRights -and $exactInheritance -and $exactPropagation -and $exactAudit) {
            if ($PSCmdlet.ShouldProcess($resolved, 'Remove exact FI example audit ACE')) {
                [void]$acl.RemoveAuditRuleSpecific($rule)
                $removed++
            }
        }
    }

    if ($removed -gt 0) {
        Set-Acl -LiteralPath $resolved -AclObject $acl
    }
    Write-Host "Exact explicit FI example audit rules removed from $resolved : $removed"
}

Write-Warning 'Global advanced audit-policy settings were NOT disabled. Manage those through GPO or the system policy owner.'
