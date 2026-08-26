[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$FileSystemAuditGuid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$HandleManipulationAuditGuid = '{0CCE9223-69AE-11D9-BED3-505054503030}'
$DetailedFileShareAuditGuid = '{0CCE9244-69AE-11D9-BED3-505054503030}'
$AuditPolicyChangeGuid = '{0CCE922F-69AE-11D9-BED3-505054503030}'

$ChangeMask = 0x000D0156
$ReadMask = 0x00000001

Write-Host '=== Advanced audit precedence ==='

try {
    Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
        -Name 'SCENoApplyLegacyAuditPolicy' |
        Select-Object SCENoApplyLegacyAuditPolicy |
        Format-List
}
catch {
    Write-Warning "Could not read SCENoApplyLegacyAuditPolicy: $($_.Exception.Message)"
}

Write-Host '=== Effective advanced audit policy ==='
& auditpol.exe /get /subcategory:$FileSystemAuditGuid
& auditpol.exe /get /subcategory:$HandleManipulationAuditGuid
& auditpol.exe /get /subcategory:$DetailedFileShareAuditGuid
& auditpol.exe /get /subcategory:$AuditPolicyChangeGuid

Write-Host ''
Write-Host '=== Governed-root SACL ==='

foreach ($requestedPath in $Path) {
    $resolved = (Resolve-Path -LiteralPath $requestedPath).ProviderPath
    Write-Host "Path: $resolved"

    try {
        $acl = Get-Acl -LiteralPath $resolved -Audit
        $changeFound = $false
        $readFound = $false

        foreach ($rule in $acl.GetAuditRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )) {
            $sid = $rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value

            $mask = [int]$rule.FileSystemRights

            $hasSuccess =
                (($rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Success) -ne 0)

            $hasFailure =
                (($rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Failure) -ne 0)

            $hasObjectInherit =
                (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0)

            $hasContainerInherit =
                (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0)

            $isInheritOnly =
                (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)

            $hasChangeRights = (($mask -band $ChangeMask) -eq $ChangeMask)
            if (
                $sid -eq 'S-1-1-0' -and
                $hasChangeRights -and
                $hasObjectInherit -and
                $hasContainerInherit -and
                -not $isInheritOnly -and
                $hasSuccess -and
                $hasFailure
            ) {
                $changeFound = $true
            }

            $hasReadRights = (($mask -band $ReadMask) -eq $ReadMask)
            if (
                $sid -eq 'S-1-1-0' -and
                $hasReadRights -and
                $hasObjectInherit -and
                $hasSuccess -and
                $hasFailure
            ) {
                $readFound = $true
            }

            [pscustomobject]@{
                Identity    = $sid
                Rights      = $rule.FileSystemRights
                Mask        = $mask
                AuditFlags  = $rule.AuditFlags
                Inheritance = $rule.InheritanceFlags
                Propagation = $rule.PropagationFlags
                Inherited   = $rule.IsInherited
            } | Format-List
        }

        Write-Host "FI recommended change coverage present: $changeFound"
        Write-Host "FI recommended read coverage present:   $readFound"
    }
    catch {
        Write-Warning "Could not read SACL for $resolved : $($_.Exception.Message)"
    }

    Write-Host ''
}

Write-Host 'FI performs the authoritative locale-independent policy/SACL coverage check during: fi.exe -run'
