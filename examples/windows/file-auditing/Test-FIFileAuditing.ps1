[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$FileSystemAuditGuid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$HandleManipulationAuditGuid = '{0CCE9223-69AE-11D9-BED3-505054503030}'
$AuditPolicyChangeGuid = '{0CCE922F-69AE-11D9-BED3-505054503030}'
$RecommendedMask = 0x000D0156

Write-Host '=== Effective advanced audit policy ==='
& auditpol.exe /get /subcategory:$FileSystemAuditGuid
& auditpol.exe /get /subcategory:$HandleManipulationAuditGuid
& auditpol.exe /get /subcategory:$AuditPolicyChangeGuid

Write-Host ''
Write-Host '=== Governed-root SACL ==='

foreach ($requestedPath in $Path) {
    $resolved = (Resolve-Path -LiteralPath $requestedPath).ProviderPath
    Write-Host "Path: $resolved"

    try {
        $acl = Get-Acl -LiteralPath $resolved -Audit
        $found = $false

        foreach ($rule in $acl.GetAuditRules(
            $true,
            $true,
            [Security.Principal.SecurityIdentifier]
        )) {
            $sid = $rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]
            ).Value

            $mask = [int]$rule.FileSystemRights
            $hasRights = (($mask -band $RecommendedMask) -eq $RecommendedMask)

            $hasInheritance =
                (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0) -and
                (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0)

            $hasSuccess =
                (($rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Success) -ne 0)

            $hasFailure =
                (($rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Failure) -ne 0)

            if (
                $sid -eq 'S-1-1-0' -and
                $hasRights -and
                $hasInheritance -and
                $hasSuccess -and
                $hasFailure
            ) {
                $found = $true
            }

            [pscustomobject]@{
                Identity    = $sid
                Rights      = $rule.FileSystemRights
                AuditFlags  = $rule.AuditFlags
                Inheritance = $rule.InheritanceFlags
                Propagation = $rule.PropagationFlags
                Inherited   = $rule.IsInherited
            } | Format-List
        }

        Write-Host "FI recommended root rule present: $found"
    }
    catch {
        Write-Warning "Could not read SACL for $resolved : $($_.Exception.Message)"
    }

    Write-Host ''
}

Write-Host 'FI itself performs the authoritative locale-independent policy/SACL coverage check during: fi.exe -run'
