[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$FileSystemAuditGuid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$AuditPolicyChangeGuid = '{0CCE922F-69AE-11D9-BED3-505054503030}'
$RecommendedMask = 0x000D0156

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this example from an elevated PowerShell window.'
}

if ($PSCmdlet.ShouldProcess('Local advanced audit policy', 'Enable Audit Policy Change Success and Audit File System Success/Failure')) {
    # Enable policy-change auditing first so later changes to File System auditing
    # can themselves be represented by Security event 4719.
    & auditpol.exe /set /subcategory:$AuditPolicyChangeGuid /success:enable
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed for Audit Policy Change with exit code $LASTEXITCODE" }

    & auditpol.exe /set /subcategory:$FileSystemAuditGuid /success:enable /failure:enable
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed for File System with exit code $LASTEXITCODE" }
}

$everyone = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList 'S-1-1-0'
$rights = [Security.AccessControl.FileSystemRights]$RecommendedMask
$inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagation = [Security.AccessControl.PropagationFlags]::None
$auditFlags = [Security.AccessControl.AuditFlags]::Success -bor [Security.AccessControl.AuditFlags]::Failure

foreach ($requestedPath in $Path) {
    $resolved = (Resolve-Path -LiteralPath $requestedPath).ProviderPath
    $acl = Get-Acl -LiteralPath $resolved -Audit

    $sufficient = $false
    foreach ($rule in $acl.GetAuditRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        $mask = [int]$rule.FileSystemRights
        $hasRights = (($mask -band $RecommendedMask) -eq $RecommendedMask)
        $hasInheritance = (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0) -and
                          (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0)
        $hasSuccess = (($rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Success) -ne 0)
        $hasFailure = (($rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Failure) -ne 0)
        if ($sid -eq 'S-1-1-0' -and $hasRights -and $hasInheritance -and $hasSuccess -and $hasFailure) {
            $sufficient = $true
            break
        }
    }

    if ($sufficient) {
        Write-Host "FI recommended audit coverage already present: $resolved"
        continue
    }

    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAuditRule -ArgumentList @(
        $everyone,
        $rights,
        $inheritance,
        $propagation,
        $auditFlags
    )

    if ($PSCmdlet.ShouldProcess($resolved, 'Add FI recommended Success/Failure change-auditing SACL')) {
        [void]$acl.AddAuditRule($rule)
        Set-Acl -LiteralPath $resolved -AclObject $acl
        Write-Host "Added FI recommended audit rule: $resolved"
    }
}
