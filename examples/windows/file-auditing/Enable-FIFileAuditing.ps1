[CmdletBinding(SupportsShouldProcess = $true)]
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

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this example from an elevated Windows PowerShell window.'
}

if ($PSCmdlet.ShouldProcess(
    'Local advanced audit policy',
    'Enable FI Windows Security audit prerequisites'
)) {
    $LsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    New-ItemProperty `
        -Path $LsaPath `
        -Name 'SCENoApplyLegacyAuditPolicy' `
        -PropertyType DWord `
        -Value 1 `
        -Force | Out-Null

    # Enable policy-change auditing first so later audit-policy changes can
    # themselves be represented by Security event 4719.
    & auditpol.exe /set /subcategory:$AuditPolicyChangeGuid /success:enable
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed for Audit Policy Change with exit code $LASTEXITCODE"
    }

    & auditpol.exe /set /subcategory:$FileSystemAuditGuid /success:enable /failure:enable
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed for File System with exit code $LASTEXITCODE"
    }

    # Server 2016 validation showed denied file-handle requests did not emit
    # Event ID 4656 until Handle Manipulation failure auditing was enabled.
    # FI does not currently require Handle Manipulation Success.
    & auditpol.exe /set /subcategory:$HandleManipulationAuditGuid /failure:enable
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed for Handle Manipulation with exit code $LASTEXITCODE"
    }

    # FI uses Detailed File Share / 5145 for governed SMB path and remote-client
    # source context. The File Share / 5140 subcategory is not currently an FI
    # prerequisite.
    & auditpol.exe /set /subcategory:$DetailedFileShareAuditGuid /success:enable /failure:enable
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol failed for Detailed File Share with exit code $LASTEXITCODE"
    }
}

$everyone = New-Object Security.Principal.SecurityIdentifier 'S-1-1-0'

$changeRights = [Security.AccessControl.FileSystemRights]$ChangeMask
$changeInheritance =
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [Security.AccessControl.InheritanceFlags]::ObjectInherit
$changePropagation = [Security.AccessControl.PropagationFlags]::None

$readRights = [Security.AccessControl.FileSystemRights]::ReadData
$readInheritance = [Security.AccessControl.InheritanceFlags]::ObjectInherit
$readPropagation = [Security.AccessControl.PropagationFlags]::InheritOnly

$auditFlags =
    [Security.AccessControl.AuditFlags]::Success -bor
    [Security.AccessControl.AuditFlags]::Failure

foreach ($requestedPath in $Path) {
    $resolved = (Resolve-Path -LiteralPath $requestedPath).ProviderPath
    $acl = Get-Acl -LiteralPath $resolved -Audit

    $changeSufficient = $false
    $readSufficient = $false

    foreach ($rule in $acl.GetAuditRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    )) {
        $sid = $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value

        if ($sid -ne 'S-1-1-0') {
            continue
        }

        $mask = [int]$rule.FileSystemRights

        $hasSuccess =
            (($rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Success) -ne 0)

        $hasFailure =
            (($rule.AuditFlags -band [Security.AccessControl.AuditFlags]::Failure) -ne 0)

        if (-not $hasSuccess -or -not $hasFailure) {
            continue
        }

        $hasObjectInherit =
            (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0)

        $hasContainerInherit =
            (($rule.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0)

        $isInheritOnly =
            (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)

        $hasChangeRights = (($mask -band $ChangeMask) -eq $ChangeMask)
        if (
            $hasChangeRights -and
            $hasObjectInherit -and
            $hasContainerInherit -and
            -not $isInheritOnly
        ) {
            $changeSufficient = $true
        }

        $hasReadRights = (($mask -band $ReadMask) -eq $ReadMask)
        if ($hasReadRights -and $hasObjectInherit) {
            $readSufficient = $true
        }
    }

    if (-not $changeSufficient) {
        $changeRule = [System.Security.AccessControl.FileSystemAuditRule]::new(
            $everyone,
            $changeRights,
            $changeInheritance,
            $changePropagation,
            $auditFlags
        )

        if ($PSCmdlet.ShouldProcess(
            $resolved,
            'Add FI Success/Failure change-auditing SACL'
        )) {
            [void]$acl.AddAuditRule($changeRule)
            Write-Host "Added FI change-audit rule: $resolved"
        }
    }
    else {
        Write-Host "FI change-audit coverage already present: $resolved"
    }

    if (-not $readSufficient) {
        $readRule = [System.Security.AccessControl.FileSystemAuditRule]::new(
            $everyone,
            $readRights,
            $readInheritance,
            $readPropagation,
            $auditFlags
        )

        if ($PSCmdlet.ShouldProcess(
            $resolved,
            'Add FI descendant-file Success/Failure read-auditing SACL'
        )) {
            [void]$acl.AddAuditRule($readRule)
            Write-Host "Added FI read-audit rule: $resolved"
        }
    }
    else {
        Write-Host "FI read-audit coverage already present: $resolved"
    }

    if ($PSCmdlet.ShouldProcess(
        $resolved,
        'Persist FI example SACL changes'
    )) {
        Set-Acl -LiteralPath $resolved -AclObject $acl
    }
}

Write-Host ''
Write-Host '=== Advanced audit precedence ==='
Get-ItemProperty `
    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'SCENoApplyLegacyAuditPolicy' |
    Select-Object SCENoApplyLegacyAuditPolicy |
    Format-List

Write-Host '=== Effective FI Windows audit prerequisites ==='

& auditpol.exe /get /subcategory:$FileSystemAuditGuid
& auditpol.exe /get /subcategory:$HandleManipulationAuditGuid
& auditpol.exe /get /subcategory:$DetailedFileShareAuditGuid
& auditpol.exe /get /subcategory:$AuditPolicyChangeGuid

Write-Host ''
Write-Host 'FI performs the authoritative runtime coverage check during: fi.exe -run'
