# FI Windows Auditing Example

This example documents the Windows audit settings currently validated for FI Windows Security activity collection.

These files are **administrator examples and reference material**. FI does not silently enable Windows auditing, change Group Policy, or add SACLs during normal runtime operation.

## Current validated platform

The current behavior has been validated on:

```text
Windows Server 2016
Version 10.0.14393
```

Later Windows Server versions should be validated independently before FI assumes identical event-generation behavior.

## Required audit policy

FI currently expects the following Windows audit policy for the activity being collected:

```text
Audit File System
    Success: enabled
    Failure: enabled

Audit Handle Manipulation
    Failure: enabled

Audit Policy Change
    Success: enabled
```

During Server 2016 validation, `Audit File System` was already configured for Success and Failure and the governed file had a matching Success/Failure SACL. Successful file activity produced Event ID `4663`, but denied file access did not produce Event ID `4656` until `Audit Handle Manipulation` Failure auditing was enabled.

Because FI depends on the events Windows actually emits, the Server 2016 deployment example includes that setting explicitly.

## Enable the audit policy

Run the example from an elevated Windows PowerShell prompt:

```powershell
.\Enable-FIWindowsAuditing.ps1
```

The script runs the equivalent of:

```powershell
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable
```

It then displays the resulting policy with `auditpol /get`.

In a domain environment, administrators may choose to enforce the equivalent settings through Group Policy instead of applying them locally. FI should observe and report the effective configuration; it should not silently change customer audit policy.

## Governed-root SACL requirement

Enabling Windows audit policy is not sufficient by itself. Windows also requires a matching SACL on the governed file or directory for the requested access.

The currently validated FI change-audit ACE is:

```text
Identity:      Everyone
Audit:         Success, Failure
Inheritance:   ContainerInherit, ObjectInherit
Propagation:   None
Rights:
  WriteData
  AppendData
  WriteExtendedAttributes
  DeleteSubdirectoriesAndFiles
  WriteAttributes
  Delete
  ChangePermissions
  TakeOwnership
```

For a directory root, an administrator can apply that ACE with PowerShell similar to:

```powershell
$root = "C:\Program Files\Wireshark"
$acl = Get-Acl -LiteralPath $root -Audit

$rights = [System.Security.AccessControl.FileSystemRights](
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
)

$inheritance = [System.Security.AccessControl.InheritanceFlags](
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
)

$auditFlags = [System.Security.AccessControl.AuditFlags](
    [System.Security.AccessControl.AuditFlags]::Success -bor
    [System.Security.AccessControl.AuditFlags]::Failure
)

$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    $rights,
    $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    $auditFlags
)

$acl.AddAuditRule($rule)
Set-Acl -LiteralPath $root -AclObject $acl
```

Administrators must review the target root and existing SACL before applying or replacing audit ACEs. FI itself remains read-only and does not perform this configuration automatically.

## Verify the policy

```powershell
auditpol /get /subcategory:"File System" /r
auditpol /get /subcategory:"Handle Manipulation" /r
auditpol /get /subcategory:"Audit Policy Change" /r
```

For a governed object:

```powershell
$target = "C:\Program Files\Wireshark\README.txt"
(Get-Acl -LiteralPath $target -Audit).Audit
```

## Validated denied-access result

On Windows Server 2016, a denied write attempt against a governed file produced Security Event ID `4656` after Handle Manipulation Failure auditing was enabled.

The event supplied FI with source facts including:

- account SID, domain, and username;
- process ID and process path;
- object type and object path;
- requested access mask;
- requested access list and Windows access-reason data; and
- Audit Failure result.

FI preserves that Windows Security record independently from NTFS/USN observations. A denied access request must not be represented as though the file changed.
