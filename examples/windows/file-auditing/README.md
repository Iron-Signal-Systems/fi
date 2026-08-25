# FI Windows file-auditing example

This folder contains **example administrator actions** that configure the Windows audit settings and governed-root SACLs FI currently expects for Windows Security activity collection.

The FI collector itself does not enable auditing, edit SACLs, grant access, or otherwise change the governed files/directories. FI only observes the effective configuration and reports whether monitoring coverage is complete or partial.

## Current validated platform

The current behavior has been validated on:

```text
Windows Server 2016
Version 10.0.14393
```

Later Windows Server versions should be validated independently before FI assumes identical event-generation behavior.

## Why this is required

USN + direct NTFS re-observation tells FI what Windows reported changed and what the object looks like now. It does not reliably identify the user/process that requested access.

Windows Security events can provide that missing source data, but they are generated only when the relevant audit policy and object SACL are configured.

FI currently checks:

- Audit File System `{0CCE921D-69AE-11D9-BED3-505054503030}`: Success + Failure
- Audit Handle Manipulation `{0CCE9223-69AE-11D9-BED3-505054503030}`: Failure
- Audit Policy Change `{0CCE922F-69AE-11D9-BED3-505054503030}`: Success
- each configured governed root for the recommended FI change-auditing SACL
- readability/continuity of the local `Security` event log

On the validated Windows Server 2016 system, File System Success/Failure plus a matching governed-object SACL produced successful file activity such as Event ID `4663`, but denied file access did not produce Event ID `4656` until Handle Manipulation Failure auditing was also enabled.

FI therefore treats Handle Manipulation Failure as a collector prerequisite for the current Windows Security coverage model.

Handle Manipulation **Success** is not required by FI at this time.

FI initially collects these Security event IDs:

- 4656: handle/access requested; failure events can show denied write attempts
- 4663: an access right was actually used
- 4660: object deleted; the event does not contain the object path, so FI preserves it as unresolved for later correlation
- 4664: hard link created
- 4670: permissions changed
- 4907: auditing settings/SACL changed
- 1102: Security audit log cleared
- 4719: system audit policy changed

FI preserves Windows Security records independently from NTFS/USN observations. A denied access request must not be represented as though the file changed.

## Recommended SACL

The example adds one explicit inheritable `SYSTEM_AUDIT_ACE` for Everyone (`S-1-1-0`) on each governed root.

It audits **Success and Failure** for change-capable rights only:

- WriteData / CreateFiles
- AppendData / CreateDirectories
- WriteExtendedAttributes
- DeleteSubdirectoriesAndFiles
- WriteAttributes
- Delete
- ChangePermissions
- TakeOwnership

Combined mask: `0x000D0156` (decimal `852310`).

The ACE inherits to files and directories. It does **not** grant any filesystem permissions; a SACL controls auditing, not access.

A descendant can protect its SACL from inheritance. FI therefore does not claim that a root SACL proves every descendant is covered. Each NTFS observation still preserves the actual SACL observed on that object.

## Domain/GPO warning

`auditpol` changes the effective local advanced audit policy. In a domain, Group Policy can overwrite the local setting.

For production deployment, configure the same effective audit subcategories through the organization's GPO or configuration-management process rather than relying on a one-time local script.

FI should observe and report the effective configuration. It should not silently change customer audit policy.

The scripts use subcategory GUIDs instead of localized display names.

## 1. Inspect without changing anything

Run elevated if you want the SACL inspection to succeed:

```powershell
.\Test-FIFileAuditing.ps1 -Path 'C:\Program Files\Wireshark'
```

Multiple roots:

```powershell
.\Test-FIFileAuditing.ps1 `
  -Path 'C:\Users\jwood.admin\Downloads','C:\Program Files\Wireshark'
```

This script does not change the system.

It displays:

- File System audit policy
- Handle Manipulation audit policy
- Audit Policy Change audit policy
- the visible audit ACEs on each supplied governed root
- whether the FI-recommended root audit rule is present

FI itself performs the authoritative locale-independent prerequisite check during `fi.exe -run`.

## 2. Enable the example configuration

Run from an elevated PowerShell window:

```powershell
.\Enable-FIFileAuditing.ps1 -Path 'C:\Program Files\Wireshark'
```

Multiple roots:

```powershell
.\Enable-FIFileAuditing.ps1 `
  -Path 'C:\Users\jwood.admin\Downloads','C:\Program Files\Wireshark'
```

The script enables:

```text
Audit File System
    Success
    Failure

Audit Handle Manipulation
    Failure

Audit Policy Change
    Success
```

It also adds the FI-recommended governed-root audit ACE when a sufficient rule is not already visible.

The script is idempotent for the recommended ACE. It preserves the existing DACL and SACL and adds the FI-recommended audit ACE only when a sufficient explicit/inherited rule is not already visible on the governed root.

The script does not disable unrelated audit settings.

## 3. Let FI verify the effective configuration

```powershell
cd C:\Users\jwood.admin\src\fi\go
.\fi.exe -run
```

For the current validated configuration, look for:

```text
monitoring_prerequisites_satisfied: true
windows_security.coverage.status: Ready
```

The Windows Security coverage record should include:

```text
file_system_policy
    success_enabled: true
    failure_enabled: true

handle_manipulation_policy
    success_enabled: false
    failure_enabled: true

audit_policy_change_policy
    success_enabled: true
```

If a required policy setting or governed-root SACL is missing/unreadable, FI reports:

```text
monitoring_prerequisites_satisfied: false
windows_security.coverage.status: Partial
```

`Ready` means the required host policy and governed-root audit rule were observed when FI ran. It does not claim that a descendant with protected SACL inheritance is covered.

FI does not infer that missing Security events mean no activity occurred.

## 4. Reproduce a denied write

Use a normal, non-elevated application/window to attempt a write against an existing governed file for which the current user can read but cannot write, for example:

```text
C:\Program Files\Wireshark\README.txt
```

Then run FI again:

```powershell
.\fi.exe -run
```

On the validated Windows Server 2016 system, a denied write produced Security Event ID `4656` once Handle Manipulation Failure auditing was enabled.

The event supplied FI with source facts including:

- account SID, domain, and username
- logon ID
- process ID and process path
- object type and object path
- requested access mask
- requested access list
- Windows access-reason data
- Audit Failure result
- EventRecordID and timestamp
- raw event XML

Two source events with different EventRecordIDs/timestamps are preserved as two source events. FI does not deduplicate separate Windows Security records merely because they refer to the same object/process.

## 5. Inspect the events directly in Windows

This is read-only:

```powershell
.\Show-FIFileAuditEvents.ps1 -Minutes 10
```

Optionally restrict output to a path fragment:

```powershell
.\Show-FIFileAuditEvents.ps1 `
  -Minutes 10 `
  -PathContains 'C:\Program Files\Wireshark'
```

## Rollback

The safest production rollback is through the same GPO/configuration-management mechanism that established the policy.

For the lab, `Remove-FIRecommendedAudit.ps1` removes only an **explicit** audit ACE that exactly matches the FI example rule from the specified root.

It intentionally does not disable global audit-policy subcategories because the script cannot know whether those settings predated FI or are required by another security control.

```powershell
.\Remove-FIRecommendedAudit.ps1 -Path 'C:\Program Files\Wireshark'
```

An identical pre-existing explicit ACE is indistinguishable from one added by the example. Review before removal.
