# FI Windows file-auditing example

This folder contains **example administrator actions** that change Windows audit configuration so FI can observe the actor/process side of file activity.

The FI collector itself does not enable auditing, edit SACLs, grant access, or otherwise change the governed files/directories. FI only observes the effective configuration and reports whether monitoring coverage is complete or partial.

These examples target Windows Server 2016 and later.

## Why this is required

USN + direct NTFS re-observation tells FI what Windows reported changed and what the object looks like now. It does not reliably identify the user/process that requested access.

Windows Security events can provide that missing source data, but they are generated only when the relevant audit policy and object SACL are configured.

FI v6 checks:

- Audit File System `{0CCE921D-69AE-11D9-BED3-505054503030}`: Success + Failure
- Audit Audit Policy Change `{0CCE922F-69AE-11D9-BED3-505054503030}`: Success
- each configured governed root for the recommended FI change-auditing SACL
- readability/continuity of the local `Security` event log

FI initially collects these Security event IDs:

- 4656: handle/access requested; failure events can show denied write attempts
- 4663: an access right was actually used
- 4660: object deleted; the event does not contain the object path, so FI preserves it as unresolved for later correlation
- 4664: hard link created
- 4670: permissions changed
- 4907: auditing settings/SACL changed
- 1102: Security audit log cleared
- 4719: system audit policy changed

FI does not enable Audit Handle Manipulation/4658 by default because of its additional event volume.

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

`auditpol` changes the effective local advanced audit policy. In a domain, Group Policy can overwrite the local setting. For production deployment, configure the same subcategories through the organization's GPO rather than relying on a one-time local script.

The scripts use subcategory GUIDs instead of localized display names.

## 1. Inspect without changing anything

Run elevated if you want the SACL inspection to succeed:

```powershell
.\Test-FIFileAuditing.ps1 -Path 'C:\Program Files\Wireshark'
```

This script does not change the system.

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

The script is idempotent for the exact recommended ACE. It preserves the existing DACL and SACL and adds the FI-recommended audit ACE only when a sufficient explicit/inherited rule is not already visible on the governed root.

## 3. Let FI verify the effective configuration

```powershell
cd C:\Users\jwood.admin\src\fi\go
.\fi.exe -run
```

Look for:

```text
monitoring_prerequisites_satisfied: true
windows_security.coverage.status: Ready
```

If policy or a root SACL is missing/unreadable, FI reports `Partial`. `Ready` means the required host policy and governed-root audit rule are present; it does not claim that a descendant with protected SACL inheritance is covered. Each NTFS object observation still records that object's actual SACL. It does not infer that missing Security events mean no activity occurred.

## 4. Reproduce a denied write

Use a normal, non-elevated application/window to attempt a write under a governed protected directory such as:

```text
C:\Program Files\Wireshark\README.txt
```

Then run FI again:

```powershell
.\fi.exe -run
```

With Failure auditing and a matching SACL active, a denied file access should be represented by Security event 4656 when Windows emits the event. The spooled event preserves the account SID/name, logon ID, process information, requested access fields, result, object path, EventRecordID, timestamp, and raw event XML supplied by Windows.

## 5. Inspect the events directly in Windows

This is read-only:

```powershell
.\Show-FIFileAuditEvents.ps1 -Minutes 10
```

Optionally restrict output to a path fragment:

```powershell
.\Show-FIFileAuditEvents.ps1 -Minutes 10 -PathContains 'C:\Program Files\Wireshark'
```

## Rollback

The safest production rollback is through the same GPO/configuration-management mechanism that established the policy.

For the lab, `Remove-FIRecommendedAudit.ps1` removes only an **explicit** audit ACE that exactly matches the FI example rule from the specified root. It intentionally does not disable the global audit-policy subcategories because the script cannot know whether those settings predated FI or are required by another security control.

```powershell
.\Remove-FIRecommendedAudit.ps1 -Path 'C:\Program Files\Wireshark'
```

An identical pre-existing explicit ACE is indistinguishable from one added by the example. Review before removal.
