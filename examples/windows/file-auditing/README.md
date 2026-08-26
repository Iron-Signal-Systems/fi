# FI Windows file-auditing example

This folder contains **example administrator actions** that configure the Windows
advanced audit settings and governed-root SACLs FI currently expects for Windows
Security activity collection.

The FI collector itself does not enable auditing, edit SACLs, grant access, or
otherwise change governed files/directories. FI observes the effective
configuration and reports whether its current monitoring prerequisites are
`Ready` or `Partial`.

These examples are intended for **Windows PowerShell 5.1** as shipped with
Windows Server 2016.

## Current validated platform

Current behavior has been live validated on:

```text
Windows Server 2016
Version 10.0.14393
```

Later Windows Server versions must be validated independently before FI assumes
identical event-generation behavior.

## Why Windows auditing is required

USN + direct NTFS re-observation tells FI what Windows reported changed and what
the object looks like now. It does not reliably identify the user/process that
requested or used access.

Windows Security events can provide independent actor/process/access facts, but
they are emitted only when the effective audit policy and object SACL are
sufficient.

FI currently checks the effective state of:

- Audit File System `{0CCE921D-69AE-11D9-BED3-505054503030}`:
  Success + Failure;
- Audit Handle Manipulation `{0CCE9223-69AE-11D9-BED3-505054503030}`:
  Failure;
- Audit Detailed File Share `{0CCE9244-69AE-11D9-BED3-505054503030}`:
  Success + Failure;
- Audit Policy Change `{0CCE922F-69AE-11D9-BED3-505054503030}`:
  Success;
- each configured governed root for sufficient FI change-auditing coverage;
- each configured governed root for sufficient descendant-file read-auditing
  coverage; and
- readability of the local `Security` event log.

FI does not currently require Handle Manipulation Success.

FI does not require the basic/legacy **Audit object access** category. Production
deployment should use Advanced Audit Policy and force subcategory policy to
override legacy category policy.

## Advanced Audit Policy precedence

For production, configure the FI prerequisites with a dedicated scoped GPO or
equivalent configuration-management process.

Enable:

```text
Computer Configuration
  Windows Settings
    Security Settings
      Local Policies
        Security Options
          Audit: Force audit policy subcategory settings
          (Windows Vista or later) to override audit policy category settings
```

The corresponding registry value is:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
SCENoApplyLegacyAuditPolicy = 1
```

The example enable script sets this value locally for lab/testing. In a domain,
the production owner should establish it through policy.

FI's current `Ready` assessment verifies the effective advanced subcategory state,
Security log readability, and governed-root SACL coverage. The precedence
registry value is a deployment recommendation and is not currently a separate
`Ready` field.

## Events currently selected by FI

FI currently selects:

- `4656` — handle/access requested;
- `4663` — an access right was used;
- `4660` — object deleted; the event has no path, so FI preserves it as
  unresolved for later correlation;
- `4664` — hard link created;
- `4670` — permissions changed;
- `4907` — auditing settings/SACL changed;
- `5145` — detailed SMB share access check;
- `1102` — Security audit log cleared; and
- `4719` — system audit policy changed.

FI preserves Windows Security records independently from NTFS/USN observations.
A denied request is not represented as though the file changed.

## Recommended governed-root SACLs

The example uses two separate audit rules because change auditing and successful
file-read auditing have different noise characteristics.

### Change-capable rule

Principal:

```text
Everyone / S-1-1-0
```

Audits Success + Failure for:

- WriteData / CreateFiles;
- AppendData / CreateDirectories;
- WriteExtendedAttributes;
- DeleteSubdirectoriesAndFiles;
- WriteAttributes;
- Delete;
- ChangePermissions; and
- TakeOwnership.

Combined mask:

```text
0x000D0156
decimal 852310
```

Inheritance:

```text
ObjectInherit
ContainerInherit
```

Propagation:

```text
None
```

This rule is intended to apply to the root and descendants.

### Descendant-file read rule

Principal:

```text
Everyone / S-1-1-0
```

Audited right:

```text
ReadData
mask 0x00000001
```

Inheritance:

```text
ObjectInherit
```

Propagation:

```text
InheritOnly
```

Audit flags:

```text
Success
Failure
```

The `InheritOnly` design avoids adding `ReadData` to the root directory itself,
where the same bit represents `ListDirectory` and can create unnecessary
directory-enumeration noise.

FI's current coverage check accepts a sufficient read rule that contains
ObjectInherit + Success + Failure + ReadData. The example installs the narrower
ObjectInherit + InheritOnly form.

Neither SACL rule grants filesystem access. SACLs control auditing, not
authorization.

A descendant can protect its SACL from inheritance. A correct root SACL therefore
does not prove every descendant is covered. FI preserves the actual SACL observed
on each NTFS object.

## Current Windows Server 2016 findings

On the validated Server 2016 system:

- File System Success/Failure plus the change rule produced successful file
  activity such as `4663`;
- denied file-handle requests did not produce `4656` until Handle Manipulation
  Failure auditing was enabled;
- a fresh descendant file inheriting the read rule produced `4663` on read;
- Detailed File Share Success/Failure produced `5145`;
- File Share/`5140` was not required for the current FI `5145` source;
- local UNC activity preserved source address `::1`;
- true remote SMB activity preserved the remote client IP; and
- a remote operation denied by NTFS could produce `5145` Success for the
  share-level check and `4656` Failure for the NTFS handle request with matching
  logon/access context.

A successful `5145` means the share-level access check represented by that event
succeeded. It does **not** prove the final NTFS operation succeeded.

FI suppresses a bare share-root `5145` when it represents only the share root
rather than a descendant governed-object path.

## Domain/GPO warning

`auditpol` changes effective local advanced audit policy. Domain Group Policy can
overwrite local settings.

For production, use the organization's GPO/configuration-management process
rather than relying on a one-time local script.

Do not mix broad legacy/basic Audit Policy with Advanced Audit Policy for FI.
Prefer explicit Advanced Audit subcategories with the subcategory-override
security option enabled.

The scripts use subcategory GUIDs instead of localized display names.

## 1. Inspect without changing anything

Run elevated if you want SACL inspection to succeed:

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

- `SCENoApplyLegacyAuditPolicy`;
- File System policy;
- Handle Manipulation policy;
- Detailed File Share policy;
- Audit Policy Change policy;
- visible audit ACEs on each root;
- FI change-rule coverage; and
- FI read-rule coverage.

FI itself performs the authoritative locale-independent runtime coverage check
during `fi.exe -run`.

## 2. Enable the lab/example configuration

Run from an elevated Windows PowerShell 5.1 window:

```powershell
.\Enable-FIFileAuditing.ps1 -Path 'C:\Program Files\Wireshark'
```

Multiple roots:

```powershell
.\Enable-FIFileAuditing.ps1 `
  -Path 'C:\Users\jwood.admin\Downloads','C:\Program Files\Wireshark'
```

The script ensures:

```text
SCENoApplyLegacyAuditPolicy = 1

Audit File System
    Success
    Failure

Audit Handle Manipulation
    Failure

Audit Detailed File Share
    Success
    Failure

Audit Policy Change
    Success
```

It also adds the FI example change and read SACL rules when sufficient rules are
not already visible.

The script does not disable unrelated audit settings.

## 3. Let FI verify the effective configuration

From the Go project directory:

```powershell
.\fi.exe -run
```

For the current validated configuration, look for:

```text
monitoring_prerequisites_satisfied: true
windows_security.coverage.status: Ready
```

The coverage record should include effective policy state for:

```text
file_system_policy
handle_manipulation_policy
detailed_file_share_policy
audit_policy_change_policy
```

Each root should report both:

```text
recommended_change_audit_present: true
recommended_read_audit_present: true
```

If a required policy setting, Security-log read, or governed-root audit rule is
missing/unreadable, FI reports `Partial`.

`Ready` describes the prerequisites FI observed at that run. It does not prove
that every descendant inherits the root SACL or that Windows emitted every
possible activity record.

FI never interprets a missing Security event as proof that no activity occurred.

## 4. Reproduce a local denied write

Use a normal non-elevated application/window to attempt a write against an
existing governed file for which the user can read but cannot write.

Then run FI again:

```powershell
.\fi.exe -run
```

On the validated Server 2016 system, a denied write produced `4656` after Handle
Manipulation Failure auditing was enabled.

The source record can preserve facts such as:

- account SID/domain/username;
- logon ID;
- process ID/path;
- object type/path;
- requested access mask/list;
- Windows access-reason data;
- Audit Failure result;
- EventRecordID/timestamp; and
- raw event XML.

## 5. Reproduce a successful descendant-file read

Create or choose a file that actually inherited the FI read-audit rule from a
governed root.

Read it normally, then run FI:

```powershell
.\fi.exe -run
```

A successful read should be evaluated from the resulting Security source record
and the actual observed SACL on the file.

Do not use the root directory itself as the read test: the example read rule is
intentionally `InheritOnly`.

## 6. Reproduce SMB/5145 context

With a governed root exposed through an SMB share, perform both:

- local UNC access; and
- access from a different Windows host.

Then run FI and inspect selected Security records.

For a descendant target, FI should preserve source `5145` fields such as:

- ShareName;
- ShareLocalPath;
- RelativeTargetName;
- SubjectLogonId;
- source IP/port;
- AccessMask;
- AccessList; and
- AccessReason.

A remote NTFS denial can still have a successful share-level `5145`; treat the
subsequent NTFS failure as an independent source fact.

## 7. Inspect events directly in Windows

This is read-only:

```powershell
.\Show-FIFileAuditEvents.ps1 -Minutes 10
```

Optionally restrict output to a path/share fragment:

```powershell
.\Show-FIFileAuditEvents.ps1 `
  -Minutes 10 `
  -PathContains 'Wireshark'
```

## Rollback

The safest production rollback is through the same GPO/configuration-management
mechanism that established the policy.

For the lab, `Remove-FIRecommendedAudit.ps1` removes only explicit audit ACEs
that exactly match the two FI example rules from the supplied root.

It intentionally does not disable global audit-policy subcategories or reset
`SCENoApplyLegacyAuditPolicy`, because those settings may predate FI or be
required by another security control.

```powershell
.\Remove-FIRecommendedAudit.ps1 -Path 'C:\Program Files\Wireshark'
```

An identical pre-existing explicit ACE is indistinguishable from one added by the
example. Review before removal.
