# FI NTFS USN Privilege Boundary, Authentication, and Containment Model

## Purpose

This document defines the current Windows privilege boundary between
`FICollector` and `FIUSNReader`.

It covers:

- why FI uses the NTFS USN Journal;
- which operations require a privileged Windows helper;
- how the local broker authenticates the real FICollector service;
- how configured-volume authorization works;
- how protected-object containment is handled;
- the Windows Server 2022-specific scoped `SeBackupPrivilege` fallback;
- failure semantics; and
- the deployment properties that must remain true.

It is written for:

- IT directors who need to understand the operational and security value;
- security administrators who need the trust and authorization model;
- Windows administrators who deploy and support the services; and
- FI engineers who must preserve the privilege boundary in code.

The current validated Windows Server releases are:

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
```

Release-specific results are recorded in:

```text
docs/WINDOWS-SERVER-VALIDATION.md
```

---

# 1. USN is a change source

FI uses the NTFS USN Journal for efficient change discovery and continuity.

FI cannot assume continuous uptime. Servers reboot, services stop, maintenance
occurs, and dependencies fail. File servers can contain millions of objects.

Without a durable change source, FI would have to choose between assuming nothing
changed while FI was unavailable or repeatedly rescanning the full governed tree.
Neither is acceptable as the normal incremental model.

NTFS continues recording journal changes while FI is unavailable:

```text
FI accepted checkpoint = USN X
        |
        | FI stops / host reboots / maintenance
        |
        | NTFS continues journaling
        v
FI resumes
        |
        | validate journal continuity
        | read after USN X
        v
changed NTFS object identities
        |
        v
fresh targeted re-observation
```

FI's USN checkpoint preserves the source identity and forward boundary needed to
determine whether continued journal reading remains valid. If continuity fails,
FI records the gap and reconciles current state. Missing source history is never
rewritten as complete historical coverage.

USN can report source facts such as:

- file reference number;
- parent file reference number;
- USN;
- reason bits;
- journal timestamp;
- source information;
- security ID;
- file attributes; and
- the name carried in the journal record.

Those facts do not prove current governed scope.

An object may have been renamed, moved, deleted, replaced, or moved outside the
governed root after the journal record was written.

FI therefore separates:

```text
USN
    -> what changed?

fresh object observation
    -> what is the object now?

current containment
    -> is that current object governed?
```

---

# 2. Why the privileged helper exists

Direct-volume USN access uses a device path such as:

```text
\\.\C:
```

The current validated design requires the narrow helper to run inside the local
Windows administrative boundary.

2019 and 2022 characterization explicitly established:

```text
Non-admin                         FAIL
Non-admin + SeManageVolume        FAIL
Local Administrator               PASS
FILE_READ_DATA                    least tested successful raw-volume access
```

`SeManageVolumePrivilege` alone is not the production access model.

The design response is not to run the complete collector as Administrator.

The privileged operation is isolated:

```text
FICollector
    non-admin
        |
        v
local authenticated FI-USN broker
        |
        v
FIUSNReader
    local Administrator
        |
        +-- bounded USN query
        +-- bounded USN read
        +-- bounded mechanical containment check
```

---

# 3. Per-host identity model

Every monitored Windows server uses a unique identity pair.

Example:

```text
ISS-FS-01
    ISS\gFI-FS01$          -> FICollector
    ISS\gFI-USN-FS01$      -> FIUSNReader
```

The collector and helper gMSAs are not shared across monitored hosts.

The matching computer account should be the only principal authorized to
retrieve each assigned managed password.

This gives FI:

- host attribution;
- function attribution;
- smaller credential blast radius;
- per-host revocation; and
- clearer operational auditing.

---

# 4. FICollector responsibilities

`FICollector` runs under the restricted per-host collector gMSA.

It is not local Administrator.

It owns:

- FI configuration processing;
- governed-root processing;
- baseline collection;
- USN parsing;
- normal File-ID re-observation;
- governed-root collection policy;
- NTFS metadata/security/stream/reparse collection;
- content hashing;
- local spool writing and verification;
- checkpoint persistence and advancement;
- continuity decisions;
- Windows Security collection;
- SMB/local/AD supporting sources;
- operation history; and
- resource history.

It does not directly open raw NTFS volumes for USN query/read.

---

# 5. FIUSNReader responsibilities

`FIUSNReader` runs under a separate per-host helper gMSA.

For the current validated design, that helper identity is local Administrator on
its assigned host.

The helper exposes three logical operations:

```text
QueryJournal(governedRoot)

ReadJournal(
    governedRoot,
    startUSN
)

CheckContainment(
    governedRoot,
    fileReferenceNumber,
    sequenceNumber
)
```

The helper is not a second collector.

It does not own:

- USN parsing policy;
- organizational scope policy;
- hashing;
- source-file content collection;
- spool persistence;
- checkpoint persistence;
- checkpoint advancement;
- Windows Security collection;
- SMB/local/AD collection;
- journal creation;
- journal deletion;
- journal resizing; or
- arbitrary administrative commands.

---

# 6. CheckContainment is mechanical

The containment operation exists for a narrow reason.

The normal collector attempts current File-ID re-observation itself.

Only when that operation fails with the exact Windows Access Denied condition
does FI use the helper to answer the mechanical question:

```text
Does this current NTFS object identity resolve inside this exact configured
governed root?
```

The broker result is only:

```text
Contained
Outside
Unavailable
```

No target path crosses the broker boundary.

No target metadata crosses the broker boundary.

No ACL, hash, stream, content, owner, or classification crosses the broker
boundary.

The helper does not decide what the organization should do with the result.

---

# 7. Configured roots are the authorization source

FI does not maintain a second helper allowlist.

The administrator-controlled FI configuration is the source of truth.

Example:

```text
C:\ProgramData\FI\config\fi.conf

version_id: 1.0
governed_root: C:\FI-Lab
governed_root: D:\CountyShares
```

The helper independently loads FI configuration for requests.

For raw USN operations, approved local volumes are derived from configured
governed roots.

For `CheckContainment`, the requested governed root must match configured FI
scope.

The collector cannot make an unconfigured volume eligible merely by sending a
different path to the broker.

---

# 8. Volume-wide USN visibility

The USN Journal is volume-wide.

Once a governed root exists on a volume, raw USN metadata can describe unrelated
changes elsewhere on that approved volume.

That does not make the entire volume governed.

The volume-wide change stream allows FI to determine which changed object
identities need current scope resolution.

Unrelated objects are filtered before they become governed-object history.

This source-access property remains part of the deployment boundary.

---

# 9. Local named-pipe boundary

The broker uses:

```text
\\.\pipe\FI-USN
```

The pipe rejects remote clients.

The DACL permits:

```text
SYSTEM
Builtin Administrators
NT SERVICE\FICollector
```

DACL reachability is not the complete authorization decision.

---

# 10. Runtime service-SID authentication

The expected broker client is the actual Windows FICollector service token.

The helper requires:

```text
NT SERVICE\FICollector
```

as an enabled, non-deny-only token group.

Conceptually:

```text
ConnectNamedPipe
        |
        v
read one bounded request
        |
        v
ImpersonateNamedPipeClient
        |
        v
open impersonated thread token
        |
        v
require NT SERVICE\FICollector
        |
        +-- missing / deny-only -> ACCESS_DENIED
        |
        +-- enabled             -> continue
```

A normal elevated administrator may reach the pipe because Administrators is in
the DACL.

That administrator is still rejected by runtime authorization when the service
SID is absent.

Account identity alone is not equivalent to the service token.

---

# 11. Broker protocol remains bounded

The helper does not expose:

- arbitrary device paths;
- arbitrary access masks;
- arbitrary FSCTLs;
- arbitrary output sizes;
- arbitrary target paths;
- journal create/delete/resize;
- generic file reads; or
- general administrative commands.

Requests use a fixed protocol magic/version, fixed operation set, bounded root
length, and bounded operation-specific fields.

Responses use fixed status/error fields and bounded payloads.

Current request controls include:

- fixed protocol magic/version;
- fixed operation set;
- bounded UTF-8 governed-root length;
- non-negative `StartUSN` where applicable;
- bounded File-ID/sequence fields where applicable; and
- reserved fields required to be zero.

Current response controls include:

- fixed protocol magic/version;
- explicit success/failure status;
- Windows-style error code where available;
- bounded error text;
- bounded containment result values; and
- maximum raw USN data of 1 MiB for the read operation.

The collector remains responsible for parsing returned USN records.

The bounded request is read before named-pipe client impersonation because
Windows associates `ImpersonateNamedPipeClient` with the security context of the
last message read from the pipe.

No privileged operation proceeds until service-SID runtime authorization
succeeds.

Raw USN data remains bounded to the protocol maximum.

---

# 12. Raw-volume access

The production raw-volume package uses the least tested successful access needed
for the validated USN query/read operation:

```text
FILE_READ_DATA
```

It does not use `GENERIC_READ` merely because `GENERIC_READ` also works inside
the local administrative boundary.

The privileged package exposes fixed query/read behavior rather than a generic
`DeviceIoControl` API to FICollector.

---

# 13. Windows Server 2022 protected-object difference

Windows Server 2022 build `20348` exposed an additional protected-object
behavior.

For some protected system ETL objects, the helper could:

```text
open governed root                         PASS
resolve root final normalized GUID path   PASS
OpenFileById target with desired access 0 FAIL / Access Denied
```

This localized the problem to target File-ID open, not root-path comparison.

The same call succeeded while `SeBackupPrivilege` was enabled and failed again
after the privilege was restored to its previous disabled state.

---

# 14. Server 2022 scoped SeBackup fallback

The production fallback is release-specific.

It applies only when:

```text
Windows major = 10
Windows minor = 0
Windows build = 20348
```

and only after the normal zero-access target `OpenFileById` has already returned
Access Denied.

```text
normal zero-access OpenFileById
        |
        +-- success
        |      -> normal containment
        |
        +-- Access Denied
               |
               +-- not build 20348
               |      -> existing error behavior
               |
               +-- build 20348
                      |
                      +-- open process token
                      +-- enable SeBackupPrivilege
                      +-- retry same zero-access OpenFileById
                      +-- resolve final path internally
                      +-- determine Contained / Outside
                      +-- restore exact previous privilege state
                      +-- close privilege token
```

Important boundaries:

- the fallback is not attempted before the normal zero-access open;
- no `SeRestorePrivilege` is enabled;
- no broader target-object desired access is requested;
- raw USN Query/Read behavior is unchanged;
- broker protocol is unchanged;
- no target path is returned to the collector; and
- 2016/2019 do not enter the 20348-specific fallback.

If privilege restoration fails, the operation fails closed.

---

# 15. Why the fallback is not common Windows behavior

FI does not encode:

```text
Access Denied -> always enable SeBackupPrivilege
```

as a generic Windows rule.

Instead:

```text
2016
    existing containment behavior

2019
    existing containment behavior

2022 / build 20348
    release-specific scoped fallback

future release
    characterize first
```

This preserves already-proven behavior and keeps release-specific Windows
differences visible.

---

# 16. Failure semantics

If `FIUSNReader` is unavailable or a broker/raw-volume operation fails:

- FI reports the source failure explicitly;
- FI does not claim successful USN continuity for that work;
- the applicable USN checkpoint does not advance;
- other collector source work may continue; and
- helper recovery resumes from the previously accepted checkpoint.

The common Test 04 waits for an actual configured collection cycle while the
helper is unavailable. It does not rely on a fixed sleep shorter than the
configured collection interval.

---

# 17. Configuration permissions

FI configuration remains administrator-controlled.

Intended shape:

```text
C:\ProgramData\FI\config

SYSTEM                  Full
Administrators          Full
FICollector gMSA        Read/Execute
FIUSNReader gMSA        Read/Execute
```

and:

```text
C:\ProgramData\FI\config\fi.conf

SYSTEM                  Full
Administrators          Full
FICollector gMSA        Read
FIUSNReader gMSA        Read
```

Broad `BUILTIN\Users` access should not be present.

## 17.1 Effective-rights clarification

The helper gMSA is local Administrator on the currently validated split-privilege
design.

Windows Allow permissions accumulate. An explicit read-only ACE on the helper
does **not** remove authority the token receives through Builtin Administrators.

FI therefore does not claim:

```text
FIUSNReader can be cryptographically or ACL-sandboxed away from FI config
```

while simultaneously running it as local Administrator.

The correct security claims are:

```text
FICollector
    non-admin
    config read-only
    cannot redefine governed roots through its normal token

FIUSNReader
    local Administrator inside the Windows administrative trust boundary
    runtime code reads config but owns no config-write path
    compromise of helper == local Windows administrative compromise
```

The primary split-privilege boundary protects against compromise of the
non-administrative collector automatically becoming local Administrator.

---

# 18. State and spool permissions

Conceptually:

```text
C:\ProgramData\FI\state
    SYSTEM                  Full
    Administrators          Full
    FICollector gMSA        Modify

C:\ProgramData\FI\spool
    SYSTEM                  Full
    Administrators          Full
    FICollector gMSA        Modify
```

FIUSNReader does not need an FI-specific state/spool ACE.

Checkpoint and durable spool custody remain with FICollector.

Final deployment validation must inspect actual effective ACLs and confirm that
the restricted collector can perform required writes without gaining broad
administrative rights.

---

# 19. Program and service-object permissions

The split privilege is meaningless if the non-admin collector can replace or
reconfigure the privileged helper.

Deployment must prove that FICollector cannot, through its normal service token:

- replace `fi-usn.exe`;
- replace FI program files in a way that controls the helper;
- change the FIUSNReader executable path;
- change the FIUSNReader service identity;
- change the helper service security descriptor; or
- otherwise reconfigure the privileged service.

Local Administrators and approved deployment mechanisms retain their normal
administrative authority.

---

# 20. Service identity and service SID

These are separate controls.

```text
ISS\gFI-FS01$
    -> Windows service logon identity
    -> source access granted to the collector account

NT SERVICE\FICollector
    -> service-specific SID in the service token
    -> local broker runtime authentication principal
```

The current validated service SID type is:

```text
SERVICE_SID_TYPE: UNRESTRICTED
```

---

# 21. gMSA intent and revocation

The helper gMSA exists for FIUSNReader.

It should not be deliberately reused for:

- scheduled tasks;
- PowerShell automation;
- IIS application pools;
- SQL services;
- unrelated FI components;
- administrative scripting; or
- interactive administration.

Where appropriate, environment policy may deny unnecessary interactive, remote
interactive, or network logon types while preserving the service logon required
by FIUSNReader.

Because identities are separate and per host, an organization can contain one FI
host without revoking every collector/helper identity.

Disabling a gMSA does not invalidate an already-created running service token.

```text
disable AD service-account object
        |
running token can still exist
        |
stop helper
        |
fresh service logon fails
        |
re-enable gMSA
        |
helper can obtain fresh service token
```

The validated AD disable operation is:

```powershell
Set-ADServiceAccount `
    -Identity "gFI-USN-YOURHOST" `
    -Enabled $false
```

Re-enable with:

```powershell
Set-ADServiceAccount `
    -Identity "gFI-USN-YOURHOST" `
    -Enabled $true
```

If immediate containment of a running privileged helper is required, disabling
the AD object alone is insufficient.

Appropriate local incident-response action may include:

- stop `FIUSNReader`;
- disable the service;
- isolate the endpoint; and
- use the organization's EDR/incident-response controls.

The gMSA is a central provisioning/re-logon control, not invalidation of an
already-created local Windows token.

---

# 22. Collector compromise boundary

The principal security objective is:

```text
compromise FICollector
        |
        v
restricted collector token
        |
        v
bounded authenticated broker only
```

rather than:

```text
whole collector runs as Administrator
        |
        v
collector compromise == local Administrator
```

A compromise of FIUSNReader itself is already a local Windows administrative
incident.

FI does not claim that local Administrator or SYSTEM can be permanently
sandboxed from another local administrative service.

Windows administrators inherently possess broad local authority.

The intended protection is against:

- ordinary users;
- unrelated services;
- unrelated gMSAs;
- remote callers;
- ordinary processes using the collector gMSA; and
- compromise of the non-administrative FICollector alone.

---

# 23. Normal operational flow

1. FICollector runs as the restricted per-host collector gMSA.
2. FIUSNReader runs as the separate helper gMSA.
3. FICollector determines that a bounded helper operation is required.
4. The collector connects to `\\.\pipe\FI-USN`.
5. Windows applies the pipe DACL.
6. The collector sends one bounded request.
7. FIUSNReader reads the request.
8. The helper impersonates the client.
9. The helper requires the enabled `NT SERVICE\FICollector` service SID.
10. The helper reverts to its own identity.
11. The helper loads administrator-controlled FI configuration.
12. The helper validates the requested governed-root/volume boundary.
13. The helper performs the fixed requested operation.
14. The helper returns only the bounded result.
15. FICollector performs normal source interpretation.
16. FICollector writes and verifies durable spool output.
17. FICollector advances the applicable checkpoint only after the durable
    boundary succeeds.

For normal changed-object handling, FICollector attempts File-ID re-observation
before it asks the helper for containment.

---

# 24. Verification requirements

Deployment verification must prove at least:

- collector non-admin;
- helper inside the intended local administrative boundary;
- managed-account configuration;
- collector service SID enabled;
- positive broker use by the real collector;
- ordinary local administrator rejection;
- remote pipe rejection;
- helper failure freezes accepted USN continuity;
- helper recovery catches up from the prior checkpoint;
- config/state/spool ACL boundaries;
- collector inability to replace/reconfigure the helper through its normal token;
- exact service-token boundary; and
- release-specific behavior where the Windows release actually differs.

See:

```text
tools\README.md
docs\VERIFICATION-RECORD.md
docs\WINDOWS-SERVER-VALIDATION.md
```

---

# 25. Design invariants

## Rule 1 — one host, one identity pair

Do not share collector/helper gMSAs across monitored hosts.

## Rule 2 — FIUSNReader is not a second collector

Keep the privileged helper mechanically narrow.

## Rule 3 — configuration is the source of truth

Do not create a second hidden volume allowlist.

## Rule 4 — checkpoint ownership remains in FICollector

Helper failure cannot move accepted continuity forward.

## Rule 5 — service-SID runtime authentication is required

Account identity alone is insufficient.

## Rule 6 — privileged API surface stays fixed and bounded

No generic device, file, or administrative RPC surface.

## Rule 7 — release-specific Windows behavior stays release-specific

Do not change common behavior until characterization proves the common behavior
is wrong.

## Rule 8 — uncertainty stays explicit

An unresolved source fact is not converted into certainty merely to keep a
collection green.


---

# 26. Why This Design Matters to an IT Director

USN allows FI to efficiently determine what changed instead of rescanning every
governed file on every cycle.

The split-service design preserves that capability without making the entire FI
collector an Administrator.

Per-host identities provide direct accountability and focused containment.

---

# 27. Why This Design Matters to a Security Administrator

The model layers multiple controls:

1. per-host gMSAs;
2. host-specific managed-password retrieval;
3. non-administrative main collector;
4. separate privileged helper identity;
5. local-only named pipe;
6. explicit pipe DACL;
7. service-SID runtime authentication;
8. administrator-controlled configured-root/volume authorization;
9. fixed operations;
10. bounded requests and responses;
11. separate checkpoint/spool ownership;
12. protected program/service configuration; and
13. independent incident-response and revocation controls.

No single layer is expected to carry the entire security model.

---

# 28. Why This Design Matters to an FI Engineer

The privileged code should remain small enough that an engineer can answer:

> What can this privileged process actually do?

with approximately:

```text
load FI configured roots
authorize one configured source boundary
open the approved local volume when required
query the USN journal
read one bounded USN buffer
perform one bounded mechanical File-ID containment check when required
return only the bounded result
```

If the helper begins accumulating parsing policy, checkpoint state, spool
behavior, hashing, file-intelligence decisions, arbitrary FSCTLs, generic file
reads, or general administrative functions, the boundary is drifting.

---

# 29. Summary

FI uses the NTFS USN Journal for efficient change discovery and continuity.

`FICollector` remains the actual collector. It parses, re-observes, applies
governed-root policy, hashes, writes and verifies spool output, and advances
continuity.

The privileged Windows requirements are isolated in `FIUSNReader`:

```text
FICollector
    unique restricted per-host gMSA
    non-admin
        |
        | local pipe
        | NT SERVICE\FICollector SID required
        v
FIUSNReader
    unique privileged per-host gMSA
    local Administrator on that host only
        |
        +-- approved bounded NTFS USN query/read
        |
        +-- bounded mechanical File-ID containment when required
```

Windows Server 2019 and 2022 characterization established `FILE_READ_DATA` as
the least tested successful raw-volume access for the production USN query/read
path and showed that `SeManageVolumePrivilege` alone is insufficient.

Windows Server 2022 build `20348` additionally requires the release-specific
scoped `SeBackupPrivilege` retry for the tested protected-object containment
case. That behavior is not copied to 2016, 2019, or future releases without
characterization.

The privileged helper is not an ACL sandbox from Windows administrators. It is a
deliberately small privileged process inside the operating system's
administrative trust boundary.

The principal security gain is that normal FI collection, and compromise of the
non-administrative collector alone, do not automatically grant a local
Administrator token.
