# FI NTFS USN Privilege Boundary, Authentication, and Collection Model

## Purpose

This document explains why FI uses the NTFS USN Journal, what the journal
provides, why Windows Server 2016 requires a privileged helper for FI's current
direct-volume access path, and the exact trust boundary between `FICollector` and
`FIUSNReader`.

It is written for:

- IT directors who need to understand the operational and security value;
- security administrators who need the trust and authorization model;
- Windows administrators who deploy and support the services; and
- FI engineers who must preserve the privilege boundary in code.

---

## Executive Summary

FI uses the NTFS USN Journal for efficient change discovery and collection
continuity.

The USN Journal is **not** treated as the authoritative current state of a file.
It tells FI that an NTFS object changed and identifies that object. `FICollector`
then performs fresh File-ID re-observation and determines whether the object is
currently inside a configured governed root.

Live testing on Windows Server 2016 established that FI's current
`FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL` path requires an
administrative-capable direct-volume handle.

FI therefore uses two services and two unique gMSAs per monitored host:

```text
FICollector
    restricted per-host gMSA
    non-admin
        |
        | \\.\pipe\FI-USN
        | local-only
        | NT SERVICE\FICollector service SID required
        v
FIUSNReader
    separate per-host gMSA
    local Administrator on this host only
        |
        v
approved local NTFS volume
        |
        +-- FSCTL_QUERY_USN_JOURNAL
        |
        +-- FSCTL_READ_USN_JOURNAL
```

`FIUSNReader` is intentionally small.

> **If an operation does not require privileged direct-volume access, it does not
> belong in FIUSNReader.**

`FICollector` continues to own parsing, re-observation, containment, hashing,
spooling, continuity decisions, checkpoints, Windows Security collection, and
supporting-source collection.

---

# 1. Why FI Uses the NTFS USN Journal

## 1.1 The operational problem

FI cannot assume continuous uptime.

Servers reboot. Services stop. Maintenance occurs. Dependencies fail. File
servers can contain millions of objects.

Without a durable change source, FI would have to choose between:

1. assuming nothing changed while FI was unavailable; or
2. repeatedly rescanning the full governed tree.

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

## 1.2 What USN provides

USN records can provide source facts such as:

- file reference number;
- parent file reference number;
- USN;
- reason bits;
- journal timestamp;
- source information;
- security ID;
- file attributes; and
- the name carried in that journal record.

FI preserves those facts, but it does not confuse them with current object state.

## 1.3 USN is a change source, not the final answer

An object may change several times before FI re-observes it.

Therefore:

```text
USN
    -> what changed and in what journal order?

fresh NTFS observation
    -> what is the object now?

governed containment
    -> is that current object in FI scope?
```

An old filename in a USN record is not sufficient proof of current scope.

## 1.4 Object identity is preferred over path

FI uses NTFS object identity to re-open changed objects by File ID when possible.

A changed object can be:

- renamed;
- moved;
- renamed again;
- moved out of scope;
- deleted; or
- replaced.

FI therefore does not decide governed scope from the USN filename alone.

## 1.5 Continuity

FI's USN checkpoint includes the source identity and forward boundary required to
determine whether continued journal reading is valid.

If the journal identity changed, the required USN aged out, the governed root was
replaced, or another continuity condition fails, FI records the gap and
reconciles current state.

FI does not turn:

```text
missing source history
```

into:

```text
complete historical coverage
```

---

# 2. Why the Privileged Operation Is Split Out

Windows direct-volume access uses a path such as:

```text
\\.\C:
```

Server 2016 testing tried reduced access approaches before accepting the helper
design.

Observed behavior included:

- zero-access and `FILE_READ_ATTRIBUTES` handles could open but USN query/read did
  not provide a usable path;
- access combinations containing `FILE_READ_DATA` were denied to the restricted
  service identity;
- `GENERIC_READ` was denied until administrative capability was present; and
- the tested unprivileged-USN control path did not provide a usable Server 2016
  alternative.

Adding the test account to local Administrators made the required direct-volume
query/read work.

The design response is **not** to run the full collector as Administrator.

It is to isolate the unavoidable capability:

```text
                 NTFS
                  |
                  v
          +----------------+
          | FIUSNReader    |
          | privileged     |
          | narrow purpose |
          +-------+--------+
                  |
                  | bounded result
                  v
          +----------------+
          | FICollector    |
          | non-admin      |
          +-------+--------+
                  |
       +----------+-----------+
       |          |           |
       v          v           v
    parse USN   reobserve   containment
       |          |           |
       +----------+-----------+
                  |
                  v
           spool/checkpoint
```

---

# 3. Per-Host Identity Model

Every monitored Windows server gets a unique identity pair.

Example:

```text
ISS-FS-01
    ISS\gFI-FS01$          -> FICollector
    ISS\gFI-USN-FS01$      -> FIUSNReader

ISS-FS-02
    ISS\gFI-FS02$          -> FICollector
    ISS\gFI-USN-FS02$      -> FIUSNReader
```

No collector gMSA or privileged helper gMSA is shared across monitored hosts.

Each matching computer account should be the only principal authorized to
retrieve its assigned gMSA passwords.

This provides:

- host attribution;
- function attribution;
- smaller credential blast radius;
- per-host revocation;
- clearer incident response; and
- simpler customer auditing.

---

# 4. Service Responsibilities

## 4.1 FICollector

`FICollector` runs under the restricted per-host collector gMSA.

It is not local Administrator.

It owns:

- FI configuration and governed-root processing;
- baseline collection;
- USN parsing;
- continuity assessment;
- NTFS File-ID re-observation;
- current governed-root containment;
- NTFS metadata/security/stream/reparse collection;
- content hashing;
- local spool writing and verification;
- checkpoint persistence and advancement;
- Windows Security source collection;
- SMB/local/AD supporting-source collection;
- operation history; and
- resource history.

It does **not** directly open raw NTFS volumes for USN access.

## 4.2 FIUSNReader

`FIUSNReader` runs under a separate per-host helper gMSA.

On the currently validated Windows Server 2016 design, that gMSA is local
Administrator on its assigned host.

The helper may:

- derive the local drive from a requested governed root;
- confirm that drive is represented by configured FI governed roots;
- open the raw local volume;
- query the current USN Journal;
- read one bounded USN Journal buffer; and
- return the result.

It does not own:

- USN parsing decisions;
- File-ID re-observation;
- governed-root containment decisions;
- hashing;
- spool persistence;
- checkpoints;
- checkpoint advancement;
- Windows Security collection;
- SMB/local/AD collection;
- journal creation;
- journal deletion;
- journal resizing; or
- arbitrary administrative operations.

---

# 5. Single Source of Truth for Volume Authorization

FI does not maintain a second USN allowlist.

The existing administrator-controlled FI configuration is the source of truth.

Example:

```text
C:\ProgramData\FI\config\fi.conf

version_id: 1.0
governed_root: C:\FI-Lab
governed_root: D:\CountyShares
```

The helper derives:

```text
approved USN volumes:
    C:
    D:
```

The authorization is deliberately volume-level because the USN Journal itself is
volume-wide.

That has an important deployment consequence: once any governed root exists on a
volume, the broker can return raw USN metadata for unrelated changes elsewhere on
that same approved volume. `FICollector` needs that volume-wide change stream in
order to determine which changed objects belong to governed scope.

That does **not** make the entire volume governed and it does not allow unrelated
volume activity to become FI governed-object history automatically.

`FICollector` later decides which changed objects are governed using File-ID
re-observation and containment rules. Unrelated volume-wide changes are filtered
from governed-object processing.

Customers should nevertheless treat volume-wide USN metadata visibility as part
of the collector's documented source-access boundary when deciding where
governed roots are deployed.

A compromised collector cannot make an otherwise unconfigured volume eligible
merely by sending a path on that volume. `FIUSNReader` loads FI configuration
itself for each request and checks the requested drive against the configured
roots.

---

# 6. Local Named-Pipe Boundary

The broker uses:

```text
\\.\pipe\FI-USN
```

The pipe is created with `PIPE_REJECT_REMOTE_CLIENTS`.

Only one sequential pipe instance is required for the current single local
collector.

## 6.1 Pipe DACL

The current DACL grants:

```text
SYSTEM                         Generic All
BUILTIN\Administrators         Generic All
NT SERVICE\FICollector         Generic Read + Generic Write
```

The service SID is resolved at helper startup.

Allowing local Administrators to reach the pipe does not make them authorized to
perform the privileged operation. Runtime authentication is a separate check.

## 6.2 Runtime service-SID authentication

The helper does **not** authenticate the client merely by checking that the
process runs as the collector gMSA.

The expected client identity is:

```text
NT SERVICE\FICollector
```

The request flow is:

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
enumerate token groups
        |
        v
require NT SERVICE\FICollector
    enabled
    not deny-only
        |
        +-- absent -> ACCESS_DENIED
        |
        +-- present -> continue
```

The bounded request is read before impersonation because
`ImpersonateNamedPipeClient` uses the security context associated with the last
message read from the pipe.

No privileged raw-volume work occurs before the service-SID check succeeds.

This is stronger than accepting any ordinary process that happens to run as the
same gMSA.

## 6.3 Ordinary administrator negative test

A normal elevated administrator can connect because Builtin Administrators is in
the pipe DACL.

The request is still rejected unless that process token also carries the enabled
FICollector service SID.

Expected helper response:

```text
Status:       failure
ErrorCode:    5
Error:        FICollector service SID is required
```

That behavior has been live validated.

---

# 7. Narrow Broker Protocol

The helper is not a general RPC or administrative service.

The protocol is bounded binary little-endian data over the local pipe.

Current logical operations are:

```text
QueryJournal(governedRoot)

ReadJournal(
    governedRoot,
    startUSN
)
```

The caller does **not** supply:

- an arbitrary device path;
- an arbitrary access mask;
- an arbitrary FSCTL;
- an arbitrary output size;
- a journal-create operation;
- a journal-delete operation;
- a journal-resize operation; or
- a JournalID to force on the helper.

The helper independently opens the approved volume and queries the current
journal state.

## 7.1 Request bounds

Current request controls include:

- fixed protocol magic/version;
- fixed operation set;
- bounded UTF-8 root length;
- non-negative `StartUSN`; and
- reserved fields required to be zero.

## 7.2 Response bounds

Current response controls include:

- fixed protocol magic/version;
- explicit success/failure status;
- Windows-style error code where available;
- bounded error text; and
- maximum raw USN data of 1 MiB.

The collector remains responsible for parsing returned USN records.

---

# 8. Privileged Raw-Volume Package

The privileged raw-volume code is intentionally small.

Its effective behavior is approximately:

```text
DriveForRoot
    |
    v
\\.\X:
    |
    +-- CreateFile(GENERIC_READ)
    |
    +-- FSCTL_QUERY_USN_JOURNAL
    |
    +-- FSCTL_READ_USN_JOURNAL
            |
            v
       <= 1 MiB result
```

It does not expose a generic `DeviceIoControl` interface to `FICollector`.

---

# 9. Failure Semantics

If `FIUSNReader` is unavailable or a broker/raw-volume operation fails:

- FI reports the USN source failure explicitly;
- FI does not claim successful USN continuity for that work;
- the applicable USN checkpoint must not advance;
- other FI source collection may continue; and
- later helper recovery resumes from the previously accepted checkpoint.

This has been live validated:

```text
helper available
    -> checkpoint X accepted

helper stopped
    -> governed file changed
    -> collector continues other source work
    -> USN checkpoint remains X

helper restarted
    -> FI resumes from X
    -> downtime change appears in catch-up output
    -> checkpoint advances only after accepted work
```

---

# 10. Configuration Permissions

FI configuration should remain administrator-controlled.

Intended explicit ACL shape:

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

## 10.1 Important effective-rights clarification

The helper gMSA is a local Administrator on the validated Server 2016 design.

Windows Allow permissions accumulate. An explicit read-only ACE on the helper
does **not** remove access that the token receives through Builtin Administrators.

Therefore FI does **not** claim:

```text
FIUSNReader can be cryptographically/ACL sandboxed away from FI config
```

while simultaneously running it as local Administrator.

The correct security claims are:

```text
FICollector
    non-admin
    config read-only
    cannot redefine governed roots through its normal token

FIUSNReader
    local Administrator by necessity for validated Server 2016 USN access
    runtime code reads config but owns no config-write path
    compromise of helper == local Windows administrative compromise
```

The primary split-privilege boundary protects against compromise of the
non-administrative collector becoming local Administrator automatically.

---

# 11. State and Spool Permissions

FICollector requires the access necessary to maintain FI-owned local state.

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

`FIUSNReader` does not need FI state/spool write access for its runtime function.

The helper does not own checkpoint or durable queue custody.

Final deployment validation must inspect the actual effective ACLs and confirm
that the restricted collector can perform required writes without gaining broad
administrative rights.

---

# 12. Program and Service Object Permissions

The split privilege is incomplete if the restricted collector can replace or
reconfigure the privileged helper.

Deployment therefore needs to prove that `FICollector` cannot:

- replace `fi-usn.exe`;
- modify the FI program directory in a way that replaces the helper;
- change the `FIUSNReader` executable path;
- change the helper service identity;
- change the helper service security descriptor; or
- otherwise reconfigure the privileged service.

Local Administrators and approved deployment/management mechanisms retain that
authority.

This is a Gate 1 deployment-validation requirement.

---

# 13. Service Identity and Service SID

The service-account identity and the Windows service SID solve different
problems.

```text
ISS\gFI-FS01$
    -> service logon identity
    -> source access granted to the collector account

NT SERVICE\FICollector
    -> service-specific SID placed in FICollector token
    -> local broker authentication principal
```

The `FICollector` service SID type must be enabled so the token carries the
service SID.

The current validated setting is:

```text
SERVICE_SID_TYPE: UNRESTRICTED
```

The helper requires that service SID as an enabled, non-deny-only token group.

---

# 14. gMSA Logon Intent

The privileged helper gMSA exists for `FIUSNReader`.

It should not be deliberately reused for:

- scheduled tasks;
- PowerShell automation;
- IIS application pools;
- SQL services;
- unrelated FI components;
- administrative scripting; or
- interactive administration.

The intended relationship is:

```text
gFI-USN-<HOST>$
        |
        v
FIUSNReader
        |
        v
bounded approved raw-volume USN operations
```

Where appropriate, environment policy may deny unnecessary interactive, remote
interactive, or network logon types while preserving the service logon required
by `FIUSNReader`.

---

# 15. Incident Response and Revocation

Because identities are separate and per host, customers can contain one FI host
without revoking every collector.

## 15.1 gMSA disable behavior

Disabling a gMSA does not retroactively destroy an already-running Windows token.

For the helper, the validated AD operation is:

```powershell
Set-ADServiceAccount `
    -Identity "gFI-USN-FS01" `
    -Enabled $false
```

That prevents a normal fresh service logon after the currently running helper is
stopped and Windows must obtain a new service token.

Re-enable with:

```powershell
Set-ADServiceAccount `
    -Identity "gFI-USN-FS01" `
    -Enabled $true
```

## 15.2 Immediate containment

If immediate containment of a running privileged helper is required, disabling
the AD object alone is insufficient.

Appropriate local/incident-response action may include:

- stop `FIUSNReader`;
- disable the service;
- isolate the endpoint; and
- use the organization's EDR/incident-response controls.

The gMSA is a central provisioning/re-logon control, not a magic invalidation of
an already-created local token.

---

# 16. Collector Compromise Boundary

If `FICollector` is compromised, the design should not automatically yield a
local Administrator token.

```text
FICollector compromise
        |
        v
restricted collector token
        |
        v
attacker may attempt FI-USN requests
        |
        v
helper independently enforces:
    local-only pipe
    bounded protocol
    FICollector service SID
    configured-volume authorization
    fixed operation set
    bounded response
```

This is materially different from:

```text
whole collector runs as Administrator
        |
        v
collector compromise == local Administrator
```

The split architecture intentionally reduces the privileged attack surface.

---

# 17. Local Administrator / SYSTEM Boundary

FI does not claim that a local Administrator or SYSTEM process can be permanently
prevented from controlling another local service on the same host.

Windows administrators inherently possess broad local authority.

The intended protection is against:

- ordinary users;
- unrelated services;
- unrelated gMSAs;
- remote callers;
- ordinary processes using the collector gMSA; and
- compromise of the non-administrative FICollector alone.

A compromise of `FIUSNReader` itself is already a local-Administrator incident.

---

# 18. Normal Operational Flow

1. `FICollector` runs as the restricted per-host collector gMSA.
2. `FIUSNReader` runs as the separate privileged per-host helper gMSA.
3. `FICollector` determines that a USN query/read is required.
4. The collector connects to `\\.\pipe\FI-USN`.
5. Windows applies the pipe DACL.
6. The collector sends one bounded request.
7. `FIUSNReader` reads the bounded request.
8. The helper impersonates the connected client.
9. The helper requires the enabled `NT SERVICE\FICollector` service SID.
10. The helper reverts to its own identity.
11. The helper loads administrator-controlled FI configuration.
12. The helper derives the requested drive from the supplied governed root.
13. The helper confirms that drive is configured by at least one governed root.
14. The helper opens the raw local volume.
15. The helper performs the fixed query or bounded read.
16. The helper returns the response.
17. The response is flushed before the pipe is disconnected.
18. `FICollector` parses the result.
19. `FICollector` re-observes changed objects by File ID.
20. `FICollector` proves current governed-root containment.
21. `FICollector` performs normal hashing/source collection as required.
22. `FICollector` writes and verifies durable spool output.
23. `FICollector` advances its checkpoint only after the applicable durable
    boundary succeeds.

---

# 19. Design Invariants

## Rule 1: One Host, One Identity Pair

Every monitored Windows server gets one restricted collector gMSA and one
privileged USN-helper gMSA.

No sharing across monitored hosts.

## Rule 2: FIUSNReader Is Not a Second Collector

It is a narrow raw-volume USN broker.

## Rule 3: FI Configuration Is the Single Source of Truth

Approved USN volumes are derived from configured governed roots.

No second helper allowlist exists.

## Rule 4: Checkpoint Ownership Remains in FICollector

Only the collector owns continuity decisions and checkpoint advancement.

## Rule 5: Privileged API Surface Stays Small

No arbitrary device paths, access masks, FSCTLs, output sizes, or administrative
commands.

## Rule 6: Service-SID Authentication Is Required

The expected local broker client is the actual `FICollector` service token, not
merely any process using the collector gMSA.

## Rule 7: If It Does Not Require Privileged Direct-Volume Access, It Does Not
Belong in FIUSNReader

Examples that remain in `FICollector`:

- USN parsing;
- File-ID re-observation;
- containment;
- hashing;
- spool writing;
- checkpoints;
- Windows Security collection;
- SMB/local/AD collection.

## Rule 8: Helper Failure Cannot Advance USN Continuity

A failed or unavailable helper must not cause the collector to move the accepted
USN boundary forward.

---

# 20. Gate 1 Verification Properties

Before Gate 1 acceptance, deployment and validation should prove:

- `FICollector` is not local Administrator;
- `FIUSNReader` is local Administrator on its assigned host only;
- each host has a unique gMSA pair;
- managed-password retrieval is host-bound;
- the `FICollector` service SID is enabled;
- the real collector can perform positive broker reads;
- an ordinary elevated local administrator request is rejected;
- remote pipe use is rejected;
- helper failure freezes the USN checkpoint;
- other collector source work can continue during helper failure;
- restart catches up changes made while the helper was unavailable;
- config ACLs do not contain broad `BUILTIN\Users` access;
- the collector cannot write FI configuration;
- the collector cannot replace the helper binary;
- the collector cannot reconfigure the privileged service;
- state/spool permissions allow only the intended FI writes; and
- service restart/reboot behavior preserves the same continuity guarantees.

---

# 21. Why This Design Matters to an IT Director

USN allows FI to efficiently determine what changed instead of rescanning every
governed file on every cycle.

The split-service design preserves that capability without making the entire FI
collector an Administrator.

Per-host identities provide direct accountability and focused containment.

---

# 22. Why This Design Matters to a Security Administrator

The model layers multiple controls:

1. per-host gMSAs;
2. host-specific managed-password retrieval;
3. non-administrative main collector;
4. separate privileged helper identity;
5. local-only named pipe;
6. explicit pipe DACL;
7. service-SID runtime authentication;
8. administrator-controlled configured-volume authorization;
9. fixed operations;
10. bounded requests/responses;
11. separate checkpoint/spool ownership;
12. protected program/service configuration; and
13. independent incident-response/revocation controls.

No single layer is expected to carry the entire security model.

---

# 23. Why This Design Matters to an FI Engineer

The privileged code should remain small enough that an engineer can answer:

> What can this privileged process actually do?

with approximately:

```text
load FI configured roots
authorize one configured volume
open that local volume
query USN journal
read one bounded USN buffer
return result
```

If the helper begins accumulating parsing policy, checkpoint state, spool
behavior, hashing, file-intelligence decisions, arbitrary FSCTLs, or general
administrative functions, the boundary is drifting.

---

# 24. Summary

FI uses the NTFS USN Journal for efficient change discovery and continuity.

USN tells FI which NTFS objects changed.

`FICollector` then performs FI's actual source interpretation:

- parse;
- re-observe;
- prove scope;
- hash;
- spool;
- verify; and
- advance continuity.

Windows Server 2016 requires administrative-capable direct-volume access for FI's
validated USN query/read path.

FI isolates that requirement:

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
        v
approved bounded NTFS USN query/read
```

The privileged helper is not an ACL sandbox from Windows administrators; it is a
deliberately small privileged process inside the operating system's
administrative trust boundary.

The principal security gain is that normal FI collection and compromise of the
non-administrative collector do not automatically grant a local Administrator
token.
