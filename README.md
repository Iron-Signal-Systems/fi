# File Intelligence (FI)

<p align="center">
  <img src="docs/images/fi.png" alt="FI — File Intelligence" width="100%">
</p>

**File Intelligence (FI)** is a non-remediating, read-oriented system for
building a historical understanding of explicitly governed files.

FI is designed around a simple question:

> **What do we know about this file?**

Over time that includes its identity, locations, metadata, storage, security,
access, activity, relationships, history, and later classification.

The file remains the center of that history.

Normal FI collection does not intentionally modify governed customer files,
directories, permissions, identities, shares, or customer configuration.

---

## Why FI exists

Understanding a file in a real environment often requires information from many
different sources.

A question such as:

> Why can this user access this file?

may require correlating:

- the file's identity;
- current and historical paths;
- NTFS permissions;
- SMB share permissions;
- local identities;
- Active Directory identities and direct membership facts;
- inheritance;
- effective-access inputs;
- permission changes;
- governed-file activity; and
- the state of those facts at the time being investigated.

A different question may start with an identity:

> If this account is compromised, what governed files could it affect?

Or with a file:

> Where has this file been, who could access it, what happened to it, and what
> changed?

FI preserves the source facts needed to answer those questions without
intentionally changing governed source state.

---

## File-centered intelligence

FI treats a governed file as more than a pathname.

A pathname can change. A file can be renamed, moved, exposed through different
shares, have its permissions changed, or have relationships to different
identities over time.

For a governed file, FI is intended to answer questions such as:

- What file is this?
- Where is it now?
- Where has it been?
- Has it been renamed or moved?
- What metadata has been observed?
- What NTFS security applied to it?
- What SMB shares exposed it?
- Who could access it?
- Why could that identity access it?
- Was access direct, inherited, or obtained through group membership?
- When did access change?
- Who changed permissions when the available source information can establish
  that?
- What access, attempted access, modification, creation, deletion, rename/move,
  or security activity involving the file has been observed?
- What was known about the file at a particular point in time?
- Where are there gaps that prevent FI from making a definitive conclusion?
- What classification was later associated with a particular observation?

FI distinguishes between what was directly observed, what can be
deterministically derived, what was classified, and what remains unknown or
incomplete.

A gap in available information must never be presented as proof that an event
did not occur.

---

## Governed-file activity

FI is not intended to become a general Windows event collector or SIEM.

Activity collection is file-centered.

FI preserves Windows activity when it concerns a governed file or directory,
including where observable:

- access and attempted access;
- successful and denied access;
- creation;
- modification;
- deletion;
- rename and move activity;
- ownership, ACL, and other security changes;
- hard-link activity; and
- SMB/share activity associated with the governed object.

Where Windows provides the information, FI preserves source facts such as:

- account/SID;
- process;
- object identity and path;
- access requested or used;
- success/failure;
- timestamp and source record identity;
- share used;
- remote workstation or IP; and
- session/logon identifiers needed to explain governed-object activity.

Supporting SMB, logon, or session records are collected only when needed to
explain activity associated with governed objects. FI does not collect broad
server activity merely because Windows exposes it.

Windows auditing is not perfect. FI reports coverage and limitations explicitly
and never interprets the absence of an event as proof that no activity occurred.

---

## Useful across IT

FI records one underlying history. Different parts of an IT organization can use
views over that same recorded and correlated information for different purposes.

### Service Desk

Examples include:

- Why did a user lose access to a file or directory?
- What access should the user currently have?
- Through which group or ACL is access granted?
- Did something recently change?

### Developers and DevOps

Examples include:

- What application files changed?
- Which identities can modify application-controlled locations?
- Did filesystem security or ownership change around a deployment?
- What related file state changed during an incident or application failure?

### System Administration

Examples include:

- Who has effective access to a governed location?
- Which shares expose it?
- Which permissions are direct or inherited?
- What changed in the filesystem or security configuration?
- What objects may require review following compromise of a privileged identity?

### Security

Examples include:

- What governed files could a compromised identity reach?
- What did that identity actually interact with where source information
  supports that conclusion?
- What permissions changed?
- What is the difference between observed activity and potential reach?
- What is the possible blast radius?
- Where are there gaps or incomplete coverage?

### Management and Reporting

Examples include:

- Which organizational areas may be affected?
- What is confirmed versus potentially affected?
- What information is currently known?
- What remains unknown?
- Which teams or reporting chains need to become involved?

These are different views of the same underlying recorded history, not
independent copies of the data.

---

## Non-remediating by design

FI is intentionally non-remediating and read-oriented with respect to the
customer environment.

FI may observe files, filesystem metadata, security information, identities,
shares, activity sources, and other configured sources necessary to build its
historical model.

FI does not:

- modify governed files;
- change governed ACLs;
- grant or revoke access;
- modify users or groups;
- change SMB shares;
- quarantine systems;
- alter network configuration; or
- automatically remediate the environment.

The ability to observe and explain a problem remains separate from the authority
to change the systems involved.

A source read can still cause operating-system-managed side effects. For example,
reading file content can update NTFS `LastAccessTime` on systems where last-access
updates are enabled. FI does not write or restore that timestamp to hide the
source-side effect of the read.

Administrator-run deployment examples may configure Windows audit policy, SACLs,
service identities, services, or related prerequisites. Those are deliberate
customer administrative actions and are not FI runtime behavior.

---

## Customer-controlled deployment

FI is designed to operate entirely within infrastructure controlled by the
customer.

Windows collectors, FI records, historical information, identity and security
metadata, classification results, PostgreSQL data, and other FI backend
information remain on customer-controlled systems unless the customer explicitly
chooses otherwise.

The FI backend may be deployed on a customer-provided server or virtual machine,
or on a dedicated FI appliance located within the customer environment.

Iron Signal Systems does not require persistent administrative or remote access
for FI to operate.

Customers may optionally grant controlled access for maintenance, upgrades,
troubleshooting, or other support services. Any such access is
customer-authorized and is not required for normal FI operation.

FI is intended to remain fully operational in environments where no vendor remote
access is permitted.

---

## Initial platform scope

Initial development targets **Windows Server and NTFS file services**.

Monitoring is explicitly scope-driven. FI operates only against configured
**governed roots**. Installing FI on a server does not mean the entire server,
volume, or share is governed.

The Phase 1 Windows collector preserves or is being validated to preserve:

- NTFS object and volume identity;
- exact path representation;
- file and directory metadata;
- content hashes;
- alternate data streams;
- reparse information;
- Windows security descriptors, ACLs, SACLs, and ACEs;
- SMB share exposure and share security;
- local Windows identities;
- Active Directory identities and direct membership facts;
- effective-access source inputs;
- USN journal change signals;
- governed-file Windows activity;
- source checkpoints and continuity;
- explicit gap/reconciliation history;
- durable local spool batches; and
- major collector operation history.

Other filesystems and operating systems are outside the initial scope.

---

## Current Windows runtime

Phase 1 now has a persistent Windows service runtime around the existing
configured collector.

The runtime does not create a second collection path.

```text
FICollector
    restricted per-host gMSA
    non-admin
        |
        | configured collection
        | Windows Security
        | NTFS observation
        | SMB/local/AD
        | spool/checkpoints
        |
        +------ local authenticated pipe ------+
                                               |
                                               v
                                      FIUSNReader
                                      separate per-host gMSA
                                      local Administrator
                                      on that host only
                                               |
                                               v
                                      raw NTFS USN query/read
                                      bounded File-ID containment
                                      bounded exact-object SACL read
```

The service runtime can schedule:

- the configured collector cycle; and
- the slower supporting-source refresh.

Work is sequential. FI does not intentionally overlap configured collection and
supporting-source refresh inside the service runtime.

The exact production intervals remain an operational measurement and deployment
decision.

---

## USN split-privilege boundary

The underlying split-privilege Windows behavior has been characterized on:

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
Windows Server 2025    10.0.26100
```

Exact Candidate #4 Gate 1 acceptance is tracked separately:

```text
Windows Server 2016    10.0.14393    COMPLETE
Windows Server 2019    10.0.17763    PENDING
Windows Server 2022    10.0.20348    PENDING
Windows Server 2025    10.0.26100    PENDING
```

2019, 2022, and 2025 characterization explicitly established that a restricted
helper remains unable to perform the required raw-volume USN query/read even
when `SeManageVolumePrivilege` is enabled in-process. The narrow helper therefore
remains inside the local Windows administrative boundary. `FILE_READ_DATA` is
the least tested successful raw-volume access used by the production query/read
path on those characterized releases.
FI does **not** run the entire collector as Administrator to obtain that
capability.

Instead:

- `FICollector` remains non-admin;
- `FIUSNReader` exposes only four bounded privileged operations:
  `QueryJournal`, `ReadJournal`, `CheckContainment`, and `ReadSACL`;
- `CheckContainment` is the narrow mechanical File-ID containment path used when
  the collector receives Access Denied during current-object re-observation;
- `ReadSACL` performs a separately authorized exact-object SACL read and returns
  only the bounded raw descriptor for collector-side parsing;
- the pipe rejects remote clients;
- the helper requires the enabled `NT SERVICE\FICollector` service SID;
- the helper independently loads FI configuration and authorizes requests from
  configured governed roots;
- the helper exposes no arbitrary device/FSCTL interface; and
- `FICollector` retains parsing, governed-root policy, normal re-observation,
  descriptor parsing, record construction, hashing, spool, and checkpoint
  ownership.

Windows Server 2022 build `20348` exposed one additional protected-object
behavior: some protected system objects deny the helper's normal zero-access
`OpenFileById` containment open. Windows Server 2025 build `26100` was
independently characterized and reproduced the same bounded behavior. Only on
those exact characterized builds, and only after the normal open returns Access
Denied, FI temporarily enables `SeBackupPrivilege`, retries the same zero-access
open, resolves mechanical containment, and restores the previous privilege state.
The fallback is not enabled for 2016, 2019, or an uncharacterized future or
adjacent Windows Server build.
A controlled helper outage has been live validated to freeze the USN checkpoint
while other collector work continues. After helper recovery, FI resumes from the
old checkpoint and catches up changes made during the outage.

See:

- [FI USN Architecture Summary](docs/README-USN-SUMMARY.md)
- [FI NTFS USN Privilege Boundary](docs/security/usn-privilege-boundary.md)
- [FI Windows Server Validation](docs/WINDOWS-SERVER-VALIDATION.md)
- [FI USN Split-Privilege Verification Kit](tools/README.md)

---

## Current Windows Security activity validation

FI reads the local Windows Security log as an independent activity source.

FI does not automatically enable Windows audit policy or add SACLs to governed
roots. Those are administrator-controlled deployment settings.

The Security Event Log collection/checkpoint path has been live validated across
the current Windows Server acceptance set:

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
Windows Server 2025    10.0.26100
```

Detailed audit-event generation still depends on Windows release, effective
Advanced Audit Policy, SACL coverage, and the access path. Later Windows Server
versions must still be characterized independently before FI assumes identical
event-generation behavior.

The current FI coverage model requires effective:

- **Audit File System**: Success and Failure;
- **Audit Handle Manipulation**: Failure;
- **Audit Detailed File Share**: Success and Failure;
- **Audit Policy Change**: Success;
- a sufficient change-capable Success/Failure audit ACE on every governed root;
- a sufficient descendant-file read Success/Failure audit ACE on every governed
  root; and
- readable local Security log access.

For production, FI recommends Advanced Audit Policy through a dedicated scoped
GPO or equivalent configuration-management mechanism. The Windows setting
**Audit: Force audit policy subcategory settings (Windows Vista or later) to
override audit policy category settings** should be enabled so legacy category
policy does not override the intended advanced subcategories.

The detailed event-generation examples below were established during the
Windows Server 2016 activity characterization:

- successful governed-file activity produced Event ID `4663`;
- denied file-handle requests produced Event ID `4656` after Handle Manipulation
  Failure auditing was enabled;
- a descendant-file read under the FI read-audit rule produced Event ID `4663`;
- Detailed File Share auditing produced Event ID `5145`;
- local UNC access preserved `::1` as the source address;
- true remote SMB access preserved the remote client IP; and
- a denied remote NTFS access could produce a successful `5145` share-level
  access-check record followed independently by a failed `4656` NTFS
  handle-request record.

A successful `5145` means the SMB/share-level check represented by that event
succeeded. It does **not** by itself prove the final NTFS operation succeeded.

FI currently selects:

- `4656` — handle/access requested;
- `4663` — an access right was used;
- `4660` — object deleted;
- `4664` — hard link created;
- `4670` — permissions changed;
- `4907` — auditing settings/SACL changed;
- `5145` — detailed SMB share access check;
- `1102` — Security audit log cleared; and
- `4719` — system audit policy changed.

FI preserves Security records independently from NTFS/USN observations. It does
not collapse a share-level event, a denied handle request, and a filesystem
change into one inferred event.

A root SACL does not prove every descendant is covered. Descendants can protect
their SACL from inheritance, and FI preserves the actual SACL observed on each
object.

See the
[Windows file-auditing example](examples/windows/file-auditing/README.md).

---

## Historical model

FI is not intended to keep only the latest state of a file.

An initial governed-root baseline establishes what FI knows at the beginning of
observation. Subsequent observations add history.

Material changes create new records rather than silently rewriting prior history.

Historical records are authoritative. Current-state, operational, reporting, and
role-oriented backend views are rebuildable representations of that history.

---

## Collection and continuity

The Windows source-side model is:

1. establish an initial governed-root baseline;
2. use the NTFS USN journal and relevant Windows activity as independent source
   signals;
3. freshly observe affected governed objects;
4. preserve applicable identity, security, share, and governed-file activity
   source facts;
5. write and verify durable local FI spool batches;
6. advance source checkpoints only after the applicable local durable boundary is
   satisfied;
7. explicitly record continuity gaps and degraded coverage;
8. reconcile current governed-source state after a known continuity gap without
   pretending the missing history was reconstructed; and
9. preserve major collector operation lifecycle history.

USN and Windows Security normal checkpoint continuation have been live validated.

USN and Windows Security continuity-gap detection, durable gap records,
reconciliation, and re-established forward boundaries have also been live
validated.

The configured collector uses append-only operation lifecycle journals for major
boundaries. A durably started operation that has no terminal record after a
process restart is closed as `Interrupted` with reason `ProcessRestart` before new
configured work begins.

Phase 1 owns local source collection and local durable queueing.

Phase 2 owns authenticated transport, retries, downstream acknowledgement, and
removal of acknowledged batches from the source spool.

FI must not silently convert missing coverage into certainty.

---

## Supporting source freshness

The initial baseline captures supporting source facts such as:

- local SMB share state and share security;
- local users, groups, and direct memberships; and
- relevant current-domain principals and direct membership facts.

Those sources change more slowly than the filesystem but still change over time.

FI provides a bounded `-supporting-refresh` operation for SMB, local identity, and
relevant Active Directory source facts. It writes new versioned observations into
verified local spool batches, retains previously relevant current-domain SIDs in
FI-owned operational state, and reads large relevant-SID sets in bounded
directory snapshots rather than truncating them.

The Windows service runtime can schedule this same operation at an explicit
operator-provided interval.

The collector does not compute transitive membership or final effective-access
conclusions. Production refresh cadence should be established from representative
measurement rather than invented inside the collector.

---

## Local durable spool

Phase 1 writes finalized JSONL batches and manifests locally.

The spool verifies record count, data byte count, and SHA-256 before a batch is
accepted as the local durable boundary.

Finalized batches remain on the source until Phase 2 transport exists.

FI does not use:

```text
send succeeded -> delete
```

as a custody rule.

Phase 2 must establish durable downstream custody and acknowledgement before an
acknowledged local batch may be retired.

The Phase 1 SHA-256 manifest is a local corruption/integrity check, not a claim of
cryptographic authenticity against an attacker who can rewrite both data and
manifest.

---

## Current Phase 1 focus

The core Phase 1 source architecture is largely established.

Windows Server 2016 build `14393` has completed the exact Candidate #4 Gate 1
campaign. That campaign includes:

- reproducible two-service/two-gMSA deployment and exact deployment acceptance;
- service, executable, configuration, state, spool, and service-token boundary
  validation;
- local and true remote-SMB governed-file activity coverage;
- collector restart, spool-write-denial, governed-root-unavailable, and bounded
  dependency-observation exercises;
- bounded performance, churn, spool-pressure, and operation/resource
  characterization;
- historical containment without stale-path trust;
- content-prefix / magic-byte durable custody; and
- the four-operation `FIUSNReader` broker, including live exact-object
  `ReadSACL`, while `FICollector` remains non-administrative.

The underlying Windows split-privilege behavior is characterized and green for
the split-privilege acceptance baseline on:
```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
Windows Server 2025    10.0.26100
```

Exact Candidate #4 Gate 1 acceptance is:

```text
Windows Server 2016    10.0.14393    COMPLETE
Windows Server 2019    10.0.17763    PENDING
Windows Server 2022    10.0.20348    PENDING
Windows Server 2025    10.0.26100    PENDING
```

Remaining Gate 1 work is therefore primarily:

- exact Candidate #4 acceptance on Server 2019, 2022, and 2025;
- repeated representative performance/source-impact measurement across the
  intended supported deployment set where needed;
- production collection/supporting-refresh cadence selection from accumulated
  measurements; and
- final review of the Gate 1 result record across the intended release/build set.

The Gate 1 test deployment uses `1m` collection and `30m` supporting-source
refresh only as an acceptance configuration. Production cadence remains
`NOT_EVALUATED`.

Gate 1 remains open overall until those remaining cross-version and production
acceptance boundaries are resolved.

No additional Phase 1 source subsystem should be added unless a concrete Gate 1
requirement demonstrates that a required source fact is missing.

---

## Source file content and classification

Normal FI record transport does not carry customer source-file content.

Later classification and enrichment may require bounded access to file or stream
content. That capability belongs to the **Separate Protected Classification
Stream** and its streaming/read-broker service in Phase 4, not to the normal
Phase 1 record collector.

Source content is processed transiently and is not stored as normal FI
source-file content in the backend.

Classification results become additional records associated with the exact file
or stream observation that was classified.

**Classification enriches FI's understanding of a file. It does not define the
file's identity or history.**

---

## High-level architecture

```text
             Windows File & Identity Collection
                         |
                         v
                 Durable Local Spool
                         |
                         v
                  Secure Transport
                         |
                         v
                      Ingest
                         |
                         v
                 PostgreSQL Recorder
                         |
              +----------+----------+
              |                     |
              v                     v
        Historical Records      Correlation
                                    |
                                    v
                             PostgreSQL Views
                                    |
                                    v
                             Query / UI / API
```

The collector observes.

The backend preserves and correlates.

Views present the same underlying information for different operational
questions.

FI remains non-remediating toward the systems it observes.

---

## Core design principles

- The file is the primary subject of FI.
- File identity must not depend solely on pathname.
- FI operates only on explicitly governed roots.
- FI does not intentionally change governed customer state during normal
  collection.
- Preserve historical state instead of keeping only current state.
- Preserve native source information needed for later verification or
  reinterpretation.
- Keep observed, derived, classified, unknown, and incomplete information
  distinct.
- Never hide collection gaps or uncertainty.
- Never interpret a missing Windows activity record as proof that no activity
  occurred.
- Maintain relationships between files, storage, paths, shares, permissions,
  identities, governed-file activity, and time.
- Make historical records append-only.
- Keep normal customer source-file content outside the FI record path.
- Add classification only after the underlying file/stream observation exists.
- Prefer simple collectors that report source facts over collectors that make
  organizational decisions.
- Keep privileged Windows code narrow and obvious.
- Present the same FI truth at the appropriate depth: user-facing experiences
  answer environmental questions without requiring knowledge of FI internals,
  while administrative interfaces expose the technical detail required to
  operate and verify FI.

---

## Development roadmap

FI is being developed in phases:

1. **Windows File & Identity Intelligence**
2. **Secure Record Transport**
3. **Ingest & Recorder**
4. **Classification & Enrichment**
5. **Projection, Query & Protected UX**
6. **Integrated Deployment & Release**

See the [FI Roadmap](fi-roadmap/roadmap.md) for detailed implementation status,
boundaries, and phase gates.

---

## Project status

FI is currently **pre-alpha** and under active development.

Current code, record structures, schemas, command names, interfaces, deployment
scripts, and internal package layouts may change as the architecture is
implemented and validated.

No production-readiness or compatibility guarantee should be inferred from the
current repository.

---

## Engineering standard

FI adopts the Iron Signal Systems Engineering Standards `2026.09`, as recorded in
[`ENGINEERING-STANDARD`](ENGINEERING-STANDARD).

The adopted standards release corresponds to engineering-standards commit
`0eef381f678a71aa24e48ff7bfab0ee23da92e67`.

Later Engineering Standards releases do not automatically apply to FI. Adoption
of a newer standards version requires deliberate review and an update to FI's
standards reference.

---

## Licensing

**FI is proprietary source-available software. It is not open-source software.**

Source review and non-production evaluation are permitted only under the terms of
the repository [LICENSE](LICENSE).

FI is developed by **John J. Wood** under the **Iron Signal Systems** project and
brand name.

**Iron Signal Systems is currently a project/brand name and GitHub/domain
identity used by John Joseph Wood. It is not represented by this repository as a
separate corporation, LLC, or other legal entity.**

Copyright ownership and licensing for FI are held and granted by
**John Joseph Wood** unless a future written agreement expressly states
otherwise.

---

## Security

Security issues that could expose an active vulnerability or sensitive
implementation detail should not be reported through public GitHub issues.

See [SECURITY.md](SECURITY.md) for the current security reporting process.
