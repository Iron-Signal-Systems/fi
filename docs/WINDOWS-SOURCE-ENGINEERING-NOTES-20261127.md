# FI Windows Collection and Source Engineering Notes

> **Reference status — historical snapshot (November 27, 2026).**
> This material was relocated from the original root README at commit [`1d16760bd137`](https://github.com/Iron-Signal-Systems/fi/commit/1d16760bd1375b9cd37f7f98472d944593e414aa) to keep the repository landing page focused on the FI mission.
> It preserves implementation details and historical validation notes, not a fresh acceptance or a guarantee of current runtime behavior. The Windows volume-first redesign remains pre-alpha.
>
> **Current authorities:** [Windows collector contract](COLLECTOR-CONTRACT.md) · [Windows installer](WINDOWS-INSTALLER.md) · [Windows validation](WINDOWS-SERVER-VALIDATION.md) · [USN privilege boundary](security/usn-privilege-boundary.md) · [Product definition](PRODUCT-DEFINITION.md).

The sections below retain their prior technical substance. References to *current* versions, service details, and acceptance reflect the original document's date; verify them against current source, documentation, and acceptance records before operational use.

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

---

## Initial platform scope

Initial development targets **Windows Server and NTFS file services** for collectors.

The FI **backend runtime target is FreeBSD**, currently validated in development on the C220 FreeBSD 15.1 host. Linux is **not** an FI backend deployment target. Windows remains the collector target; it is not a PostgreSQL backend requirement. GitHub-hosted Ubuntu jobs may be used only as toolchain/CI hosts to cross-compile binaries for FreeBSD; cross-compilation is not a FreeBSD runtime acceptance test. Backend integration and performance acceptance must run on FreeBSD against disposable PostgreSQL clones before any authoritative changes.

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

---

## Windows runtime — November 2026 snapshot

Phase 1 has a persistent Windows service runtime with three intentional source
execution lanes. The lanes are concurrent with one another, but each lane remains
sequential within its own checkpoint/source boundary.

```text
FICollector
    restricted per-host gMSA
    non-admin
        |
        +-- governed-root/current-state lane
        |      baseline / root reconciliation ownership
        |      governed-root configured work
        |      slower supporting-source refresh
        |
        +-- independent USN lane
        |      default interval: 10m
        |      override: FI_SERVICE_USN_EVERY
        |      existing continuous checkpoints only
        |      fresh object re-observation + hashing
        |      durable spool/checkpoint ownership
        |
        +-- independent Windows Security lane
        |      default interval: 1m
        |      override: FI_SERVICE_WINDOWS_SECURITY_EVERY
        |      single sequential Security checkpoint owner
        |      bounded EventRecordID windows
        |      immediate additional windows while behind
        |      durable spool verification before checkpoint advance
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

Service startup completes interrupted-spool publication recovery before any
independent writer begins. After that boundary, governed-root work, USN catch-up,
and Windows Security collection have separate scheduling and checkpoint
ownership.

Initial USN onboarding remains intentionally exclusive: when a governed root has
no checkpoint yet, the independent USN worker skips it and the governed-root lane
owns baseline creation plus anchored catch-up. The USN lane also does not initiate
a same-root continuity-gap reconciliation.

Windows Security is different because the Security Event Log is an independent
host source. Its service worker starts immediately, never overlaps itself, and
reads the existing bounded EventRecordID windows. When a completed window shows
that more Security history is already available, the worker immediately processes
another bounded window instead of sleeping for the steady-state interval. Once
caught up, it returns to its configured cadence.

A service-mode Windows Security continuity gap remains explicit and incomplete.
The Security worker records the gap, records current Security-specific coverage
(audit-policy state, Security-log readability, and governed-root SACL coverage),
then establishes a fresh forward Security boundary. It does not block Security
collection behind a full file-tree rescan. The one-shot configured
`fi.exe -run` path retains its existing configured-collection behavior.

The independent intervals default to `10m` for USN and `1m` for Windows
Security. They may be overridden through `FI_SERVICE_USN_EVERY` and
`FI_SERVICE_WINDOWS_SECURITY_EVERY`. Effective intervals are written to
`service-runtime.jsonl` in `ServiceStarted`, `USNCatchUp`, and
`WindowsSecurityCatchUp` records.

On 2026-09-19, the 10-minute USN lane was live validated on the Server 2016 lab.
A single NTFS object (FRN 45 / sequence 9) was renamed and extended while a long
configured collection was still active. FI preserved the raw
`RenameOldName`, `RenameNewName`, and `DataExtend` USN facts, freshly
re-observed the same object at its new path, computed new content hashes, sealed
the records into a generation, and established receiver custody about 7 minutes
13 seconds after the mutation.

The later 250K resilience campaign exposed a separate cross-root USN scheduling
defect. Commit `41906af` replaced the process-global governed-root lock with
governed-root-scoped synchronization. Live validation then recorded 33
independent USN cycles on the intended approximately 10-minute cadence while a
different governed root remained in a 5h32m baseline.

On 2026-09-20, the same 250K campaign exposed a Windows Security scheduling
defect: Security catch-up could remain coupled to multi-hour root work long enough
for a small Security log to overwrite the next required EventRecordID range.
The independent Security worker was then live validated on Server 2016 with the
Security log returned to 20 MiB. During sampled operation every checkpoint
remained inside the retained log window; the largest observed head lag was 584
EventRecordIDs. A controlled File System audit-policy toggle produced two real
Event ID 4719 records (185819888 and 185819899); FI selected both, durably
verified their batch, and advanced the Security checkpoint to 185820374. This
source-side result was subsequently carried through the Phase 3 receiver and
relational materialization path as real `WindowsSecurityEvent` input, closing the
record-family receiver/database proof while the broader Phase 3 acceptance
campaign remained active.

---

---

## USN split-privilege boundary

The underlying split-privilege Windows behavior has been characterized on:

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
Windows Server 2025    10.0.26100
```

Exact Gate 1 acceptance is tracked separately:

```text
Windows Server 2016    10.0.14393    COMPLETE
Windows Server 2019    10.0.17763    COMPLETE
Windows Server 2022    10.0.20348    COMPLETE
Windows Server 2025    10.0.26100    COMPLETE
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

- [FI USN Architecture Summary](../docs/README-USN-SUMMARY.md)
- [FI NTFS USN Privilege Boundary](../docs/security/usn-privilege-boundary.md)
- [FI Windows Server Validation](../docs/WINDOWS-SERVER-VALIDATION.md)
- [FI USN Split-Privilege Verification Kit](../tools/README.md)
- [FI Gate 1 — Windows Server 2019 Verification](../docs/GATE-1-SERVER-2019.md)

---

---

## Windows Security validation — November 2026 snapshot

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

In service mode, Windows Security is collected by an independent sequential
worker rather than waiting for governed-root baseline/reconciliation work. The
worker defaults to a one-minute cadence, immediately drains another bounded
EventRecordID window when backlog remains, and advances its checkpoint only after
the corresponding local spool batch is durably finalized and verified.

The 2026-09-20 Server 2016 post-Gate-1 resilience test demonstrated this behavior
with the Security log at 20 MiB under the active 250K lab workload. The test
proved the collector could remain within the retained Event Log window and
select/durably spool a controlled pair of Event ID 4719 audit-policy changes
without requiring a large Event Log as a workaround. That result is a tested lab
condition, not a universal production Security-log sizing guarantee.

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
[Windows file-auditing example](../examples/windows/file-auditing/README.md).

---

---

## Historical data model

FI is not intended to keep only the latest state of a file.

An initial governed-root baseline establishes what FI knows at the beginning of
observation. Subsequent observations add history.

Material changes create new records rather than silently rewriting prior history.

The PostgreSQL FI System of Record is the authoritative relational
representation of accepted FI history.

Current-state, operational, reporting, search, and role-oriented
representations are **Published FI Projections**: validated, rebuildable,
query-optimized representations of authoritative history through an explicit
publication boundary. A Published FI Projection is not a second source of
truth.

---

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

---

## Supporting-source freshness

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

---

## Local durable spool

Phase 1 writes finalized JSONL batches and manifests locally.

The spool verifies record count, data byte count, and SHA-256 before a batch is
accepted as the local durable boundary.

Finalized batches remain on the source until Phase 2 establishes the exact
durable downstream custody and acknowledgement required for retirement.

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

---

## Source content and planned classification

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
