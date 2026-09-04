# Phase 1 — Windows File & Identity Intelligence

## Purpose

Establish and continuously maintain source-side historical intelligence for each
explicitly governed Windows/NTFS root.

Phase 1 owns what FI can directly observe from the governed Windows source, the
local mechanisms needed to maintain those observations over time, and durable
local queueing before Phase 2 transport begins.

Phase 1 is file-centered. It does not attempt to become a general Windows event
collector or SIEM.

---

## Governed Scope

FI operates only against approved governed roots.

Installing FI on a server does not mean the entire server, volume, or share is
governed.

Each governed root is associated with its source server, volume, collection
policy, activity/audit policy, and later classification policy.

The current configuration format intentionally remains small: it identifies the
governed roots. Collection behavior remains defined by FI code.

The privileged USN helper is authorized at the **volume** level because the NTFS
USN journal is volume-wide. That does not make the whole volume governed.
`FICollector` still performs File-ID re-observation and governed-root containment
before volume-wide USN activity is treated as governed-object activity.

---

## Current Implementation Status

| Capability | Status | Current State |
| --- | --- | --- |
| Governed-root NTFS collection | Implemented | Collects only within explicitly governed local NTFS roots and validates scope using handle-derived identity and paths. |
| NTFS object identity | Implemented | Records volume identity, file reference number, and sequence number independently of path. |
| File and directory metadata | Implemented | Records size, allocation, timestamps, attributes, link count, subject type, and integrated content hashes. |
| Alternate data streams | Implemented | Enumerates NTFS streams and preserves exact stream names and raw representation. |
| Reparse-point observation | Implemented | Preserves raw reparse data and parses supported mount-point and symbolic-link forms without guessing unknown formats. |
| Collection consistency checks | Implemented | Detects object replacement, metadata changes during collection, scope replacement, and incomplete observations. |
| Governed-root recursive walk | Implemented | Walks governed NTFS roots without following reparse-point directories outside the governed namespace. |
| Windows security descriptors and ACLs | Implemented | Exact owner, DACL, SACL, ACE order, masks, inheritance, and related security state are collected. |
| SMB share state and share security | Implemented + refresh scheduled | Records share exposure and share ACL state at baseline and through the bounded supporting-source refresh. The service runtime can schedule refreshes; production interval acceptance remains. |
| Local Windows identity | Implemented + refresh scheduled | Local users, groups, and direct memberships are collected at baseline and through the bounded supporting-source refresh. |
| Active Directory identity | Implemented foundation + refresh scheduled | Resolves relevant current-domain principals and direct `member` relationships using Windows DC Locator, trusted LDAPS/636, Schannel validation, and the collector's current Windows token. Raw `primaryGroupID` is preserved without deriving a membership edge. |
| Effective-access source inputs | Strong foundation | NTFS, share, local-identity, AD identity, and direct-membership inputs exist. Backend correlation owns nested membership and final effective-access conclusions. |
| USN journal change detection | Implemented and integrated | Configured runs use persistent checkpoints, bounded USN catch-up, governed-object selection, File-ID re-observation, durable local spooling, verification, and checkpoint advancement. |
| USN privilege isolation | Implemented; Candidate #4 live accepted on Server 2016 | `FICollector` remains non-admin. `FIUSNReader` is a separate local-Administrator service exposing only bounded USN query/read, mechanical containment, and exact-object SACL-read operations. Local IPC requires the enabled `NT SERVICE\FICollector` service SID and rejects remote clients. Exact Candidate #4 acceptance on Server 2019/2022/2025 remains pending. |
| Windows Security governed-file activity | Implemented foundation and live validated | Selected file/security events, read/denied access, Detailed File Share/5145 context, coverage assessment, durable spooling, and Security checkpoints are integrated. The broader behavior matrix remains. |
| Local durable spool | Implemented | Writes finalized JSONL batches and manifests, verifies count/size/SHA-256, retains accepted local batches, and does not remove them before Phase 2 acknowledgement exists. |
| Normal-run checkpoint continuity | Implemented and live validated | USN and Windows Security checkpoints resume from the previously accepted boundary without replaying the prior accepted range. |
| Continuity-gap history and reconciliation | Implemented and live validated | USN and Windows Security gaps are persisted explicitly as incomplete, current state is reconciled, and a new forward boundary is established without pretending missing history was reconstructed. |
| Operation journal | Implemented and live validated for major boundaries | Append-only Started/Finished lifecycle history covers baseline, USN catch-up, Windows Security catch-up, reconciliation, and SupportingSourceRefresh. Orphaned Started operations are recovered as Interrupted/ProcessRestart. |
| FI runtime resource journal | Implemented foundation / non-blocking | CPU, RAM, and process-I/O history exists for journaled USN operations. Broader coverage is useful for sizing and pilot validation but is not itself a Gate 1 blocker. |
| Supporting-source refresh | Implemented, live validated, and service scheduled | `-supporting-refresh` records current SMB, local-identity, and relevant AD source facts into verified spool batches. `-service` can schedule it at an explicit operator-provided interval. Production cadence still requires measurement. |
| Windows service runtime | Implemented foundation and live validated | The SCM runtime invokes the existing configured collector, prevents overlapping FI-owned write modes through runtime ownership, schedules configured collection and supporting refresh sequentially, and supports stop/shutdown cancellation. Broader failure and boot/restart validation remains. |
| gMSA runtime | Implemented foundation and live validated | Per host, `FICollector` runs as a non-admin gMSA and `FIUSNReader` uses a separate privileged gMSA. Remaining work is deployment reproducibility and validation of service/binary/config/state/spool rights. |
| Failure/restart campaign | Partially validated | Checkpoint gaps, operation restart recovery, helper outage, frozen USN checkpoint, collector continuation, helper restart, and USN catch-up are validated. Broader adverse-condition cases remain. |
| Performance/source impact | Server 2016 Candidate #4 campaign complete; production sizing remains | Tests 13 through 16 provide bounded baseline, churn, spool-pressure, and operation/resource characterization on Server 2016. Repeated representative measurements are still required before production cadence or general sizing limits are declared. |

---

## Initial Baseline

FI performs an applicable observation of every governed file and relevant
directory object.

The baseline establishes the starting historical record and a continuity boundary
for ongoing monitoring.

A missing USN checkpoint causes a safe baseline and catch-up. An existing
continuous checkpoint causes catch-up rather than a new baseline.

The baseline currently includes:

- collector/process identity;
- local SMB share state and share security;
- local users, groups, and direct memberships;
- governed-root NTFS observations;
- the SIDs actually observed from those source facts; and
- relevant current-domain principals plus direct AD membership facts for those
  observed domain SIDs.

The NTFS tree streams during collection rather than being retained as one giant
in-memory baseline.

---

## File, Storage, and Location Intelligence

FI records where applicable and determinable:

- source-server and volume identity;
- NTFS File ID and parent File ID;
- volume serial and drive association;
- filesystem and object type;
- current path;
- applicable hard-link/parent relationship facts;
- applicable SMB shares and UNC exposure; and
- entry into or departure from governed scope where source data can establish it.

Object identity is preferred over path alone so rename/move history can follow
the underlying NTFS object where possible.

Deep storage implementation remains bounded by concrete FI questions. Phase 1
does not become an open-ended NTFS research project merely because Windows
exposes additional structures.

---

## File State

FI records applicable logical and allocated size, attributes, timestamps, content
hashes, stream state, reparse information, security state, and journal-related
state.

A Windows timestamp is a Windows source observation. It is not proof that a
particular identity performed an action.

---

## Streams and Reparse Information

The unnamed stream and observable named `$DATA` streams are preserved as source
observations associated with the governed object.

FI preserves exact stream names and raw representation.

Reparse information is collected without following reparse-point directories out
of the governed namespace. Supported forms may be parsed, while unknown formats
remain raw rather than guessed.

---

## Windows Security State

FI records the Windows security state required for historical interpretation,
including where available:

- raw/native security descriptor;
- owner SID;
- DACL and SACL;
- ACE ordering and type;
- allow/deny semantics;
- SID;
- exact access mask;
- inheritance/propagation flags;
- direct/inherited state; and
- descriptor control state.

Underlying Windows rights/access masks are retained rather than only friendly
labels such as Read, Modify, or Full Control.

---

## Share Exposure

FI records applicable share identity, name, backing path, security descriptor,
share ACL, and the relationship between a governed object/root and each exposing
share.

Because share configuration and share security can change without immediately
causing governed-file activity, supporting-source refresh re-observes share state.

The Windows service runtime can schedule that refresh. Production cadence remains
an operational measurement/acceptance decision, not collector logic.

---

## Local and Directory Identity

FI collects local identities, local groups, direct membership relationships, and
domain principal/direct-membership facts required to explain access to governed
files.

AD identity collection uses Windows DC Locator and trusted LDAPS/636 through the
collector's current Windows token. In deployed service operation that token is
the restricted per-host `FICollector` gMSA.

Collectors preserve source identity facts. They do not calculate transitive
membership or final effective access. Backend correlation owns those
relationships.

Identity state can change without a file operation occurring. Supporting-source
refresh re-observes local identity and relevant AD principal/direct `member`
relationship source facts while retaining previously relevant current-domain SIDs
in FI-owned operational state.

The refresh remains source-driven and bounded. Large relevant-SID sets are split
into bounded directory snapshots rather than truncated, and the collector does
not turn into an Active Directory inventory product.

---

## Governed-File Activity

Phase 1 activity collection is explicitly **governed-object centered**.

FI preserves Windows activity involving a governed file or directory, including
where observable:

- access and attempted access;
- successful and denied access;
- creation;
- modification;
- deletion;
- rename and move activity;
- ownership and permission/security changes;
- hard-link activity; and
- SMB/share activity associated with the governed object.

Where Windows provides it, FI preserves source facts such as:

- account/SID;
- process;
- object identity/path;
- requested or used access mask;
- success/failure;
- event record identity and timestamp;
- share used;
- remote workstation/IP; and
- supporting session/logon identifiers.

Supporting SMB, logon, or session records are collected only when needed to
explain governed-object activity.

FI does not collect broad server logon/session/process activity simply because it
exists.

### Current activity boundary

The current Windows Security source selects:

- `4656` — handle/access requested;
- `4663` — access right used;
- `4660` — object deleted;
- `4664` — hard link created;
- `4670` — permissions changed;
- `4907` — auditing settings/SACL changed;
- `5145` — detailed SMB share access check;
- `1102` — Security log cleared; and
- `4719` — audit policy changed.

Current Windows Server 2016 validation has established:

- successful change-capable file activity;
- successful descendant-file read observation under the FI read-audit rule;
- denied file-handle requests;
- local UNC `5145` source context;
- true remote SMB `5145` source IP context; and
- independent preservation of a successful share-level `5145` and failed NTFS
  `4656` from the same denied remote access attempt.

A successful `5145` means the SMB/share-level check represented by that event
succeeded. It does not prove the final NTFS operation succeeded.

The current coverage model requires effective:

- File System Success and Failure;
- Handle Manipulation Failure;
- Detailed File Share Success and Failure;
- Audit Policy Change Success;
- a sufficient change-capable governed-root SACL; and
- a sufficient descendant-file read governed-root SACL.

The recommended production configuration uses Advanced Audit Policy with the
Windows setting that forces audit subcategory policy to override legacy category
policy.

A missing Windows event must never be interpreted as proof that no activity
occurred.

### Remaining activity validation

The event-selection foundation is implemented, but Gate 1 still needs an explicit
behavior matrix that exercises representative:

- create;
- modify/write;
- successful read;
- denied read/write;
- rename;
- move;
- delete;
- ACL/security change;
- ownership change;
- hard-link creation; and
- local and remote SMB access.

For every supported Windows Server version, the matrix should record exactly
which source facts Windows supplies, what FI preserves, and which facts remain
unavailable or ambiguous.

This is primarily a validation campaign, not a new activity architecture.

---

## Continuous Monitoring

USN and governed-file Windows activity are independent source signals.

USN identifies that an NTFS object changed and drives fresh File-ID
re-observation.

Windows Security provides independent activity facts such as actor, process,
requested/used access, share context, remote source, and result where Windows
emitted the applicable event.

The configured collection path:

1. anchors the Windows Security source;
2. processes each configured governed root;
3. safely baselines a root when no checkpoint exists;
4. otherwise performs bounded USN catch-up;
5. re-observes selected changed governed objects;
6. catches the Security source up through a fixed target;
7. writes and verifies local spool batches;
8. advances checkpoints only after the applicable local durable boundary is
   satisfied;
9. persists and reconciles known USN/Security continuity gaps; and
10. journals major configured operation lifecycle boundaries.

The Windows service runtime invokes this same configured path. It does not create
a second collection implementation.

The service runtime performs work sequentially rather than overlapping collection
cycles. The configured interval is measured after a cycle completes, preventing a
slow run from creating a backlog of concurrent FI collectors.

---

## Supporting-Source Refresh

The filesystem and Security sources provide high-frequency signals.

SMB configuration, local identity, and AD identity/direct membership usually
change less frequently, but they cannot remain frozen forever at baseline.

Phase 1 provides an explicit bounded `fi.exe -supporting-refresh` operation for:

- local SMB shares and share ACLs;
- local users/groups/direct memberships; and
- relevant current-domain principals/direct `member` relationships.

The refresh:

- writes new source observations rather than mutating older history;
- writes and verifies durable local spool batches before reporting success;
- retains previously relevant current-domain SIDs in FI-owned operational state;
- splits large relevant-SID sets into bounded directory snapshots rather than
  truncating them;
- preserves raw `primaryGroupID` without deriving a primary-group membership
  edge;
- leaves backend correlation responsible for transitive membership and
  effective-access conclusions; and
- records its own append-only operation lifecycle.

The Windows service runtime can schedule this operation using an explicit
operator-provided interval.

The collector does not choose a "smart" cadence. Production interval acceptance
should come from representative measurements and operational requirements.

---

## Local Durable Spool Boundary

Phase 1 owns durable local queue creation and verification.

Finalized batches remain on the source until Phase 2 transport exists.

The current spool:

- writes JSONL source records;
- finalizes batches;
- syncs the data file before finalization;
- records record count and data byte count;
- records the data SHA-256;
- records collector executable identity; and
- verifies the manifest/data pair before the applicable checkpoint is accepted.

Interrupted or incomplete FI spool artifacts are preserved separately and are
not reconstructed or promoted into accepted batches.

Phase 1 does not delete a local batch merely because a later send attempt may
occur.

Phase 2 owns authenticated transport, retry behavior, duplicate safety, durable
downstream acknowledgement, and removal of acknowledged local spool batches.

The ordinary SHA-256 manifest digest is a local corruption/integrity check. It is
not claimed to provide cryptographic authenticity against an attacker that can
rewrite both the data and manifest.

---

## Continuity

FI tracks progress through applicable USN and Windows Security sources.

Normal-run behavior has been live validated to resume from the previously
accepted checkpoint boundary without replaying the prior accepted range.

If source history is no longer available, FI preserves that fact explicitly.

A continuity gap identifies, where known:

- source/feed;
- governed scope;
- last known accepted boundary;
- newly available boundary;
- time observed;
- reason/status; and
- resulting incomplete interval/state.

FI never silently treats a known gap as complete coverage.

### USN continuity

The current USN checkpoint assessment detects source/scope replacement and
journal-boundary problems, including journal ID changes, aged-out checkpoints,
and checkpoints outside the available journal window.

Live validation has proved:

1. a known gap is detected;
2. a `USNContinuityGap` record is durably spooled and verified;
3. the historical interval remains `Incomplete`;
4. current-state baseline/reconciliation runs;
5. a new checkpoint is established only after the current-state snapshot is
   accepted; and
6. bounded USN catch-up resumes from the new forward boundary.

The split-privilege helper failure path has also been validated:

1. `FIUSNReader` becomes unavailable;
2. `FICollector` continues other work;
3. the USN checkpoint remains frozen;
4. governed changes occur while the helper is unavailable;
5. the helper returns; and
6. FI resumes from the old checkpoint and preserves the downtime changes during
   catch-up.

### Windows Security continuity

The current Security checkpoint assessment detects:

- reset/clear-style discontinuity where the checkpoint is ahead of the current
  log; and
- overwritten records where the next required EventRecordID is older than the
  oldest available record.

A `WindowsSecurityContinuityGap` is durably recorded before current-state
reconciliation and a new fixed forward Security boundary is established.

Current-state reconciliation does **not** reconstruct missing historical Security
events.

---

## Reconciliation

When FI detects a continuity gap, it cannot reconstruct source history that
Windows no longer retains.

FI:

1. persists the continuity gap;
2. preserves the historical interval as incomplete;
3. performs bounded reconciliation against current governed-source state; and
4. establishes the applicable new forward boundary only after reconciliation
   output is durably accepted.

A reconciliation or new baseline establishes current knowledge. It does not erase
or hide the historical gap.

---

## Historical Access-Analysis Inputs

Phase 1 collects and versions the primary source inputs required for later
historical access analysis:

- NTFS security;
- share security;
- local identity;
- AD identity/direct membership;
- exact Windows rights; and
- applicable governed-file activity.

Additional Windows privilege/bypass observations may be added only where a
concrete access-analysis requirement demonstrates that they materially change the
answer.

Nested membership, cross-source identity correlation, and effective-access
conclusions belong to backend correlation.

---

## Operation Journal

Operation journaling distinguishes:

- no source activity;
- an operation that completed successfully;
- an operation that failed;
- an operation interrupted by process restart; and
- an operation that never reached a terminal result.

Phase 1 journals major collector boundaries, not every internal function.

The configured collector journals:

- baseline;
- USN catch-up;
- Windows Security catch-up;
- reconciliation; and
- SupportingSourceRefresh.

USN catch-up may contain lower-level `USNRead` and `ReObservation` lifecycle
records produced by the USN source implementation.

The configured collector performs restart recovery once at the outer scope
boundary before starting new work. Nested USN work does not re-run restart
recovery against a currently running parent operation.

Resource measurements remain separate from the lifecycle journal.

---

## Windows Service and gMSA Runtime

The Phase 1 Windows runtime uses two services and two unique gMSAs per monitored
host.

```text
FICollector
    restricted per-host gMSA
    non-admin
        |
        | local named pipe
        | NT SERVICE\FICollector service SID required
        v
FIUSNReader
    separate per-host gMSA
    local Administrator on this host only
        |
        v
NTFS raw-volume USN query/read
```

### FICollector

`FICollector` owns normal FI behavior:

- configuration/root handling;
- Windows Security collection;
- NTFS baseline and re-observation;
- USN parsing;
- governed-root containment;
- hashing;
- SMB/local/AD source collection;
- spool writing and verification;
- continuity decisions;
- checkpoint advancement; and
- operation/resource history.

It must remain non-admin.

### FIUSNReader

`FIUSNReader` is the narrow privileged Windows source helper. Candidate #4
exposes exactly four bounded logical operations:

- `QueryJournal` for an approved configured volume;
- `ReadJournal` for one bounded USN Journal read;
- `CheckContainment` for one exact NTFS object identity when the restricted
  collector cannot resolve current containment directly; and
- `ReadSACL` for one exact authorized NTFS object identity when the restricted
  collector cannot perform the required SACL read.

It must not own USN parsing, governed-root collection policy, normal File-ID
re-observation, descriptor parsing, record construction, hashing, configuration
writes, checkpoint state, spool custody, supporting-source collection, or
arbitrary administrative operations.

Candidate #4 live acceptance of this four-operation helper is complete on Server
2016 build `14393`. Equivalent Candidate #4 acceptance remains pending on Server
2019 `17763`, Server 2022 `20348`, and Server 2025 `26100`.

### IPC authentication

The pipe is local-only and rejects remote clients.

The DACL permits:

- SYSTEM;
- Builtin Administrators; and
- the `NT SERVICE\FICollector` service SID.

After a bounded request is read, the helper impersonates the connected client and
requires the FICollector service SID to be present as an enabled, non-deny-only
token group before any raw-volume work occurs.

This means an ordinary elevated administrator can be allowed to reach the pipe
for diagnostic verification and still be denied by runtime service-SID
authentication.

### Configuration authorization

The helper loads FI's administrator-controlled configuration itself.

For `QueryJournal` and `ReadJournal`, the supplied governed root authorizes the
corresponding configured volume.

For `CheckContainment` and `ReadSACL`, the request carries the exact governed
root plus NTFS file-reference number and sequence number. The helper independently
validates the configured root before performing the bounded object operation.

There is no second helper-maintained allowlist.

### Windows administrative trust boundary

On the validated Server 2016 design, the helper gMSA is a local Administrator.
An explicit read-only ACE on FI configuration describes normal runtime intent,
but it does not sandbox a compromised local Administrator.

The security property FI relies on is that compromise of the **non-admin
collector** does not automatically produce a local Administrator token.

The helper's local-Administrator authority remains the Windows administrative
trust boundary.

---

## Failure and Recovery Acceptance

Continuity-gap, operation-restart, helper-outage, and catch-up paths are live
validated.

The Server 2016 Candidate #4 closure campaign additionally includes:

- Test 12A collector restart/recovery;
- Test 12B bounded lab spool-write denial;
- Test 12C bounded lab governed-root unavailability/recovery;
- Test 12D bounded passive dependency observation around an externally controlled
  AD/LDAPS fault;
- bounded churn and spool-pressure campaigns;
- deployment/service/config/state/spool/service-token boundary validation; and
- confirmation that the non-admin collector cannot replace or reconfigure the
  privileged helper through its normal service token.

The original unsafe 12D validation harness is retired. The current 12D
implementation is a bounded passive observer and does not itself create the
dependency outage.

These results do not claim that every possible Windows or infrastructure failure
has been exhausted. Additional hardening and pilot work can still exercise, for
example:

- machine reboot during additional operation boundaries;
- unwritable service-runtime journal;
- interrupted/open spool batch handling;
- corrupted or unverifiable finalized batch/manifest;
- Security-log unavailability;
- local identity/share-source failure; and
- additional source-state changes during collection.

Expected source failures remain explicit `Partial`, `Incomplete`, `Failed`, or
other source-status facts rather than being silently converted into success.

---

## Performance and Source Impact

FI has:

- `-perf-root` measurement of the real NTFS walk/collection path;
- focused NTFS benchmarks;
- process resource-journal support around journaled USN operations; and
- the bounded Gate 1 Tests 13 through 16 for baseline, churn, spool pressure, and
  operation/resource characterization.

The Server 2016 Candidate #4 campaign has completed an initial bounded
performance/source-impact acceptance campaign. Those results prove the tested
workloads remained bounded and measurable; they do not establish general
production sizing or production cadence.

Before FI declares production defaults, repeated representative measurements
should cover:

- initial baseline;
- normal low-churn catch-up;
- high-churn catch-up;
- Security activity volume;
- supporting-source refresh;
- CPU/RAM/I/O;
- spool growth;
- service restart/recovery; and
- gap reconciliation.

Production cadence remains `NOT_EVALUATED`. Thresholds and intervals should be
based on repeated representative measurements rather than invented from one
machine or one run.

---

## Supported Windows Versions

The current exact characterized Windows Server build set is:

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

An adjacent build or later Windows Server release must be characterized
independently before FI claims identical audit, USN, service, permission,
protected-object, or SACL-broker behavior.

The old direct-volume privilege probes remain engineering characterization aids,
not product runtime components.

---

## Classification Content Streaming Is Not Phase 1

Protected source-content streaming/read-broker behavior is not owned by the
normal Phase 1 Windows record collector.

It belongs to the **Separate Protected Classification Stream** in Phase 4.

Normal FI Phase 1 record transport does not carry customer source-file content.

---

## Gate 1 — Source Intelligence & Continuity

Gate 1 proves FI can baseline and continuously maintain an explicitly governed
Windows/NTFS root while preserving:

- file/object identity;
- applicable NTFS/file state;
- streams/reparse state;
- security;
- shares;
- local and directory identity source facts;
- governed-file activity;
- historical access-analysis inputs;
- local durable queue state;
- source checkpoints;
- explicit continuity/gap state;
- reconciliation state; and
- major collector operation history.

Gate 1 also proves:

- the collector does not escape governed scope;
- missing source history remains visibly incomplete;
- previously accepted USN/Security ranges are not replayed as new activity;
- unrelated volume-wide USN activity is not treated as governed activity;
- local spool batches remain queued until Phase 2 owns acknowledgement/removal;
- supporting SMB/local/AD source facts remain sufficiently current for the
  historical model;
- the main collector remains non-administrative;
- privileged Windows source operations are isolated to the narrow
  `FIUSNReader` helper while `FICollector` remains non-administrative;
- failure of the helper cannot silently advance USN continuity;
- deployment/service/config/state/spool permissions match the documented trust
  model; and
- source impact remains bounded and measurable.

### Remaining work before Gate 1 acceptance

Windows Server 2016 build `14393` has completed the exact Candidate #4 Gate 1
campaign.

Gate 1 remains open overall for:

1. exact Candidate #4 acceptance on Windows Server 2019 build `17763`;
2. exact Candidate #4 acceptance on Windows Server 2022 build `20348`;
3. exact Candidate #4 acceptance on Windows Server 2025 build `26100`;
4. repeated representative performance/source-impact measurement where needed
   across the intended supported deployment set;
5. production collection/supporting-refresh cadence selection from accumulated
   measurements; and
6. final review of `docs/GATE-1-RESULT-RECORD.md` across the intended exact
   release/build set.

The `1m` collection / `30m` supporting-source cadence used by the Gate 1 test
deployment is an acceptance configuration, not a production default. Production
cadence remains `NOT_EVALUATED`.

No new Phase 1 source subsystem should be added unless a concrete Gate 1
requirement demonstrates that an existing source fact is missing.
