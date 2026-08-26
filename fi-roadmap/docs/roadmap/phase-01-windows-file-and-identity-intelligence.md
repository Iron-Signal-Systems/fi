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
| SMB share state and share security | Implemented baseline source | Records share exposure and share ACL state. Bounded continuous refresh remains. |
| Local Windows identity | Implemented baseline source | Local users, groups, and direct memberships are collected. Bounded continuous refresh remains. |
| Active Directory identity | Implemented baseline source; deployment validation remains | Resolves relevant current-domain principals and direct memberships using Windows DC Locator, trusted LDAPS/636, Schannel validation, and the collector's current Windows token. Production service operation is intended to use the FI gMSA. Bounded refresh remains. |
| Effective-access source inputs | Strong foundation | NTFS, share, local-identity, AD identity, and direct-membership inputs exist. Additional Windows privilege/bypass inputs remain Phase 1 hardening only where a concrete Gate 1 need is proved. Backend correlation owns nested membership and final effective-access conclusions. |
| USN journal change detection | Implemented and integrated | Configured runs use persistent checkpoints, bounded USN catch-up, governed-object selection, File-ID re-observation, durable local spooling, verification, and checkpoint advancement. |
| Windows Security governed-file activity | Implemented foundation and live validated | Selected file/security events, read/denied access, Detailed File Share/5145 context, coverage assessment, durable spooling, and Security checkpoints are integrated. The broader activity behavior matrix remains to be completed. |
| Local durable spool | Implemented | Writes finalized JSONL batches and manifests, verifies count/size/SHA-256, retains accepted local batches, and does not remove them before Phase 2 acknowledgement exists. |
| Normal-run checkpoint continuity | Implemented and live validated | USN and Windows Security checkpoints resume from the previously accepted boundary without replaying the prior accepted range. |
| Continuity-gap history and reconciliation | Implemented and live validated | USN and Windows Security gaps are persisted explicitly as incomplete, current state is reconciled, and a new forward boundary is established without pretending missing history was reconstructed. |
| Operation journal | Implemented and live validated for major configured boundaries | Append-only Started/Finished lifecycle history covers baseline, USN catch-up, Windows Security catch-up, and reconciliation. Orphaned Started operations are recovered as Interrupted/ProcessRestart. |
| FI runtime resource journal | Implemented foundation / non-blocking | CPU, RAM, and process-I/O history exists for journaled USN operations. Broader coverage is useful for sizing and pilot validation but is not itself a Gate 1 blocker. |
| Supporting-source refresh | Remaining | SMB share state, local identity, and relevant AD identity/direct membership need bounded refresh after baseline so later history does not rely indefinitely on the initial snapshot. |
| Windows service runtime | Remaining | FI still needs a simple persistent Windows service runtime around the configured collector. |
| gMSA least-privilege runtime | Remaining | The deployed service identity must be tested with only the rights/access FI actually requires. |
| Failure/restart campaign | Partially validated | Checkpoint gaps and operation restart recovery are validated. Broader service, spool/state, source-unavailable, and resource-exhaustion cases remain. |
| Performance/source impact | Measurement tooling exists; acceptance campaign remains | `-perf-root` and resource measurements exist. Representative workload sizing and impact limits remain Gate 1 work. |

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

The baseline share snapshot is implemented.

Because share configuration and share security can change without immediately
causing governed-file activity, Phase 1 still needs a bounded refresh mechanism
for share state.

---

## Local and Directory Identity

FI collects local identities, local groups, direct membership relationships, and
domain principal/direct-membership facts required to explain access to governed
files.

AD identity collection uses Windows DC Locator and trusted LDAPS/636 through the
collector's current Windows token. In deployed service operation that token is
intended to be the FI gMSA.

Collectors preserve source identity facts. They do not calculate transitive
membership or final effective access. Backend correlation owns those
relationships.

Identity state can change without a file operation occurring. Phase 1 therefore
still needs bounded refresh of local identity and relevant AD principal/direct
membership source facts.

The refresh mechanism should remain source-driven and bounded. It should not turn
the Windows collector into an Active Directory inventory product.

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
- local and remote SMB access

and records exactly which source facts Windows supplies for each case on each
supported Windows Server version.

This is primarily a validation campaign, not a new activity architecture.

---

## Continuous Monitoring

USN and governed-file Windows activity are independent source signals.

USN identifies that an NTFS object changed and drives fresh File-ID
re-observation.

Windows Security provides independent activity facts such as actor, process,
requested/used access, share context, remote source, and result where Windows
emitted the applicable event.

The configured `fi.exe -run` path currently:

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

Persistent service scheduling remains deployment/runtime work.

---

## Supporting-Source Refresh

The filesystem and Security sources provide high-frequency signals.

SMB configuration, local identity, and AD identity/direct membership usually
change less frequently, but they cannot remain frozen forever at baseline.

Phase 1 still needs a bounded refresh policy for:

- local SMB shares and share ACLs;
- local users/groups/direct memberships; and
- relevant current-domain principals/direct memberships.

The refresh should:

- write new source observations rather than mutate older history;
- remain scoped to information relevant to governed roots and observed SIDs;
- leave backend correlation responsible for transitive membership and
  effective-access conclusions; and
- produce an operation lifecycle record when the refresh becomes a material
  configured collector boundary.

The exact cadence is a deployment/runtime policy decision and should not be
invented in the collector before operational testing establishes a useful
default.

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

Phase 1 does not delete a local batch merely because a later send attempt may
occur.

Phase 2 owns authenticated transport, retry behavior, duplicate safety, durable
downstream acknowledgement, and removal of acknowledged local spool batches.

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

### Windows Security continuity

The current Security checkpoint assessment detects:

- reset/clear-style discontinuity where the checkpoint is ahead of the current
  log; and
- overwritten records where the next required EventRecordID is older than the
  oldest available record.

Live validation has proved both reason classes.

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

Additional Windows privilege/bypass observations may be added where a concrete
access-analysis requirement demonstrates that they materially change the answer.

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

The current configured collector journals:

- baseline;
- USN catch-up;
- Windows Security catch-up; and
- reconciliation.

USN catch-up may contain lower-level `USNRead` and `ReObservation` lifecycle
records produced by the existing USN source implementation.

The configured collector performs restart recovery once at the outer scope
boundary before starting new work. Nested USN work does not re-run restart
recovery against a currently running parent operation.

Live validation has proved:

- normal Started/Finished lifecycle pairs;
- recovery of an orphaned Started operation as
  `Interrupted / ProcessRestart`;
- no duplicate terminal records after recovery;
- normal USN catch-up after recovery;
- USN-gap `Reconciliation / Complete`; and
- Windows Security-gap `Reconciliation / Complete`.

A future supporting-source identity/share refresh may add another major operation
kind if it becomes operationally useful.

Resource measurements remain separate from the lifecycle journal.

---

## Windows Service and gMSA Runtime

The collector core currently runs interactively through `fi.exe -run`.

Gate 1 still requires a simple Windows service runtime that:

- invokes the existing configured collector rather than duplicating collector
  logic;
- prevents overlapping configured runs;
- supports graceful service stop;
- preserves restart-safe journal/checkpoint behavior; and
- uses an intended gMSA service identity.

The gMSA must be validated with only the rights/access FI actually needs.

The validation must determine the minimum practical access for:

- Security log reading;
- USN journal access;
- governed-root traversal and file reading;
- security descriptor and SACL reading;
- hashing;
- SMB share query;
- local identity query;
- LDAPS/AD lookup;
- FI configuration read;
- FI state/spool write; and
- operation/resource journal write.

Testing under LocalSystem, Domain Admin, or broad local Administrator rights is
not a substitute for the least-privilege service test.

---

## Failure and Recovery Acceptance

Continuity-gap and operation-restart paths are already live validated.

Before Gate 1 closes, representative failure testing should also include:

- service/process termination during a configured operation;
- unwritable FI state directory;
- unwritable spool directory;
- interrupted/open spool batch handling;
- corrupted or unverifiable finalized batch/manifest;
- missing or inaccessible governed root;
- Security log unavailable/unreadable;
- AD/DC/LDAPS unavailable;
- local identity/share source failure;
- source state changing during collection; and
- bounded local storage/resource exhaustion.

Expected source failures should be explicit `Partial`, `Incomplete`, `Failed`, or
other source-status facts rather than silently converted into success.

---

## Performance and Source Impact

FI already has:

- `-perf-root` measurement of the real NTFS walk/collection path;
- focused NTFS benchmarks; and
- process resource-journal support around journaled USN operations.

Gate 1 still needs representative workload measurements for:

- initial baseline;
- normal low-churn catch-up;
- high-churn catch-up;
- Security activity volume;
- CPU/RAM/I/O;
- spool growth; and
- recovery/reconciliation work.

Thresholds should be based on repeated representative measurements rather than
invented before data exists.

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
- the deployed service identity has only the privileges/access FI actually
  requires; and
- source impact remains bounded and measurable.

### Remaining work before Gate 1 acceptance

At the current development point, the primary remaining work is:

1. supporting-source refresh for SMB/local/AD facts;
2. governed-file activity behavior matrix;
3. Windows service runtime;
4. gMSA least-privilege validation;
5. broader failure/recovery campaign;
6. representative performance/source-impact campaign; and
7. validation/documentation of supported Windows Server versions and known
   coverage limits.
