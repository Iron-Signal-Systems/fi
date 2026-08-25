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
| SMB share state and share security | Implemented | Records share exposure and share ACL state. |
| Local Windows identity | Implemented | Local users, groups, direct memberships, and related identity records are implemented. |
| Active Directory identity | Implemented; deployment validation remains | Resolves current-domain principals and direct memberships using Windows DC Locator, trusted LDAPS/636, Schannel validation, and the collector's current Windows token. Production service operation is intended to use the FI gMSA. |
| Effective-access source inputs | Strong foundation | NTFS, share, local-identity, AD identity, and direct-membership inputs exist. Additional Windows privilege/bypass inputs are later Phase 1 hardening unless a concrete Gate 1 requirement proves they are needed sooner. Backend correlation owns nested membership and effective-access conclusions. |
| USN journal change detection | Implemented and integrated | Configured runs use persistent checkpoints, bounded USN catch-up, governed-object selection, File-ID re-observation, durable local spooling, verification, and checkpoint advancement. |
| Windows Security governed-file activity | Implemented foundation; completeness remains | Collects selected file/security events, preserves raw source facts, assesses audit coverage, durably spools and verifies records, and checkpoints the Security channel. Current validated SACL focuses on change-capable rights; complete read/access visibility and remote SMB context remain Phase 1 work. |
| Local durable spool | Implemented | Writes finalized JSONL batches and manifests, verifies count/size/SHA-256, retains accepted local batches, and does not remove them before Phase 2 acknowledgement exists. |
| Normal-run checkpoint continuity | Implemented and live validated | USN and Windows Security checkpoints persist across runs and resume exactly from the previously accepted boundary without replay. |
| Continuity-gap history and reconciliation | In process | Continuity problems are detected. Explicit persisted gap records and bounded reconciliation/rebaseline behavior remain. |
| Operation journal | In process | USN lifecycle operations have append-only Started/Finished/Interrupted history. Broader coverage should remain limited to major collector operations. |
| FI runtime resource journal | In process / non-blocking | CPU, RAM, and process-I/O history exists for journaled operations. Broader coverage is useful for sizing and pilot validation but is not a Gate 1 blocker. |
| Windows service / gMSA runtime | Remaining | FI still needs deployment and least-privilege validation as a Windows service under its intended gMSA identity. |

---

## Initial Baseline

FI performs an applicable observation of every governed file and relevant
directory object.

The baseline establishes the starting historical record and a continuity boundary
for ongoing monitoring.

A missing checkpoint causes a safe baseline and catch-up. An existing continuous
checkpoint causes catch-up rather than a new baseline.

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

Deep storage implementation should remain bounded by concrete FI questions. Phase
1 does not become an open-ended NTFS research project merely because Windows
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

---

## Governed-File Activity

Phase 1 activity collection is explicitly **governed-object centered**.

FI should preserve Windows activity involving a governed file or directory,
including where observable:

- access and attempted access;
- successful and denied access;
- creation;
- modification;
- deletion;
- rename and move activity;
- ownership and permission/security changes;
- hard-link activity; and
- SMB/share activity associated with the governed object.

Where Windows provides it, FI should preserve source facts such as:

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

The current Windows Security implementation has established the file/security
activity foundation, including selected Security events, audit-policy/SACL
coverage assessment, Security-channel continuity, durable local spooling, and
checkpoint progression.

Current Windows Server 2016 validation proves change-capable activity and denied
handle requests under the documented audit configuration.

The currently recommended SACL does **not** claim complete successful-read
visibility. Expanding and validating governed-file read/access coverage is
remaining Phase 1 work.

Remote SMB client/share context should be added only to the extent required to
explain activity involving governed objects.

A missing Windows event must never be interpreted as proof that no activity
occurred.

---

## Continuous Monitoring

USN and governed-file Windows activity are independent source signals.

USN identifies that an NTFS object changed and drives fresh File-ID
re-observation.

Windows Security provides independent activity facts such as actor, process,
requested/used access, and result where Windows emitted the applicable event.

The configured `fi.exe -run` path currently:

1. anchors the Windows Security source;
2. processes each configured governed root;
3. safely baselines a root when no checkpoint exists;
4. otherwise performs bounded USN catch-up;
5. re-observes selected changed governed objects;
6. catches the Security source up through a fixed target;
7. writes and verifies local spool batches; and
8. advances checkpoints only after the applicable local durable boundary is
   satisfied.

Persistent service scheduling remains deployment/runtime work.

---

## Local Durable Spool Boundary

Phase 1 owns durable local queue creation and verification.

Finalized batches remain on the source until Phase 2 transport exists.

Phase 1 does not delete a local batch merely because a later send attempt may
occur.

Phase 2 owns authenticated transport, retry behavior, duplicate safety, durable
downstream acknowledgement, and removal of acknowledged local spool batches.

---

## Continuity

FI tracks progress through applicable USN and Windows Security sources.

Normal-run behavior has been live validated to resume from the previously
accepted checkpoint boundary without replaying the prior accepted range.

If source history is no longer available, FI must preserve that fact explicitly.

A continuity gap must identify, where known:

- source/feed;
- governed scope;
- last known accepted boundary;
- newly available boundary;
- time observed;
- reason/status; and
- resulting incomplete interval/state.

FI never silently treats a known gap as complete coverage.

---

## Reconciliation

When FI detects a continuity gap, it cannot reconstruct source history that
Windows no longer retains.

FI should:

1. persist the continuity gap;
2. preserve the historical interval as incomplete;
3. perform bounded reconciliation against current governed-source state; and
4. rebaseline when the gap or source replacement makes a new baseline necessary.

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

Operation journaling is used to distinguish:

- no source activity;
- an operation that completed successfully;
- an operation that failed;
- an operation interrupted by process restart; and
- an operation that never reached a terminal result.

Phase 1 should journal major collector boundaries, not every internal function.

The intended major boundaries are:

- baseline;
- USN catch-up/re-observation;
- Windows Security catch-up;
- reconciliation/rebaseline; and
- identity refresh where operationally useful.

Resource measurements remain separate from the lifecycle journal and are useful
for performance sizing and pilot validation.

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
- the deployed service identity has only the privileges/access FI actually
  requires; and
- source impact remains bounded and measurable.
