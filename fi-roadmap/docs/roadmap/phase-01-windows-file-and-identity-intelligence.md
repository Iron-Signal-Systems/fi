# Phase 1 — Windows File & Identity Intelligence

## Purpose

Establish and continuously maintain the source-side historical intelligence model
for each explicitly governed Windows/NTFS root.

Phase 1 owns what FI can directly observe from the governed source and the
source-side mechanisms needed to maintain that knowledge over time.

## Governed Scope

FI operates only against approved governed roots. Installing FI on a server does
not mean the entire server, volume, or share is governed.

Each governed root is associated with its source server, volume, collection
policy, activity/audit policy, and classification policy.

## Initial Baseline

FI performs an applicable observation of every governed file and relevant
directory object. This establishes the starting historical record.

## Implementation Status

| Capability | Status | Current State |
| --- | --- | --- |
| Governed-root NTFS collection | Implemented | Collects only within explicitly governed local NTFS roots and validates scope using handle-derived identity and paths. |
| NTFS object identity | Implemented | Records volume identity, file reference number, and sequence number independently of path. |
| File and directory metadata | Implemented | Records size, allocation, timestamps, attributes, link count, and subject type. |
| Alternate data streams | Implemented | Enumerates NTFS streams and preserves exact stream names and raw representation. |
| Reparse-point observation | Implemented | Preserves raw reparse data and parses supported mount-point and symbolic-link forms without guessing unknown formats. |
| Collection consistency checks | Implemented | Detects object replacement, metadata changes during collection, scope replacement, and incomplete observations. |
| Governed-root recursive walk | Implemented | Walks governed NTFS roots without following reparse-point directories outside the governed namespace. |
| Windows security descriptors and ACLs | Implemented | Exact owner, DACL, SACL, ACE order, masks, inheritance, and related security state are collected. |
| SMB share state and share security | Implemented | Share exposure and share ACL collection. |
| Local Windows identity | Implemented | Local users, groups, direct memberships, and related identity records are implemented. |
| Active Directory identity | Implemented | Resolves current-domain principals and direct memberships required by observed SIDs using Windows DC Locator, LDAPS/636, certificate validation through Schannel, and current-token authentication. Directory collection fails closed when trusted LDAPS is unavailable. |
| Effective-access analysis inputs | in-process | NTFS, share, local-identity, and directory direct-membership inputs are present. Remaining Phase 1 inputs include applicable privilege/bypass and activity observations; nested membership and effective-access reasoning belong to backend correlation. |
| USN journal change detection | in-process | Queries journal state, reads bounded USN batches, re-observes changed objects by NTFS file ID, and supports local checkpoint initialization/status. Continuous scheduling and full monitoring integration remain. |
| Activity history | Planned | Relevant Windows filesystem, SMB, security, identity, logon, and session activity collection has not yet been implemented. |
| Continuity and reconciliation | in-process | USN checkpoint state and continuity assessment are implemented. Durable progression tied to downstream custody, explicit gap history, restart recovery, and bounded reconciliation remain. |
| Operation journal | in-process | Operation lifecycle entries, validation, local append-only JSONL storage with flush, and bounded USN read/re-observation integration are implemented. Durable Started entries are written before source work; terminal Finished entries record the outcome. Broader operation coverage and interrupted-operation recovery remain. |
| Protected source-content read broker | Planned | Bounded protected access to source content for later classification is not yet implemented. |

## File, Storage, and Location Intelligence

FI records where applicable and determinable:

- FI object identity;
- source-server identity;
- NTFS File ID and parent File ID;
- NTFS volume identity and serial;
- drive association;
- disk/LUN relationship;
- physical allocation/extents where policy requires;
- filesystem and object type;
- current and historical paths;
- hard links;
- applicable SMB shares and UNC exposure;
- entry into and departure from governed scope.

Object identity is preferred over path alone so rename/move history follows the
underlying NTFS object where possible.

## File State

FI records applicable logical and allocated size, attributes, timestamps, hashes,
signature observations, reparse information, and journal-related state.

A Windows last-access timestamp is a Windows timestamp observation, not proof that
a particular identity actually read a file.

## Deep NTFS Object Inspection

FI treats an NTFS object as a compound forensic object.

FI discovers and records where supported and applicable:

- unnamed/default data stream;
- every observable named `$DATA` stream / Alternate Data Stream (ADS);
- Extended Attributes (EA);
- reparse information and raw reparse data where appropriate;
- object identifiers;
- relevant logged utility stream information;
- relevant directory/index information;
- other supported NTFS attributes material to identity, behavior, security,
  storage, or forensic interpretation.

### Stream Observations

The unnamed stream and named streams are distinct observations associated with the
governed object.

For each stream FI records where applicable:

- exact stream name;
- stream type;
- parent NTFS object identity;
- logical and allocated size;
- hash;
- observation time;
- collection status;
- access/read failure;
- change relationship;
- classification relationship.

FI does not invent a recursive NTFS ADS hierarchy where NTFS does not expose one.

Content within an ADS may itself contain structured or active material such as an
executable, DLL, script, archive, document, database, configuration, encrypted
content, or nested container. Classification may recursively inspect such content
to a bounded policy-defined depth.

Creation, modification, truncation, replacement, or deletion of an applicable
stream results in fresh stream enumeration and new write-once FI observations.

## Windows Security

FI records the Windows security state required for historical interpretation,
including:

- raw/native security descriptor;
- descriptor identity/hash;
- owner SID;
- primary group SID where applicable;
- DACL and SACL;
- ACE ordering and type;
- allow/deny semantics;
- SID;
- exact access mask;
- inheritance/propagation flags;
- direct/inherited state;
- descriptor control flags;
- integrity information where applicable.

Underlying Windows rights/access masks are retained rather than only friendly
labels such as Read, Modify, or Full Control.

## Share Exposure

FI records applicable share identity, name, backing path, security descriptor,
share ACL, and relationship between the governed object and each exposing share.

## Local and Directory Identity

FI collects local identities, groups, direct membership relationships, and domain
principal relationships required to explain access to governed files.

FI performs:

> **AD identity collection using Windows DC Locator and trusted LDAPS/636 through
> the collector's current Windows token. In deployed service operation that token
> is intended to be the FI gMSA.**

Directory identity records preserve versioned principal facts and direct
membership relationships. FI collectors do not calculate transitive/nested group
membership or effective access; those relationships are correlated later by the
backend from the collected source facts.

Each monitored Windows source performs the identity collection necessary for its
governed roots. FI does not require a centralized Windows identity tier.

## Historical Access-Analysis Inputs

Phase 1 collects and versions sufficient source inputs to reproduce historical
effective-access analysis, including NTFS security, share security, local
identity, directory identity, direct membership facts, exact Windows rights, and
applicable privilege/bypass observations.

Nested membership, cross-source identity correlation, and effective-access results
are backend-derived relationships. Any access-analysis result must identify the
exact versioned source inputs used.

## Windows Activity

FI continuously consumes relevant Windows filesystem, SMB, security, identity,
logon, and session activity associated with governed roots.

Where observable this may establish create, read, write, delete, rename, move,
security change, share access, source identity, workstation, IP, session, or logon
relationships.

FI captures applicable Windows activity into FI history before normal Windows log
retention removes it.

## Continuous Monitoring

USN and relevant Windows activity act as change signals. A signal causes FI to
identify the affected governed object and obtain fresh applicable observations.

USN is a change detector, not forensic truth by itself.

Current Phase 1 code can query USN journal state, read bounded batches, re-observe
distinct changed objects by NTFS file ID, and assess a local USN checkpoint. The
continuous monitor that schedules and advances those operations is still future
work.

## Continuity

FI durably tracks progress through applicable USN journals, Windows event
channels, and other continuous feeds.

If source history is no longer available, FI writes a continuity/coverage-gap
record identifying the affected source, feed, scope, and known incomplete
interval.

FI never silently treats a known gap as complete coverage.

Local USN checkpoint initialization and continuity assessment exist now. Automatic
checkpoint progression, restart recovery, explicit persisted gap history, and
continuity tied to later durable downstream custody remain to be implemented.

## Reconciliation

FI performs bounded reconciliation to identify divergence between the maintained
FI model and the governed source. Significant continuity loss may require broader
reconciliation or re-baselining.

## Protected Read Broker

Phase 1 owns the source-side Protected Read Broker used by the Separate Protected
Classification Stream.

It validates the exact governed object/stream and scope, opens content read-only,
and provides bounded sequential/range access with cancellation, timeout,
backpressure, and safe handle cleanup.

Source content never travels through normal FI record transport.

## Journal Requirements

Material Phase 1 operations produce immutable journal history, including baseline,
collection, re-observation, stream enumeration, activity collection,
reconciliation, coverage degradation, continuity loss, and protected-read
outcomes.

The current operation-journal core validates lifecycle entries and writes them as
append-only local JSONL with a flush before return. Bounded USN read and
re-observation operations write a durable Started entry before source work and a
Finished entry afterward. Broader operation coverage and restart recovery of
unmatched Started operations remain.

## Gate 1 — Source Intelligence & Continuity

Gate 1 proves FI can baseline and continuously maintain a governed Windows/NTFS
root while preserving:

- file/object identity;
- storage and location;
- deep NTFS and ADS/stream state;
- security;
- shares;
- local and directory identity;
- activity;
- historical access-analysis inputs;
- continuity;
- reconciliation state;
- immutable operation journaling.

It also proves bounded source impact and safe Protected Read Broker operation.
