# ADR-0002 — Windows Volume-First Source Observation and Governed-Root Policies

**Date:** 2026-11-08
**Status:** Proposed full architecture; isolated volume discovery, configuration, continuity and USN broker foundations partially implemented/tested. NO integrated volume-first runtime or acceptance.
**Branch:** `dev/windows-volume-first-20261108`
**Windows engineering/test machine:** `adminbox`

## Decision

FI will separate NTFS **change acquisition** from governed-root **observation policy**. Each explicitly enrolled local NTFS volume owns exactly one USN capture stream, continuity record, durable checkpoint, and bounded scheduler. A volume may have zero, one, or several governed roots, including overlaps. A governed root controls deeper object observation, priority, audit requirements, and reporting association; it does not own the USN journal.

FI remains a non-remediating, file-centered historical intelligence system, not a general Windows event collector or SIEM. The existing root-centric implementation and historical test records remain valid descriptions of what was actually exercised; this proposal does not imply changed binaries or an accepted new design.

```text
FICollector (restricted per-host gMSA)
  |-- Volume discovery, eligibility and separately approved enrollment
  |-- Volume A: one checkpoint, capture, continuity epoch, bounded worker
  |     |-- source USN facts, whether governed or ungoverned
  |     |-- root policy A1 -> extra object observations
  |     '-- root policy A2 -> possibly different observation policy
  |-- Volume B: independent journal, checkpoint, worker, fault state
  |-- Windows Security lane: independent host-level checkpoint
  '-- verified local spool publication; no checkpoint before custody
FIUSNReader: bounded, locally authenticated privileged volume journal broker
FIObjReader: separately authorized exact-object observation broker
FICRLRefresher: certificate revocation freshness
FISender: authenticated transport, independent service
```

## Authorized volumes and identity

1. Discover local NTFS volumes including drive-letter, mounted-folder and volume-GUID-only devices. Distinguish *discovered*, *eligible*, *enrolled*, *unavailable*, *replaced*, *discontinuous* and *unsupported*. No newly discovered volume becomes enrolled automatically.
2. The administrator expressly approves volumes, especially the system volume. Volume discovery never authorizes capture or blanket audit changes.
3. Preserve enrollment identity separately from the observed NTFS instance, current mount/drive-letter aliases, journal ID and the FI-assigned continuity **epoch**. Volume GUID and path alone do not establish uninterrupted history across a reformat.
4. A per-volume pipeline owns checkpoint/capture/retry, and a host-level resource budget bounds all pipelines. One failed or disconnected volume must not stall independent volumes.
5. On journal reset, replacement, an aged-out USN boundary or other proven discontinuity, emit an explicit incomplete historical interval, preserve previous custody, establish a new epoch and reconcile present state without fabricating the lost interval.

## Source facts and governed observation

- On enrolled volumes preserve bounded native change facts: volume/epoch and journal provenance, file/parent IDs, USN, reason bits, source-provided name and timestamp. Paths can be unavailable or ambiguous, particularly for deletion, rename, hard links and inaccessible objects.
- Outside governed roots FI may retain **minimal change evidence** but may not automatically hash content, read protected objects, conduct a full tree baseline, or collect full ACL/SACL state.
- Governed roots are policy assignments bound to observed volume/object identity rather than string-prefix containment alone. Root policies define deeper metadata/security/content rules, priority, reporting and optional audit prerequisites. Zero governed roots is valid for a volume enrolled for minimal observation.
- Overlapping roots must not multiply source USN acquisition; one source change may have multiple policy memberships. Policy resolution must be deterministic and must not silently loosen privilege or content-access restrictions.
- Reparse points, mount points, cross-volume moves and file replacement must not escape the approved policy boundary.
- USN does **not** identify a user. Windows Security evidence can supply attribution only when an independently observed event securely correlates to a specific object/activity. Otherwise mark attribution unknown. A gap or missing audit coverage cannot establish absence of activity.

## Privilege, security and installer invariants

- Preserve the five Windows services, gMSA split, FICollector non-admin identity, authenticated local pipes, FIUSNReader narrow raw-volume journal authority, and FIObjReader narrow protected-object authority. A volume-level USN query is never an arbitrary disk, file, FSCTL or privilege proxy.
- Runtime collection remains read-oriented/non-remediating. Installer actions are explicitly approved administrative mutations, never a property of the collector's ordinary execution identity.
- The new volume-first installer is **fresh-install only on a machine with no FI**. Its future native creation transaction must journal durable intent before each exclusive create, verify/sync each created artifact before acknowledgement, and quarantine uncertain interrupted steps instead of silently deleting/repairing prior FI evidence. See `docs/development/WINDOWS-VOLUME-FIRST-CREATION-JOURNAL.md`.  Configuration, discovery, scope approval, native broker authorization, SACL/audit planning, new service creation and failed-new-install rollback must be engineered **together with** the collector. There is **no** in-place conversion, service reconciliation, update or migration of root-only `1.1` state. See `docs/development/WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md` and `docs/development/WINDOWS-VOLUME-FIRST-FRESH-INSTALL.md`.
- A verified immutable spool publication and safe ownership transition precede USN checkpoint advancement. A retry must not erase a failure or double-retire durable records.
- Preserve current signed generation transport/receiver custody principles; update their record-validation contracts only as required by the new source model.

## Backend impact

A fresh development PostgreSQL schema is permitted. Model source host, enrolled volume, epoch, NTFS object identity, USN evidence, current-state observations, governed-policy associations, Security evidence and explicit gaps. Rebuild Go ingest and typed projectors accordingly. No old experimental schema compatibility/migration requirement is imposed. Keep source observations separate from later inference and published projections.

## Execution boundaries and proof

All Windows development and native build/testing is on `adminbox`. No staging action modifies the running `ISS-FS-22A` services or starts FISender (intentionally stopped). Until tests in `docs/development/WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md` establish otherwise, every target capability is **unimplemented/unverified**.

`main` remains untouched. Any future integration of this branch requires a separate explicit decision, complete code/installer/docs alignment, and actual native Windows failure-path evidence.
