# Windows USN volume-first capture and scoped processing — development gate

Status: **UNRELEASED / NOT ACCEPTED / NOT SAFE TO INSTALL ON ISS-FS-22B**  
Branch: `windows-usn`  
Source: current FI `main` with the 2026-10-20 durable capture foundation restored

## Observed failure on ISS-FS-22B (2026-11-28)

A sustained G:\\FI-Test file-generation campaign exposed the historical
synchronous read/re-observation pipeline. FI's G: root checkpoint was
NextUSN=32,276,992 while Windows' FirstUSN was already 134,217,728 with the
journal capped at 512 MiB. The collector entered reconciliation and independent
per-root USN catch-up skipped the same root. The run was stopped; no success
acceptance should be inferred from backend receiving other records.

The missing component was NOT a larger journal. USN source capture had to be
decoupled from file-ID re-observation and sender/network availability.

## Governed architecture

1. **One raw capture cursor per NTFS volume**, not per governed root. Multiple
   roots on the volume subscribe to one source stream. Volume identity and journal
   ID must be verified. A changed journal ID, lost history or damaged queue
   fails closed rather than rebasing the capture cursor.
2. FIUSNReader remains the privileged Windows USN I/O broker. FICollector
   rapidly reads the complete volume journal and publishes immutable, checked
   segments with atomic durable cursor updates. A low-water free-space policy,
   owner-only ACLs and local queue capacity bound are installer gates.
3. A **separate**, independently scheduled FICollector processing lane consumes
   the durable source segments. It does not gate further raw capture. It uses
   baseline-derived historical parent/directory/link evidence and ordered USN
   changes to decide governed-root membership. Files only have current
   containment evidence after reopening them: that is NOT proof of historical
   outside-of-scope membership.
4. Local scope decisions are tri-state: Governed, ProvenOutside, or Unresolved.
   Unresolved records are retained, not silently dropped. Any negative filtering
   proof must identify exact volume, journal, root, file identity including
   NTFS sequence, parent, event USN, complete historical ancestry and hard-link
   coverage. A durable, replayable historical index and negative-proof ledger
   are required before exclusions are admitted to a transport projection.
5. The observation worker independently performs **policy-required** Windows
   NTFS reads and content hashing for selected objects. It must coalesce
   repeated changes and emit actual observation timestamps. The SoR correlates
   historical identities/relationships but cannot derive missing DACL, SACL,
   ADS or file hashes from raw USN.
6. The processing lane publishes verified FI spool batches in an explicitly
   versioned **capture-only USN contract**. Source records MUST NOT be disguised
   as successful re-observations or as deleted/unavailable objects. FISender,
   C1 and SoR must understand this record contract before it is enabled.
7. Advance the independent processed cursor **only after** validated scope
   decisions, required enrichment/custody, spool finalization, spool integrity
   validation and a durable publication receipt. The sender retry and C220
   availability must not prevent continued raw source capture. Original source
   segments can only be reclaimed under a reviewed retention policy after a
   matching receipt; no source file is deleted on an incomplete operation.

## Implemented so far (branch only)

- Recovered original 2026-10-20 raw capture queue, its immutable segment
  storage, startup replay, independent capture/processing cursors, and tests.
- Added a bounded fast capture lane in the FICollector Windows code, which uses
  FIUSNReader but deliberately does not yet activate the `-service` path.
- Removed O(number-of-segments) queue directory scans from every capture batch.
- Added raw capture health telemetry fields including queue bytes, capture
  cursor, processed cursor and NTFS journal FirstUSN/NextUSN.
- Added stable volume-scoped capture identity and grouping of multiple
  configured governed roots on one volume, with journal change detection.
- Added a fail-closed local scope-decision contract. Unknown, ambiguous and
  current-path-only evidence cannot silently discard historical USN changes.
- Added durable per-segment spool-publication intents. Processing now refuses
  automatic replay if a crash leaves a publication outcome ambiguous; capture
  continues independently. A durable intent is required before recording the
  processed cursor. This is a fail-closed recovery guard, not yet automated
  reconciliation or service activation.
- Added an immutable-source-digest-bound scoped projection candidate and
  tests for retained change order and explicit rejection of unproved losses.
  This projection is NOT a sender or backend record type.

## Remaining *required* before 22B installation or end-to-end stress test

- Wire the volume-level raw worker into a reviewed, explicit versioned service
  configuration. Disable concurrent legacy checkpoint owners for the same
  stream, while preserving independent Windows Security and supporting workers.
- Implement verified baseline-to-capture anchor migration and the historical
  directory/hard-link scope index with persistent restart/replay semantics.
  A prior aged-out checkpoint is NEVER a valid migration anchor.
- Implement persistent scope-exclusion receipts, checked projection replay,
  multi-root fan-out, and observed-vs-source event time semantics.
- Implement independently scheduled selective NTFS observation work and its
  bounded, policy-governed coalescing; make capture progress independent.
- Define and integrate the source-bound scoped USN transport contract across
  collector/spool/sender/receiver/C1/PostgreSQL with matching canonical and
  relational acceptance, rejecting unknown record kinds.
- Introduce installer-managed secure queue path, capacity policy, startup
  recovery, operational alerting, rollback and immutable evidence retention.
- Test capture exhaustion, power loss at each atomic-write boundary, journal
  wrap, read-broker failure, multiple roots on one volume, hard links,
  rename/move/delete, File-ID reuse, server transport outage, tampering,
  missing spool proofs, and a stopped/restarted FICollector.
- Run native AdminBox Go build/tests plus controlled FI-free fresh install and
  measured Windows capture backlog test, then full transport and SoR proof.
  Review and accept evidence before promoting into `main`.

## Immediate operational restriction

Do not change ISS-FS-22B's live FICollector binary/configuration, existing
USN checkpoints, operation journal, capture custody or Windows journal while
this branch remains unaccepted. CI compilation is not deployment acceptance.
