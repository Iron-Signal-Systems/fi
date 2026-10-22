# FI USN durable correlation cache — M2 (2026-10-20)

**Status: implemented inactive correlation foundation; NOT installed or enabled.**

M1's complete volume-wide source batches and capture checkpoint remain authoritative for
what NTFS journal history was durably captured. M2 adds a *separate*, checksummed,
immutable correlation-work cache for each captured segment, under that same queue root.
M2 does not change the currently installed FICollector, existing `root-*-usn.json`
checkpoint, NTFS re-observation, verified FI spool, sender, receiver, installer, or
Windows service scheduler.

## Data and custody boundary

1. `Store.CorrelateNext(governedRootIdentity)` reads the oldest still-unprocessed
   M1 segment and verifies the underlying source batch and index.
2. It creates `correlation-batch-<startUSN>.json` with one work entry per
   **distinct full NTFS File-ID plus sequence-number identity**, while retaining
   all of the event USNs and all distinct observed parent IDs.
3. The artifact records a SHA-256 of the source batch and a SHA-256 of the
   entire derived correlation payload. Replay recomputes expected results from
   the verified source batch. A mismatched root, mutated data, corrupted checksum
   or different derived work fails closed; nothing is replaced silently.
4. M1's queue budget now counts **both** source batch files and correlation
   files. Cache-capacity exhaustion blocks correlation/reading rather than
   changing `capture.json`, `processed.json`, or FI's old checkpoint.
5. The result is recoverable after restart and **does not move** `processed.json`.
   The verified FI spool publisher must later own that advancement.

## Safe scope hints, NOT final membership classification

M2 does not equate a current parent path to historical scope. It publishes only:

- `DirectParentObserved`: a particular source USN record named the configured
  root File ID as its parent (or named the root object itself). Only those exact
  event USNs are identified as direct source facts in `direct_usns`.
- `PossibleAncestry`: there exists an observed parent chain **within the bounded
  captured segment**, but timing, moves, hard links, deletion and parent
  identity history have NOT been verified. This is only a priority hint.
- `Unresolved`: no relationship is established from these bounded source facts.

**There is deliberately no `Outside` classification** and no fast-path
record drop. Every distinct object (including possibly out-of-scope ones)
continues to the later authoritative correlation stage, and every individual
source USN record stays in the M1 segment. An MFT file reference with a different
NTFS sequence number is a different object: it cannot inherit the previous
object's ancestry. Cycles don't imply root membership.

## Tests

The additional tests cover direct-child source facts, objects later moved out,
multiple parent IDs/hard links, distinct sequence-number identities, possible
ancestry, unreachable cycles, crash/restart idempotence, root conflicts,
checksum tampering, valid re-signing with unexpected payload, unchanged
processing checkpoint, and shared disk-budget exhaustion. The M1 tests continue
passing on the isolated sandbox. Native Windows full-suite acceptance is still
required on ADMINBOX.

## Required for M3 before activation

- Build a trusted, time-aware governed-root ancestry resolver seeded by validated
  baseline identity/parent-binding observations, with move/rename/delete,
  hard-link and File-ID reuse behavior. Historical uncertainty remains explicit.
- Connect a work consumer to existing bounded File-ID observation workers,
  `USNReadBoundary` source records, durable FI spool manifests and fail-safe
  support-SID updates. Do not manufacture journal operation timestamps on replay.
- Replace M1's caller-supplied string `publishedProof` with proof of a verified
  FI spool/manifest transaction (and a verified no-governed-work decision).
- Introduce a migration gate from the old USN checkpoint, coordinated with the
  existing per-root locks and reconciliation, and test mid-baseline journal wrap.
- Add installer config/permissions, operations telemetry and matching binary
  validations. Stop safely when source queue storage cannot keep up.
- Validate on ADMINBOX, then separately approve any deployment on ISS-FS-22A.

**No automatic data loss or gap healing:** an already-aged-out live USN checkpoint
cannot be repaired by installing M1/M2; keep the original continuity-gap record
and perform a validated rebaseline under the old FI process before migration.
