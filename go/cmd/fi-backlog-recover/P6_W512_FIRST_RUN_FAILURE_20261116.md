# FI P6 — first C220 two-window replay rejection (2026-11-16)

**State: FAIL — window 1 did not commit or pass relational acceptance.**
Keep accepted P5 as the control. This is an isolated development SQL clone;
do NOT publish this candidate or bypass the failing validation check.

## Proven run inputs

- P6 branch: `experiment/fi-atomic-family-buffers-p6-20261116`.
- Tested exact controller pin: `6cdb591fb52a3eccf8f75fa5821dedef27211ed1`.
- Private pinned source: `6a839d8c71ade909a4d9d19c5d94fe824cb40d46`.
- Original signed seed: `20261115T153532Z`; target windows 1 and 2.
- Failed private clone outputs: `/var/tmp/fi-window-chunks-family-p3-20261116T221554Z`.
- Failure after 121.04 seconds: `FI typed window: FileObservation validation count mismatch source=0 reused=0 expected=52519`.
- Runner reported `FI W512 PILOT FINISHED exit=1`, clean PostgreSQL shutdown and `original_seed_unchanged=true`.

## What passed / what did not

- Read-only signed source, trust paths, exact-anchor audit (22 edits, 6 files), P5 test/report preflights and P6 source overlay/build passed.
- The private runner reached P6 SQL processing and emitted all five family accounting receipts for window 1:
  - Original signed source ledger: **499,052** parent records / 127 COPY handoffs.
  - Security: **446,275** rows / 112 handoffs (111 capacity, 1 final).
  - NTFS/File: **52,519** rows / 8 handoffs (7 capacity, 1 final).
  - Coverage: **206** rows / 1 final handoff.
  - USN/dependency: **52** rows / 1 final handoff.
  - Other: **0** rows.
- `FI P6 WINDOW READY window=1 source=499052 typed=499052` is the **P6 buffer's own count**, not a committed SQL or full relational acceptance.
- The existing typed-window validator rejected before first W512 commit. Window 2, signed byte-identical readback, FK/schema queries and end-to-end performance **were not accepted**.

## Engineering diagnosis — not yet confirmed as the sole cause

P6 introduces a new direct family handoff from the prepared record loop;
this bypasses the older FileObservation writer path in the C220 optimized
seed. That seed has specialized FileObservation validation and validated-
observation reuse tracking. The P6 NTFS module calls `ntfs.ValidateObservation`
and the P5 worker also validates observations, but **neither establishes**
the original optimized seed's source/reuse counters. Consequently its
existing exact ledger reports `source=0 reused=0 expected=52519`.

The fix must find the original seed counter-increment/provenance path
and rejoin it with P6's signed parent identity and validated NTFS
observation. **Do not set counters to expected totals, fake validation
receipts, skip `validated.observation`, or weaken foreign-key checks.**
Also verify that the P6 module's validation covers all constraints of
the optimized seed validator before designating a source record reused.

## Required next evidence

Read only the original C220 seed validation code. Helper (no database,
no source changes):

`go/cmd/fi-backlog-recover/diagnostics/read_p6_file_validation_c220.sh`

After reviewing its output:

1. Implement a private P6-only validation bridge using the seed's
   **actual** verified NTFS FileObservation path and signed source IDs.
2. Add unit/race tests for exactly-once source/reused validation evidence
   across capacity handoffs and signed batch boundaries, including a
   poisoned/invalid payload, duplicate signed ordinal, and rollback.
3. Pin new source, runner, controller and preflight; leave failed P6
   version intact as an audit record and keep accepted P5 unchanged.
4. Only then rerun the two-window P6 experiment. Require all original
   SQL, 13-kind typed parent, child/FK, signed data/manifest, checkpoint
   and private shutdown gates before discussing elapsed time.

The matched P5/P6 ten-window benchmark remains blocked until P6 passes
its real two-window relational acceptance.
