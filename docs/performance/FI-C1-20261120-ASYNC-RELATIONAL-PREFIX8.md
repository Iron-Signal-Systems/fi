# FI C1 – Independent read-only relational verification / 8 GiB development gate

Date: 2026-11-20. Status: **unreleased C1 development candidate — untested on C220**.

## User architecture

The continuous FI stream (signed custody → P5 adaptive family preparation → P6 persistent family buffers → source-parent and five relational SQL lanes) must not be serialized by separate *read-only* relational reconciliation. **PostgreSQL COPY/COMMIT, ordered source-parent ACK, and File-before-USN prerequisites still require their existing causal guarantees**. Independent reconciliation must not advance Accepted, publish, or replace a transactional dependency.

## Changes in this branch

- Original per-batch signed SHA-256/manifest/framing/ordinal checks remain.
- A **single Go background verification worker**, separate from the ingest thread, owns a distinct **read-only PostgreSQL clone connection**. This is not yet a separately managed OS service.
- The signed reader emits a bounded group-sealed signal only after the group's final original batch passes integrity checks.
- The worker checks source row count/bytes and missing typed roots via existing unchanged functions using a repeatable-read transaction. If P6 SQL for the group is still pending, the worker retries. It never marks an incomplete group successful.
- After P6's original five-family SQL barrier passes, the worker must report one proof for every sealed group. Any mismatch fails closed before typed-window markers can advance.
- **The original final transactional counts, coverage scans, and typed markers are unchanged in this first experiment**. A later separately approved optimization could remove duplicate scans only after equivalence is demonstrated.
- No independent 4 GiB crash-safe restart/resume is introduced.

## Short-run acceptance – first 8 GiB only

The runner mode `prefix8` chooses exactly two **4 GiB groups** from the original signed W512 backlog, using the existing canonical grouping routine. The cutoff is comprised only of whole original signed batches; no hash/record/byte/ordinal checks are relaxed. It will not read the remainder.

Required evidence:
1. Go build and race tests PASS before PostgreSQL clone startup.
2. Fresh private PostgreSQL clone; unchanged original seed (493,478 records); live ingest stopped.
3. P5 continuous signed-stream receipt (`sessions=1`) and **two** signed group-seal receipts.
4. **Two** read-only asynchronous relational group PASS receipts. Compare `phase=during_ingest` and `phase=after_drain` to determine whether proof can complete before P6 finishes; no speedup is assumed.
5. All required original P6 family/source SQL ACKs; source/child count equality.
6. Exactly **three** typed-window rows (original seed + two newly verified groups); correct signed byte and record sums; no other typed markers or complete generation claim.
7. Canonical published rows=0, Accepted journal rows=0, source/artifact markers still seed-only.
8. Automatic host/ZFS/CPU telemetry started **before** SQL processing and finalized on success/failure.
9. A prefix-only proof clearly states `full_generation=false`; never represent a controlled `context.Canceled` prefix return as a completed generation.

To run on C220, use the pinned controller from this branch. Execute `compile` first, then `prefix8`. Only after 8 GiB passes should a separate full-run `c1` experiment be considered. Do not promote either result to the authoritative SoR.
