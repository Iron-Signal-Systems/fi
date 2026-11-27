# FI Candidate A — isolated W512 / 2 GiB window experiment

**Status:** development design and planner-test staging only; **NOT** an executable W512 benchmark, acceptance, or release authorization. 2026-11-13.

## Baseline and precise requested change

The accepted, pinned Candidate A W128/K32/P3/F3 experiment completed the original
signed W3–W12 test: 566 batches, 1,297,765 newly committed records, exactly
10 durable W128 transactions in 438.824 seconds; SQL integrity and signed-byte
readback passed, with 0 authoritative and 0 Accepted writes.

Experiment B changes exactly the **outer transactional recovery window**:

- **W512** = maximum **524,288 original source records**, maximum **2 GiB
  original signed source-data bytes**. The first bound reached closes a
  window; never split an authenticated original source batch.
- Keep the **K32 = 32,768-record input processing unit**, the independent P3
  Security (4,096 rows/16 MiB) and F3 File (8,192 rows/32 MiB) buffer limits,
  the other bounded dependency/coverage buffers, and the 2 preparation workers,
  4 in-flight records, **one original ordered PostgreSQL writer**, strict
  Security JSON, signed-source and per-record SHA-256 rules.
- Keep atomic source+typed SQL commit per **entire W512 window** and private
  field-partition attach/verification before the typed marker; **no cross-window
  deferred typed records**. This does not implement continuous family
  transactions.
- Keep original PostgreSQL durability settings (fsync, synchronous_commit,
  full_page_writes), 1 GiB max_wal_size, 4 MiB wal_buffers, and collect
  WAL/checkpointer/IO stats. A 1 GiB max_wal_size is a checkpoint trigger, not
  a hard cap on WAL written by a transaction.
- No authoritative SoR writes, publication, Accepted outcomes, Windows code,
  or active working-tree modifications.

## Separate future steady-state ingest time bound

This W512 **backlog replay experiment is size-bound**, not a redesign of
normal ingest scheduling. If a W512 window policy is later evaluated for
low-volume steady-state sources, the proposed initial time bound is **15
minutes from the first still-uncommitted record**, in addition to the
524,288-record and 2 GiB limits. Any one of these boundaries closes a
window. Never reset this deadline when new records arrive; otherwise a busy
but under-capacity source could defer its oldest records indefinitely.
Urgent security visibility may require stricter application-specific
durability/processing limits. The established signed generation interval
is a separate collection cadence, not a reason to force empty typed buffers
to flush. Time-bound behavior is **not implemented by this seed-only runner**.

## Hard incompatibilities: do not change flags in the W128 runner

The existing CLI only accepts W32/W64/W96/W128; it gates K32, verified-cache
resume, field partitions, mixed/dependency buffering and the Candidate A
context specifically to W128. The continuous-private input validator rejects
source-window data limits larger than 1 GiB. Multiple test/fixture messages and
exact-stop checks assume W128. All must be audited, adjusted **only inside
disposable source overlays**, and independently tested before any replay.

Most critically, the accepted historical seed is three **W128** checkpoints
(3|390387|2), with descriptor hashes, field partitions and SQL rows indexed
under that window plan. W512 produces a *different immutable signed
descriptor chain*. **Never** restore those committed W128 rows as the W512
prefix and never relabel W128 checkpoint indices as W512.

Create a new isolated PostgreSQL cluster and **fresh W512 seed using
authenticated original signed batches**, or a separately verified cache-based
seed construction with exactly equivalent receipt/manifest/digest/SQL proofs.
No loss of signing trust, typed identity, source-batch ordinal, or dependency
ordering is acceptable.

## Required staged acceptance sequence

1. Pure deterministic planner: W512/2GiB caps, whole signed batches, count
   and byte precedence, exact receipts, duplicate rejection and descriptor
   continuity; retain all earlier W32–W128 behavior unchanged.
2. CLI and source gates: only disposable W512 profile permits 2 GiB windows;
   no relaxation of authoritative or ordinary modes, single writer, signed
   verification, size bounding, cancellation, rollback or original H16 source.
3. Fresh W512 private seed: original signed receipt and all 8,399 batch
   identities verified, source/index/SQL prefix agree, every descriptor
   SHA matches the W512 planner, no inherited W128 checkpoint rows.
4. Real signed **short pilot** with at least two W512 commits, exact relational
   projection and source identity readback, independent Security/File/
   coverage/USN route evidence, zero published/canonical/Accepted changes,
   error-path rollback proof and complete sampled host/PG telemetry.
5. Only then approve an expanded W512 sample. Compare **throughput across
   matched original signed record/batch ranges**, not "10 W512 vs 10 W128":
   W512 windows carry up to roughly four times the record work. Report
   records, signed bytes, record-type composition, SQL COPY calls, partial
   boundary flushes, WAL/checkpoints, RSS, window p95/mean and total elapsed
   excluding seed/provisioning, with actual observed denominators.
6. Repeat a pinned W128 control on the same host and settings if environmental
   drift makes historical 438.824-second comparison ambiguous.

## Performance hypothesis and risk

At P3 capacity, each approximately 116K-Security-event W128 window already
requires about 29 full/partial COPY calls. Raising the outer window can remove
some **end-of-window** drains, but it does not change the small, independent
P3/F3 capacity or true dependency barriers. Therefore do **not** predict
a 4x gain. Bigger transactions also increase potential rollback work,
recovery time, partition-attach cost, WAL and storage pressure. Enforce clear
private-space and safe-abort gates.

## Workflow

GitHub **experimental branch** -> operator SSH to **fi-dev** for a pinned
fetch, builds and tests -> operator SSH to **fi-backend-b** for verified
private-only execution. Preserve the original W128 Candidate A commit
cda074bbb8b007009af57aca9c6ba61ff765d85b and its diagnostic artifact.

**Do not run a W512 replay from this design-stage branch.**
