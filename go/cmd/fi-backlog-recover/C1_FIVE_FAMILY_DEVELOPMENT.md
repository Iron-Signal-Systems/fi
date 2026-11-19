# C1 — five-family FI ingestion (development only)

## Name and scope

**C1** is the current **unreleased development** integration of the original
P5 and P6 work. It is not a version, release, promotion, or production
acceptance statement. Do not label earlier tests as released or accepted.

## Invariants being implemented

1. **P5 preparation:** five independently scheduled pools (Security,
   NTFS/File, Coverage, USN/Dependency, Other); 2–16 actual workers per
   family, bounded global inflight admission and original signed-byte
   verification.
2. **P6 family buffers:** one bounded buffer per family. Hand off a completed
   buffer as soon as its own row/byte capacity requires, or for a genuine
   File-to-USN dependency. Never flush another family because a signed
   batch, read chunk, or W512 reporting window ended. At true end of input,
   drain the remaining partial buffers once.
3. **SQL:** five persistent family-specific connections and SQL modules
   (one per family) plus one separate *ordered source-parent* connection.
   Preserve source-batch/ordinal identity rather than SQL-ID assumptions;
   retain every original relational projector, source FK, child COPY, check,
   and unique key. File SQL commit becomes visible before a dependent USN
   writer starts. The source ledger writer is not a sixth *family* writer.
4. **Data:** original signed cache and manifest readback; 13 record kinds;
   49-table relational source model; no second source staging, duplicate
   signed payload store, additional source artifact copy, or canonical
   fi.* writes.
5. **No premature checkpoint:** the contiguous typed-window marker can
   advance only after five family SQL writers have finished, each family
   count matches the original signed parent count, and the existing SQL
   relational checks have passed. Do not publish authoritative or Accepted
   outcomes.

## Current engineering state and explicit limitation

The C1 development path is implemented under `testdata/c1`, and a
C220-only disposable-clone controller runs it against the authenticated
W512 source. **Five independently committing PostgreSQL connections
cannot give all-family ACID atomicity across six sessions.** Source/typed
rows may remain on an interrupted private clone with *no completed typed
checkpoint*. The implemented C1 clean-start guard rejects any retry
against that dirty clone, instead of silently duplicating or skipping
partial rows. The C220 harness creates a fresh private clone from the
unchanged verified seed for the next attempt.

This **does not yet implement in-place transactional crash replay for an
authoritative production SoR**. That remains development work. Do not use
this path on the canonical FI database.

## Built code

- `testdata/c1/private_c1_direct.go` — original P5 signed streaming into
  the persistent P6 buffer set and clean-destination SQL guard
- `testdata/c1/private_c1_family_buffers.go` — five capacity-driven
  buffers, File-to-USN prerequisite and final-only drain
- `testdata/c1/private_c1_five_sql.go` — five independent family SQL
  modules/sessions, source parent and barrier; optional File post-commit
  failure injection restricted to C1 private development
- `testdata/c1/private_c1_modules.go` — original P6 Security, NTFS,
  Coverage, USN and Other relational projectors
- `testdata/c1/private_c1_cached_recovery.go` — private C1 selector
- `testdata/c1/private_c1_direct_test.go` and
  `testdata/c1/private_c1_correctness_test.go` — signed source, P5 worker
  persistence, buffer independence, capacity, dependency, FK and failure
  guard tests

## C220 development gates

The preflight and compile stages do not copy or start PostgreSQL. Both
run only in fi-dev with pinned source code and the verified historical
W512 seed. The compile stage runs original Go tests, the Go race detector,
and the actual FreeBSD build against the isolated C220 optimized source.

- `preflight`: source/seed, trust, filesystem and original P5/P6 proof
- `compile`: full C1 Go/race/build, no PostgreSQL started
- `c1`: two-window signed replay; 431 batches, 997434 original records,
  five SQL family writers plus one ordered source writer, all relational
  checks, five family completion and clean clone shutdown
- `inject-file`: development-only File SQL commit succeeds but C1
  deliberately fails *after* commit; verify zero new typed-window markers
  and dirty-clone quarantine, then stop and discard that clone

C1 must retain original signed data, not overwrite the original source
seed, and must never run while the live FI ingest worker is active. Do not
bypass a failing check or modify PostgreSQL roles, grants, indexes, or
canonical FI tables to make the experiment pass.

## P5/P6 continuous handoff improvement (C1 development)

C220 two-window C1 observation: 997434 signed records in 304.735 seconds
(~3273 records/sec), with five independently committing family SQL lanes.
P5 and P6 are the original development architecture foundations, not
comparison candidates to promote or release.

The first C1 throughput correction retains the **P5 five-family priority-fill
preparation**, **P6 per-family capacity/dependency buffers**, and **five
dedicated PostgreSQL family SQL lanes**. Previous SQL backpressure forced the
signed-source reader to wait for *every* one of the four outstanding family
handoff acknowledgments whenever that family reached its four-buffer bound.
This created a burst/drain cycle and could leave a family SQL worker idle.

C1 now retires **only the oldest completed SQL handoff** when a family has
four outstanding buffers and immediately enqueues the next capacity handoff.
Unrelated families remain independent. File-to-USN dependencies still use the
full File family SQL acknowledgment fence, and the final completion barrier
still awaits all five family writers. No extra SQL writers, source
materialization, COPY-envelope changes, buffer capacities, schema or
permissions are introduced. Failure still stops admission, and no typed
checkpoint may advance after a failed SQL ACK.

C1 Go/race regression tests cover oldest-only admission, in-flight bound,
FIFO ordering, error propagation, cancellation, and the full dependency
fence.

## Second direct P5/P6 correction — ordered parent SQL must not stop preparation

Code review found that the signed reader was executing each ordered
source-parent PostgreSQL COPY synchronously while the five family SQL lanes
were otherwise asynchronous. C1 now has one *bounded, ordered* source-parent
queue (four handoffs maximum) and its original dedicated SQL connection.
Each family job waits on a broadcast completion fence for the exact latest
committed parent set it needs. This happens in its SQL worker, **not** in
the shared P5 preparation consumer. The one oldest source ACK is retired
only when the four-handoff limit is reached. Source identity, parent-first FK
visibility, and File-before-USN are unchanged. No extra data store or SQL
connection is created.

In addition, the Security family already resolved every parent ID from its
signed batch and ordinal before invoking original P6 Security bulk COPY.
A C1-only context passes those verified IDs into the original COPY code,
avoiding its duplicate SQL FK lookup; P5, P6 and normal FI retain their
original lookup. SQL row values, copy targets, FKs and field children remain
unchanged.

**These are code changes, not C220 performance results.** The exact C220
compile/race gate, signed two-window data and FK proof, five-writer replay,
post-File-commit failure injection, and ten-window continuity still must be
run; exact same-database recovery is not yet implemented. The C220 test runner writes `C1_CONTINUOUS_FAMILIES.txt` with
`backpressure_waits` and `backpressure_wall` for all five families.

**A speedup is not yet claimed.** A complete C220 signed two-window replay
must pass the same data and SQL integrity checks and the File post-commit
fault test. Judge improvement against the 304.735-second C1 starting run,
not against a new architecture or unrelated COPY tuning. The original
Security relational field COPY remains a likely throughput limiter after
removing unnecessary ACK-drain gaps.

## Remaining work

After the full C220 build and two-window/fault-injection checks pass,
extend the C1 development implementation to exact same-database
idempotent/crash restart (without duplicate payload staging) and
10-window continuity. A green CI syntax check is **not** a C220 runtime
test. All work remains development.
