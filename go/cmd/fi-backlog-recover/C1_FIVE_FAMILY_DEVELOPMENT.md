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

## Remaining work

After the full C220 build and two-window/fault-injection checks pass,
extend the C1 development implementation to exact same-database
idempotent/crash restart (without duplicate payload staging) and
10-window continuity. A green CI syntax check is **not** a C220 runtime
test. All work remains development.
