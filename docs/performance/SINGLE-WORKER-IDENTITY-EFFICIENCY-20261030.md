# FI single-worker relational-ingest efficiency — 2026-10-30

## State and acceptance scope

This change is a **single-worker efficiency correction**, not an acceptance of
same-source parallelism, bounded generation transactions, or the interrupted
20-million-file acceptance run.

The production `fi_ingest_worker` and Windows sender were stopped by the
operator before this development branch was created. Do not restart or deploy
this branch without separately passing the isolated and production-readiness
gates below. Immutable receiver receipts, READY discovery, the PostgreSQL
source-of-record, and accepted generations must not be cleared or reset.

Evidence from PostgreSQL 18.6 on 2026-10-30:

- `iss-fs-22a.iss.local`: 54,027,695 committed source records across 2,324
  accepted generations before interrupting the next generation.
- The twelve earlier 2026-10-29 generations were all committed.
- `20261030T000032.061323100Z-3e38b2210771462c` has an immutable receipt
  with 15,140,785 records, 8,399 batches, and 65,211,978,577 canonical bytes.
  Its prior transaction was rolled back on an operator-requested clean stop.
- PostgreSQL statement counters since 2026-10-18: 30,790,827 individual
  `SELECT fi.ntfs_object` calls and 27,993,637 individual INSERT calls; these
  counters include older software versions and cannot establish the current
  per-generation rate by themselves.
- The content-hash COPY path accumulated 13,258.6 execution seconds, 8,300.4
  seconds of shared-block read time, and ~258 GiB statement-attributed WAL.
  It is a separate measured cost; this change does not claim to fix it.
- One telemetry `SELECT json_build_object(...)` accumulated ~286 GiB temporary
  writes over ~5,600 calls. That query must be optimized independently.
- The SOR had `shared_buffers=128MiB`, `wal_buffers=4MiB`,
  `max_wal_size=1GiB` when sampled. No server settings change here.

## Identified implementation defect

`ntfsObjectCacheMaxEntries = 262144` bounds a generation-scoped NTFS
identity cache. The previous prefetch logic stopped adding uncached identities
to its batch query when `len(cache.objects)` reached that threshold.
`ensureNTFSObject` then performed individual SELECT/INSERT/re-SELECT database
operations for uncached identities, indefinitely, even when the subsequent
input could otherwise be handled in set-oriented batches.

This is an *actual code-path defect* for generations with more distinct NTFS
identities than the cache can hold. The live production query counters support
investigating it but do not uniquely quantify its contribution without an
equivalent-workload replay.

## Correction

- Keep the cache bounded to 262,144 entries, using a fixed-size FIFO
  insertion-order ring to replace old entries with new ones.
- Do not evict when remembering an already cached key.
- Preserve method-version conflict checking and source/volume identity
  isolation. Cache evictions only change lookup costs, not database authority.
- Continue to include every missing identity in the existing 512-identity
  PostgreSQL batch prefetch. Saturation must not silently switch to a
  per-identity query loop.
- Preserve the original single-generation transaction, batch order,
  foreign-key parent ordering, and rejection/rollback semantics.
- Do **not** increase worker concurrency as part of this correction.

## Acceptance gates

1. Run `cd go && go test ./internal/recordingest -run 'TestNTFSCache|TestNTFSIdentityPrefetch|TestCanonicalNTFSIdentity' -count=1 -v`.
2. Run `cd go && go test ./...` and the FreeBSD compile gates.
3. Run the isolated `fi_ntfs_identity_prefetch_integration` test with its
   required explicitly isolated PostgreSQL environment. Do not run against the
   live FI source-of-record database.
4. Reproduce a workload with >262,144 **distinct** NTFS identities; compare
   pre- and post-change runs with identical input, hardware, PostgreSQL
   configuration, and warm/cold cache conditions.
5. Record: worker wall-clock time; source records/sec; memory peak; cache
   hit/miss/eviction observations; PostgreSQL per-query call counts and
   time; WAL; shared reads; COPY-call timing; rollback/replay results.
6. Verify no duplicate authoritative rows, no method-version conflict
   suppression, no unexpected identity ordering changes, and exact
   receipt/record/accepted-generation reconciliation.
7. Retain the change only if measured efficiency and resource usage improve
   without correctness regression. No broad deployment or throughput acceptance
   is claimed by a unit-test pass alone.

## Separate, ordered follow-ups

1. Profile content-hash COPY: FK checks, index maintenance, relation reads,
   WAL/checkpoint behavior. The two nullable hash indexes were observed with
   zero index scans since the statistics window began, but do not drop indexes
   without validating the query contract and a supported migration.
2. Replace the telemetry query's expensive all-source aggregation/sorts with
   bounded current-generation lookups. Its ~286 GiB temp writes are not an
   acceptable ongoing observer overhead.
3. Benchmark PostgreSQL memory, WAL and checkpoint settings *after* fixing
   unnecessary relational work, one change at a time.
4. Only after a stable single-worker baseline, design bounded, recoverable
   same-source work units and variable parallelism without compromising
   custody, ordered replay, or generation-level acceptance.
