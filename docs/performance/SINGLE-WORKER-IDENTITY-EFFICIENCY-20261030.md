# FI: single-worker SQL efficiency, controlled first change

**Development state: NOT ACCEPTED for deployment.** Local source patch only.

## Evidence and scope (October 30, 2026)

The FI FreeBSD receiver holds the immutable receipt for source `iss-fs-22a.iss.local`, generation
`20261030T000032.061323100Z-3e38b2210771462c`, with 15,140,785 source records,
8,399 source batches and 65,211,978,577 canonical bytes. An interrupted ingestion transaction
was cleanly stopped and rolled back. At the stopping point the SOR contained 54,027,695
committed records from that source, including the previous 12 accepted generations.

PostgreSQL 18.6 `pg_stat_statements` history began October 18, 2026 and mixes old and new
FI executable versions. Its cumulative measurements included:

| Statement | Calls | Execution seconds | Read seconds |
|---|---:|---:|---:|
| `COPY fi.content_hash_observation` | 23,957 | 13,258.6 | 8,300.4 |
| `COPY fi.windows_security_event_field` | 58,992 | 8,412.4 | 285.6 |
| `INSERT fi.file_observation` | 16,854,337 | 7,688.6 | 3,738.3 |
| `INSERT fi.ntfs_object` | 27,993,637 | 5,951.9 | 3,251.1 |
| `SELECT fi.ntfs_object` | 30,790,827 | 4,680.4 | 2,993.2 |

A separate telemetry `SELECT json_build_object(...)` had written approximately
286 GiB in temporary files across ~5,600 calls. This is a follow-up, not fixed here.

## Demonstrated source-code defect

The generation-scoped NTFS object cache had a fixed 262,144-entry maximum. In the
existing `prefetchNTFSObjectIdentities` code, saturation caused all additional
uncached identities to skip set-oriented 512-row prefetch and fall through to
per-identity `ensureNTFSObject` SQL. Large generations could therefore perform
millions of unnecessary database round trips despite having a batching path.

## This patch

- Retains a bounded 262,144-key cache with FIFO replacement, not unlimited growth.
- Allows missing identities to continue through bounded 512-row set-oriented
  prefetch after saturation.
- Keeps existing PostgreSQL uniqueness, conflict checking, transaction, custody,
  batch-ordering, and parent-before-child rules intact.
- Adds an eviction count to `INGEST NTFS CACHE` logs.
- Adds a post-saturation Go unit test and an isolated-database integration test.

No DB DDL, PostgreSQL configuration, production service lifecycle, sender,
receiver, or Git refs are modified. No parallelism or generation splitting is
claimed by this change.

## Mandatory local acceptance gates

1. Confirm local branch is not `dev`, `main`, or `master` and no modified target files.
2. Run `python3 apply_local.py --check /home/jwood/src/fi` from the staged package.
3. Run `python3 apply_local.py --apply /home/jwood/src/fi` locally in `fi-dev` only.
4. `gofmt -w` the five changed `.go` files, `git diff --check`, and review every diff.
5. Run focused Go unit tests, full Go suite, `go vet ./...`, and local FreeBSD builds.
6. Run isolated PostgreSQL integration under the explicitly isolated test environment
   `FI_IDENTITY_PREFETCH_TEST_*`; do **not** run against live `fi-sor-db`.
7. Run a same-input, same-hardware one-worker baseline comparison above 262,144
   distinct NTFS identities and inspect cache evictions, identity SQL calls,
   per-stage times, memory and I/O. Acceptance needs measured improvement and
   unchanged relational correctness/replay behavior.
8. Validate sender custody, absence of duplicate authoritative records, error
   handling, ordering and rollback before any deploy/commit/push.

## Next prioritized work, explicitly outside this patch

1. Investigate content-hash COPY's substantial FK/read cost and WAL with focused
   staging replay. The existing MD5/SHA256 indexes had zero observed scans in
   the statistics window but **must not** be dropped without requirements,
   workload verification, a reviewed migration, and rollback plan.
2. Optimize the telemetry mega-query causing 286 GiB temporary writes, including
   expensive global aggregation and sorting every sampling interval. Preserve
   all mandatory monitoring fields without doing full-history analytics in a
   15-second collection loop.
3. Benchmark WAL/checkpoint and shared-buffer settings after removing avoidable
   SQL work; measure each change individually.
4. Only after efficient one-worker acceptance: design dependency-safe and
   independently recoverable bounded units, then test variable same-source
   concurrency on equivalent replay workloads.
