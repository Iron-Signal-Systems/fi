# FI hash COPY / digest lookup candidate — 2026-10-30

## Contract

Single-worker efficiency first. No production database changes, no service
restart, no GitHub writes, and no concurrency change are authorized by this
benchmark. The existing single-generation transaction is NOT accepted at
15-million-record scale and is not modified by this gate.

## Evidence prior to this gate

Production PostgreSQL 18.6 statement statistics accumulated 23,957 content-hash
COPY calls, 13,258.6 seconds execution, 8,300.4 seconds shared-block read time,
and ~258 GiB statement-attributed WAL since the statistics reset window. The
content-hash SHA-256 and MD5 B-tree indexes accounted for 30,268,981 and
26,226,742 cumulative index block reads; both had zero recorded index scans.
Counters are cumulative, not a controlled experiment or single-generation
attribution. FI's product contract requires direct digest equality lookup,
so zero scans are not grounds to remove the indexes.

A previous same-host 2-million-row isolated `INSERT ... SELECT` microbenchmark
measured 54.312s for the B-tree variant and 24.894s for the hash-index variant,
with a 9.844s PK-only control. It *did not* enforce the production foreign key
or exercise binary `pgx.CopyFrom`; it was not sufficient to approve a migration.

## This gate

Tagged test: `go/internal/recordingest/hash_copy_index_gate_integration_test.go`

- Exact isolated PostgreSQL 18 fixture `/home/jwood/fi-prefetch-20261030.CTwtoA`
  on Unix socket `55442`, with live address disabled and `jwood` + `fi_ingest`
  role verification. Refuse all other endpoints/roots; no writes to `fi.*`.
- One newly named disposable schema with `LIKE fi.content_hash_observation
  INCLUDING CONSTRAINTS` and explicit identical primary-key and FK dependency
  shape, referencing a dedicated synthetic parent table. *Not* the full signed
  generation, production `file_observation` or a copy of the production DB.
- Compare existing partial MD5/SHA-256 B-trees against partial hash indexes and
  a PK-only control, with 1,000,000 identical synthetic `Present` observations
  per trial by default, up to 1,000,000. All source hashes are precomputed
  before timed ingestion. Two opposite insertion orders: B-tree → hash, then
  hash → B-tree. Each trial starts from an empty table.
- Real `pgx.Tx.CopyFrom` calls of <=1024 rows, matching the production row
  bound (payload size here is below 2 MiB). One transaction per trial.
- Confirm exact inserted count, duplicate MD5/SHA-256 equality results,
  actual planner use of expected digest index, two non-Present nullable states,
  FK violation rejection, and deliberate transaction rollback.
- Record execution wall time, rows/sec, COPY calls, relation index sizes, and
  WAL-counter deltas (WAL statistics can lag). Do not treat one run as a
  publishable throughput prediction or a full end-to-end ingest comparison.
- Test schema is removed by the tagged test's cleanup, and the fixture is
  stopped only when the local runner started it. Logs persist.

## Acceptance still outstanding after a passing gate

1. Query-contract review for MD5 and SHA-256 (equality versus other operators,
   partial predicates, planner choices, and any index-only/range requirements).
2. Full signed/verified generation replay with the candidate indexes present
   in an isolated FI database. The current tagged test is deliberately narrower.
3. Mixed file/security/USN record types and realistic index/data scale; compare
   repeated equivalent runs with CPU, memory, WAL, ZFS/PG waits recorded.
4. Production-governed forward migration with space and index-build monitoring,
   explicit checks that two candidate hash indexes are valid, then a separate
   *reviewed* cutover of the original B-trees. No old-index DROP is provided as
   part of this acceptance package.
5. Reversible rollback and generation custody/reconciliation verification.

## Migration candidate policy

`migration/01_create_candidate_only.sql` adds candidate hash indexes
CONCURRENTLY but deliberately retains both originals. It is *not* invoked by
`run-fi-dev.sh` and must not be run on production without explicit approval.
`migration/02_readonly_candidate_verification.sql` reports index readiness.
`migration/03_rollback_candidate_only.sql` drops **only** the proposed
candidate indexes; the current B-trees are untouched.

Both concurrent DDL commands run outside transaction blocks, per PostgreSQL 18
requirements. No production tuning or system-level changes are included.
