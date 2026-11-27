# FI P6 — family-owned relational SQL ingestion (development)

**State 2026-11-16: first source implementation and C220 runner are committed.**
**Not yet compiled on the C220, not SQL-accepted, and not a release.**

## Why P6 exists

Accepted P5 preparation, Security/File/Coverage/USN/Other 2..16 worker
priority-fill, achieved **997,434 records in 237.995 s** (4,190.987
records/s) over two real signed W512 windows. P5 is frozen.

P6 **keeps P5 as the preparation stage** and replaces the monolithic
typed SQL handoff with independently owned family buffer and relational
ingestion modules, without sacrificing the 49-table relational schema,
13 supported record kinds, source custody, or W512 atomic commit.

## Separate, owned SoR relational modules

| SQL module | Supported source kind(s) | Existing relational contract |
|---|---|---|
| Security | WindowsSecurityEvent | Existing source parent, 40-column event, matched scopes, all event fields |
| NTFS/File | FileObservation | Volumes, NTFS objects, governed roots, file observations, metadata, hashes, ACEs, streams, nested children |
| Coverage | WindowsSecurityCoverage; WindowsSecurityContinuityGap | Policy/root coverage rows, continuity detail |
| USN | USNReadBoundary; USNObjectObservation; USNContinuityGap | Source-ordered read boundaries, exact file identity, captured changes, dependencies, nested NTFS, continuity |
| Other | CollectorIdentity; DirectoryPrincipalSnapshot; LocalPrincipalSnapshot; NTFSCollectionError; SMBShareSnapshot; SupportingSourceCollectionError | Complete principal, membership, collector, share, ACE, collection-error children |

New separate modules live under
`go/cmd/fi-backlog-recover/testdata/family-p6/`:

- `private_p6_family_buffers.go` — five owned bounded queues, signed
  source order, autonomous capacity handoffs, dependency fences, atomic
  W512 final barrier.
- `private_p6_sql_coordinator.go` — central signed source_record parent
  COPY ledger (source order is preserved), exact FK ID lookup by
  (source_batch_id, ordinal), one private SQL transaction.
- `private_p6_sql_security.go`, `_ntfs.go`, `_coverage.go`,
  `_usn.go`, `_other.go` — family-specific typed relational writes.
- `private_p6_family_buffers_test.go` — coverage of all 13 kinds,
  independent capacity handoffs, USN prerequisites, never flushing
  unrelated families, preserving signed batch order, and injected SQL
  failure/rollback gates.

## Critical source ordering

The existing USN projector resolves an earlier read boundary by comparing
`source_record_id` values. Naively giving each family its own source-row
COPY would change that identity ordering and break capture semantics.
P6 therefore has ONE shared parent `fi.source_record` ledger. All parents
are copied **in their original signed batch/ordinal sequence**; children
are then written by the appropriate family module, using an exact pair
lookup for their real SQL parent IDs.

A USN handoff may drain File first when required by an actual NTFS
identity dependency. It may NOT opportunistically empty Security,
Coverage, or Other. The family limit triggers handoffs by row/byte
capacity; *signed batch* and *K32 read chunk* are not independent flush
boundaries. An incomplete buffer finally drains only at the W512
atomic commit barrier during this first P6 experiment.

## Preserved database rules

- Exactly the existing relational projection schema (including original
  child tables, FK graph, unique constraints, source rows and type rules).
- Identical signed payload and manifests, validated record bytes and
  digests, source batch/ordinal identity, SHA reuse and recovery markers.
- Single existing private PostgreSQL writer, one outer transaction per
  W512 typed window, existing SQL durability and rollback requirements.
- P6 uses `privateProjectionTx` that rewrites only audited statements
  into the isolated `fi_recovery_projection` schema.
- No independent family commit, no authoritative SoR mutation, no
  Accepted publication, no change to canonical FI migrators.
- Family-specific child writes use *existing* FI record projectors and
  CopyFrom routines. P6 is a modular SQL orchestration rebuild first.
  Further one-pass SQL-ready child-row precomputation is a follow-on
  optimization, gated separately by relational equivalence tests.

## Matched benchmark stages

1. **P5 two-window baseline, already accepted**: signed seed
   `20261115T153532Z`; W512 windows 1 and 2; 431 signed batches;
   997,434 records; 237.995 s; SHA-verified metrics archive:
   `7f8f1fadfe8bc48529dfffc654fd08fd06aed5ac767d480a52bf99d2f52e184a`.
2. **P6 two-window candidate**: exactly the same signed seed, windows,
   transaction settings, P5 worker scheduler, 32 global preparation
   credits, 256 MiB admitted input-byte budget, one writer and
   measurements. P6 cannot be called accepted until C220 Go/race tests,
   SQL relational coverage, 5 family completion proofs, all 431 signed
   batch readbacks, clone shutdown and the original SQL integrity gates
   pass.
3. **P5 ten-window reference**: fresh private clone from the **same**
   accepted seed, windows 1–10; no P6 code selected. Obtain per-window
   record/batch totals from authenticated descriptors (never extrapolate
   the first two windows).
4. **P6 ten-window challenger**: same ten source descriptors, same source
   cache, storage/durability configuration and instrumentation. Require
   byte-identical signed manifests and payloads, 13-kind relational
   coverage, all child/FK checks and complete ten-window checkpoint
   continuity. Compare total throughput, per-window variance, queue
   handoffs, bytes, WAL, checkpoints, CPU and I/O.
5. Only after those gates: durable source-first cross-window buffers and
   multi-connection PostgreSQL experiments, with explicit transactional
   atomicity and crash/replay tests.

**Do not reuse two-window constants (997,434 records or 431 batches) as
ten-window totals.** Read and prove exact values from the signed
descriptors in each run.

## Pinned C220 test code

- P6 development branch: `experiment/fi-atomic-family-buffers-p6-20261116`
- Source, module code, tests and exact-anchor patcher:
  `6a839d8c71ade909a4d9d19c5d94fe824cb40d46`.
- Private W512 SQL test runner:
  `b26f20e08107403d71060f0d198f7db2d0277159`.
- Two-window P6 control script:
  `6cdb591fb52a3eccf8f75fa5821dedef27211ed1`.

## How P6 runs and when to stop

Run the two-window P6 controller on `root@c220` only from its
immutable Git commit. `preflight` is read-only and does not start
PostgreSQL. Run `p6` only after it passes. Actual clone mode runs
Go unit and race tests (including the new P6 tests) before copying any
PostgreSQL seed. Every rejection stops: do not bypass a failing Go,
SQL, original-signature, or foreign-key verification.

The P6 controller requires the exact accepted P5 archive/checksum
and preserves its metrics separately. Report performance only after
full P6 acceptance receipts; any Go build or relational check failure
means P5 remains the accepted baseline.

## Work still open

The modules are **written**, not yet proven to compile or run against the
live C220 seed. P6 still uses existing nested projector logic within each
module; moving all per-kind child SQL values into prevalidated, SQL-ready
preparation batches is future engineering. The accepted atomic W512
transaction requires its incomplete buffers to be drained at the
window boundary for now. A true capacity-only cross-window SQL handoff
requires a separately verified durable source-first publication model.
P5 and P6 10-window scripts are not accepted yet; they must be adapted
from the existing W512 ten-window clone benchmarks and passed through
their own preflights before use.
