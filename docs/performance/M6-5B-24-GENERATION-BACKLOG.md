# M6.5B — 24-Generation Backlog Acceptance

## Status

**PASS — actual FI ingest-worker, isolated 24-generation backlog**

Date: 2026-10-25

Repository baseline:
`bf58e6852046f67941585c1886f7d98ffb6565d2`

Worker binary SHA-256:
`390adb44307734d076446d4ca8af0ec493e8807f9576eaf7715483a65f79625a`

## Objective

Measure FI ingest-worker backlog-drain throughput, cumulative PostgreSQL
growth, WAL activity, and authoritative per-generation relational correctness
using a large set of real, immutable signed Windows generations.

This is an **accelerated backlog drain** campaign, not a four-hour
normal-arrival stability acceptance.

## Environment

- FreeBSD `fi-dev` jail and actual `fi-ingest-worker`, built from pinned FI source.
- Fresh isolated PostgreSQL 18 cluster, Unix socket only, private port 55519.
- `fsync`, `synchronous_commit`, and `full_page_writes` enabled.
- Committed schema migration 0004 applied.
- Security field-name index removed; composite primary key preserved.
- Private worker singleton lock, recorder/FIGT custody, READY, and staging roots.
- 24 signed FIGT generations from `iss-fs-22a.iss.local`, transfer SHA-256
  validated against the immutable recorder receipts.
- No live SOR, production custody, or FI Git modifications during the campaign.

## Workload and Procedure

Source collection window: October 18, 2026, 13:19–17:09 UTC;
approximately ten-minute intervals in the original Windows capture.

The isolated worker was started with all 24 previously captured generations
**already pending**. Startup reconciliation discovered the backlog, and the
worker drained it into a single accumulating relational database.
The actual worker was stopped gracefully after all generations completed.
PostgreSQL metrics were sampled every ten seconds.

| Workload | Value |
| --- | ---: |
| Source | `iss-fs-22a.iss.local` |
| Accepted generations | 24 / 24 |
| Signed source batches | 4,964 |
| Source records | 5,829,439 |
| Staged FIGT transfer data | approximately 0.591 GiB |

## Actual Worker Throughput and Memory

| Measurement | Result |
| --- | ---: |
| Worker drain wall time, including startup | 4,407 s (73m 27s) |
| Overall worker drain throughput | 1,322.77 records/s |
| Telemetry samples | 439 |
| Peak sampled FI worker RSS | 93,420 KiB |
| Peak sampled ingest PostgreSQL backend RSS | 264,356 KiB |

The 24 signed generations were accepted through the actual FI worker.
All authoritative generation record/batch totals matched the individual
signed receipts, not merely the aggregate total.

### Final relational authority

| Measurement | Verified total |
| --- | ---: |
| `fi.recorded_generation` | 24 |
| `fi.source_record` | 5,829,439 |
| `fi.source_batch` | 4,964 |
| `Accepted / AuthoritativeRecord` journal entries | 24 |
| `Incomplete / AttemptStarted` journal entries | 24 |
| `Failed` journal entries | 0 |
| `AlreadyAccepted` journal entries | 0 |

The `Incomplete / AttemptStarted` rows record individual attempt starts;
they are **not** evidence of 24 failed ingestions. The worker made exactly
24 authoritative acceptances in the fresh database, without test-injected
interruption or duplicate acceptance.

## PostgreSQL Size, WAL and Checkpoints

| Measurement | Observed |
| --- | ---: |
| Final database bytes | 19,172,374,207 |
| Final Security field relation bytes | 9,487,925,248 |
| Final `pg_stat_wal.wal_bytes` | 44,588,454,208 |
| WAL byte increase, first-to-last telemetry sample | 43,754,709,802 |
| Final WAL records counter | 209,646,115 |
| Final WAL full-page images counter | 2,276,886 |
| Final WAL buffers-full counter | 203,998 |
| Final WAL writes, PostgreSQL 18 `pg_stat_io` | 235,673 |
| Final requested checkpoints counter | 80 |
| Final timed checkpoints counter | 0 |

The final `pg_stat_wal` and checkpointer values are cumulative cluster
counters, not necessarily exact campaign-only deltas. First-to-last telemetry
WAL growth excludes bytes generated before the first sample. The retained
`before.stats` and `after.stats` allow exact baseline-to-final comparison.
Database size excludes WAL stored outside the database relations. Memory
figures are sampled peaks, not proven absolute process maxima.

WAL volume and checkpoint activity justify separate controlled examination.
They do not independently demonstrate that checkpoints or storage latency
caused the observed throughput.

## Comparison with M6.3

| Campaign | Generations | Records | Throughput |
| --- | ---: | ---: | ---: |
| M6.3 chronological backlog | 3 | 862,498 | 1,416.81 records/s |
| M6.5B actual worker backlog | 24 | 5,829,439 | 1,322.77 records/s |

M6.5B measured approximately 6.6% lower overall records/sec, while ingesting
substantially more cumulative data. The two campaigns have different harness
timing boundaries; the difference is not sufficient to attribute a bottleneck.

The selected source's original four-hour interval corresponds to approximately
405 records/s averaged over that period. M6.5B's backlog drain rate is
approximately 3.27 times that average **under the tested conditions**.
This is not a production hardware capacity guarantee.

## Acceptance Conclusion

**PASS — M6.5B actual-worker backlog drain and authoritative relational
acceptance.** All 24 generations and all 5,829,439 records passed the
relational checks. The PostgreSQL telemetry preflight and campaign completed.

M6.5B does **not** establish four-hour normal-arrival stability, READY
processing during continuous arrival, or capacity under different hardware
contention. Those remain the objectives of M6.5A.

## Retained Results (fi-dev, not committed)

`/home/jwood/fi-m65b-isolated-results-20261025-backlog24-r2`

The test retained `summary.txt`, `metrics.psv`, `before.stats`,
`after.stats`, `final-relational.txt`, expected/accepted generation TSVs,
worker build SHA-256, worker log, and isolated runtime objects. The 24 signed
FIGT source fixtures and local test harnesses remain outside the repository.

## Next Test

M6.5A — fresh isolated database and worker, with the same verified generations
introduced every ten minutes through the actual READY workflow. Measure
queue depth and age, per-arrival drain, CPU/memory, WAL and database growth.
