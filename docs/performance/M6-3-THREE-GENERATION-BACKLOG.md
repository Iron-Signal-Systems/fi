# M6.3 — Three-Generation Backlog Acceptance

## Status

**PASS — isolated chronological backlog ingestion**

Date: 2026-10-25

Repository baseline:
`572ebabb525c7657454987bb699420446fa3746e`

## Purpose

Measure sequential ingestion of multiple Security-heavy
signed generations into one accumulating PostgreSQL database.

This test evaluates bounded backlog throughput, cumulative
relational growth, WAL activity, and authoritative acceptance.

It does not simulate a worker interruption or concurrent
arrival of new generations.

## Environment

- FreeBSD fi-dev isolated test environment
- PostgreSQL 18
- Local Unix socket only
- Fresh database initialized once
- Migration 0004 applied before ingestion
- fsync enabled
- synchronous_commit enabled
- full_page_writes enabled
- Same FI ingest binary for all three generations
- Signed custody and recorder receipts retained
- No live SOR modification

## Workload

Source: `iss-fs-22a.iss.local`

| Generation | Records | Batches | Wall time |
| --- | ---: | ---: | ---: |
| 13:29 UTC | 295,067 | 201 | 208.71 s |
| 13:39 UTC | 288,104 | 202 | 199.65 s |
| 13:49 UTC | 279,327 | 204 | 200.40 s |
| **Total** | **862,498** | **607** | **608.76 s** |

The database was not reset between generations.

Aggregate replay throughput: approximately 1,416.81
source records per second, excluding harness setup and
inter-generation verification.

All three generations reported Accepted.

## Final Relational Distribution

| Record kind | Count |
| --- | ---: |
| WindowsSecurityEvent | 806,279 |
| USNObjectObservation | 55,612 |
| WindowsSecurityCoverage | 593 |
| USNReadBoundary | 14 |
| **Total** | **862,498** |

Cumulative relational verification: PASS.

- Recorded generations: 3
- Recorded batches: 607
- Accepted journal outcomes: 3
- Failed journal outcomes: 0
- Composite Security field primary key preserved
- Security field foreign key preserved
- Unused Security field-name index absent

## Security Field Ingestion

| Generation | Field rows | Field COPY |
| --- | ---: | ---: |
| 1 | 4,125,077 | 59.524 s |
| 2 | 4,080,180 | 59.373 s |
| 3 | 3,888,930 | 56.707 s |
| **Total** | **12,094,187** | **175.604 s** |

## PostgreSQL WAL Activity

Counters are differences between the saved before/after
pg_stat_wal, pg_stat_io and pg_stat_checkpointer snapshots.

| Measurement | Gen 1 | Gen 2 | Gen 3 |
| --- | ---: | ---: | ---: |
| WAL generated, MiB | 1342.775 | 2006.776 | 1924.927 |
| WAL records | 10,298,997 | 10,135,021 | 10,024,096 |
| WAL buffers full | 7,672 | 8,801 | 9,597 |
| WAL writes | 7,680 | 8,804 | 9,004 |
| Relation evictions | 73,538 | 72,042 | 76,345 |
| Requested checkpoints | 2 | 4 | 4 |

Total WAL generated: approximately 5,274.478 MiB.

WAL generation was higher in generations 2 and 3
than in generation 1, despite comparable record counts.

These counters do not independently establish whether
checkpoint activity, full-page images, storage latency,
or another factor caused the increase.

## Database Growth

| Generation accepted | Database bytes | Field relation bytes |
| --- | ---: | ---: |
| 1 | 976,197,311 | 484,212,736 |
| 2 | 1,908,070,079 | 962,732,032 |
| 3 | 2,824,173,247 | 1,418,625,024 |

Database size includes relations and indexes but excludes
PostgreSQL WAL files outside the database size calculation.

## Interpretation

Three chronological generations were fully accepted into
one accumulating relational database.

Ingest throughput remained relatively stable throughout
this bounded workload.

The isolated test exceeded the earlier 1,000-record/sec
engineering target without removing relational constraints.

The WAL and checkpoint results warrant separate controlled
characterization before drawing storage or tuning conclusions.

This campaign is not a sustained production-capacity guarantee.

## Next Acceptance Boundary

Test backlog recovery with:

- previously queued immutable generations;
- controlled ingest-worker interruption;
- restart without duplicate or partial authority;
- continued arrival of new generations;
- verified chronological drain and relational completeness;
- bounded memory, CPU, WAL and storage activity.

Preserve the existing custody and relational acceptance
contracts throughout recovery.
