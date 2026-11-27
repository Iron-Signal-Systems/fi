# FI — per-relation COPY profiling and isolated PostgreSQL parameter comparison

Date: 2026-10-30. Status: **LOCAL DEVELOPMENT ONLY** until passing acceptance.

## Problem and baseline

During targeted ingestion of the immutable signed generation
`20261030T000032.061323100Z-3e38b2210771462c` (15,140,785 records,
8,399 batches), the running `fi-ingest-progress-20261030` process reported
3,157,649 records read after 51 minutes of its relational transaction,
16,628 tracked COPY calls and 33m59s cumulative tracked COPY time. Live WAL
LSN advanced 504.8 MiB over 60 seconds, one checkpoint was requested; 1,692
client-normal buffer evictions occurred. The sampled backend was variously
executing, writing relations/WAL, and waiting for client input. Do not infer
COPY source cost from one database wait state.

The baseline hardware workload remains active. No run in this package may
signal it, restart it, change production PostgreSQL settings, or edit custody.

## Per-table Go profiler

An embedded `pgx.Tx` wrapper intercepts *only* CopyFrom, delegates every call
exactly once with unchanged arguments and errors, and records cumulative
elapsed duration, rows returned by successful CopyFrom calls, errors, calls, extrema and 100/500/1000 ms
thresholds by bounded relation name (64 slots and one overflow summary).
It uses the same goroutine as the ingest; there is no database query and no
per-record output. The existing 30-second immutable heartbeat receives
`copy_top=relation:elapsed:calls,...`. Terminal logs include sorted
`INGEST COPY TABLE ...` summaries on both accepted and non-confirmed outcomes; a failed COMMIT can have an
indeterminate outcome and is never labeled a confirmed rollback. Counts
are never labeled committed until after the generation transaction commits.

The current running production ingester cannot acquire this instrumentation
without a restart. The patch is for the next isolated replay / candidate
binary; do NOT stop the current transaction to obtain these metrics.

## Isolated tuning sequence

Use the pre-existing *stopped*, exact-path PostgreSQL 18 fixture inside
`fi-dev`: `/home/jwood/fi-prefetch-20261030.CTwtoA/data`, Unix socket
`/home/jwood/fi-prefetch-20261030.CTwtoA/socket`, port 55442,
`listen_addresses=''` (no network). Production PostgreSQL and its
`fi` schema are never modified. Run the existing tagged hash-copy gate,
which writes **only its disposable fixture schema** and removes it afterward.

Run five states, one at a time, without modifying postgresql.conf:

- baseline-1: 128 MiB shared buffers; 1 GiB max WAL; 5-minute checkpoint
- wal-only: 128 MiB shared buffers; 8 GiB max WAL; 5-minute checkpoint
- buffers-only: 512 MiB shared buffers; 1 GiB max WAL; 5-minute checkpoint
- combined: 512 MiB shared buffers; 8 GiB max WAL; 5-minute checkpoint
- baseline-2: baseline repeated at the end to detect systematic drift

**Important:** each gate re-creates/truncates its own synthetic per-relation
bench tables. This A/B is a *narrow parameter sensitivity test*, not proof
of a 3x end-to-end signed generation speedup. No configuration is applied
to production. The full signed-generation replay and equivalent index-size
workload must follow before recommending deployment.

## Acceptance and non-goals

- Pass `go test ./...`, `go vet ./...`, focused `-race`, and build the worker
  on existing FreeBSD `fi-dev` branch.
- Repeat the previous hash-index tagged gate in each isolated setting and
  retain full separate logs. Validate exact source counts, index equality,
  unique/foreign-key handling, and rollback as implemented by the gate.
- Do not claim a triple speedup unless at least 3,000 source records/sec
  sustained, on a representative mixed full relational workload, with
  identical validation and atomic generation acceptance.
- The local benchmark intentionally cannot establish effects of a large
  uncommitted generation on production's index sizes and WAL/checkpointer.
- Do not commit/push, change runtime configs, or deploy any new binary as
  part of these steps. Preserve the active 15M run.
