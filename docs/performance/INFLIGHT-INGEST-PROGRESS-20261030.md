# FI in-flight relational ingest progress — October 30, 2026

## Goal

Report useful progress throughout long, single-worker relational generation
transactions, including an attempted generation that fails or is interrupted.
Do not modify transaction/commit boundaries, custody, table schemas, data,
or any existing successful `INGEST PROFILE`/`INGEST NTFS` output fields.

## Implementation contract

- `IngestPreparedGeneration` retains one PostgreSQL transaction per signed
  generation. No batch is committed independently. Existing validation,
  projection coverage, failure and rollback behavior is unchanged.
- A lightweight heartbeat prints one `INGEST PROGRESS` line every **30 seconds**
  of in-flight activity, including during a stalled PostgreSQL call.
- One ingestion goroutine publishes an **immutable atomic snapshot** after
  each 1,024 input records and after each completed batch. The heartbeat
  goroutine only reads that snapshot and the monotonic transaction clock.
  There are no new PostgreSQL calls, no source data, paths, hashes, or
  per-record messages. The heartbeat is joined on every normal return.
- `snapshot_age` explicitly exposes how stale counters are while the ingest
  goroutine is blocked in a database operation. The transaction's actual age
  continues to increase.
- `records_read` means input lines reached the ingest path, **not committed
  or successfully projected records**. `committed=0` remains true until the
  final atomic commit. Only completed batches increase `batches_completed`.
- Existing timing counters are read by the ingestion goroutine alone. The
  tracked COPY duration includes supported file, metadata, hash, USN, ACE,
  security and source batch COPY calls. These are `pgx.CopyFrom` call times,
  not standalone storage or SQL-only time. They may overlap with existing
  `projection`/`source_sql` timings; **do not sum the fields**.
- The logging process has no extra locks or allocations per input record;
  checks are bounded to a 1,024-record checkpoint and a 30-second heartbeat.
- On a non-successful return, print a final `status=uncommitted` snapshot.
  This status is not evidence that the rollback itself succeeded; the
  existing error path remains the source of that outcome.

## Logging example (illustrative; not measured)

`INGEST PROGRESS source=... generation=... status=inflight batches_completed=30/8399 records_read=54122/15140785 committed=0 tx_age=30s snapshot_age=1s rate=1804.1_records_per_s read=... batch_hash=... prepare=... source_sql=... projection=... ntfs_identity=... tracked_copy=... tracked_copy_calls=...`

## Local-only acceptance

Run the staged `run-fi-dev.sh` as `jwood` in the `fi-dev` jail. Require
`git diff --check`, focused tests, `go test -count=1 ./...`, `go vet ./...`,
`go build`, and preferably `go test -race` on the focused progress tests.
All tests must pass before considering a separate isolated PostgreSQL
interrupted-generation test. The 15.14-million-record receipt remains
untouched; no runtime worker or sender is restarted here.

## Limits

The progress heartbeat is not a guarantee that the transaction will finish
within a fixed duration. Counts may lag up to the current record checkpoint
or an in-progress database call; `snapshot_age` makes this observable.
This patch does **not** fix transaction size, introduce partial commits,
implement checkpoints, or change index structures. Once accepted, use the
new evidence during **isolated** representative long-generation replay to
separate SQL, COPY, file parsing, and transaction visibility problems.

## Acceptance evidence (fill after fi-dev runs)

- Current working branch: `work/ingest-single-worker-efficiency-local-20261030`
- Patch application: PENDING
- Focused Go tests and race: PENDING
- Full Go regression and vet: PENDING
- FreeBSD worker build: PENDING
- Isolated long-generation and interrupted-transaction replay: PENDING
- Production deployment: NOT AUTHORIZED
