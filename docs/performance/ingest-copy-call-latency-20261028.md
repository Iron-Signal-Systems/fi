# FI ingestion COPY call latency — October 28, 2026

## Purpose

Record the variability of individual PostgreSQL COPY operations without
changing ingestion order, transaction boundaries, schema, memory limits,
index definitions, or existing aggregate timing field names.

This document records the October 28 baseline for the FreeBSD FI ingest
worker processing recovered generations from `iss-fs-22a.iss.local`.
All FI hosts and sources in this test are development systems. The
telemetry-enabled worker was activated in the shared development SoR
ingest jail on October 28 after isolated regression and replay checks.
The previous worker binary was retained for rollback. Activation confirms
observability, not representative heavy-workload performance acceptance.

## Existing baseline (measured, not extrapolated)

Five successive completed generations at 09:23:30 UTC:

- Source records: 197,831.
- Summed relational ingest profile time: 268.184 seconds.
- Aggregate generation-local rate: approximately 738 records/second.
- Summed `INGEST HASH COPY copy`: 37.908 seconds.
- Summed `INGEST PROFILE projection`: 215.707 seconds.
- Hash COPY rows: 67,935.
- PostgreSQL recovery backlog and other source traffic were present.
- The measurements use generation-local durations. They are **not**
  receiver custody publication rates or end-to-end collector-to-query rates.

An earlier recovered generation showed 6,453 hash rows in 84.782
seconds of COPY calls and 18,292 total source records in 182.610 seconds
of worker-attempt time. Subsequent hash operations had lower per-generation
COPY times. The source of this variation has not been established.

The observed SQL wait `DataFileRead` indicates I/O wait at sample time;
it does not identify index, heap, foreign-key, or underlying ZFS latency
as the sole cause.

## Telemetry contract

Two new per-generation log lines are written **only after successful
database commit**:

- `INGEST COPY LATENCY FILE` includes hash, file parent, metadata.
- `INGEST COPY LATENCY SECURITY` includes source records, security events,
  scopes, and fields.

Each table reports a constant-space distribution of individual
`pgx.Tx.CopyFrom` call durations:

- `calls`: number of COPY calls that returned, including errors in an
  attempt that subsequently fails (failed attempts do not emit these
  successful-generation log lines).
- `min`, `max`: minimum and maximum elapsed call durations, rounded to
  milliseconds on output. With zero calls, both are zero.
- `ge_1s`, `ge_5s`: count of calls with elapsed time greater than
  or equal to one second and five seconds.

Existing `INGEST HASH COPY`, `INGEST PROFILE`, `INGEST NTFS STAGES`,
and `INGEST SECURITY BULK` log lines remain unchanged.

The COPY call timer includes client encoding, network or jail transport,
PostgreSQL execution, indexes, constraint checks, and waits. It is **not**
a standalone disk measurement. New distributions overlap the existing
aggregate stage timers and must not be added to them.

All counters are generation-local, bounded, and constant-space. They do
not collect filenames, paths, hashes, event payloads, or sensitive values.
No new imports/dependencies are required beyond the Go standard library.

## Acceptance sequence

Run from the development jail's `/home/jwood/src/fi/go` directory with
the new branch checked out and a cleanly understood working tree:

```sh
gofmt -l internal/recordingest/copy_call_latency.go \
  internal/recordingest/copy_call_latency_test.go \
  internal/recordingest/content_hash_copy_latency_test.go \
  internal/recordingest/content_hash_copy.go \
  internal/recordingest/security_bulk.go \
  internal/recordingest/ntfs_stage_timing.go \
  internal/recordingest/file_observation_bulk.go \
  internal/recordingest/postgres_ingest.go

go test ./internal/recordingest
go test ./...
go vet ./internal/recordingest
```

Integration tests gated by PostgreSQL DSN environment variables must be
run with an isolated test database before considering this accepted.
Do not point destructive test fixtures at the live recovery database.

Compare equivalent source-record type mixes and row counts. Check:

1. Existing rows and accepted generation counts remain unchanged.
2. Rollback on COPY error remains unchanged.
3. Per-call counts agree with successful COPY calls.
4. The `min`/`max` values bound each observed call and slow buckets
   count 1s and 5s inclusive.
5. `INGEST PROFILE` and pre-existing SQL/copy timers have the same
   measurement boundaries as before.
6. CI and FreeBSD build/acceptance gates succeed before merge/deployment.

## Out of scope

No tuning of PostgreSQL shared buffers, autovacuum, WAL, ZFS, hash indexes,
batch-size limits, concurrency, or transaction durability in this change.

## Development validation — October 28, 2026

Environment: FreeBSD fi-dev jail.
Branch: work/ingest-copy-call-latency-20261028.

### Completed acceptance

| Check | Result |
|---|---|
| Five focused telemetry unit tests | PASS |
| Complete recordingest package regression | PASS |
| Full Go regression: go test ./... -count=1 | PASS |
| Full static analysis: go vet ./... | PASS |
| Three PostgreSQL integration test configurations compiled | PASS |
| Content hash COPY PostgreSQL integration | PASS |
| File observation bulk PostgreSQL integration | PASS |
| Security bulk PostgreSQL integration | PASS |

Integration tests ran against a temporary Unix-socket-only
PostgreSQL cluster with three separate test databases.

Verified behaviors included bounded hash COPY, valid and invalid
hash states, generated source identities, numeric and digest
preservation, foreign-key enforcement, duplicate rejection,
security-event projection, and transaction rollback.

No shared development SoR database, running ingest worker, or deployed
application binaries were modified during isolated test acceptance.

### Outstanding performance acceptance

The isolated security-event and file/hash generation replays have
now produced initial per-COPY timing observations; both 1,024- and
4,096-record runs passed projection verification and fixture cleanup.
See [security replay](COPY-LATENCY-SECURITY-REPLAY-20261028.md)
and [file replay](COPY-LATENCY-FILE-REPLAY-20261028.md).

Three additional sequential 4,096-event security replays passed with
relational verification and cleanup after correcting an intermittent
synthetic timestamp-format validation defect. The five observed 4,096-event
ingest times were 11.066s, 2.710s, 2.520s, 2.510s and 1.926s. Their
security-field COPY totals were 6.730s, 1.662s, 1.495s, 1.557s and
1.127s. None of the 16 field COPY calls in the four later runs exceeded
one second. See the [security replay record](COPY-LATENCY-SECURITY-REPLAY-20261028.md)
for per-call ranges, the pre-ingestion fixture failure, its bounded
fix and completed test-source checkpoint (`62c0af0`).

Repeatability of the isolated security workload has now been observed,
but the initial slow run remains unexplained. Equivalent data/index
scale, PostgreSQL wait correlation, storage correlation, and mixed
source workloads remain open. These results do not establish general
performance scaling or throughput improvement.

Development SoR worker activation passed as an observability checkpoint.
Representative heavy-load performance acceptance remains open. See
[development SoR activation evidence](INGEST-COPY-TELEMETRY-DEV-SOR-ACCEPTANCE-20261028.md).
