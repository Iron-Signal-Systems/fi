# FI isolated security-heavy COPY latency replay — October 28, 2026

## Scope

An opt-in, FreeBSD-only integration fixture tests a real signed generation,
receiver custody, recorded receipt, and FI 49-table relational ingest path.
It uses existing M1 isolated PostgreSQL 18 fixture in `fi-dev` at
`$HOME/fi-m1-postgres-20261012` (Unix socket port 55418).

The test creates 1,024 synthetic Windows Security Event 4663 records by
default, each with one matched scope and 15 event fields: 15,360 event-field
rows. `FI_COPY_LATENCY_SECURITY_RECORDS` may be set from 1 to 4,096.
The fixture is a performance *diagnostic*, not a throughput optimization or
a reliable direct comparison to the live 20M-row hash-observation database.

One extra helper function in `multisource_signed_custody_freebsd_test.go`
extends the existing signed-generation fixture to accept bounded validated
records. Its original one-record helper stays available and unchanged in
behavior. The new opt-in test is separately build-tagged and does not run
under ordinary `go test ./...`.

## Safety contract

- The test refuses to run unless `FI_M1_ALLOW_ISOLATED_WRITES=1` and the
  expected exact M1 PostgreSQL fixture root, PostgreSQL 18 marker, socket,
  roles, database, 49 relational tables, and TCP-disabled configuration match.
- All custody/receipt source records are generated under a Go `t.TempDir`.
- The generation is uniquely identified; cleanup only removes that
  generation's security fields, scopes, events, source records, batches,
  generation, and journal rows from the isolated fixture. The test confirms
  that its generation no longer exists after cleanup.
- Failures in cleanup are test failures; the fixture remains isolated.
- No shared development SoR source material, deployed worker, or live SoR
  PostgreSQL is used.
- Do not run this test against a database different from the verified M1
  fixture. Do not run other M1 integration fixtures concurrently.

## Initial acceptance and measurement

From `/home/jwood/src/fi/go` in `fi-dev`:

```sh
go test -tags fi_copy_latency_replay_integration \
    ./internal/recordingest -run '^$' -count=1

go vet -tags fi_copy_latency_replay_integration ./internal/recordingest

FI_M1_TEST_POSTGRES_ROOT="$HOME/fi-m1-postgres-20261012" \
FI_M1_ALLOW_ISOLATED_WRITES=1 \
FI_COPY_LATENCY_SECURITY_RECORDS=1024 \
go test -tags fi_copy_latency_replay_integration \
    ./internal/recordingest \
    -run '^TestCopyLatencySecurityGenerationReplay$' -count=1 -v
```

Acceptance requires the `INGEST COPY LATENCY SECURITY` generation record,
accepted source record count 1,024, exactly 1,024 events, 1,024 scopes,
15,360 fields, and successful isolated fixture cleanup. Record the `INGEST
PROFILE` output, and `FI SECURITY REPLAY ACCEPTED` duration and rate.

The control signed-generation test must also still pass unchanged:

```sh
FI_M1_TEST_POSTGRES_ROOT="$HOME/fi-m1-postgres-20261012" \
FI_M1_ALLOW_ISOLATED_WRITES=1 \
go test ./internal/recordingest \
    -run '^TestM1TwoSourceRelationalIngestRoundTrip$' -count=1 -v
```

## Not yet covered

The initial file/metadata/hash replay has now completed in the
isolated M1 fixture at 1,024 and 4,096 records; see
[file replay results](COPY-LATENCY-FILE-REPLAY-20261028.md).
Three additional sequential 4,096-event security replays passed after a
fixture-only timestamp correction. The slow first run was not reproduced;
its cause is still unknown. Live-scale index pressure, PostgreSQL wait
correlation, equivalent-hardware comparison, and full-end-to-end
collector/receiver throughput remain pending. Development SoR telemetry activation is a separate observability
checkpoint, not representative heavy-workload performance acceptance. See
[development SoR activation evidence](INGEST-COPY-TELEMETRY-DEV-SOR-ACCEPTANCE-20261028.md).
Do not treat these initial isolated runs as sufficient for a merge or
broader rollout.

## Measured results — October 28, 2026

Environment: fi-dev, isolated PostgreSQL 18, 49-table FI schema.
Each event contains one scope and 15 event fields.

| Metric | 1,024 events | 4,096 events |
|---|---:|---:|
| Accepted events | 1,024 | 4,096 |
| Accepted fields | 15,360 | 61,440 |
| Ingest duration | 1.145s | 11.066s |
| Records/second | 894.2 | 370.1 |
| Source COPY total | 578ms | 776ms |
| Event COPY total | 30ms | 2.016s |
| Scope COPY total | 24ms | 1.094s |
| Field COPY total | 270ms | 6.730s |
| Projection total | 329ms | 9.864s |
| Transaction commit | 131ms | 22ms |

Both runs passed relational verification and fixture cleanup.

At 4,096 events, all four field COPY calls exceeded one second.
No COPY call exceeded five seconds.

These are single-run observations, not established scaling
characteristics. Repeatability, PostgreSQL waits, and storage
measurements remain outstanding. No root cause is assigned.

## Repeat 4,096-event run — 2026-10-28 22:19 UTC

Same tagged test, M1 fixture and 4,096-event / 61,440-field
configuration as the initial 4,096-event run; no ingestion code,
PostgreSQL configuration, batch size or schema change was made.
The replay again passed row verification and isolated fixture cleanup.

| Metric | Initial 4,096-event run | Repeat 4,096-event run |
|---|---:|---:|
| Ingest duration | 11.066s | 2.710s |
| Records/second | 370.1 | 1,511.5 |
| Source COPY | 776ms | 152ms |
| Event COPY | 2.016s | 279ms |
| Scope COPY | 1.094s | 217ms |
| Field COPY | 6.730s | 1.662s |
| Projection | 9.864s | 2.180s |
| Transaction commit | 22ms | 14ms |
| Field COPY calls | 4 | 4 |
| Field calls >=1s | 4 | 0 |
| Field COPY min/max | not recorded here | 318ms / 516ms |
| Relational verification | PASS | PASS |
| Isolated cleanup | PASS | PASS |

The repeat was approximately 4.08 times faster in overall ingest
duration, with improvement across source, event, scope and field
COPY calls. The earlier latency spike was therefore **not reproduced**
on this second 4,096-event run. No single security-field table or code
change can be assigned as the cause. Cache state, concurrent activity,
storage behavior and PostgreSQL waits are hypotheses only.

## Fixed-width timestamp fixture correction and sequential repetitions — October 28, 2026

An attempted three-run sequence stopped before ingestion on its first run:

```text
invalid security fixture 0: InvalidTimestamp: observed_at
--- FAIL: TestCopyLatencySecurityGenerationReplay (0.04s)
```

The test constructed `ObservedAt`, `TimeCreated`, and `WrittenAt`
with `time.Now().UTC().Format(time.RFC3339Nano)`. That Go format
elides trailing fractional-second zeros, while FI's canonical validator
requires exactly nine fractional digits followed by `Z`. This
timestamp-format mismatch intermittently invalidated the synthetic
fixture before COPY was reached; it does not indicate a PostgreSQL
failure. The test-only line now uses
`time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")`.
No production validator or ingest behavior was modified.

The interrupted attempt generated no ingestion performance result.
Its failure log and the following accepted runs are preserved on
`fi-dev` under `/home/jwood/fi-security-repeat-A34eom`
(`run-1.log` and `run-fixed-{1,2,3}.log`).

Three sequential executions used the same isolated M1 PostgreSQL
fixture, the same source, 4,096 Windows Security 4663 observations,
4,096 scopes, and 61,440 field rows. Each produced four field COPY
calls. The table also retains the two earlier measured runs:

| Metric | Initial 4,096 | First repeat | Fixed run 1 | Fixed run 2 | Fixed run 3 |
|---|---:|---:|---:|---:|---:|
| Accepted events | 4,096 | 4,096 | 4,096 | 4,096 | 4,096 |
| Accepted field rows | 61,440 | 61,440 | 61,440 | 61,440 | 61,440 |
| Ingest duration | 11.066s | 2.710s | 2.520s | 2.510s | 1.926s |
| Throughput (events/s) | 370.1 | 1,511.5 | 1,625.7 | 1,631.7 | 2,126.7 |
| Source COPY | 776ms | 152ms | 130ms | 173ms | 143ms |
| Event COPY | 2.016s | 279ms | 337ms | 258ms | 149ms |
| Scope COPY | 1.094s | 217ms | 145ms | 133ms | 112ms |
| Field COPY | 6.730s | 1.662s | 1.495s | 1.557s | 1.127s |
| Projection | 9.864s | 2.180s | 1.996s | 1.967s | 1.407s |
| Field COPY calls | 4 | 4 | 4 | 4 | 4 |
| Field calls >=1s | 4 | 0 | 0 | 0 | 0 |
| Field COPY min/max | not recorded | 318/516ms | 307/435ms | 267/475ms | 266/299ms |
| Relational verification | PASS | PASS | PASS | PASS | PASS |
| Isolated fixture cleanup | PASS | PASS | PASS | PASS | PASS |

The four later executions provide 16 observed field COPY calls,
none >=1s; their highest reported per-call latency was 516ms.
The isolated synthetic workload did **not** reproduce the initial
slowdown. The three corrected runs also completed with sequential
cleanup verification and without any production ingestion changes.

**Interpretation:** initial 11.066-second ingestion remains an unexplained
outlier. These observations alone do not establish warm caches,
database checkpoint activity, competing I/O, indexes, or any other
specific cause. The isolated diagnostic does not reproduce shared
development SoR index/data scale or a representative mixed ingest load.

**Next diagnostic:** preserve the isolated repeatability evidence, then
correlate COPY call latency with PostgreSQL waits and system CPU,
memory and storage metrics during a representative, safely bounded
development-scale workload. Do not tune batch sizes, indexes,
concurrency, WAL, or ZFS on the strength of these isolated results.

**Checkpoint complete:** the canonical timestamp test-only correction
passed three sequential replays, fixture cleanup and tagged `go vet` on
`fi-dev`, then was committed and pushed to this working branch as
`62c0af0de269900eac693a6a43dcdd4e6cadef9a` on October 28, 2026.
The three unrelated untracked working-tree files were not staged.
No production ingestion code or shared SoR dataset was modified by
this test correction. Development-scale latency causality and representative
heavy-workload acceptance remain open.
