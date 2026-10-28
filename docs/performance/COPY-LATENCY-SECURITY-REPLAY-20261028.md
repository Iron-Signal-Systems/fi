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
Repeatability, live-scale index pressure, equivalent-hardware
comparison, and full-end-to-end collector/receiver throughput remain
pending. Development SoR telemetry activation is a separate observability
checkpoint, not representative heavy-workload performance acceptance. See
[development SoR activation evidence](INGEST-COPY-TELEMETRY-DEV-SOR-ACCEPTANCE-20261028.md).
Do not treat the isolated single runs as sufficient for a merge or
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
