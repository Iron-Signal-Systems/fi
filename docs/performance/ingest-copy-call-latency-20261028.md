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


## Development SoR read-only footprint and I/O baseline (prepared, not yet run)

After the five accepted 4,096-event security replays, the live development
worker was observed running in the `fi-ingest` jail and accepted one
11-record `iss-fs-22b.iss.local` security-coverage generation. That
generation had zero instrumented hash, file, metadata or security-field
COPY calls. The current and two rotated `daemon.log` windows had no
matching nonzero instrumented COPY calls. No representative new COPY
event is available for direct wait correlation in that observation window.

The next diagnostic is now packaged at
[`scripts/ingest_copy_sor_readonly_baseline.sql`](../../scripts/ingest_copy_sor_readonly_baseline.sql).
It is **not** ingestion or tuning code and is **not yet runtime-validated**
against the development SoR. Run it from an existing shell on
`fi-backend-b`, where PostgreSQL 18 is in the `fi-sor-db` jail:

```sh
# After obtaining an up-to-date copy of the script on fi-backend-b:
sudo jexec -U postgres fi-sor-db /usr/local/bin/psql \
    -X -q -w -U postgres -h /tmp -p 5432 \
    -v ON_ERROR_STOP=1 -P pager=off -d fi \
    -f /path/to/ingest_copy_sor_readonly_baseline.sql
```

Use a known local path for the SQL file; the repository checkout on
`fi-dev` is not assumed to be available inside the database jail.
The script uses a read-only transaction, 5-second per-statement timeout,
1-second lock timeout, no scans/counts of FI evidence records, and
only catalog/statistics queries. It prints PostgreSQL identity, settings,
largest tables/indexes, index readiness, cumulative database and relation
I/O counters, WAL/checkpointer state, and the current wait events
(without query text). No schema, worker, custody, or PostgreSQL
configuration changes are authorized by this diagnostic.

All PostgreSQL activity counters are cumulative since their indicated
stats-reset epochs; a single post-load snapshot is **not** evidence of
which earlier COPY call caused a spike. Meaningful root-cause correlation
requires a representative heavy ingest operation while measuring waits,
checkpoint/WAL and host I/O. The existing M6.2 and M6.5B performance
acceptance remains valid; no performance change is justified here
without stronger evidence.


## Measured 138 GB SoR catalog and cumulative I/O snapshot — October 29, 2026

**Source:** read-only PostgreSQL 18.6 `psql` here-document completed
from the existing `root@fi-backend-b` shell using
`jexec -U postgres fi-sor-db /usr/local/bin/psql -X -w -h /tmp -p 5432 -U postgres -d fi`.
The operator executed the inline diagnostic from the conversation;
the standalone SQL script above was **not** copied or executed. The
inline transaction issued `BEGIN READ ONLY`, 10-second statement timeout,
2-second lock timeout, catalog/statistics SELECTs and `COMMIT`. Output
ended with `DIAGNOSTIC COMPLETE`. No source ingestion, worker restart,
SQL data mutation or configuration modification was part of this step.

Database size: **138 GB** reported by `pg_size_pretty(pg_database_size('fi'))`.

### Largest relation samples (catalog-estimated rows; rounded display sizes)

| FI relation | Estimated rows | Table | Indexes | Total |
|---|---:|---:|---:|---:|
| `windows_security_event_field` | 218,792,912 | 18 GB | 6,994 MB | 25 GB |
| `file_observation` | 22,367,392 | 20 GB | 2,070 MB | 22 GB |
| `source_record` | 36,545,308 | 8,213 MB | 5,775 MB | 14 GB |
| `windows_security_event` | 14,861,748 | 10 GB | 2,643 MB | 13 GB |
| `security_ace` | 74,520,904 | 9,265 MB | 2,725 MB | 12 GB |
| `usn_object_change` | 27,540,820 | 4,261 MB | 4,561 MB | 8,822 MB |
| `content_hash_observation` | 22,297,272 | 2,592 MB | 2,185 MB | 4,777 MB |

The counts come from `pg_class.reltuples`, not authoritative row
counts, and are not directly interchangeable with committed
source-record totals from `fi.recorded_generation`.

The largest observed index was
`windows_security_event_field_pkey` at **6,994 MB**. Other large
indexes included `source_record_scope_time_idx` (2,335 MB),
`security_ace_pkey` (2,256 MB),
`source_record_kind_time_idx` (1,469 MB), and
`windows_security_event_record_idx` (1,288 MB). The field table's
total reported index footprint equaled the reported primary-key
index size; the 15-index listing did not show the previously removed
field-name index. This agrees with the established M6.2 schema
migration, but the inline query did not enumerate *every* field index
to independently verify that invariant. Index `idx_scan` counters
measure usage over the statistics history and do not by themselves
prove an index is safe to remove.

### Cumulative PostgreSQL evidence

| Measurement | Observed |
|---|---:|
| `pg_stat_database` shared-buffer hit rate | 98.10% |
| `pg_stat_database` blocks read / hit | 189,440,772 / 9,769,243,485 |
| `pg_stat_database` read / write time | 26,691,426.288ms / 6,644,086.713ms |
| `pg_stat_wal` records | 2,249,083,021 |
| `pg_stat_wal` full-page images | 92,453,859 |
| `pg_stat_wal` reported bytes | 817 GB |
| `pg_stat_wal` buffer-full events | 13,655,022 |
| `pg_stat_checkpointer` timed / requested / done | 3,247 / 1,062 / 3,283 |
| `pg_stat_checkpointer` buffers written | 3,464,888 |
| `pg_stat_checkpointer` write / sync time | 312,353,354ms / 161,569ms |
| `pg_stat_io` client-backend normal reads | 138,189,033 |
| `pg_stat_io` client-backend normal read time | 19,480,425.287ms |
| `pg_stat_io` client-backend normal writes | 47,349,979 |
| `pg_stat_io` client-backend normal evictions | 151,477,661 |
| `pg_stat_io` autovacuum-worker vacuum reads | 10,697,199 |
| `pg_stat_io` autovacuum-worker vacuum read time | 6,508,085.899ms |
| Active non-idle database backends/waits at snapshot | 0 |

`pg_stat_wal` and `pg_stat_checkpointer` displayed
`stats_reset=2026-10-16 16:36:26.414104+00`; the displayed
`pg_stat_database.stats_reset` field was blank. The inline query
did not request `pg_stat_io.stats_reset`, therefore its reset epoch
is not established here. These are **cumulative counters, not
interval deltas**. In particular, 817 GB of historical WAL and
13.7 million WAL-buffer-full events do not prove that an earlier
specific COPY call blocked on WAL. A 98.10% cumulative buffer-hit
ratio is compatible with costly misses; it does not localize
read pressure to a specific table or index.

`pg_stat_io` evictions describe PostgreSQL buffer replacement;
they must not be treated as proven ZFS ARC evictions or physical
device I/O latency. The zero-wait snapshot was taken after the
heavy ingestion window and cannot rule out earlier waits.

### Diagnostic decision

This database is materially larger than the dedicated 4,096-event
fixture: approximately 219 million security event-field tuples and
a nearly 7 GB primary-key index alone. Large index footprint,
historic buffer I/O, WAL-buffer activity and checkpoint writes are
**credible candidate contributors**, not an established root cause.

The earlier 11.066-second isolated replay (versus 1.926–2.710s
subsequent repeats) also shows intermittent latency can occur
without altering the software. No ingestion, index, PostgreSQL
memory/WAL, ZFS, or worker-concurrency tuning is accepted from
this cumulative snapshot alone.

**Further root-cause acceptance requires a real nonzero heavy COPY
episode with synchronized per-call worker timing, PostgreSQL
wait/statistics deltas, and FreeBSD storage observations.** The
completed recovery backlog must not be recreated merely to obtain
another sample. Until such correlated evidence exists, the accepted
ingest and telemetry implementation remains unchanged.
