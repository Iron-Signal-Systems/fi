# FI private W128 signed W3–W22 insert-vacuum candidate trial

**2026-11-10 — experimental development only, no release/main changes**

## Goal and provenance

The five-window matched control/candidate pilot on real signed W3–W7 records improved candidate ingestion elapsed by 13.539s (~4.86%), 2,332.4 to 2,451.6 records/s (+5.11%). After manual vacuum repayment (integer-second measures), the apparent net saving was about 6.539s. Detailed PostgreSQL counters were mixed: the candidate eliminated insert-triggered vacuum on its five new field leaves but increased overall autovacuum-worker relation I/O, autoanalyze time, generated WAL and full-page images. The pilot therefore did **not** establish a net database-efficiency or causal benefit.

User requested an extended **20 NEW windows**, same actual signed source evidence, to characterize behavior under a longer workload. This is a one-arm candidate trial against the earlier 15-window signed reference, **not** a randomized A/B. Do not use one-run speed differences to claim causation or justify production configuration.

## Precisely scoped change

Runner: `go/cmd/fi-backlog-recover/run_private_vacuum_candidate_signed20_host.sh`.

Candidate SQL fixture: `go/cmd/fi-backlog-recover/testdata/private_field_insert_vacuum_candidate.sql` from pinned commit `dc556813d450f7ab79121d05e10e54c6d2732d01`.

The tested source executable is assembled from immutable known Go commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`. It contains four previously accepted reusable COPY row candidates plus the canonical private Security single-pass scanner. In an **archived throwaway source tree only**, the original CLI test-stop guard is patched to permit `-test-stop-after-windows=20`. No working branch, main or service installation is rewritten.

The freshly initialized private PostgreSQL 18.6 database is recreated from the independently verified W0–W2 seed; the function `fi_recovery_projection.begin_security_field_window(integer)` is then replaced **only in that disposable clone**, retaining original owner, definer security, grants, validation and partition constraints, with one addition for each newly created detached Security field leaf:

```sql
ALTER TABLE fi_recovery_projection.windows_security_event_field_wNNNNNN
    SET (autovacuum_vacuum_insert_threshold = -1);
```

NNNNNN is generated from the validated integer window index inside the function; the displayed SQL is explanatory, not a command for manual execution. No global autovacuum, autoanalyze, WAL, indexes, schema, fsync, synchronous commit, or full-page write settings are changed. Seed W0–W2 leaves remain unaltered.

## Workload and acceptance

- Signed workload: original verified 8,399-batch cache from `iss-fs-22a.iss.local`, original generation ID `20261030T000032.061323100Z-3e38b2210771462c`, new W128 indices **W3..W22**, exactly **20** newly committed windows (not 20 total including seed). Source W0–W2 provides a 390,387-record starting prefix; W0–W17 was previously verified at exactly **2,338,918**. The 20 new windows' record total is intentionally **not guessed**; it must exceed the independently measured W3–W17 1,948,531 records and reconcile with PostgreSQL markers.
- Source recorder process: W128/P3/F3 and 32,768-record single-worker processing chunks. Postgres `max_wal_size=1024MB`; `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`, `autovacuum=on`, `track_counts=on`, global `autovacuum_vacuum_insert_threshold=1000`. Original source body and signature validation are unchanged. Source namespaces/canonical publication disabled, private writes and detached partitions required, `fi-sor-db` JID distinct and running.
- Exact completion: `FI PRIVATE EXACT WINDOW STOP start=3 windows=20 last=22`; exactly 23 SQL durable marker rows W0–W22, 20 newly committed windows; signed source/ledger/typed count equality and descriptors match; field partitions attached and totals match; `fi.recorded_generation=0` and Accepted journal=0.
- Private leaf reloptions: **20|20** (W3–W22) carry the candidate reloption; original seed leaves are **3|0**. Security private canonical single-pass selected-row count must be positive. Signed data *and manifests* for every published batch must match the immutable original cache byte-for-byte, with batch count derived from the ledger rather than invented.
- The runner preflights socket path lengths, available 8,399 signed batches, stopped private PG postmasters, identity, seed, source SHA and function ACL/security status. A trap stops the disposable PostgreSQL instance on success or failure.

## Capture and reporting

Per-window durable records/sec, 28 stage/profile columns, per-window Security/file/field counts and partition finalize/attach, processing chunks, complete `recover.log`, GC lines, FreeBSD `time -l` peak RSS, 5-second host iostat/vmstat, PostgreSQL 18 named `pg_stat_wal`, `pg_stat_checkpointer`, `pg_stat_io`, and relation autovacuum/autoanalyze snapshot deltas. Five-second PG watcher includes last durable SQL window index, WAL, checkpoint, I/O, active vacuum and worker wait-events. The latest state sampling supports approximate alignment, not exact boundary attribution.

AFTER timed ingestion AND independent SQL/signed-custody checks, the runner executes `VACUUM (ANALYZE)` on **all 20 new private field leaves**, recording per-leaf wall seconds and a separately bracketed maintenance phase with additional PostgreSQL counters. It re-verifies the same durable SQL checkpoint and absence of SoR/Accepted journal entries after maintenance. This is necessary to avoid presenting deferred work as eliminated cost. Note that raw integer-second vacuum timing lacks subsecond precision and is not a replacement for controlled instrumented timings.

One metrics-only `fi-vacuum-candidate20-<timestamp>.tar.gz` includes source manifest and all performance evidence, but excludes original signed payloads, copied artifacts, PostgreSQL database/dump and source archive.

## Execution / limitations

Retrieve the experiment-branch runner at its final audited commit using `git show` inside `fi-dev` as `jwood`, require `sh -n` success, then run **once on `fi-backend-b` as root** with `sh "${jail_root%/}/home/jwood/fi-vacuum-candidate20.sh"`, after computing `jail_root=$(jls -j fi-dev path) || exit 1`. Do not run a second private test concurrently; preflight rejects another `fi-dev` postmaster. Attach the metrics tar for analysis. **The runner is staged but not yet executed on the host.**

Do not treat a faster window rate alone as acceptance: compare workload shape, field-copy/index/partition time, WAL/checkpoints/worker reads/writes, GC/CPU/host I/O, and manual vacuum repayment. A true production change would require separate repeatability and full query-read correctness/visibility/freeze analysis, and explicit configuration lifecycle decisions. Nothing in this experiment changes production FI or main.
