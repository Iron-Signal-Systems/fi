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

## 2026-11-10 11:01 UTC — W3–W22 ingestion completed; post-run seed-leaf acceptance gate defect

Actual operator output from running pinned W128 optimized Go source and private leaf-only vacuum candidate on `fi-backend-b`: `FI EFFICIENCY HOST OBSERVERS captured iostat=1145 vmstat=252`, Go `gc_trace_lines=1546` and `peak_rss_kib=388536`; source prefix `W0_W17=2338918`, new W3–W22 `2597716`, cumulative SQL marker `23|2988103|22`. **`FI CLONE SQL INTEGRITY PASS checkpoint=23|2988103|22 canonical=0 accepted=0`**. Private field new-leaf gate (`20|20`) did not fail. The runner then exited nonzero at an incorrect seed-leaf gate: `FI CLONE STOP: seed leaf options were changed: 2|0`. The script assumed all three seed window *markers* W0–W2 correspond to actual Security-field *leaf relations*. W0 is a seed marker without a separate leaf; the real two original seed leaves W1/W2 yield **`2|0`**, correct and unchanged. Earlier retained 15-window analysis also saw 18 populated partitions (W1–W17 plus one counting nuance in cumulative query), emphasizing to count physical relations, not marker rows.

**Engineering classification:** *acceptance harness bug*, not established ingestion failure. Do not mark the whole trial as fully accepted yet: original runner exited before independently comparing all published signed batches/manifests, exporting stage matrices, running 20 manual private leaf VACUUMs, or archiving comprehensive metrics. Both the original recorder and PostgreSQL cluster were stopped cleanly. No authoritative SoR/Accepted entries were recorded; source signed evidence and original performance logs remain preserved.

Private stopped cluster to resume: `/home/jwood/fi-window-bench-optfield-v20-c-20261110T103933Z/clone-11-08-26/data`; host diagnostic output `/var/tmp/fi-window-chunks-v20-c-20261110T103933Z`. **Never rerun ingestion solely because a postrun harness count was wrong.** Fixed the original experiment-only runner gate to test W1 and W2 leaf relations and expect `2|0` at commit `a753d2439e23be9370a7015ea1d49435214ef946`.

Recovery continuation (no Go build, no signed replay, no new seed/clone): `go/cmd/fi-backlog-recover/finish_completed_private_vacuum_candidate20_host.sh`, commit `3844be5d43acad141f5295066a3678827311f6fd`. It is pinned to the old stopped cluster and output timestamp, verifies pinned source SHA, exact run manifest, persisted exact W3–W22 stop, original 20-window SQL integrity PASS, 23 markers and 2,988,103 cumulative records, 2,597,716 new W3–W22 records, known W0–W17 prefix, all 20 modified new leaf reloptions and both unchanged seed leaves plus absent W0 leaf, distinct dev/SoR JIDs and stopped private PostgreSQL. It restarts **only the retained disposable clone** on its private Unix socket, captures explicitly labeled restart-before-maintenance statistics (without overwriting the actual ingress before/after counters), finishes byte-for-byte signed readback, builds 20-window stage/family/chunk/SQL matrices, performs 20 **private** post-run leaf VACUUM(ANALYZE) operations, revalidates checkpoint and no authoritative/Accepted rows, writes metrics-only `fi-vacuum-candidate20-20261110T103933Z.tar.gz`, then shuts down this private cluster. PostgreSQL restart may modify internal DB files; this is not a forensic disk-read-only operation. The recovery script itself has **not yet been host syntax-checked or executed**; require `sh -n` on FreeBSD before execution.

Next engineering study: once metrics archive exists, analyze the **actual 20-window** aggregate and per-window Go stage costs (Security envelope preparation; File observation projection; Security field/event/source COPY; hash/read/verification; 20 window partition validate/attach) and SQL stage costs (relation-level autovacuum/autoanalyze, PostgreSQL WAL/checkpoints/pg_stat_io, active vacuum workers, leaf-only deferred repayment) separately, using nested stage semantics and signed invariants. Identify a specific Go code path and SQL query/index/timing change; introduce one isolated change per experiment with exact acceptance and before/after counters. The longer candidate run, without an equally long matched control, cannot establish a causal speedup or validate changing production configuration.

## Resumption instructions (the already completed 20-window private clone only)

As `jwood` inside `fi-dev`: fetch branch `experiment/fi-file-validation-once-20261108`, then extract the exact commit's `go/cmd/fi-backlog-recover/finish_completed_private_vacuum_candidate20_host.sh` to `/home/jwood/fi-candidate20-finish.sh`. **Run `sh -n` and stop if nonzero**. Do **not** run the original ingestion runner again. The host script expects the retained clone under `/home/jwood/fi-window-bench-optfield-v20-c-20261110T103933Z`; all paths are fixed to the run whose SQL integrity passed. As root on `fi-backend-b`, obtain `jail_root=$(jls -j fi-dev path) || exit 1` and run `sh "${jail_root%/}/home/jwood/fi-candidate20-finish.sh"`.

Updated continuation audited through commit `3844be5d43acad141f5295066a3678827311f6fd` re-runs **the complete original SQL custody/typed/source/manifest integrity** after private PostgreSQL restart; preserves the original 20-window timed snapshots, writes *restarted_before_maintenance* snapshots separately, checks **new leaves 20|20, seed W1/W2 leaves 2|0, absent W0 leaf**, revalidates original signatures by byte-for-byte cache readback, exports all per-window profile matrices, and performs 20 explicit private VACUUM (ANALYZE) operations only after the original signed run. Stop-and-cleanup trap always attempts to shut down retained clone. Only a successful continuation exit 0 and signed-readback result qualifies the full trial as accepted. The PostgreSQL restart might add background maintenance after the original measured run; those counters must not be misattributed to original ingestion.

## 2026-11-10 11:22 UTC — completed recovery and accepted 20-window signed candidate

Operator executed the pinned continuation `finish_completed_private_vacuum_candidate20_host.sh` against the original stopped 20-window clone (`fi-window-bench-optfield-v20-c-20261110T103933Z`). The run completed with **exit=0**. The originally successful 20-window ingestion was not replayed.

- **SQL:** `FI CANDIDATE20 RECHECK SQL INTEGRITY PASS checkpoint=23|2988103|22 authoritative=0 accepted=0`, `FI CANDIDATE20 RECOVERY GATE PASS checkpoint=23|2988103|22 new=20|20 seed=2|0`, and postmaintenance SQL integrity `PASS state=23|2988103|22 authoritative=0 accepted=0`.
- **Signed evidence:** 1,176 signed batch data files and matching manifests byte-identical to original verified cache.
- **Security/records:** W3–W22 exactly 20 committed windows with `2,597,716` new source records. W0–W22 cumulative `2,988,103`. `FI EFFICIENCY SINGLE PASS PASS windows=20 selected_rows=2313320`.
- **Resources:** Replay Go peak RSS `388536 KiB`, traced GC lines `1546`. These are process-only measurements, not PostgreSQL/host memory.
- **Performance:** committed-window time `1143.827s` (**19m03.827s**), `2271.1` records/sec. Postrun 20-leaf `VACUUM (ANALYZE)` separately measured `30` elapsed seconds (whole-second precision), giving a simple ingest+manual-maintenance accounting of `1173.827s`. This combined figure is not exhaustive system/idle debt accounting.
- **Private PostgreSQL:** source commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`; clone shut down cleanly at `FI CANDIDATE20 FINISHED exit=0`; real fi-sor-db untouched; zero authoritative or Accepted rows.

### Per-window result

| Window | Records | Committed seconds |
|---:|---:|---:|
| 3 | 129435 | 55.315 |
| 4 | 129743 | 52.491 |
| 5 | 130642 | 52.564 |
| 6 | 130755 | 52.082 |
| 7 | 128951 | 52.142 |
| 8 | 129842 | 53.018 |
| 9 | 129722 | 53.697 |
| 10 | 129213 | 54.465 |
| 11 | 128575 | 54.296 |
| 12 | 130887 | 61.434 |
| 13 | 130574 | 58.754 |
| 14 | 130377 | 58.829 |
| 15 | 129866 | 57.210 |
| 16 | 129892 | 62.364 |
| 17 | 130057 | 62.992 |
| 18 | 129270 | 60.533 |
| 19 | 130952 | 60.223 |
| 20 | 129718 | 60.254 |
| 21 | 128222 | 58.679 |
| 22 | 131023 | 62.485 |

Same-window candidate W3–W17 = `841.653s`, compared with old 15-window W3–W17 `906.203s` (`64.550s` less, `7.12%` elapsed reduction; **uncontrolled sequential historical comparison**, not an attributable vacuum-setting improvement). New candidate W3–W12 first 10 = `541.504s` vs W13–W22 last 10 = `602.323s` (both ten-window groups have slightly differing record counts). This is a concrete later-window slowdown worth diagnosing with SQL/host/Go stage metrics.

**Accepted metrics bundle:** `/var/tmp/fi-window-chunks-v20-c-20261110T103933Z/fi-vacuum-candidate20-20261110T103933Z.tar.gz`, generated and accepted on host, not yet uploaded into the assistant's working environment. The archive includes retained real replay before/after PostgreSQL counters and separately labeled `restarted_before_maintenance`/`maintenance_after` snapshots from continuation, Go stage/family/time, GC/RSS, signed readback and host I/O. Do not mix restart/maintenance samples with the timed replay.

**Engineering next step:** ingest full archive and use **measured W3–W22 per-stage and PostgreSQL evidence** to isolate Go envelope preparation, Security/File COPY, SQL table/index/partition finalization, WAL/checkpoints and vacuum/autoanalyze. Classify each nested stage before computing time attribution. Only then implement a small, benchmarked Go/SQL candidate, with regressions/rollback and no main changes. Do not claim the current per-leaf setting is production-justified based on a one-arm 20-window trial.