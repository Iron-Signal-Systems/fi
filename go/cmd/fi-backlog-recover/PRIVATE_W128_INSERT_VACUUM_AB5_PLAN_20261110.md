# Private W128 insert-triggered vacuum A/B pilot — 2026-11-10

## Decision being tested

The accepted 15-window FI Security/File replay showed approximately 275 seconds of cumulative PostgreSQL autovacuum worker time, concentrated in Security field leaves and source/event tables. This does NOT establish equivalent time lost from ingest: vacuum work can overlap ingest, and PostgreSQL VACUUM on insert-only tables is useful for all-visible/all-frozen pages and long-term visibility. The narrower hypothesis is that **deferring insertion-triggered VACUUM for NEW private Security field leaf partitions** might reduce ingest contention without increasing total ingestion-plus-maintenance cost.

PostgreSQL 18 documents `autovacuum_vacuum_insert_threshold=-1` as disabling insert-count-driven VACUUM for a table. It is **not** `autovacuum_enabled=false`, does not suppress autoanalyze and does not exempt anti-wraparound vacuum. See https://www.postgresql.org/docs/18/runtime-config-vacuum.html and https://www.postgresql.org/docs/18/routine-vacuuming.html.

## Controlled variables and scope

**Both modes build identical pinned Go source commit** `b01ff0d8cb6559797de052f34b18bd84a395dc4c`, with all accepted reusable COPY row paths plus the private canonical single-pass Security parser. Both modes replay the exact same verified signed W128 source window indexes 3–7, on independent freshly cloned PostgreSQL 18.6 databases restored from the same W0–W2 seed. Both use Security P3, File F3, K32=32768, window W128, `max_wal_size=1GiB`, `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`, unchanged source/manifest checks and byte-for-byte signed readback.

Only one independent variable changes:

- `control`: original SQL `fi_recovery_projection.begin_security_field_window(integer)` function creates each detached leaf without a per-table insert-vacuum override.
- `candidate`: same function in the **newly restored disposable clone** creates each detached leaf and adds `ALTER TABLE ... SET (autovacuum_vacuum_insert_threshold=-1)`. All other function behavior, owner/SECURITY DEFINER status and grants are checked unchanged. The candidate SQL is pinned to commit `dc556813d450f7ab79121d05e10e54c6d2732d01`; the original signed cache, seed and authoritative SoR are never modified.

No global autovacuum changes, no index drops, no WAL/durability relaxation, no producer code changes, no main merge.

## Acceptance criteria

- Each run must independently succeed with exact `FI PRIVATE EXACT WINDOW STOP start=3 windows=5 last=7`, five durable source and artifact windows, 649,526 new records, and cumulative W0–W7 of 1,039,913 records; SQL checkpoint `8|1039913|7`.
- `fi.recorded_generation=0`, Accepted journal=0; SQL counts, Security field partitions, verified source/artifact/typed markers, byte-for-byte signed data and manifests must match.
- New Security field leaf count must equal five. Per-table reloptions count must be `control=5|0` and `candidate=5|5`, checked against `pg_class` after replay. Original seed leaves unchanged. Optimized single-pass rows must be nonzero.
- Both runs execute identical process-only Go GC tracing, FreeBSD `time -l` max RSS, five-second host iostat/vmstat plus a **preflighted** five-second PostgreSQL WAL/checkpointer/vacuum/worker sampler. Relation-level vacuum and analyze statistics are captured before and after, including leaf `reloptions`.
- **Both modes run the same explicit VACUUM (ANALYZE) on their five private field leaves after the timed ingest and signed-custody checks**. This records possible deferred maintenance separately, with per-leaf and total postrun elapsed seconds, then captures distinct postmaintenance I/O and relation statistics. If candidate merely shifts expensive vacuum after ingestion, its total work must be considered before retention.

## Run protocol

Before starting **each** variant: verify no other `fi-dev` PostgreSQL postmasters are active, the seed and verified signed 8,399-batch cache match, socket path fits FreeBSD, and no output directory collision. The script has its own fail-closed checks and cleanup trap.

1. As `jwood` inside `fi-dev`, fetch `experiment/fi-file-validation-once-20261108`; extract the pinned pilot runner to `/home/jwood/fi-vacuum-ab5.sh`; run `sh -n /home/jwood/fi-vacuum-ab5.sh` and **do not run if syntax validation fails**.
2. On `fi-backend-b` as root: `jail_root=$(jls -j fi-dev path) || exit 1`. Run `sh "${jail_root%/}/home/jwood/fi-vacuum-ab5.sh" control`. Ensure exit 0 and record its `fi-vacuum-pilot-control-*.tar.gz` metrics archive.
3. After the control stopped its private clone, run the **same script** with argument `candidate`. Ensure exit 0 and record `fi-vacuum-pilot-candidate-*.tar.gz` metrics archive.
4. Analyze the **two actual metric archives** together. Compare per-window typed/projection/envelope and COPY timing, relation-level autovacuum worker durations/counts, WAL bytes/checkpoints/buffer_full, 5-second worker progress, host IO and process GC, and `MAINTENANCE_REPAYMENT.tsv` from each. Process-GC trace imposes similar overhead on both, so do not compare absolute speed to untraced historical results.

The script is `go/cmd/fi-backlog-recover/run_private_vacuum_ab5_host.sh` on the experiment branch, with supporting SQL in `testdata/private_field_insert_vacuum_candidate.sql`. **Status**: staged only, not executed on the user's FreeBSD host. No claim of speedup until matched control/candidate data are analyzed.

## Interpretation

A successful pilot establishes *direction*, not a production change. If observed ingest time drops, but manual repayment is correspondingly longer or storage/visibility costs increase, it is postponement, not an efficiency win. If the pilot shows a credible benefit with unchanged integrity and total maintenance cost, repeat with 15 windows in alternating control/candidate runs, with fresh clones and identical accepted input, to reduce I/O variability. If the pilot is neutral or worse, stop this idea and return to COPY/SQL or envelope-profile work.

PostgreSQL cumulative worker times overlap ingestion and each other; do not add their sums to ingest wall time. Cumulative relation stats may include restore/seed work; rely on **before/after differences from the same clone**.

## Final staged runner revision and gate

Runner file `go/cmd/fi-backlog-recover/run_private_vacuum_ab5_host.sh` audited through commit `210a500d0aacccb6a0546669c0fb056173f1daea`. It checks `SHOW autovacuum=on`, `SHOW track_counts=on`, global `autovacuum_vacuum_insert_threshold=1000`, and all original durability settings before applying the candidate to the disposable restored function. If these are not true, both variants MUST stop rather than silently benchmarking a changed global configuration. The five-second PostgreSQL sampling SQL is preflighted **before** the signed replay; the sample count and error log are checked on completion.

Both variants must be run separately; they create timestamped, mode-specific private clusters and outputs, automatically stopping clone and seed PostgreSQL. **Do not run baseline and candidate concurrently**; the environment preflight deliberately rejects another active `fi-dev` postmaster. Control must complete and clean up before the candidate starts. Both variants explicitly vacuum and analyze ONLY private Security field leaves W3–W7 after the timed replay, preserving both pre/post-ingest counters and separate postmaintenance counters; no production autovacuum or SQL objects are changed.

The runner has been authored and static source-guarded on the experiment branch, but not executed on FreeBSD. Required acceptance before any replay is `sh -n` on `fi-dev` plus all of the built-in shell/SQL preflights. Do not infer the experiment succeeded until both real signed runs exit 0 and their diagnostic archives are analyzed.
