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

## 2026-11-10 10:14 UTC — operator-run five-window paired pilot: both PASS

Operator reported successful consecutive `control` and `candidate` runs of the pinned private leaf-only insert-vacuum pilot against real signed W3–W7. Exact optimized source SHA used in both: `b01ff0d8cb6559797de052f34b18bd84a395dc4c`. PostgreSQL 18.6, W128/P3/F3/K32, seed W0–W2. Both finished `exit=0`, no production/SoR changes. These are measured **console summary** results, not yet an analysis of their detailed archive counters.

| Acceptance/measurement | Control | Candidate |
|---|---:|---:|
| New durable windows | W3–W7 | W3–W7 |
| Exact new source records | 649,526 | 649,526 |
| Total SQL marker/checkpoint | `8|1039913|7` | `8|1039913|7` |
| Signed data+manifest bytes identical | 281 batches | 281 batches |
| Private new field leaf option count (total|overrides) | `5|0` | `5|5` |
| Single-pass Security event rows | 583,727 | 583,727 |
| Ingestion duration, sum committed windows | 278.481 s | 264.942 s |
| Throughput | 2,332.4 rec/s | 2,451.6 rec/s |
| Explicit five-leaf postrun `VACUUM (ANALYZE)` duration (wall seconds integer) | 4 s | 11 s |
| Ingest + explicit maintenance (rounded maintenance timing) | 282.481 s | 275.942 s |
| Peak replay-process RSS | 366,788 KiB | 366,016 KiB |
| GC lines | 387 | 390 |
| Canonical authoritative/Accepted rows | 0/0 | 0/0 |

Candidate improved committed-window elapsed by **13.539s (4.86% less time)** or **5.11% higher records/sec** on this exact fixed source. The slower postrun manual maintenance was **+7s**, leaving **6.539s (~2.32%) lower combined wall duration** when simply adding the independently rounded maintenance figures. This sum does not include all background maintenance before/after the run, and the runs were sequential rather than randomized/repeated, with possible host I/O variation: **no causal performance improvement claim yet**.

| Window | Control elapsed | Candidate elapsed | Candidate difference |
|---|---:|---:|---:|
| W3 (129,435 records) | 61.675s | 54.710s | -6.965s |
| W4 (129,743 records) | 52.929s | 51.895s | -1.034s |
| W5 (130,642 records) | 55.745s | 54.154s | -1.591s |
| W6 (130,755 records) | 53.603s | 51.876s | -1.727s |
| W7 (128,951 records) | 54.529s | 52.307s | -2.222s |

Recorded pilot output directories on host:

- Control: `/var/tmp/fi-window-chunks-v-b-20261110T100125Z/fi-vacuum-pilot-control-20261110T100125Z.tar.gz`
- Candidate: `/var/tmp/fi-window-chunks-v-c-20261110T100805Z/fi-vacuum-pilot-candidate-20261110T100805Z.tar.gz`

Both runners' own SQL integrity, signed readback, vacuum option, exact source-count, Security fast-path and cleanup checks passed. However, only the terminal outputs were provided so far. Next: inspect **both metrics-only tar archives** and compare relation before/after autovacuum/autoanalyze counters, PostgreSQL WAL/checkpoint/IO, timestamped vacuum samples, partition finalize timing, host iostat and the manual postrun vacuum cost. Look especially at W3, which produced 6.965s of the 13.539s ingress time difference. Retain the experiment and avoid changing default FI maintenance behavior before replicated alternating-order trials (including postrun repayment).