# Private W128 15-window efficiency review — 2026-11-10

Scope: `b01ff0d8cb6559797de052f34b18bd84a395dc4c`, W3–W17, `fi-dev` detached PostgreSQL 18.6 clone, signed-cache original 8,399 batches. Metrics supplied in `fi-efficiency-metrics-20261110T073931Z.tar.gz`. This file is experiment-branch documentation; no main or SoR promotion.

## Verified integrated result

- `FI EFFICIENCY FINISHED exit=0`: W3–W17 all 15 windows durable, 1,948,531 new source records in 906.203s, 2,150.2 records/sec; cumulative W0–W17=2,338,918; W0–W12 prefix=1,688,152. Private SQL integrity passed; canonical SoR and accepted journal rows=0; 873 signed data/manifest files matched byte-for-byte; temporary PostgreSQL stopped.
- Source-family totals: Security events=1,737,100; fields=24,432,896; scopes=1,466,499; FileObservation=210,439. All Security events used the private canonical single-pass parser (`security_single_pass_rows=1,737,100`). All Security field row counts match attached partition rows. File observation source validation=210,439; reuse=210,439; additional bulk validations=0. All per-window family sums and SQL committed record counts reconcile.
- Historical first-ten-window 523.424s is not a comparable current control under different I/O load. Later clean control W3–W12=590.910s; current traced W3–W12=592.089s (+0.20% elapsed). `GODEBUG=gctrace=1` and host variability prevent a proven end-to-end speedup assertion. Retain allocation improvements as independently validated; no measured pre/post peak memory difference.

## Application-stage wall cost (stage counters are nested: DO NOT SUM THEM)

| Measured stage | W3–W17 seconds | Comment |
|---|---:|---|
| Typed-window stage | 885.855 | Compare with 906.203s total committed-window time |
| Batch ingest | 745.552 | Nested inside typed |
| Relational projection | 341.821 | Security and File included |
| Security projection | 208.261 | All Security event/scope/field COPY nearly equals this |
| File projection | 130.770 | Spikes on file-heavy W12/W17 and on W16 |
| Envelope preparation | 169.953 | ~11.33s/window, consistently high |
| Security field COPY | 96.372 | 24.43M field rows, partitioned |
| Security event COPY | 78.934 | 1.737M event rows |
| Security scope COPY | 32.904 | 1.466M scope rows |
| Source SQL | 59.635 | Includes source-record COPY/lookup |
| Batch hashing | 54.883 | Signed evidence remains mandatory |
| Source reading | 51.556 | Input ownership and source read |
| Verification | 44.058 | Do not bypass accepted durability/coverage checks |

Security field+event+scope COPY = 208.210s of the 208.261s inclusive Security projection. The measured SQL COPY call duration includes pgx encoding, host/relay transport, and PostgreSQL processing; the archive alone cannot assign the 208s to a single layer. Logs also contain 282 `INGEST COPY TABLE` summaries across 34 named relations, 0 reported errors. Main table COPY totals: Security field 96.37s, events 78.93s, source_record 56.59s, scopes 32.90s, file_observation 18.86s, content_hash_observation 18.56s, security_ace 15.80s. All COPY totals are included in other stage categories and should not be blindly added.

## Workload and late-window slowdown

- W3–W12: 1,297,765 records / 592.089s = 2,191.8 rec/s. W13–W17: 650,766 records / 314.114s = 2,071.8 rec/s.
- W3–W12 average typed stage 58.302s and relational projection 22.118s per window; W13–W17 averages 60.567s and 24.129s. Envelope preparation stayed broadly flat: 11.367s vs 11.257s per window.
- W12 had 19,907 FileObservation records with File projection 12.02s; W17 had 19,714 and File projection 12.06s, vs ordinary ~13,000 FileObservations and ~7–9s file projection.
- W16 was slower with a normal 13,269 FileObservation count: 66.931s committed time, 63.356s typed stage, 10.545s File projection, 15.087s Security projection and 2.182s signed artifact stage. W17 signed artifact stage=3.196s. W15 partition validate/attach=8.661s yet committed time=60.047s; partition finalize alone cannot explain slow W16/W17.

## PostgreSQL before/after counters (same stats_reset)

| Counter | Delta |
|---|---:|
| `pg_stat_wal.wal_bytes` | 16,086,069,260 B = 14.981 GiB |
| `pg_stat_wal.wal_records` | 67,037,436 |
| `pg_stat_wal.wal_buffers_full` | 329,011 |
| Requested checkpoints | 29 (0 timed) |
| Checkpointer cumulative write_time | 801.503s (overlapping background work; NOT 801s ingest stall) |
| Checkpointer cumulative sync_time | 3.587s |
| Autovacuum-worker relation read_bytes | 18,512,715,776 B = 17.24 GiB across normal + vacuum context (vacuum context alone=18,453,037,056 B = 17.18 GiB) |
| Autovacuum-worker relation write_bytes | 5,295,202,304 B = 4.93 GiB (vacuum context alone=5,278,138,368 B = 4.92 GiB) |
| Autovacuum-worker WAL write_bytes | 7,376,740,352 B = 6.87 GiB of WAL writes attributed to process, NOT extra generated WAL |

These are PostgreSQL backend I/O counters; they must not be treated as unique physical disk transfer totals. The run used PostgreSQL `max_wal_size=1GB`, `wal_buffers=4MB`, with `fsync`, `synchronous_commit` and `full_page_writes` all ON. `track_io_timing=off` and `track_wal_io_timing=off` leave I/O wait-time attribution unavailable. There is no per-relation vacuum table or per-window PostgreSQL counter series in the archive. No specific table, vacuum, checkpoint or Proxmox source is proven responsible for the throughput variability.

## Go/host resource evidence

- Go GC cycles=1,176; total reported stop-the-world pause=0.186s, median STW pause 0.146ms, p95 0.201ms. Reported GC heap peak 331 MiB; process peak RSS 389,208 KiB (~380 MiB). This is NOT total machine memory, nor proof of memory reduction against an unavailable baseline.
- Guest disk `vtbd0` busy averaged 36.8%, p95 ~84.9%, max 95% over 182 5-second samples; `vmstat` host-wide average CPU idle ~83.4%. This supports I/O variability as a hypothesis, not a causal diagnosis of Proxmox/storage.
- The recovery process used 375.73s user CPU plus 55.68s system CPU. GC concurrent activity can consume CPU even though stop-the-world pauses were tiny; do not eliminate GC optimization purely because pauses were short.

## Decision and next data-collection gate

Keep all four reusable COPY row sources and the strict-equivalent canonical Security single-pass scanner in experiment. The run establishes private signed workload correctness, not a clean speedup. Do not change main, disable autovacuum, remove SQL validation, weaken fsync, or adjust PostgreSQL WAL limits based solely on this run.

Next **measurement-only** isolated replay should add: relation-level `pg_stat_user_tables` including per-table `autovacuum_count`, `autoanalyze_count`, total autovacuum/analyze times, inserted/dead tuples, and relation/index sizes; sampled `pg_stat_progress_vacuum` joined to `pg_class`/`pg_namespace`; the autovacuum portions of `pg_stat_activity`; per-window snapshots of `pg_stat_wal`, `pg_stat_checkpointer`, `pg_stat_io`; and (only on the disposable clone) an explicit decision on `track_io_timing`/`track_wal_io_timing` with its overhead documented. Correlate exact snapshots to durable window index. Inspect per-relation maintenance before choosing a WAL-size or autovacuum experiment. A separate CPU/alloc profile should target the still costly envelope and File subpaths.

All metrics originate from actual user-supplied private run logs. The experiment documentation's longer original run output remains the authoritative acceptance trace.
