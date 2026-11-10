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

## Next diagnostic: reuse stopped 15-window clone before any new replay

PostgreSQL 18 persists cumulative stats through clean shutdown. The optimized W3-W17 private PostgreSQL clone completed cleanly and was stopped, not deleted. Retrieve the relation-level maintenance counters now instead of immediately replaying another 15 windows. See PostgreSQL 18 §27.2 cumulative statistics documentation.

On experiment branch: `go/cmd/fi-backlog-recover/inspect_completed_private15_postgresql_host.sh` (postrun reviewer, fixed in commit `a14229428bf78621304690a430cbff9007fd0401`). It is pinned to the original private `fi-dev` clone path and actual built source commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`. It checks the accepted 15-window run manifest, verifies that no other `fi-dev` PostgreSQL postmaster is running, restarts **only that private stopped clone** with Unix sockets only, SQL read-only by default and autovacuum OFF **for inspection only**, verifies `fi_recovery.typed_window` is `18|2338918|17` and that canonical/Accepted rows stay zero, then emits relation maintenance, TOAST-to-parent mapping, largest indexes and PostgreSQL statistics identity. The host script's exit trap stops the clone again.

Created metrics: `RELATION_MAINTENANCE.jsonl` (all `fi*` schema partitions and their owned `pg_toast` tables, vacuum/analyze duration/count/last timestamp, dead/insertion estimates, relation size/reloptions); `FI_INDEXES.jsonl` (index sizes and scan counters); `TOP_MAINTENANCE.csv`; `STATISTICS_IDENTITY.jsonl` (stats resets and counters); `PG_AFTER_RESTART.jsonl`, README and one **metadata-only** tar.gz. No signed payloads, table contents, or database dumps included.

**Important:** PostgreSQL startup/shutdown is not bit-for-bit read-only on disk, even with read-only SQL sessions. Data lives in the disposable clone; the SoR, trusted seed and original signed cache remain untouched. `autovacuum=off` affects *only this postrun inspection session*. Relation stats are cumulative since statistic reset, not precise W3-W17 deltas; PG startup can also add small maintenance. Confirm `stats_reset` against the prior snapshot before attributing every counted VACUUM to the signed replay. The previous 15-window archive still cannot reconstruct per-window vacuum timing or actual wait-time without new sampling.

Proceed only after host `sh -n` syntax check. Once collected, compare top relation maintenance duration with Security field partition, source, and TOAST index sizes. Then select a single controlled improvement or add short cadence per-window SQL stats capture to a future replay. Do **not** relax durability/autovacuum on ingestion based solely on aggregate counters.

## 2026-11-10 09:26 UTC — retained PostgreSQL clone relation inspection PASS

Inspection output: `fi-postrun-relation-review-20261110T092339Z.tar.gz` (operator-supplied). `inspect_completed_private15_postgresql_host.sh` completed `exit=0`, verified pinned source `b01ff0d8cb6559797de052f34b18bd84a395dc4c`, SQL checkpoint `18|2338918|17`, SQL `default_transaction_read_only=on`, inspection `autovacuum=off`, then stopped the private PostgreSQL clone cleanly. The archive contains 237 `pg_stat_all_tables` FI/TOAST relation records, 273 index-stat entries, stats identity and named PostgreSQL 18 counters. Original signed data and SoR remain unchanged.

### Time and reset provenance

`STATISTICS_IDENTITY.jsonl` inspection at 2026-11-10 04:23:40 -05:00 reports `wal_stats_reset=2026-11-10 02:39:51.328309 -05:00`, identical to the prior original run's pre/post `pg_stat_wal` snapshots. `pg_stat_database.stats_reset` is null (not proof of a reset at exact replay start). `last_autovacuum` timestamps for active FI relations lie between 02:41:31 and 02:56:35 -05:00, within the original ingestion interval. **All table stats are cumulative across this clone's restore, seed and replay, not independent W3-W17 relation deltas; do not subtract them as if they were pre/post.** PostgreSQL restart after the captured 15-window PG snapshots also caused small extra WAL/stat changes, so use the original archive's before/after deltas for timed replay volume, not the postrestart total.

### Vacuum/analyze ranked by relation (PostgreSQL pg_stat_all_tables time units are milliseconds)

| FI relation or group | Autovacuum worker time | Runs | Autoanalyze time | Autoanalyzes |
|---|---:|---:|---:|---:|
| 18 populated Security field partitions: seed plus W1–W17 | 110.094s | 18 | 13.192s | 18 |
| `fi_recovery_projection.windows_security_event` | 55.655s | 7 | 14.685s | 6 |
| `fi_recovery.pending_source_record` | 27.053s | 16 | 18.160s | 12 |
| `fi_recovery_projection.source_record` | 24.835s | 11 | 13.380s | 10 |
| `fi_recovery_projection.file_observation` | 12.290s | 15 | 8.943s | 11 |
| `fi_recovery_projection.windows_security_event_scope` | 9.620s | 11 | 3.823s | 8 |
| All remaining matching FI and FI-owned TOAST relations | 35.817s | 157 | 32.946s | 153 |
| **TOTAL (non-additive concurrent worker times)** | **275.364s** | **235** | **105.129s** | **218** |

Field partitions + Security event + two source ledgers explain **217.637s (~79.0%)** of cumulative autovacuum worker time. Each populated Security field partition was vacuumed once (5.332–6.641s per partition) and analyzed once. These are *worker durations* (which include possible cost-based sleeps) and can overlap ingest and each other: **275s is not 275s proved lost ingest time**.

### Insert-only pattern and non-leading causes

- All 237 returned relations showed `n_tup_upd=0`, `n_tup_del=0`, and `n_dead_tup=0` at collection. The latter is an estimate *after* vacuum, not a historic pre-vacuum snapshot. Along with ~41.7M cumulative inserted tuples, this strongly supports **insert-triggered VACUUM for visibility/freeze**, not dead-version cleanup, as the main maintenance pattern. PostgreSQL 18 explicitly documents insert-based vacuum thresholds and visibility-map/freezing benefits (official manual §§19.10, 24.1). Such work is not categorically wasteful.
- 117 associated `pg_toast` tables reported 0 autovacuum runs and 0 vacuum/analyze worker duration. The key maintenance load was **not** in TOAST.
- The private clone has ~5.585 GiB of heap files, ~2.081 GiB of indexes, and ~7.669 GiB total relation storage after seed plus W3–W17, with 18 field partitions alone ~3.387 GiB. Sizes are postrun totals, not incremental writes during the 15-window workload.
- 273 index entries include 125/142 unscanned read-side indexes in `fi_recovery_projection` (about 1.547 GiB) and 5/6 in `fi_recovery` (~0.149 GiB). `idx_scan=0` means no counted read-side scan in this ingest clone; it does **not** imply indexes were free to maintain on inserts or safe to remove from the published query projection. Do not drop them on this evidence.
- Original *timed* PostgreSQL `pg_stat_io` before/after deltas corroborate autovacuum worker `relation/vacuum` **18,453,037,056 B (~17.18 GiB) read** and **5,278,138,368 B (~4.92 GiB) written**. Autovacuum backend WAL write attribution ~6.87 GiB reflects writes, not additional unique WAL generated. WAL generated during timed replay was ~14.98 GiB with 29 requested checkpoints. The postrestart cumulative WAL figure is not the timed-replay delta.

### Decision: first controlled maintenance experiment, private-only

Prioritize a one-variable A/B experiment controlling **insert-triggered VACUUM on disposable private Security field leaf partitions only**, not system-wide autovacuum. On PostgreSQL 18 a leaf table storage parameter `autovacuum_vacuum_insert_threshold=-1` suppresses **insert-triggered** autovacuum on that table; it does not disable autoanalyze or emergency wraparound protection. Apply only when each disposable W3–W17 leaf partition is created, preserving the canonical SoR, old seed, 32,768 source chunk, source commit, WAL, synchronous durability, signed input, partition indexes and remaining table maintenance. Official PostgreSQL 18 `CREATE TABLE` storage parameter documentation confirms leaf-table overrides.

Measure both variants under an identical 15-window source workload, but first consider a short paired pilot to validate selection and metrics. Capture each window's `pg_stat_all_tables`, `pg_stat_io`, `pg_stat_wal`, `pg_stat_checkpointer` deltas, `pg_stat_progress_vacuum` and `pg_stat_activity` samples, per-stage latency, exact signed result, host IO, process RSS/GC and reproducible source hash. Also measure **post-run maintenance** (`VACUUM (ANALYZE)` in the disposable clone, outside timed ingest) as required; an apparent gain that merely defers work is not a net efficiency improvement. Preserve `ANALYZE`, visibility-map/query behavior, freeze safety and published-query acceptance as explicit checks. `autovacuum=off` for the postrun *inspection* did not apply during the signed replay and must not be misinterpreted as an optimized ingestion setting.

**Do not** globally turn off autovacuum, drop indexes based solely on `idx_scan`, change `max_wal_size` yet, reduce `fsync`/durability, or claim autovacuum caused any particular slow W16/W17 window without timestamp-aligned I/O/vacuum samples. The insert-only maintenance pattern is a grounded candidate, not yet a measured causality/speedup proof.