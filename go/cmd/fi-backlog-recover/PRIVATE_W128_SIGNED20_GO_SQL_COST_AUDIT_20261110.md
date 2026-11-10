# FI private signed W128: twenty-window Go and PostgreSQL cost audit

**Date:** 2026-11-10  
**Status:** accepted experimental evidence; **no production or main-branch optimization approval**  
**Source:** uploaded `fi-vacuum-candidate20-20261110T103933Z.tar.gz`, exact retained private W3–W22 trial, Go source commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`. The archive contains original replay `before/after` snapshots **and** a later separately marked `restarted_before_maintenance/maintenance_after` interval. Never merge those intervals when attributing ingest costs.

## Integrity and scope

- Exact 20 new durable windows W3–W22, 2,597,716 new records; SQL checkpoint `23|2988103|22` (2,988,103 cumulative records including original seed W0–W2).
- All 1,176 signed batch data files and manifests byte-identical; 20/20 new Security field leaves have candidate insert-autovacuum setting, 2/2 original W1/W2 seed leaves unchanged; W0 is a marker, **not** a leaf.
- 2,313,320 Security event records successfully used canonical single-pass path; PostgreSQL SQL-integrity and postmaintenance checks passed; canonical/Accepted rows both 0.
- 1,143.827s committed-window ingest elapsed (**2,271.1 records/s**), plus separately measured 30s whole-second post-ingest manual private leaf `VACUUM (ANALYZE)`. This is **not** a production benchmark or an isolation proof for the vacuum setting. Go process peak RSS 388,536 KiB, GC trace 1,546 events. Process time ~489.34s user, 70.29s sys, 1144.22s wall (host `time -l`).

## Inclusive/nested stage totals (NOT additive)

| Measured stage | W3–W22 total | First ten W3–W12 | Last ten W13–W22 | Difference |
|---|---:|---:|---:|---:|
| `typed_total` (outer typed transaction wall) | 1125.733s | 533.811s | 591.922s | +58.111s |
| `batch_ingest` | 966.749s | 466.735s | 500.014s | +33.279s |
| `projection_total` | 443.518s | 209.178s | 234.340s | **+25.162s** |
| `file_projection_inclusive` | 173.067s | 77.149s | 95.918s | **+18.769s** |
| `security_projection_inclusive` | 266.358s | 130.116s | 136.242s | +6.126s |
| `envelope_prepare` | 221.418s | 110.381s | 111.037s | +0.656s |
| `source_read` | 63.798s | 31.997s | 31.801s | -0.196s |
| `batch_hash` | 72.063s | 35.935s | 36.128s | +0.193s |
| `source_sql` | 76.294s | 37.187s | 39.107s | +1.920s |
| `verification` | 43.606s | 22.953s | 20.653s | -2.300s |
| `security_field_copy` | 119.539s | 57.844s | 61.695s | +3.851s |
| `security_event_copy` | 104.030s | 50.787s | 53.243s | +2.456s |

These counters are **nested**, e.g., the File/Security projections contribute to total projection and COPY is included in its owning projection; do not add columns to estimate absolute lost wall-clock time. The difference in committed-window elapsed is **not** entirely accounted for by typed stage differences because the outer durable window includes artifact work and other steps.

### Workload-adjusted interpretation

- FileObservation count first 10 **137,777**, last 10 **145,284**, only **+5.45%**. File projection elapsed rose **+24.33%**, hence file projection cost per file grew approximately **18%**. Periodic heavy FileObservation windows W12, W17 and W22 (approximately 19.7–19.9K vs 13K typical) matter, but do not fully explain the normalized upward trend.
- Security event count first 10 **1,159,345**, last 10 **1,153,975**. Security fields first 10 **16,298,841**, last 10 **16,244,651**. Similar or slightly smaller data volume later, yet Security field-copy latency modestly worsened.
- Independent detached Security field finish/constraint validation/attach (`PER_WINDOW_FAMILIES.partition_validate_attach`) first ten **33.521s** (3.352s/window), last ten **57.620s** (5.762s/window), **+24.099s** (+71.9%) despite similarly sized fields (~1.6M/window). This latency is a separate primary optimization target. Window W20 had an 8.876s finalize.
- **Go envelope preparation is stable**: 110.4s vs 111.0s, a large but constant **221.4s across all 20 windows**. Reading and hashing are also stable. Do not attribute later-window regression to Go decoder/JSON work without new evidence.

### Per-table PostgreSQL COPY observations

A total of 376 `INGEST COPY TABLE` rows from 20 independently committed windows were aggregated by destination table. They include returned PostgreSQL `COPY` latency, not isolated index timing.

| Table | Aggregate COPY time | Rows | Calls | First 10 vs last 10 |
|---|---:|---:|---:|---|
| `windows_security_event` | 104.02s | 2,313,320 | 1,122 | 50.79s → 53.24s |
| `source_record` | 72.28s | 2,596,574 | 1,173 | 35.29s → 36.99s |
| `windows_security_event_scope` | 42.71s | 1,953,935 | 1,122 | 21.45s → 21.27s |
| `content_hash_observation` | **25.41s** | 283,061 | 43 | **8.607s → 16.799s (+8.192s)** |
| `file_observation` | 25.25s | 283,061 | 43 | 11.93s → 13.32s |
| `security_ace` | 20.87s | 941,635 | 929 | 9.85s → 11.02s |
| `sacl_ace` | 12.15s | 566,122 | 559 | 5.83s → 6.32s |
| `file_metadata_observation` | 8.93s | 283,061 | 43 | 3.58s → 5.35s |

**Content-hash COPY latency is the clearest growing constituent of File projection**. It explains ~44% of the absolute +18.77s File projection rise, but this is not enough to claim the exact cause is a B-tree, FK, table growth, buffer eviction or autovacuum. The code sends validated rows using the bounded `contentHashCopyState.copyRows` `pgx.CopyFrom` call in `go/internal/recordingest/content_hash_copy.go`. The private projection inherits `fi.content_hash_observation` constraints and two conditional lookup indexes from `database/schema/0001_relational.sql`: a primary-key/FK to `file_observation`, and SHA-256 and MD5 partial indexes. Check measured index sizes and FK/constraint work **before** considering index changes; query/index correctness must not be sacrificed to make COPY look faster.

### Actual PostgreSQL replay vs continuation costs

All replay counters below are **after minus before** from the original **timed replay** interval:

- `pg_stat_wal`: **19.739 GiB WAL generated**, **1,174,355 WAL full-page images** and **454,014 `wal_buffers_full`**. These values measure WAL work, not direct blocked/waited seconds.
- `pg_stat_checkpointer`: **39 requested, 38 completed** checkpoints during replay. `max_wal_size=1GiB`, `wal_buffers=4MiB`, `checkpoint_timeout=5min`. `fsync`, `synchronous_commit`, and `full_page_writes` were ON and remain non-negotiable. Snapshot `track_io_timing=off` and `track_wal_io_timing=off`; cannot infer checkpoint stall seconds from PG timing counters.
- Relation totals: 279 autovacuum runs, **198.806s cumulative autovacuum-worker time**, 253 autoanalyzes, **214.443s cumulative worker time**. Times can overlap one another and ingest; **do not subtract from ingest wall time**.
- All 20 newly created W3–W22 field leaves correctly showed **0 automatic vacuum** due to candidate setting, while **19 of 20** had 1 autoanalyze by the replay after snapshot, costing **109.920s aggregate worker time**. W22 had not yet been autoanalyzed by that snapshot. Thus the option did not remove other SQL maintenance.
- `pg_stat_io` autovacuum worker cumulative during ingest: ~**20.213 GiB relation reads** and **6.278 GiB relation writes** in vacuum context, plus worker-attributed WAL writes that are *not additional unique WAL generated*. `pg_stat_io` worker categories show significant maintained shared-table work.
- `pg_5sec_samples.jsonl` 224 samples (first W0–W2 checkpoint at start; last committed W21 before final W22). It returned **zero visible `autovacuum_workers`** throughout, despite 279 completed vacuums. Therefore it **cannot** substantiate claims about worker wait states; investigate `pg_stat_activity` permissions/filtering and sampling resolution before relying on this observer. The snapshot WAL and I/O deltas remain useful.
- Host `iostat` `vtbd0`: mean busy ~33.5%, 95th-percentile busy ~78%, maximum ~92%; averages hide bursts and these samples are **host-wide**, not FI-only.
- The **later continuation** (private clone restart followed by 20 manual `VACUUM (ANALYZE)` calls, 30s whole-second elapsed) registered another **3.062 GiB WAL** and **5 requested checkpoints** between `restarted_before_maintenance` and `maintenance_after`; these counters include concurrent/background database activity and restart timing effects and are **not** attributable exclusively to each manual VACUUM operation. Do not mix with the original 19.739 GiB replay.

## Ranked engineering actions (no production behavior changed yet)

### P1 — SQL File projection / hash observation growth

Code focus: `go/internal/recordingest/content_hash_copy.go`, `file_observation_bulk.go`, `file_child_bulk.go`; `database/schema/0001_relational.sql` (hash PK/FK, SHA-256/MD5 partial indexes), private `fi_recovery_projection` equivalents.

**Next measurement:** on the disposable clone, gather `pg_relation_size`, `pg_indexes_size`, each `pg_index`/constraint definition and `pg_stat_user_indexes`, plus `pg_stat_all_tables`, relation/TOAST sizes. Correlate content-hash per-call latency by signed-window index and row count. Compare actual query needs for hash lookups before any isolated DDL candidate. **Do not disable FK, drop indexes or change canonical schema based solely on a 0 read-side `idx_scan`.**

**Go-side candidate, not yet validated:** introduce an isolated per-file-stage lifetime/batching microprofile that measures CPU allocations and row preparation separately from the existing measured `pgx.CopyFrom` time. Current `F3` hash limits are **8192 rows/8MiB**; do not assume a larger buffer solves increasing database-side latency. If tested, change only hash buffer limits in a separately named private test profile and prove identical SQL rows and allocation/heap bounds, with a matched same-source clone comparison.

### P2 — SQL Security field finalize cost

Code focus: `go/cmd/fi-backlog-recover/testdata/private_field_partitions_isolated.sql` or `private_field_partitions_finalize_timed.sql`, invoked by `go/internal/recordingest/backlog_typed_window_postgres.go`.

Current private `finish_security_field_window` performs exact `SELECT count(*), min(source_record_id), max(source_record_id)+1` over each ~1.6M-row leaf, validates a NOT VALID range CHECK, validates a NOT VALID FK to Security event parent, and then attaches it. **Profile these operations individually** inside a disposable-clone fixture to discover which full-table scan or index work expands with accumulated SQL rows. Preserve exact row count, validated range, FK integrity, atomic W128 rollback, and attachment semantics. An apparently faster attach that defers FK or count validation is **not** an improvement under FI acceptance.

### P3 — PostgreSQL WAL/checkpoint pressure

Single-variable cloned-host A/B `max_wal_size` (e.g., 1GiB control vs a larger explicit candidate) **with a free-space guard and separate postrun checkpoints/debt accounting**. Capture `wal_bytes`, requested/done checkpoints, `wal_buffers_full`, host I/O, per-window typed time and all signed-custody checks. This is a PostgreSQL **configuration experiment**, not a claim that checkpoint volume caused a specific W12/W16 delay. Never relax durability.

### P4 — Go envelope preparation, only after SQL tests

`envelope_prepare` totals 221.418s, so it is a genuine sizable optimization ceiling, but its stable 11s/window means it **does not explain the later slowdown**. Obtain private-only Go CPU/alloc profiles and targeted benchmarks of `security_single_pass_candidate.go` and their strict-envelope and malformed-input fallback/validation tests. Optimize only a measured hot call. Do not drop strict decoding, signed SHA checks, canonical source proof or fail-closed paths.

## Decision and next acceptance

**Retain the experiment, not the setting as a supported default.** This was one completed 20-window candidate with no same-run 20-window control and mixed background I/O. The available evidence most strongly supports targeting (1) growing File hash-related COPY latency and (2) growing Security field partition finalization. Keep the accepted source and original signatures immutable. Build and validate at most one experimental Go or SQL change at a time in the existing experiment branch, with no writes to SoR/main and a paired representative signed 5–10-window trial before more full replays.

No new Go or SQL optimization has been run based on this audit yet. This document defines concrete, testable next work rather than implying a demonstrated speedup.

## 2026-11-10 — targeted retained-clone SQL index metadata review staged

Read-only follow-up script: `go/cmd/fi-backlog-recover/inspect_completed_private20_sql_indexes_host.sh`, source audit commit `8903adfeab7b862242dfef5bd0d05282931f2f47`. It is adapted from the accepted no-replay 15-window relation inspector, pinned to this completed W3–W22 clone/source/checkpoint and accepted summary. It starts **only** that stopped disposable PostgreSQL instance with `listen_addresses=` (Unix socket only), `autovacuum=off` **during inspection only**, `default_transaction_read_only=on`, and unchanged source/SoR. It queries only catalog/statistics views: per-index definitions/sizes/read usage for implicated File hash and Security field tables, per-table heap/index/total sizes and constraints/validation flags, plus cumulative FI relation/TOAST maintenance. It writes a metadata-only archive and stops the clone; no signed replay, schema modifications, VACUUM or other SQL writes are attempted. PostgreSQL startup/shutdown itself may write internal data. The observer’s postrestart stats are explicitly not treated as the original replay deltas.

On `fi-dev` as `jwood`, fetch branch and extract the pinned inspector with `git show 8903adfeab7b862242dfef5bd0d05282931f2f47:go/cmd/fi-backlog-recover/inspect_completed_private20_sql_indexes_host.sh > /home/jwood/fi-postrun-index20.sh`, then require `sh -n` success. On `fi-backend-b` as root: `jail_root=$(jls -j fi-dev path) || exit 1`; `sh "${jail_root%/}/home/jwood/fi-postrun-index20.sh"`. Archive is printed as `FI POSTRUN SQL INDEX REVIEW PASS`. Never run this while any other fi-dev PostgreSQL clone is active. **This helper has not been run on the operator host; the experiment results above are fully accepted independently of this optional metadata inspection.**