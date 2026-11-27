# FI C1 single-jail Go / PostgreSQL write-path review — 2026-11-26

**Status:** Read-only source review. No C1 engine, PostgreSQL schema, production setting, or receiver custody modification. Complete end-to-end Accepted publication was not yet shown in the review evidence; ingestion was reported as complete and independent B had reached group 16.

**Reviewed source:** `dev/c1-sor-single-jail-20261124` at `e19fbd3f4070cc7738a41bff17110d87ee118a9e`.

## Baseline and comparison constraints

The single-jail, original signed-generation test reported 15,140,785 records in 741.455 seconds = **20,420.37 records/s** ingestion-only. SourceParent: 2,221 handoffs. Typed: Security 13,407,898; NTFSFile 1,698,033; Coverage 8,069; USN 26,680; Other 105. Original private direct C1 benchmark: 14,647,307 newly ingested records in 715.119 seconds = 20,482.34 records/s; **0.30% higher**. These benchmarks have different start states (original seeded, new clone empty): compare rate as an engineering signal, not an identical A/B. Both exclude verification/publication tail from ingest rate.

No performance release claim until real independent verifier B, atomic Accepted, readback, original signed custody preservation, and clean restart/replay acceptance have all passed. Leave the single-jail implementation and durability settings unchanged while diagnosing.

## Confirmed strengths of the existing Go / SQL implementation

1. **One ordered SourceParent stream, not per-family source duplication.**
   `private_p6_sql_coordinator.go` uses `pgx.CopyFrom` and a reusable `[9]any` cursor. `private_c1_five_sql.go` uses one ordered connection with at most 4 in-flight parent handoffs. No per-record INSERT round trips in this hot path.
2. **One shared adaptive SQL worker pool.** `private_c1_five_sql.go` dynamically grows from 1 to 32 PostgreSQL writers as work queues grow; it retires idle workers. Security, File, Coverage, Other and USN do not each own permanent 32-connection pools. USN is submitted serially after previous File commit fences.
3. **Bounded buffered COPY and proven family preparation.** P5 has five prep lanes, 2–32 dynamic workers per family; P6 SourceParent is capped at 8,192 records / 64 MiB and Security at 8,192 records / 32 MiB in the approved candidate. The 30-second inactivity flush on 105 Other records caused 21 small SQL handoffs; this is negligible compared with the Security volume, and is NOT evidence to disable the idle timer.
4. **Security field expansion is streamed.** `security_bulk.go` and `security_field_copy_source.go` use a shared cursor and reused `[4]any` field row, chunked by rows/bytes. Avoid replacing with giant `[][]any` allocations.
5. **Source-to-child ordering, FK resolution, and durability have explicit gates.** Child family transactions await source commit and resolve original `(source_batch_id, record_ordinal)` keys. Each family ACK follows a durable PostgreSQL COMMIT. Independent B and governed Pending-to-canonical publication are separate acceptance gates.

## Concrete investigation candidates (ranked)

### A. Redundant Security SourceRecord identity lookup — most specific Go opportunity

`private_p6_sql_coordinator.go` `Family()` already calls `sourceIDs()` for all family rows. `private_p6_sql_security.go` passes that exact ordered ID vector into `security()`, where every `pending[i].sourceRecordID` is initialized from it. However `security_bulk.go` `copySecurityBulk()` performs another `lookupBulkSourceRecordIDs()` for the **same Security events** and overwrites `pending[i].sourceRecordID`.

This entails repeated mapping work on **13,407,898 Security events**, though the wall-time impact is unmeasured and might be small because PostgreSQL caches the unique index and the worker jobs overlap. Retain the second lookup until equivalence and negative-path tests prove that a verified ordered `[]int64` from the coordinator can be safely reused. A C1-only, proven-ID option must still verify length, positive IDs, signed batch/ordinal ordering, and exact matching to the source identity; ordinary FI ingestion retains its existing lookup. Keep verifier B independent. A/B this change on a fresh, isolated PG18 clone with an identical original signed generation.

### B. Index/foreign-key write amplification — likely larger SQL cost, but high correctness and read-performance risk

Canonical schema migrations define `source_record` primary and unique keys **plus two secondary btree indexes**, `windows_security_event` primary key **plus six secondary btree indexes**, and `windows_security_event_field` primary key **plus a field-name index**. Governed Pending mirrors the 49 canonical relations. Inserts into those relations maintain indexes, check constraints, and enforce referential integrity.

This is **not evidence that any index should be dropped**. Query workloads, B verification, canonical promotion, and post-publication read availability may need them. First compare `pg_indexes_size`, `pg_relation_size`, `pg_stat_user_indexes`, and commit/copy-stage timings. Then, only if write amplification is significant, run controlled separate-clone A/B for a **specific non-constraint secondary index** while proving original query plans, FK behavior, full proof, atomic promotion, and post-publication lookup latency. Do not change PKs/uniques, drop FK checks, or rebuild indexes on the live SoR as a tuning shortcut.

### C. Security fields COPY and PostgreSQL WAL/checkpoints — evidence before tuning

`private_c1_five_sql.go` already logs `FI C1 SECURITY COPY PROFILE`, `FI C1 SECURITY COPY CALL PROFILE`, `FI C1 SOURCE PARENT STAGES`, `FI C1 SQL PROFILE`, `FI C1 ORDERED SOURCE BACKPRESSURE`, and shared SQL pool peaks. These are the first measurements to collect. Security event-field expansion and btree maintenance can dominate SQL time even when preparation itself is fast.

PostgreSQL clone is running with 8 GiB max WAL size, 16 MiB WAL buffers and full durability. Review `pg_stat_wal` (WAL byte count, `wal_buffers_full`), `pg_stat_checkpointer` (requested/timed checkpoints), `pg_stat_io`, and per-relation heap/index sizes **on the isolated clone**. If checkpoint or WAL pressure demonstrably dominates, test one clone-only configuration change at a time with equivalent durability. Do **not** disable `fsync`, `synchronous_commit`, or `full_page_writes`.

### D. Adaptive SQL concurrency and transaction size — probably lower-priority

Observed ~67% distributed CPU and multiple COPY workers support useful concurrency on dual E5-2680 hardware. `private_c1_five_sql.go` already reports `peakWorkers`, `peakSecuritySQL`, per-family `parent_wait`, `fk_lookup`, `projector`, `commit`, queue backpressure and per-COPY latency. Treat the 32-worker cap, 8,192/32-MiB Security buffer and 64-MiB SourceParent cap as frozen until profiler output identifies wait concentration. Increasing workers or buffers can increase WAL contention and per-transaction exposure rather than improving the 20.4k rec/s rate.

### E. Full end-to-end publisher/retirement — separate from ingest throughput

`c1_sor_pending_publication.go` and `c1_sor_service.go` perform an independent signed-custody proof, relational remapping under locks, atomic Accepted publication, fresh readback and Pending retirement. Measure its entire wall time and lock waits separately: any publication tail is real user-visible acceptance latency, but **must not be folded into or silently used to revise the measured ingestion-only throughput**. No shortcuts on the signed-custody proof or atomic commit.

## Minimum evidence package

Without running any destructive SQL, collect:

- Original `FI C1 SQL PROFILE`, `SOURCE PARENT STAGES`, `SECURITY COPY PROFILE/CALL PROFILE`, `SHARED SQL POOL`, `ORDERED SOURCE BACKPRESSURE`, `LOCAL INGEST THROUGHPUT`, and `VERIFICATION/PUBLICATION TIMING` log lines.
- Clone-only `pg_stat_wal`, `pg_stat_checkpointer`, `pg_stat_io`, per-table `n_tup_ins`, physical heap/index sizes, and index scan counters. Statistics may have reset or include autovacuum and must not be treated as signed acceptance proof.
- Full Accepted, independent readback, and live-SoR unchanged markers before declaring the benchmark end-to-end PASS.

A read-only C220 probe is provided in `go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_sql_write_profile_readonly.sh`.

## Recommendation / stop rule

**Freeze 20,420.37 rec/s as the new engineering baseline.** Preserve existing defaults until profiling shows a substantial, reproducible bottleneck. First investigate redundant Security FK mapping (safe narrow optimization if properly proven), then index/WAL write amplification only with controlled clone A/B. Require identical signed-source hashes, SQL row families, B proof, canonical Accepted/readback, no data loss, and repeatable results before accepting any change. A tiny speed gain does not justify increasing operational risk for the county/911 target workloads.
