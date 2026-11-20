# FI C1 development: WAL, vacuum, Security COPY, and recoverable 4 GiB groups

Date: 2026-11-20. State: **DEVELOPMENT ONLY**. No canonical FI SoR, no live
ingest, no accepted/published generation, and no production setting changes.

## Immutable acceptance baseline

Successful private C220 C1 replay on commit
`2fb7e27726b6c0bb6245ae1c6d6c5387344d3377`:
- Original receiver-signed generation: 8,399 batches, 15,140,785 records,
  65,205,192,753 bytes including prior verified seed.
- New source: 14,647,307 records, 63,081,148,153 bytes; 15 groups up to
  4 GiB; seed has 493,478 records and supplies the first typed marker.
- 16 maximum adaptive shared SQL workers; P5 five preparation families.
- Mandatory ordered USN SQL handoff ACK; other families stay concurrent.
- Full private grouped relational proof PASS, 16 typed markers, 0
  authoritative, 0 Accepted, 0 published; artifact/source markers remain
  **seed-only**.
- Full-run elapsed 1,167.289 s; 12,548.14 records/s.
- PostgreSQL baseline `max_wal_size=1GB`, `wal_buffers=4MB`,
  `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`.
- Checkpointer delta (same stats_reset): requested=209, completed=209,
  timed=0, write_time=1,003,138 ms, sync_time=88,701 ms,
  buffers_written=592,913. These phases can overlap application work.
- Approximate full-run pg_stat_wal: 107.47 GiB WAL, 7.47 million FPI,
  and 4.47 million WAL buffer-full events.

## Stage 1 — Isolated WAL size A/B (implemented; C220 execution pending)

New branch `dev/c1-pgwal-8g-20261120` changes **only**
PostgreSQL `max_wal_size` from 1GB to 8GB **on a disposable clone**.
The verified seed, source commit, Go pipeline, 4 GiB groups, pool maximum,
WAL buffers, and durability options stay unchanged.

- A: established full 1GB/4MB run (keep all evidence).
- B: new, fresh 8GB/4MB run (compile+race first; stop if preflight fails).
- Capture before/after `pg_stat_wal`, `pg_stat_checkpointer`,
  `pg_stat_io`, `pg_stat_bgwriter`, and `pg_stat_user_tables/indexes`
  as well as existing P5/P6 per-family counters, `iostat`, `vmstat`,
  and external host/ZFS resource telemetry.
- Examine requested versus timed checkpoints, FPI/record,
  WAL GiB/record, WAL buffer-full/record, input records/sec, application
  and cumulative SQL time, autovacuum load, and ZFS write latency.
- Clone startup must report `SHOW max_wal_size=8GB`, `wal_buffers=4MB`,
  and all durability switches on or fail closed.
- Hard acceptance: exact signed hash/count/bytes coverage, relational
  source/child totals and USN binding, private completeness proof,
  no canonical/Accepted/published rows, clean shutdown, unchanged seed.
- **No improvement or correctness claimed for B until its C220 evidence exists.**

## Stage 2 — WAL buffers A/B (next isolated branch, NOT enabled in Stage 1)

Only after Stage 1 passes and its metrics are reviewed, compare fresh
8GB/4MB versus 8GB/16MB private clones. `wal_buffers` is a start-time
PostgreSQL setting, not a safe live ingest adjustment. Keep
`max_wal_size=8GB`; do not change WAL segment size, checkpoint_timeout,
or any durability setting. Decide based on `wal_buffers_full`,
WAL FPI, throughput, and consistent SQL/IO measures. Additional tuning
must not hide an incomplete capture or change family scheduling.

## Stage 3 — Diagnose autovacuum; do not disable it

The Stage 1 runner captures PG18 per-relation `autovacuum_count`,
`total_autovacuum_time`, `n_dead_tup`, `n_ins_since_vacuum`,
inserts/updates/deletes, and table/index byte sizes; plus
`pg_stat_io` before/after. Compare per-relation deltas, distinguish
vacuum writer from checkpointer and background writer, correlate
with WAL/FPI and host ZFS samples. Only propose per-table tuning after
identifying the actual hot relations and verifying correctness.
Never disable autovacuum as a benchmark shortcut.

## Stage 4 — Profile native Security field COPY

Keep the original P6 five-family SQL projector and its COPY targets.
Existing C1 counters report Security source/event/scope/field COPY,
lookup, preparation and per-family SQL/commit time. Stage 1 additionally
collects per-relation insert, vacuum and index size deltas.
Initial known full-run work: ~182.57 million Security field children.
Review field COPY rows/s; time/field; total index bytes/field; source
hand-off queue/SQL wait; WAL/FPI and pressure. Only then consider
a separate code-level improvement on an isolated branch. Do not remove
FKs, indexes, signed validation or fsync to inflate throughput.

## Stage 5 — True crash-safe 4 GiB restart points (DESIGN GATE ONLY)

**Not implemented by these WAL benchmark changes.** Current C1's
`private_c1_direct.go` reads all grouped batches, calls
`buffers.Finish` once, and then `privateC1MarkTyped` for all 15 new
group descriptors in one final transaction. Only the seed owns the
three provenance ledgers; additional typed markers are not durable,
independently recoverable checkpoints.

Requirements before development acceptance:
1. For each group, bind the exact receipt, SHA-256, batch range, record
   count, source bytes and predecessor descriptor before any promotion.
2. A group restart point is eligible only after **all five family
   SQL projections and ordered source parent** have durably committed,
   every USN capture/child and File identity dependency for that group
   has satisfied the group-aware completion contract, and signed
   relational coverage is proven. A USN capture that legitimately
   spans groups must retain its unique source-bound identity and
   durable remaining allowance across restart.
3. Journal source evidence, artifact provenance, and typed completion
   as a coherent proof. A typed-only marker is insufficient.
4. Handle SQL transactions already committed before a crash **without
   treating them as an accepted checkpoint**. An atomic group promotion
   or explicitly verified idempotent rollback/replay protocol is
   required; multiple independent family SQL connections cannot be
   assumed to share one commit.
5. Resume only the most recent fully verified prefix. Detect/reject
   gaps, duplicate digests, mismatched sources, partial children, and
   dirty uncheckpointed tails. No unsafe automatic retry of a dirty
   clone without a designed cleanup protocol.
6. Inject termination before/after source-parent commit, during a
   family transaction, after USN boundary before object, after last
   family ACK before marker, during marker/provenance transaction,
   and immediately after marker commit. For every cut: restart,
   verify exact 8,399-batch final proof, source/child counts, absence
   of duplicates, correct expected restart index and 0 authoritative/
   accepted/published records.
7. Benchmark crash-safe path separately from the current continuous
   no-barrier C1 baseline; reporting groups cannot be re-labelled
   as recovery checkpoints before these tests pass.

## Engineering gates

- Stage 1 runner+controller are pinned to exact Git commits, never
  moving branch HEAD; the compile/race gate precedes PostgreSQL cloning.
- Use the C220 `fi-dev` clone only; do not touch fi-sor-db, fi-ingest,
  receiver custody files, or original seed.
- Preserve evidence from every run; do not clean/reset old failed clone
  without explicit approval and a documented custody distinction.
- Only one experimental parameter differs between A and B.
- A successful Stage 1 is a **performance experiment**, not a production
  release or a Stage 5 acceptance.
