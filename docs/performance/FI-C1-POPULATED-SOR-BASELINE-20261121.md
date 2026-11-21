# FI C1 — populated development SoR pre-acceptance baseline

**Read-only observed UTC:** 2026-11-21 12:45 (C220 `fi-sor`, PostgreSQL 18).  
**Frozen C1 full-backlog clone benchmark:** 20,890.49 rec/sec, 701.147s ingestion, passed original signed and independent verification.  
**Source code of passing clone benchmark:** `f42ec639ffeccba31f2a2d4de82f20294c90cd40`.  
**Status:** Before ANY authoritative acceptance write. Do not replace or truncate existing SoR.

## Existing canonical FI history (actual, not estimated)

| Measure | Observed |
| --- | ---: |
| `fi.source_record` | **54,114,023** |
| `fi.recorded_generation` | **6,249** |
| `fi.ingest_journal` outcome Accepted | 6,249 |
| Outcome Failed | 4 |
| Outcome Incomplete | 6,817 |
| Outcome Rejected | 537 |
| Canonical `fi` tables | 49 |
| `fi` database size, bytes | 225,001,191,103 |
| `fi` database size, approx GiB | 209.55 |
| `max_wal_size` | 4GB |
| `wal_buffers` | 16MB |
| `fsync`, `synchronous_commit`, `full_page_writes` | on / on / on |

The actual canonical SoR jail is **`fi-sor`**, PostgreSQL socket
`/var/db/fi/sor/run`, port `5432`, `data_directory=/var/db/fi/sor/postgres`.
All ZFS pools (`fast`, `work`, `cold`, `zroot`) were ONLINE.

## Target signed generation

- Source `iss-fs-22a.iss.local`.
- Generation `20261030T000032.061323100Z-3e38b2210771462c`.
- Total original signed generation records: **15,140,785**.
- `fi.recorded_generation` for that exact generation: **zero**.
- Target `fi.ingest_journal`: **one Failed** and **ten Incomplete**;
  **zero Accepted**. Preserve existing history and never assume these are
  durable partial `fi.source_record` rows.
- The previous **14,647,307-record** timing represented the new portion
  after **493,478** records already present in the **private clone seed**.
  For real canonical acceptance the full generation requires
  **15,140,785** canonical source records, unless a separate exact-data
  identity reconciliation establishes otherwise.
- Expected canonical `fi.source_record` count after one complete new
  Accepted generation (provided no other ingest writes occur):
  **69,254,808**.
- Expected accepted generations afterward (no concurrent acceptance):
  **6,250**.

## Pre-existing telemetry database

The C220 `fi_telemetry` PostgreSQL database is present on `fi-sor`.
Its existing tables report:
- `telemetry.entry`: **54,986**.
- `telemetry.delivery_receipt`: **377**.

This proves **persisted telemetry**, not that a telemetry collector or
five-minute uploader is presently running. Verify latest sample and latest
delivery timestamps before setting a real C1 acceptance test in motion.

FI backend telemetry cadence already established in development:
**15-second resource sampling**, **5-minute independent upload**, durable
local spool and separate recorder/DB. No always-on one-second profiler.

## Acceptance boundary

The user requires C1 as the **canonical FI development ingest architecture**.
The full live SoR acceptance must retain the existing 54,114,023 records,
run the unchanged C1 family preparation, buffer, ordered parent and SQL design,
record all workload/host/storage/PostgreSQL telemetry in `fi_telemetry`
through the previously designed path, verify the entire signed generation
with independent B, and make one confirmed canonical Accepted transaction.

The **private-clone runner cannot be redirected to this SoR**: it enforces
a separate PGDATA and rewrites writes to `fi_recovery_projection`.
The existing `PromoteVerifiedBacklogToPopulatedSoR` function supports
remapped promotion into already populated `fi` when the verified private
relational data exists on that SAME PostgreSQL cluster; this condition
has not yet been demonstrated. Finish the connection/staging integration and
rollback/forward-recovery gates before granting write capability.

Use `go/cmd/fi-backlog-recover/diagnostics/fi_c1_populated_sor_readiness_c220.sh`
for read-only target private-marker and telemetry freshness checks. No
authoritative acceptance write was performed by this baseline capture.
