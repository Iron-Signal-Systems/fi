# FI C1 — authorized development test sequence (2026-11-26)

**State:** development only. The operator-approved test order is original C1 private database, then populated development SoR clone, then real SoR. All gates use the same Preparation, Family Processing and independent read-only Verifier B algorithms.

## C1 contract

- Receiver durably retains original authenticated signed batches. Routine intake and any certificate, network, service or server-interruption backlog use **the same continuously operating C1 engine**.
- **Preparation:** one continuous signed stream; five adaptive families (2–32 workers/family); persistent bounded buffers. Batch and 4 GiB reporting boundaries do not force family flushes.
- **Family Processing:** one ordered SourceParent writer with PostgreSQL commit ACKs; five existing family SQL modules; one shared adaptive SQL pool (max 32); File/USN dependency fences; existing relational constraints.
- **Verifier B:** independent read-only OS process. Independently compare committed database records with original signed records, their identities/digests, typed coverage, relationships and dependencies. **B is the final data check.** There is no additional relational copy, reinsert or second family-processing pass.
- A final journal/ACK may record a successful B result without rewriting rows. An ingest-only benchmark throughput is not an end-to-end Accepted throughput.
- Failure recovery retains original custody and reconciles committed SQL to avoid duplication.

## Gate 1 — frozen C1, original private relational database

Use the **original** frozen C1 benchmark source and private PostgreSQL setup. **No governed Pending-to-fi 49-table remapper; no canonical publisher; no live SoR.**

Passing source pin: f42ec639ffeccba31f2a2d4de82f20294c90cd40.
Recorded November 21 baseline: 8,399 signed batches; 15,140,785 signed total records including 493,478 already in the original private seed; 14,647,307 new records processed at 20,890.49 records/s in 701.147 seconds; B group proof 148.087 seconds and B final proof 1.381 seconds. This was an isolated private SQL benchmark with no Accepted canonical journal. See FI-C1-INGEST-FROZEN-DEVELOPMENT-BASELINE-20261121.md.

**Gate 1 PASS:** original SourceParent/five-family durable SQL PASS, independent B verifies all expected signed records, and no additional 49-table SQL copy or late second proof. Capture ingest-only and full wall-clock timings separately. Preserve original input and clone evidence.

**Before attempting a fresh Gate 1 run:** confirm the pinned source, original seed, disposable PostgreSQL instance, read-only cache/custody, disabled services, sufficient storage, and previous run outputs. Never overwrite the interrupted clone or assume its Pending state is empty.

## Gate 2 — populated SoR copy in a physically separate PostgreSQL cluster

After Gate 1 PASS, capture the live SoR identity/schema/index/FK and accepted-record baselines **read-only**. Restore a transaction-consistent logical backup of the **populated** development SoR into a physically separate PostgreSQL 18 cluster with distinct PGDATA and control-system identifier. The restored database preserves its data, SQL schema, roles/ACLs, constraints and identities; logically rebuilt index storage and physical page layout can differ from the live source. Preserve existing canonical history, 49 relations, indexes, constraints, identities and ingest journal. Verify distinct PGDATA, unique PostgreSQL system identifier and isolated Unix socket with no TCP listener. Do not change live SoR.

Run the **same C1 algorithm** once against the clone's actual database structure, with B checking the records that Family Processing committed. No copy/reinsert of all families after B. Prove unchanged previous history, exact signed 15-million generation, no duplicates, interruption and crash/restart/replay, true end-to-end time, and correct final status. Resolve any unverified-generation reader-visibility risk before allowing live ingestion.

**Gate 2 PASS:** all expected records exist once in the populated clone and independent B verifies exactly what was persisted; no second relational data copy. A high ingest-only rate by itself is insufficient.

## Gate 3 — real C220 development SoR

Only after reviewing all Gate 2 evidence: separately audited deployment and controlled real SoR test. No live database write, grants, reset, service activation or READY retirement is authorized by this document.

## Explicitly not part of C1

- A Pending-to-canonical 49-table reinsert/remap after B.
- A replacement B algorithm or duplicate post-B full-data scan.
- Verifier B writing to SoR.
- Different ingest engines for normal batches versus outages.
- Reuse of /var/tmp/fi-c1-sor-bench.1ZjLP6eF as a fresh database without reconciliation.

## Gate status (2026-11-26)

- Gate 1: PASS on C220 (original 8,399 signed batches, 15,140,785 total records; 14,647,307 new; independent B PASS; original private SQL clone, no canonical writes). SQL drain 12m8.141s, approximately 20,116 new records/s. Historical comparator 11m41.147s, approximately 20,891/s; same algorithm, runtime variability not yet explained.
- Gate 2: PREPARATION ONLY. Read-only inventory in `fi_c1_c220_gate2_populated_sor_inventory.sh`; independent populated PostgreSQL backup/restore in `fi_c1_c220_gate2_populated_clone_prepare.sh`. Clone data copy is NOT ingestion acceptance. Do not invoke the older empty-clone bootstrap or single-jail Pending-to-canonical publisher as a substitute for the approved one-write path. Implement and verify an actual populated-clone C1 SQL destination with B verifying those committed destination rows before attempting Gate 2 ingestion.
- Gate 3: NOT STARTED. Live SoR remains unchanged.

## Existing target-generation status discovered 2026-11-26

The exact signed test generation `iss-fs-22a.iss.local / 20261030T000032.061323100Z-3e38b2210771462c` is **ALREADY Accepted** on the populated live SoR. Read-only forensics verified canonical `recorded_generation_id=6932`, `record_count=15,140,785`, `batch_count=8,399`, actual 8,399 persisted batch records with a 15,140,785 summed record count, actual 15,140,785 persisted `fi.source_record` rows, and exactly one Accepted journal matching the canonical transfer SHA and record count. The canonical insertion time is 2026-11-24 04:07 UTC and journal acceptance is 07:46 UTC; do not attribute the interval to any specific C1 component without supporting evidence.

Gate 2 clone creation **must preserve** this exact Accepted history and must **not** falsely treat this signed generation as new. First test replay/idempotency readback against this history without writes; obtain genuinely unaccepted signed custody (or separately isolated preacceptance historical fixture) before a new full-populated-SoR C1 ingest test. The updated clone-preparation script is backup/restore only and still refuses any ingestion. Earlier 6773-generation live baseline and 242GB database size were confirmed by the 2026-11-26 inventory; re-audit if they drift.
