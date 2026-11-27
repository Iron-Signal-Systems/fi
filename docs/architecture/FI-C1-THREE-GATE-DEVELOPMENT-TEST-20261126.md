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

## Approved operator change: one real development SoR, ZFS snapshot rollback (2026-11-26)

This supersedes the previous **populated-clone acceptance requirement** for the current C220 DEVELOPMENT test. The operator explicitly selected: use the existing populated PostgreSQL SoR as the test-and-final database; before the test, capture a ZFS rollback snapshot; after a verified success, keep the live database and mark Accepted; if the test fails, stop affected writers/PostgreSQL and restore the pretest ZFS snapshot. **No 242-GB `pg_dump`/restore and no separate PostgreSQL clone.**

### Confirmed rollback point

- Physical host C220; real PostgreSQL 18.6 in `fi-sor`, `/var/db/fi/sor/postgres`, live Unix socket `/var/db/fi/sor/run`, port 5432, system identifier `7690295447535908318`.
- Data, base, global, WAL all reside on dataset `fast/data/fi/sor/pgdata` mounted from `/fast/data/fi/sor/pgdata` into the jail; no external tablespaces or WAL symlinks.
- Snapshot exists: `fast/data/fi/sor/pgdata@fi-c1-real-pretest-20261126`, created Thursday 2026-11-26 at approximately 14:04 EST, referred size 58.5 GiB with ZFS compression. Snapshot captured the running PostgreSQL data + WAL atomically on the same dataset; a restoration would require PostgreSQL crash recovery, and the success of recovery has **not yet been tested**.
- A separately initialized abandoned benchmark PostgreSQL database under `/var/tmp/fi-c1-populated.osv8yjpg` was explicitly stopped. Do not reuse it or delete it implicitly.
- Snapshot rollback rewinds **every database in the cluster and all data on the snapped dataset**, not just FI's target generation, including post-snapshot telemetry and other completed work. Quiesce independent writers before testing and before any rollback. NEVER attempt `zfs rollback` while PostgreSQL is running. An active PostgreSQL snapshot is NOT a logical generation-specific undo mechanism.

### Direct-to-canonical C1 engineering required before any live write

1. The original 8,399-batch, 15,140,785-record signed generation is **already canonical Accepted** as of Nov 24, 2026. Its record and batch totals and matching journal were confirmed in the read-only Nov 26 forensic audit. Preserve it exactly once; do not replay those rows into `fi` or remove its acceptance solely to reproduce a benchmark. Select a genuinely unaccepted signed generation for new-ingest acceptance.
2. The existing `newC1SoRSQLPool` is explicitly hardcoded to the governed `fi_c1_pending` SQL destination. `privateProjectionTx.destinationSchema` allows only private/pending, and `C1SoRService.FinalProof` invokes `PublishC1VerifiedPendingGenerationWithCommitment` and Pending retirement. **The current executable DOES NOT implement the user-approved direct-to-canonical one-write path. Do not deploy or run it on live SoR expecting that behavior.**
3. Engineering must preserve the already-passing C1 Preparation, 5 family modules, ordered SourceParent, shared adaptive 1..32 worker SQL pool, bounded buffers, dependencies, committed-ACKs and original read-only Verifier B. Add a fail-closed explicit canonical SQL destination and pre-existing identity/constraint resolution, with a clear unaccepted-generation start guard and a final post-B lightweight one-event Accepted status. No second 49-table row copy or identity remap after B. The PostgreSQL write roles and B read-only role require explicit audited permissions; do not hand the general fi_ingest role blanket canonical privileges. Readers must not mistake not-yet-verified rows for Accepted history. No invented verification PASS.
4. Test deterministic correctness and negative cases in repository CI/isolated development fixtures before any live database write. The snapshot is protection, **not** a substitute for building the actual SQL destination and verifying rollback procedures.
5. During a controlled first run, record full pre/post live SoR identities, exact already-Accepted historical counts, signed new generation identity and original custody, SQL family/parent ACK evidence, original Verifier B final PASS, one Accepted journal event and database visibility. Only then declare the real test PASS and retain the database. On any failure, stop and investigate before operator-controlled rollback.

**Gate status as of snapshot:** Gate 1 original isolated C1 PASS; real SoR ZFS rollback snapshot READY; direct-to-canonical C1 integration NOT YET COMPLETE; live test NOT STARTED; no new generation has been selected. The earlier physically separate clone route is superseded by this explicit operator decision.


## Operator-approved fresh SoR data reset (2026-11-26, approximately 15:04 EST)

**Most recent operator direction supersedes retaining populated FI history for the next acceptance test:** "blank the sor db then run this into the sor db. we will start fresh". Scope: reset all FI SoR *row data* in the existing PostgreSQL 18 cluster, including the existing 6,773 canonical Accepted generations, journal, and governed Pending rows; retain SQL schemas, 49 canonical relations, 50 Pending relations, indexes, constraints, roles, database ownership, PGDATA, configured services, read-only receiver custody and signing trust.

The previous real-SoR snapshot `fast/data/fi/sor/pgdata@fi-c1-real-pretest-20261126` remains the explicit rollback point for the pre-reset 6,773-accepted-generation history. A reset loses any later PostgreSQL changes if rolled back to that snapshot. **Do not overwrite, destroy, or auto-rollback that snapshot.**

Staged a **separate** reset utility:
`go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_real_sor_fresh_reset.sh`.
It has read-only `--audit` and explicit full-history `--reset I-ACKNOWLEDGE-RESET-ALL-FI-SOR-DATA`, validates the exact physical ZFS dataset/snapshot, live cluster system identifier, 49/50 relation counts, 6,773/6,773 original history, empty Pending control, and no other active FI SQL sessions, and executes a single transactional table-level `TRUNCATE ... RESTART IDENTITY RESTRICT` (no schema/role drop). The script does NOT run C1, and its application has not been performed or proven on C220.

**Engineering STOP RULE:** Do not execute the reset before a direct-to-canonical C1 binary is actually compiled, tests pass, original signed 8,399-batch custody is available, fi-sor-only write roles are explicitly approved and B's read-only canonical SQL validation is proven. Otherwise wiping historical SoR data just leaves an empty database and the wrong Pending-to-canonical executable. The current runtime still uses `fi_c1_pending` and a post-B canonical remapper and therefore cannot be called the approved one-write test. This is not a blocker on database size; it is a C1 source-code and acceptance gap.

On the **fresh** FI database the original 15,140,785-record generation is no longer already Accepted, so it can serve as the original signed test generation, with no artificial generation IDs. Test must still prove all 8,399 batches / 15,140,785 new rows, distinct Verifier B original-custody proof, exact one Accepted, FKs/USN, role separation, no duplicate writes, no copy/remap after B, and accurate ingest-only and end-to-end timing. If any stage fails, withhold Accepted and let the operator restore the ZFS snapshot only after cleanly stopping PostgreSQL and all FI writers.

**Status at this write:** snapshot ready, guarded reset utility staged in repo, real PostgreSQL still populated with 6,773 Accepted, NO RESET APPLIED, NO NEW LIVE C1 INGESTION, direct-to-canonical C1 writer still not complete.
