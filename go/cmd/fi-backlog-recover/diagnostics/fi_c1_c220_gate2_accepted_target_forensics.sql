-- FI C1 Gate 2 — READ-ONLY forensic audit: target generation is ALREADY Accepted.
-- Exact canonical source and generation as in the signed C1 8,399-batch replay.
-- Uses PostgreSQL 18 snapshot consistency; no SQL writes or accepted changes.
\set ON_ERROR_STOP on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='600s';

\echo '===== ACTUAL LIVE CLUSTER IDENTITY ====='
SELECT current_database() AS database,
       current_setting('data_directory') AS pgdata,
       current_setting('port') AS port,
       (SELECT system_identifier FROM pg_control_system()) AS system_identifier,
       pg_is_in_recovery() AS standby;

\echo '===== EXACT CANONICAL GENERATION / RECEIPTS / INGEST VERSION ====='
SELECT recorded_generation_id,source_id,generation_id,record_count,batch_count,
       artifact_count,data_bytes,source_bytes,
       encode(receipt_sha256,'hex') AS receipt_sha256,
       encode(transfer_sha256,'hex') AS transfer_sha256,
       ingested_at, ingest_version
FROM fi.recorded_generation
WHERE source_id='iss-fs-22a.iss.local'
  AND generation_id='20261030T000032.061323100Z-3e38b2210771462c';

\echo '===== ACCEPTED JOURNAL AND PRIOR FAILED/INCOMPLETE HISTORY ====='
SELECT ingest_journal_id,attempt_id,event_sequence,occurred_at,
       outcome,stage,reason_code,records_seen,records_committed,
       encode(transfer_sha256,'hex') AS transfer_sha256,
       ingest_version
FROM fi.ingest_journal
WHERE source_id='iss-fs-22a.iss.local'
  AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
ORDER BY occurred_at,ingest_journal_id;

\echo '===== EXPECTED GENERATION / BATCH COUNTS AND RECEIPT ALIGNMENT ====='
WITH g AS (
 SELECT recorded_generation_id,record_count,batch_count,transfer_sha256
 FROM fi.recorded_generation
 WHERE source_id='iss-fs-22a.iss.local'
   AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
),b AS (
 SELECT count(*) AS persisted_batches,coalesce(sum(b.record_count),0)::bigint AS batch_claimed_records,
        coalesce(sum(b.data_bytes),0)::bigint AS batch_data_bytes
 FROM fi.source_batch b JOIN g USING(recorded_generation_id)
),j AS (
 SELECT count(*) AS accepted_events,
        count(*) FILTER (WHERE j.transfer_sha256=g.transfer_sha256
           AND j.records_committed=g.record_count) AS matching_accepted_events
 FROM fi.ingest_journal j CROSS JOIN g
 WHERE j.source_id='iss-fs-22a.iss.local'
 AND j.generation_id='20261030T000032.061323100Z-3e38b2210771462c'
 AND j.outcome='Accepted'
)
SELECT g.record_count AS generation_claimed_records,
       g.batch_count AS generation_claimed_batches,
       b.persisted_batches,b.batch_claimed_records,
       (b.persisted_batches=g.batch_count) AS batch_count_matches,
       (b.batch_claimed_records=g.record_count) AS batch_record_sum_matches,
       j.accepted_events,j.matching_accepted_events
FROM g CROSS JOIN b CROSS JOIN j;

\echo '===== ACTUAL PERSISTED SOURCE RECORD ROWS IN THIS EXACT GENERATION ====='
WITH g AS (
 SELECT recorded_generation_id,record_count,batch_count
 FROM fi.recorded_generation
 WHERE source_id='iss-fs-22a.iss.local'
   AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
), persisted AS (
 SELECT count(r.source_record_id)::bigint AS actual_source_records
 FROM fi.source_batch b JOIN g USING(recorded_generation_id)
 LEFT JOIN fi.source_record r ON r.source_batch_id=b.source_batch_id
)
SELECT g.record_count AS claimed_records,
       persisted.actual_source_records,
       persisted.actual_source_records=g.record_count AS actual_rows_match_claim
FROM g CROSS JOIN persisted;

COMMIT;
\echo 'FI C1 GATE2 ACCEPTED TARGET FORENSICS COMPLETE READ_ONLY=true'
