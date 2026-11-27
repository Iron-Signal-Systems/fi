#!/bin/sh
# FI C1: read-only private-stage and telemetry freshness check for C220.
# No live ingest, SQL writes, restart, journal changes or telemetry upload.
set -eu
umask 077
fail(){ echo "FI C1 READINESS STOP: $*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
  fail "root on physical c220 required"
# Require a unique real jail; do not assume old or new logical names.
sor_jail=''
for candidate in fi-sor-db fi-sor; do
  if jls -j "$candidate" jid >/dev/null 2>&1; then
    [ -z "$sor_jail" ] ||
      fail 'both SoR candidates are running: PostgreSQL identity ambiguous'
    sor_jail=$candidate
  fi
done
[ -n "$sor_jail" ] || fail 'no FI SoR PostgreSQL jail running'
printf 'C1_SOR_JAIL_SELECTED=%s\n' "$sor_jail"
sock=/var/db/fi/sor/run
jexec -U postgres "$sor_jail" pg_isready -h "$sock" -p 5432 >/dev/null ||
  fail "real PostgreSQL unavailable"

actual_pgdata=$(jexec -U postgres "$sor_jail" psql -X -w -h "$sock" -p 5432 \
  -d fi -At -v ON_ERROR_STOP=1 -c 'SHOW data_directory') ||
  fail "cannot identify selected SoR PostgreSQL cluster"
[ "$actual_pgdata" = /var/db/fi/sor/postgres ] ||
  fail "unexpected SoR PostgreSQL data directory: $actual_pgdata"
echo "===== C1 TARGET AND PRIVATE STAGING: READ-ONLY ====="
jexec -U postgres "$sor_jail" psql -X -w -h "$sock" -p 5432 -d fi \
  -v ON_ERROR_STOP=1 -A -F '|' <<'SQL'
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='180s';
SELECT 'CANONICAL_SOURCE_RECORDS_BEFORE' AS section,count(*)::text AS records
  FROM fi.source_record;
SELECT 'CANONICAL_GENERATIONS_BEFORE' AS section,count(*)::text AS generations
  FROM fi.recorded_generation;
SELECT 'TARGET_CANONICAL_STATE' AS section,count(*)::text AS generation_count
  FROM fi.recorded_generation
  WHERE source_id='iss-fs-22a.iss.local'
    AND generation_id='20261030T000032.061323100Z-3e38b2210771462c';
SELECT 'TARGET_JOURNAL_HISTORY' AS section,outcome,
  count(*)::text AS events,coalesce(sum(records_committed),0)::text AS committed
  FROM fi.ingest_journal
  WHERE source_id='iss-fs-22a.iss.local'
    AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
  GROUP BY outcome ORDER BY outcome;


SELECT 'C1_PRIVATE_WORKER_ROLE' AS section,
 CASE WHEN EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_ingest')
      THEN 'PRESENT' ELSE 'MISSING' END AS fi_sor_sql_worker_role,
 CASE WHEN to_regnamespace('fi_recovery_projection') IS NOT NULL
      AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_ingest')
      THEN has_schema_privilege('fi_ingest','fi_recovery_projection','USAGE')::text
      ELSE 'NOT_INSTALLED' END AS private_schema_usage,
 CASE WHEN to_regclass('fi_recovery_projection.source_batch') IS NOT NULL
      AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_ingest')
      THEN (has_table_privilege('fi_ingest','fi_recovery_projection.source_batch','SELECT')
       AND has_table_privilege('fi_ingest','fi_recovery_projection.source_batch','INSERT'))::text
      ELSE 'NOT_INSTALLED' END AS private_batch_sql_access,
 CASE WHEN to_regclass('fi_recovery.typed_window') IS NOT NULL
      AND EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_ingest')
      THEN (has_table_privilege('fi_ingest','fi_recovery.typed_window','SELECT')
       AND has_table_privilege('fi_ingest','fi_recovery.typed_window','INSERT'))::text
      ELSE 'NOT_INSTALLED' END AS private_marker_sql_access;

SELECT 'TARGET_PRIVATE_GENERATION' AS section,count(*)::text AS generations,
  coalesce(sum(record_count),0)::text AS receipt_records
  FROM fi_recovery_projection.recorded_generation
  WHERE source_id='iss-fs-22a.iss.local'
    AND generation_id='20261030T000032.061323100Z-3e38b2210771462c';

WITH target AS (
  SELECT receipt_sha256 FROM fi_recovery_projection.recorded_generation
  WHERE source_id='iss-fs-22a.iss.local'
    AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
)
SELECT 'TARGET_PRIVATE_MARKERS' AS section,
 (SELECT count(*) FROM fi_recovery.verified_artifact_window
   WHERE receipt_sha256 IN (SELECT receipt_sha256 FROM target)) AS artifacts,
 (SELECT count(*) FROM fi_recovery.source_window
   WHERE receipt_sha256 IN (SELECT receipt_sha256 FROM target)) AS sources,
 (SELECT count(*) FROM fi_recovery.typed_window
   WHERE receipt_sha256 IN (SELECT receipt_sha256 FROM target)) AS typed,
 (SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window
   WHERE receipt_sha256 IN (SELECT receipt_sha256 FROM target)) AS typed_records;
SELECT 'C1_PRIVATE_SCHEMA_MIRROR' AS section,
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='fi' AND c.relkind IN ('r','p')) AS canonical_tables,
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='fi_recovery_projection' AND c.relkind IN ('r','p')) AS private_tables,
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='fi_recovery' AND c.relkind='r') AS recovery_ledgers,
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='fi' AND c.relkind IN ('r','p') AND NOT EXISTS(
     SELECT 1 FROM pg_class p JOIN pg_namespace pn ON pn.oid=p.relnamespace
     WHERE pn.nspname='fi_recovery_projection'
       AND p.relname=c.relname AND p.relkind=c.relkind)) AS missing_private_tables;

-- Marker coverage is metadata-only: do not scan private SourceParent or
-- child rows or infer that any marker is permission to skip signed replay.
WITH target AS (
 SELECT receipt_sha256 FROM fi_recovery_projection.recorded_generation
 WHERE source_id='iss-fs-22a.iss.local'
   AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
), a AS (
 SELECT w.* FROM fi_recovery.verified_artifact_window w
 JOIN target USING(receipt_sha256)
), s AS (
 SELECT w.* FROM fi_recovery.source_window w
 JOIN target USING(receipt_sha256)
), t AS (
 SELECT w.* FROM fi_recovery.typed_window w
 JOIN target USING(receipt_sha256)
)
SELECT 'C1_PRIVATE_MARKER_CONSISTENCY' AS section,
 (SELECT count(*) FROM a) AS verified_artifacts,
 (SELECT count(*) FROM s) AS committed_source_windows,
 (SELECT count(*) FROM t) AS committed_typed_windows,
 (SELECT coalesce(min(window_index),-1) FROM a) AS first_artifact_index,
 (SELECT coalesce(max(window_index),-1) FROM a) AS last_artifact_index,
 (SELECT count(*) FROM s LEFT JOIN a
    ON s.receipt_sha256=a.receipt_sha256 AND s.window_index=a.window_index
    WHERE a.window_index IS NULL) AS sources_without_artifact,
 (SELECT count(*) FROM t LEFT JOIN s
    ON t.receipt_sha256=s.receipt_sha256 AND t.window_index=s.window_index
    WHERE s.window_index IS NULL) AS typed_without_source,
 (SELECT count(*) FROM s JOIN a
    ON s.receipt_sha256=a.receipt_sha256 AND s.window_index=a.window_index
    WHERE s.descriptor_sha256<>a.descriptor_sha256
       OR s.previous_digest_sha256<>a.previous_digest_sha256
       OR s.start_batch<>a.start_batch OR s.end_batch<>a.end_batch
       OR s.start_record<>a.start_record OR s.end_record<>a.end_record) AS source_descriptor_mismatches,
 (SELECT count(*) FROM t JOIN s
    ON t.receipt_sha256=s.receipt_sha256 AND t.window_index=s.window_index
    WHERE t.descriptor_sha256<>s.descriptor_sha256
       OR t.start_batch<>s.start_batch OR t.end_batch<>s.end_batch
       OR t.committed_records<>s.staged_records) AS typed_marker_mismatches,
 (SELECT coalesce(sum(staged_records),0) FROM s) AS source_marker_records,
 (SELECT coalesce(sum(committed_records),0) FROM t) AS typed_marker_records;
COMMIT;
SQL

echo "===== TELEMETRY FRESHNESS AND DELIVERY: READ-ONLY ====="
jexec -U postgres "$sor_jail" psql -X -w -h "$sock" -p 5432 -d fi_telemetry \
  -v ON_ERROR_STOP=1 -A -F '|' <<'SQL'
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='120s';
SELECT 'TELEMETRY_SAMPLE_FRESHNESS' AS section,stream,
  count(*)::text AS entries,min(observed_at)::text AS first_utc,
  max(observed_at)::text AS latest_utc,
  coalesce(round(extract(epoch FROM (now()-max(observed_at))))::text,'no_samples') AS seconds_since_last
  FROM telemetry.entry GROUP BY stream ORDER BY stream;
SELECT 'TELEMETRY_DELIVERY_RECEIPTS' AS section,
  count(*)::text AS receipts,
  max(delivered_at)::text AS most_recent_delivery_utc,
  coalesce(round(extract(epoch FROM (now()-max(delivered_at))))::text,'no_delivery') AS seconds_since_delivery
  FROM telemetry.delivery_receipt;
SELECT 'RECENT_TELEMETRY_TRAFFIC' AS section,
  count(*) FILTER(WHERE stream='samples')::text AS samples_last_15m,
  count(*) FILTER(WHERE stream='events')::text AS events_last_15m
  FROM telemetry.entry WHERE observed_at>=now()-interval '15 minutes';
SELECT 'LATEST_TELEMETRY_SAMPLE_KEYS' AS section,
  observed_at::text,
  jsonb_object_keys(payload) AS key
  FROM (SELECT observed_at,payload FROM telemetry.entry
        WHERE stream='samples' ORDER BY observed_at DESC LIMIT 1) x;
COMMIT;
SQL
echo "===== READ-ONLY C1 READINESS COMPLETE ====="
