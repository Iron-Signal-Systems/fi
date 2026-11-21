#!/bin/sh
# FI C1 development SoR preflight. READ-ONLY: does not stage a generation,
# modify roles, restart services, or authorize promotion/Accepted.
# Intended to be run as root on the physical C220 host.
set -eu
umask 077
fail(){ printf 'FI C1 REAL SOR PREFLIGHT STOP: %s\n' "$*" >&2; exit 1; }

[ "$(id -un)" = root ] || fail 'run as root on c220'
[ "$(hostname -s)" = c220 ] || fail 'unexpected host; requires c220'
jls -j fi-sor-db >/dev/null 2>&1 || fail 'fi-sor jail not running'
command -v jexec >/dev/null 2>&1 || fail 'missing jexec'
# C220 PostgreSQL 18 uses a dedicated Unix-domain socket directory.
pgsocket=/var/db/fi/sor/run
jexec -U postgres fi-sor-db pg_isready -h "$pgsocket" -p 5432 >/dev/null 2>&1 ||
  fail 'fi-sor jail running but PostgreSQL not ready on the configured socket'

echo '===== FI C1 REAL DEVELOPMENT SOR: READ-ONLY POSTGRESQL INVENTORY ====='
jexec -U postgres fi-sor-db psql -X -w -h "$pgsocket" -p 5432 -v ON_ERROR_STOP=1 -A -F '|' -d fi <<'SQL'
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='180s';

SELECT 'CLUSTER_IDENTITY' AS section,current_database() AS db,
 current_user AS role,pg_is_in_recovery()::text AS standby,
 pg_postmaster_start_time()::text AS postmaster_started,
 current_setting('data_directory',true) AS pgdata;


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

SELECT 'RELATION_PRESENCE' AS section,
 to_regclass('fi.recorded_generation')::text AS canonical_generation,
 to_regclass('fi.source_record')::text AS canonical_source,
 to_regclass('fi.ingest_journal')::text AS canonical_journal,
 to_regclass('fi_recovery_projection.recorded_generation')::text AS private_generation,
 to_regclass('fi_recovery_projection.source_record')::text AS private_source,
 to_regclass('fi_recovery.typed_window')::text AS private_typed_marker;

SELECT 'CANONICAL_RELATIONS' AS section, count(*)::text AS relation_count
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='fi' AND c.relkind='r';

SELECT 'CANONICAL_GENERATIONS' AS section,count(*)::text AS generations
FROM fi.recorded_generation;
SELECT 'CANONICAL_SOURCE_RECORDS' AS section,count(*)::text AS source_records
FROM fi.source_record;
SELECT 'CANONICAL_JOURNAL_OUTCOMES' AS section,outcome,count(*)::text AS events
FROM fi.ingest_journal GROUP BY outcome ORDER BY outcome;

SELECT 'TARGET_GENERATION_PRESENT' AS section,
 count(*)::text AS generation_rows
FROM fi.recorded_generation
WHERE source_id='iss-fs-22a.iss.local'
 AND generation_id='20261030T000032.061323100Z-3e38b2210771462c';

SELECT 'TARGET_ACCEPTED_JOURNAL' AS section,outcome,count(*)::text AS matching_events,
 coalesce(sum(records_committed),0)::text AS committed_records
FROM fi.ingest_journal
WHERE source_id='iss-fs-22a.iss.local'
 AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
GROUP BY outcome ORDER BY outcome;

SELECT 'DATABASE_SIZE_BYTES' AS section,pg_database_size(current_database())::text AS bytes;
SELECT 'PG_SETTINGS' AS section,
 current_setting('max_wal_size') AS max_wal_size,
 current_setting('wal_buffers') AS wal_buffers,
 current_setting('fsync') AS fsync,
 current_setting('synchronous_commit') AS synchronous_commit,
 current_setting('full_page_writes') AS full_page_writes;

SELECT 'SESSION_ACTIVITY' AS section,coalesce(application_name,'') AS application,
 coalesce(state,'') AS state,coalesce(wait_event_type,'') AS wait_type,
 count(*)::text AS backends
FROM pg_stat_activity
WHERE datname=current_database() AND pid<>pg_backend_pid()
GROUP BY application_name,state,wait_event_type
ORDER BY application_name,state,wait_event_type;

COMMIT;
SQL
echo '===== FI C1 REAL SOR READ-ONLY PREFLIGHT COMPLETE ====='
echo 'No writes, grants, schema changes, service restarts or promotion performed.'
