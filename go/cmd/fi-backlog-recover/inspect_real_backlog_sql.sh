#!/bin/sh
# Read-only SQL evidence from the two COMPLETED real signed-backlog W32/W64
# private PostgreSQL 18 test clusters (2026-11-03). Never writes SQL, alters
# cluster configuration, restarts processes, or touches signed custody.
set -eu

root=/home/jwood/fi-window-bench-20261103T090325Z
[ "$(id -un)" = jwood ] || { echo 'STOP: run as jwood INSIDE fi-dev' >&2; exit 1; }
[ -d "$root" ] || { echo "STOP: original real-data clusters not found at $root" >&2; exit 1; }
command -v psql >/dev/null || { echo 'STOP: psql unavailable' >&2; exit 1; }
[ "$#" -eq 0 ] || { echo 'STOP: this report accepts no parameters' >&2; exit 1; }

for profile in W32 W64; do
  case "$profile" in
    W32) port=55631 ;;
    W64) port=55632 ;;
  esac
  cluster="$root/$profile"
  [ "$(cat "$cluster/data/PG_VERSION")" = 18 ] ||
    { echo "STOP: $profile is not PostgreSQL 18" >&2; exit 1; }
  [ -S "$cluster/socket/.s.PGSQL.$port" ] ||
    { echo "STOP: $profile original socket missing" >&2; exit 1; }
  dsn="host=$cluster/socket port=$port user=fi_ingest dbname=fi sslmode=disable connect_timeout=3"
  preflight=$(psql "$dsn" -X -qAt -v ON_ERROR_STOP=1 -c "
SELECT CASE WHEN current_user='fi_ingest'
  AND current_database()='fi'
  AND current_setting('port')::int=$port
  AND current_setting('server_version_num')::int >= 180000
  AND to_regclass('fi_recovery.typed_window') IS NOT NULL
  AND to_regclass('fi_recovery_projection.windows_security_event_field') IS NOT NULL
  AND to_regclass('fi_recovery_projection.source_record') IS NOT NULL
  AND (SELECT count(*) FROM fi_recovery.typed_window)=7
  AND NOT EXISTS(SELECT 1 FROM fi.recorded_generation)
  AND NOT EXISTS(SELECT 1 FROM fi.ingest_journal WHERE outcome='Accepted')
  THEN 'PASS' ELSE 'FAIL' END")
  [ "$preflight" = PASS ] || {
    echo "STOP: $profile is not the preserved seven-window private real-backlog baseline" >&2
    exit 1
  }
  echo "===== FI ORIGINAL SIGNED BACKLOG $profile port=$port READ-ONLY ====="
  psql "$dsn" -X -v ON_ERROR_STOP=1 -A -F '|' -P pager=off <<'SQL'
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
\echo --- Original private checkpoint and data volume
SELECT 'checkpoint',count(*) AS windows,coalesce(sum(committed_records),0) AS records,
       max(window_index) AS last_window
FROM fi_recovery.typed_window;
\echo --- PostgreSQL settings at time of inspection (not necessarily at ingestion time)
SELECT name,setting,unit
FROM pg_settings
WHERE name IN ('shared_buffers','effective_cache_size','max_wal_size',
'checkpoint_timeout','wal_compression','synchronous_commit','fsync','full_page_writes',
'maintenance_work_mem','work_mem','track_io_timing','track_wal_io_timing',
'checkpoint_completion_target','wal_buffers','bgwriter_lru_maxpages')
ORDER BY name;
\echo --- Largest real private projection relations and index weights
SELECT c.relname AS relation,
       pg_relation_size(c.oid) AS heap_bytes,
       pg_indexes_size(c.oid) AS index_bytes,
       pg_total_relation_size(c.oid) AS total_bytes,
       coalesce(st.n_tup_ins,0) AS cumulative_inserts,
       coalesce(st.n_live_tup,0) AS estimated_live_tuples,
       coalesce(st.n_dead_tup,0) AS estimated_dead_tuples,
       coalesce(st.autovacuum_count,0) AS autovacuum_runs
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_stat_user_tables st ON st.relid=c.oid
WHERE n.nspname='fi_recovery_projection' AND c.relkind IN ('r','p')
ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 25;
\echo --- Every actual Security field index and its cumulative usage
SELECT i.relname AS index_name,
       pg_relation_size(i.oid) AS index_bytes,
       pg_get_indexdef(i.oid) AS definition,
       coalesce(stat.idx_scan,0) AS cumulative_scans
FROM pg_index ix JOIN pg_class i ON i.oid=ix.indexrelid
JOIN pg_class c ON c.oid=ix.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_stat_user_indexes stat ON stat.indexrelid=i.oid
WHERE n.nspname='fi_recovery_projection'
 AND c.relname='windows_security_event_field'
ORDER BY i.relname;
\echo --- Private File/Security table totals and current index sizes
SELECT c.relname,pg_relation_size(c.oid) AS heap_bytes,
       pg_indexes_size(c.oid) AS index_bytes,
       coalesce(s.n_tup_ins,0) AS cumulative_inserts
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid=c.oid
WHERE n.nspname='fi_recovery_projection'
 AND c.relname IN ('source_record','file_observation','file_metadata_observation',
 'windows_security_event','windows_security_event_field',
 'windows_security_event_scope','content_hash_observation')
ORDER BY c.relname;
\echo --- Actual checkpoint pressure and write/sync work (cumulative since stats_reset)
SELECT num_timed,num_requested,num_done,buffers_written,write_time,sync_time,stats_reset
FROM pg_stat_checkpointer;
\echo --- WAL pressure including buffer-full induced writes (cumulative)
SELECT wal_records,wal_fpi,wal_bytes,wal_buffers_full,stats_reset
FROM pg_stat_wal;
\echo --- Background writer pressure (cumulative)
SELECT buffers_clean,maxwritten_clean,buffers_alloc,stats_reset FROM pg_stat_bgwriter;
\echo --- PostgreSQL 18 relation and WAL I/O, including client buffer evictions
SELECT backend_type,object,context,
 reads,read_bytes,hits,writes,write_bytes,extends,extend_bytes,evictions,
 fsyncs,read_time,write_time,fsync_time,stats_reset
FROM pg_stat_io
WHERE object IN ('relation','wal') AND
 (coalesce(reads,0)+coalesce(writes,0)+coalesce(extends,0)+
  coalesce(evictions,0)+coalesce(fsyncs,0))>0
ORDER BY object,backend_type,context;
\echo --- Security-field primary key cache accesses despite zero index scans
SELECT indexrelname,idx_blks_read,idx_blks_hit
FROM pg_statio_user_indexes
WHERE schemaname='fi_recovery_projection'
 AND relname='windows_security_event_field';
\echo --- PostgreSQL cluster I/O: cumulative not necessarily incurred by timed window
SELECT datname,blks_read,blks_hit,blk_read_time,blk_write_time,temp_files,temp_bytes,
       deadlocks,conflicts
FROM pg_stat_database WHERE datname='fi';
COMMIT;
SQL
done
echo 'FI ORIGINAL REAL-BACKLOG SQL REPORT COMPLETE: no SQL writes or service changes'
