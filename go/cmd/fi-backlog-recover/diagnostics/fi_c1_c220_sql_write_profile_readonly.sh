#!/bin/sh
# Read-only C220 single-jail C1 PostgreSQL post-ingestion profile.
# Explicit physical clone and live PGDATA checks. NO table scans,
# no CREATE EXTENSION, no VACUUM/ANALYZE, no DROP/ALTER/CHECKPOINT or restart.
# DO NOT interpret pg_stat_* estimates as canonical Accepted evidence.
set -eu
die(){ echo "FI C1 PG18 PROFILE STOP: $*" >&2; exit 1; }
[ "$#" -eq 0 ] || die 'usage: script (no arguments)'
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
    [ "$(id -u)" -eq 0 ] || die 'physical C220 host root required'
clone=/var/tmp/fi-c1-sor-bench.yBi1CkVm
host=/fast/jails/roots/fi-sor
[ -d "$host$clone/pgdata" ] &&
[ -d "$host$clone/socket" ] &&
[ ! -L "$host$clone/pgdata" ] && [ ! -L "$host$clone/socket" ] ||
    die 'expected disposable clone inaccessible'
jls -j fi-sor >/dev/null 2>&1 || die 'fi-sor jail is stopped'
q(){
    jexec -U postgres fi-sor /usr/local/bin/psql -X -w \
        -v ON_ERROR_STOP=1 -P pager=off -h "$clone/socket" -p 5432 -d fi -c "$1"
}
live(){
    jexec -U postgres fi-sor /usr/local/bin/psql -X -w -At \
        -v ON_ERROR_STOP=1 -P pager=off -h /var/db/fi/sor/run -p 5432 -d fi -c "$1"
}
ident=$(jexec -U postgres fi-sor /usr/local/bin/psql -X -w -At \
    -v ON_ERROR_STOP=1 -h "$clone/socket" -p 5432 -d fi \
    -c "SELECT current_setting('data_directory') || '|' ||
        current_setting('unix_socket_directories') || '|' ||
        current_setting('listen_addresses') || '|' ||
        (SELECT system_identifier::text FROM pg_control_system())")
[ "$ident" = "$clone/pgdata|$clone/socket||7712057744289793411" ] ||
    die "clone physical PostgreSQL identity differs: $ident"
liveident=$(live "SELECT current_setting('data_directory') || '|' ||
    (SELECT system_identifier::text FROM pg_control_system())")
case "$liveident" in
    /var/db/fi/sor/postgres\|7712057744289793411)
        die 'CLONE SYSTEM IDENTIFIER MATCHES LIVE, refuse'
        ;;
    /var/db/fi/sor/postgres\|*) : ;;
    *) die "live PostgreSQL PGDATA changed: $liveident" ;;
esac
echo '===== ISOLATED PG18 PHYSICAL CLUSTER IDENTITY PASS / READ ONLY ====='
echo "CLONE_IDENTITY=$ident"
echo "LIVE_IDENTITY=$liveident"
echo '===== CLONE CANONICAL / PENDING (small metadata counts) ====='
q "BEGIN READ ONLY;
SELECT (SELECT count(*) FROM fi.recorded_generation) AS canonical_generations,
       (SELECT count(*) FROM fi_c1_pending.generation_control) AS pending_generations,
       (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted') AS accepted_journal;
COMMIT;"
echo '===== CLONE RELATION INSERT STATS AND PHYSICAL INDEX COST ====='
q "BEGIN READ ONLY;
SELECT relname,n_tup_ins,n_dead_tup,idx_scan,seq_scan,
       pg_size_pretty(pg_relation_size(relid)) AS heap,
       pg_size_pretty(pg_indexes_size(relid)) AS indexes,
       pg_size_pretty(pg_total_relation_size(relid)) AS total
FROM pg_stat_user_tables
WHERE schemaname='fi_c1_pending'
  AND relname IN ('source_record','windows_security_event',
    'windows_security_event_scope','windows_security_event_field',
    'file_observation','file_metadata_observation','content_hash_observation')
ORDER BY pg_total_relation_size(relid) DESC;
COMMIT;"
echo '===== CLONE INDEX ACCESS COUNTS (NOT A QUERY PLAN PROOF) ====='
q "BEGIN READ ONLY;
SELECT relname,indexrelname,idx_scan,idx_tup_read,idx_tup_fetch,
       pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE schemaname='fi_c1_pending'
  AND relname IN ('source_record','windows_security_event',
                  'windows_security_event_field','file_observation')
ORDER BY relname,pg_relation_size(indexrelid) DESC;
COMMIT;"
echo '===== CLONE WAL WRITE PRESSURE ====='
q "BEGIN READ ONLY;
SELECT wal_records,wal_fpi,pg_size_pretty(wal_bytes::bigint) AS wal_generated,
       wal_buffers_full,stats_reset
FROM pg_stat_wal;
COMMIT;"
echo '===== CLONE CHECKPOINT PRESSURE ====='
q "BEGIN READ ONLY;
SELECT num_timed,num_requested,num_done,write_time,sync_time,buffers_written,stats_reset
FROM pg_stat_checkpointer;
COMMIT;"
echo '===== CLONE I/O ACTIVITY ====='
q "BEGIN READ ONLY;
SELECT backend_type,object,context,
       sum(reads)::bigint AS reads,sum(writes)::bigint AS writes,
       sum(fsyncs)::bigint AS fsyncs,
       sum(evictions)::bigint AS evictions
FROM pg_stat_io
WHERE object='relation'
GROUP BY backend_type,object,context
ORDER BY writes DESC;
COMMIT;"
echo 'FI C1 PG18 WRITE PROFILE COMPLETE read_only=true original_signed_custody_untouched=true live_sor_unchanged=true no_ddl=true'
