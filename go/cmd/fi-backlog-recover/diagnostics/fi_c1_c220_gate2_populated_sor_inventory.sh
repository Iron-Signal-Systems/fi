#!/bin/sh
# FI C1 Gate 2: live C220 SoR READ-ONLY populated-clone feasibility inventory.
# DO NOT initialize any PGDATA, take a snapshot, dump, change roles,
# start a benchmark or alter ready/custody in this command.
set -eu
umask 077
die(){ printf 'FI C1 GATE2 INVENTORY STOP: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = FreeBSD ] &&
[ "$(hostname -s)" = c220 ] &&
[ "$(id -u)" -eq 0 ] || die 'root on physical C220 required'
for jail in fi-sor fi-dev fi-receiver; do
  jls -j "$jail" jid >/dev/null 2>&1 || die "required jail absent: $jail"
done
sorroot=$(jls -j fi-sor path)
[ "$sorroot" = /fast/jails/roots/fi-sor ] ||
  die "unexpected fi-sor jail root $sorroot"
socket=/var/db/fi/sor/run
pgdata=/var/db/fi/sor/postgres
jexec -U postgres fi-sor pg_isready -h "$socket" -p 5432 >/dev/null ||
  die 'live postgres cannot be reached on the original socket'
echo '===== VERIFY LIVE SOR PHYSICAL IDENTITY (SELECT ONLY) ====='
read_identity=$(jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1   -h "$socket" -p 5432 -d fi -c   "SELECT current_setting('data_directory')||'|'||
          current_setting('port')||'|'||pg_is_in_recovery()::text")
[ "$read_identity" = "$pgdata|5432|false" ] ||
  die "unexpected live SoR identity: $read_identity"
echo "PASS: live_pgdata=$pgdata port=5432 primary=true"
echo '===== EXISTING CANONICAL HISTORY / SCHEMA / TARGET ====='
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -P pager=off   -h "$socket" -p 5432 -d fi <<'SQL'
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '180s';
SELECT 'LIVE_PHYSICAL' AS section, current_database() AS database,
       current_setting('server_version') AS version,
       current_setting('data_directory') AS pgdata,
       (SELECT system_identifier FROM pg_control_system()) AS system_identifier,
       pg_is_in_recovery() AS standby;
SELECT 'LIVE_CAPACITY' AS section,
       pg_database_size(current_database()) AS database_bytes,
       pg_size_pretty(pg_database_size(current_database())) AS database_pretty;
SELECT 'LIVE_DURABILITY' AS section,
       current_setting('fsync') AS fsync,
       current_setting('synchronous_commit') AS synchronous_commit,
       current_setting('full_page_writes') AS full_page_writes,
       current_setting('max_wal_size') AS max_wal_size,
       current_setting('wal_buffers') AS wal_buffers;
SELECT 'TABLES' AS section, schemaname, count(*) AS table_count
  FROM pg_tables WHERE schemaname IN ('fi','fi_c1_pending')
  GROUP BY schemaname ORDER BY schemaname;
SELECT 'FI_HISTORY' AS section,
       (SELECT count(*) FROM fi.recorded_generation) AS generations,
       (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted') AS accepted_events,
       (SELECT count(*) FROM fi_c1_pending.generation_control) AS pending_generations;
SELECT 'TARGET_GENERATION' AS section,
       (SELECT count(*) FROM fi.recorded_generation
         WHERE source_id='iss-fs-22a.iss.local'
           AND generation_id='20261030T000032.061323100Z-3e38b2210771462c') AS recorded,
       (SELECT count(*) FROM fi.ingest_journal
         WHERE source_id='iss-fs-22a.iss.local'
           AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
           AND outcome='Accepted') AS already_accepted;
SELECT 'TARGET_JOURNAL' AS section, outcome,count(*) AS events
  FROM fi.ingest_journal
  WHERE source_id='iss-fs-22a.iss.local'
    AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
  GROUP BY outcome ORDER BY outcome;
SELECT 'FI_SIZE' AS section,
       pg_size_pretty(sum(pg_total_relation_size(c.oid))) AS relation_storage
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='fi' AND c.relkind IN ('r','m','p');
SELECT 'FI_RELATION_ESTIMATE' AS section, relname,
       n_live_tup AS estimated_rows,
       pg_size_pretty(pg_total_relation_size(relid)) AS relation_size
  FROM pg_stat_user_tables WHERE schemaname='fi'
  ORDER BY pg_total_relation_size(relid) DESC LIMIT 12;
SELECT 'FI_SCHEMA_OBJECTS' AS section,
       (SELECT count(*) FROM pg_constraint c
        JOIN pg_namespace n ON n.oid=c.connamespace
        WHERE n.nspname='fi' AND c.contype='f') AS foreign_keys,
       (SELECT count(*) FROM pg_indexes WHERE schemaname='fi') AS indexes,
       (SELECT count(*) FROM pg_trigger t
        JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='fi' AND NOT t.tgisinternal) AS user_triggers;
SELECT 'EXTENSIONS' AS section,extname,extversion
  FROM pg_extension ORDER BY extname;
SELECT 'NONDEFAULT_TABLESPACES' AS section,
       spcname,pg_size_pretty(pg_tablespace_size(oid)) AS total_bytes
  FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global');
SELECT 'REQUIRED_ROLES' AS section,rolname,rolcanlogin,rolsuper,rolreplication
  FROM pg_roles WHERE rolname IN
    ('fi_ingest','fi_c1_publisher','fi_c1_verifier','fi_sor','postgres')
  ORDER BY rolname;
SELECT 'EXISTING_CLIENT_ACTIVITY' AS section,
       application_name,usename,state,count(*) AS sessions
  FROM pg_stat_activity WHERE datname='fi' AND pid<>pg_backend_pid()
  GROUP BY application_name,usename,state
  ORDER BY application_name,usename,state;
COMMIT;
SQL
echo '===== CAPACITY ON ACTUAL FI-SOR CLONE FILESYSTEM ====='
df -Pk "$sorroot/var/tmp" "$sorroot/var/db/fi" || die 'cannot examine clone/live filesystem'
echo '===== HISTORICAL BENCHMARK DATABASES — DO NOT MODIFY ====='
find "$sorroot/var/tmp" -mindepth 1 -maxdepth 1 -type d -name 'fi-c1-sor-bench.*'   -print | sort || die 'benchmark-root enumeration failed'
echo '===== DATABASE CLIENT VERSIONS ====='
jexec -U postgres fi-sor pg_dump --version
jexec -U postgres fi-sor pg_restore --version
jexec -U postgres fi-sor initdb --version
echo 'FI C1 GATE2 POPULATED SOR INVENTORY COMPLETE read_only=true no_live_mutation=true no_postgres_started=true no_clone_created=true'
