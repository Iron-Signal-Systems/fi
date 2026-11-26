#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Development-only FI C220 real-SoR DATA reset, NOT an installer or C1 runner.
# No DROP DATABASE / DROP SCHEMA / deletion of receiver custody.
# The approved signed C1 direct-canonical runner must be separately accepted.
set -eu
umask 077

mode="${1:-}"
ack="${2:-}"
case "$mode" in
    --audit) test "$#" -eq 1 || exit 2 ;;
    --reset)
        test "$#" -eq 2 || exit 2
        test "$ack" = 'I-ACKNOWLEDGE-RESET-ALL-FI-SOR-DATA' || {
            echo "STOP: explicit full-data reset acknowledgement required" >&2
            exit 2
        } ;;
    *) echo "usage: sh $0 --audit OR --reset I-ACKNOWLEDGE-RESET-ALL-FI-SOR-DATA" >&2; exit 2 ;;
esac

dataset=fast/data/fi/sor/pgdata
snapshot="$dataset@fi-c1-real-pretest-20261126"
pgpath=/fast/jails/roots/fi-sor/var/db/fi/sor/postgres
socket=/var/db/fi/sor/run
expected_sid=7690295447535908318

echo "===== VERIFY REAL C220 SOR ZFS SNAPSHOT / STORAGE ====="
test "$(zfs list -H -t snapshot -o name "$snapshot")" = "$snapshot" || {
    echo 'STOP: exact pretest ZFS snapshot absent' >&2; exit 1
}
test "$(zfs get -H -o value mountpoint "$dataset")" = /fast/data/fi/sor/pgdata || {
    echo 'STOP: unexpected real SoR ZFS dataset mountpoint' >&2; exit 1
}
test -d "$pgpath/base" && test -d "$pgpath/global" && test -d "$pgpath/pg_wal" || {
    echo 'STOP: PostgreSQL data or WAL missing' >&2; exit 1
}
test ! -L "$pgpath/pg_wal" || {
    echo 'STOP: external WAL symlink found' >&2; exit 1
}
actual_fs=$(df -P "$pgpath" | awk 'END {print $1}')
test "$actual_fs" = /fast/data/fi/sor/pgdata || {
    echo "STOP: PGDATA not mounted on expected ZFS storage: $actual_fs" >&2; exit 1
}
zfs list -t snapshot -o name,used,refer,creation "$snapshot"

echo "===== REFUSE A RUNNING C1 PIPELINE ====="
if jexec fi-sor service fi_c1_sor onestatus >/dev/null 2>&1; then
    echo 'STOP: fi_c1_sor is running' >&2; exit 1
fi
if jexec fi-ingest service fi_c1_ingest onestatus >/dev/null 2>&1; then
    echo 'STOP: fi_c1_ingest is running' >&2; exit 1
fi
if jexec fi-sor pgrep -f 'fi-c1-sor-local' >/dev/null 2>&1; then
    echo 'STOP: fi-c1-sor-local is running' >&2; exit 1
fi

echo "===== READ-ONLY SQL IDENTITY / SCHEMA / SESSION AUDIT ====="
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -P pager=off \
    -h "$socket" -p 5432 -d fi <<'SQL'
BEGIN TRANSACTION READ ONLY;
DO $gate$
DECLARE sid text; v integer; nfi integer; npending integer;
        canonical bigint; accepted bigint; other_sessions bigint;
        pending_controls bigint;
BEGIN
 SELECT system_identifier::text INTO sid FROM pg_control_system();
 v := current_setting('server_version_num')::integer;
 SELECT count(*) INTO nfi FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='fi' AND c.relkind IN ('r','p');
 SELECT count(*) INTO npending FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='fi_c1_pending' AND c.relkind IN ('r','p');
 SELECT count(*) INTO canonical FROM fi.recorded_generation;
 SELECT count(*) INTO accepted FROM fi.ingest_journal WHERE outcome='Accepted';
 SELECT count(*) INTO pending_controls FROM fi_c1_pending.generation_control;
 SELECT count(*) INTO other_sessions FROM pg_stat_activity
     WHERE datname='fi' AND pid<>pg_backend_pid();
 IF sid<>'7690295447535908318' OR v<180000 OR v>=190000 OR
    current_database()<>'fi' OR
    current_setting('data_directory')<>'/var/db/fi/sor/postgres' OR
    pg_is_in_recovery() OR nfi<>49 OR npending<>50 OR
    canonical<>6773 OR accepted<>6773 OR pending_controls<>0 OR
    other_sessions<>0 THEN
   RAISE EXCEPTION 'C1 real SoR reset audit STOP: sid=% PGversion=% tables=%/% generations=% accepted=% pending_controls=% other_sessions=%',
      sid,v,nfi,npending,canonical,accepted,pending_controls,other_sessions;
 END IF;
 RAISE NOTICE 'C1 REAL SOR RESET PREFLIGHT PASS: sid=% fi_tables=% pending_tables=% generations=% accepted=% pending_controls=% other_sessions=%',
      sid,nfi,npending,canonical,accepted,pending_controls,other_sessions;
END $gate$;
COMMIT;
SQL
if [ "$mode" = --audit ]; then
    echo 'FI C1 REAL SOR FRESH RESET AUDIT PASS; NO ROWS MODIFIED'
    exit 0
fi

echo '===== RESET ALL FI / FI_C1_PENDING ROW DATA IN ONE TRANSACTION ====='
echo 'WARNING: this deletes ALL 6773 historical Accepted generations and all associated FI rows from the working database.'
echo "WARNING: only the ZFS snapshot preserves the pre-reset cluster."
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -P pager=off \
    -h "$socket" -p 5432 -d fi <<'SQL'
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '180s';
DO $reset$
DECLARE sid text; nfi integer; npending integer; canonical bigint;
        accepted bigint; pending_controls bigint; other_sessions bigint;
        table_list text;
BEGIN
 SELECT system_identifier::text INTO sid FROM pg_control_system();
 SELECT count(*) INTO nfi FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='fi' AND c.relkind IN ('r','p');
 SELECT count(*) INTO npending FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='fi_c1_pending' AND c.relkind IN ('r','p');
 SELECT count(*) INTO canonical FROM fi.recorded_generation;
 SELECT count(*) INTO accepted FROM fi.ingest_journal WHERE outcome='Accepted';
 SELECT count(*) INTO pending_controls FROM fi_c1_pending.generation_control;
 SELECT count(*) INTO other_sessions FROM pg_stat_activity
     WHERE datname='fi' AND pid<>pg_backend_pid();
 IF sid<>'7690295447535908318' OR
    current_database()<>'fi' OR
    current_setting('data_directory')<>'/var/db/fi/sor/postgres' OR
    pg_is_in_recovery() OR nfi<>49 OR npending<>50 OR
    canonical<>6773 OR accepted<>6773 OR pending_controls<>0 OR
    other_sessions<>0 THEN
   RAISE EXCEPTION 'C1 real SoR changed after audit; no deletion permitted';
 END IF;
 SELECT string_agg(format('%I.%I',n.nspname,c.relname),', ' ORDER BY n.nspname,c.relname)
 INTO table_list
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('fi','fi_c1_pending') AND c.relkind IN ('r','p')
 AND NOT c.relispartition;
 IF table_list IS NULL THEN RAISE EXCEPTION 'C1 real SoR has no tables to reset'; END IF;
 -- RESTRICT is deliberate: unexpected cross-schema foreign keys must abort.
 -- The command leaves schemas, constraints, indexes, and roles unchanged.
 EXECUTE 'TRUNCATE TABLE ' || table_list || ' RESTART IDENTITY RESTRICT';
 IF (SELECT count(*) FROM fi.recorded_generation)<>0 OR
    (SELECT count(*) FROM fi.ingest_journal)<>0 OR
    (SELECT count(*) FROM fi.source_record)<>0 OR
    (SELECT count(*) FROM fi_c1_pending.source_record)<>0 OR
    (SELECT count(*) FROM fi_c1_pending.generation_control)<>0 THEN
   RAISE EXCEPTION 'C1 real SoR post-reset validation failed; rolling back transaction';
 END IF;
 RAISE NOTICE 'FI C1 REAL SOR DATA RESET TRANSACTION VALIDATED; 49 canonical and 50 Pending relations retained';
END $reset$;
COMMIT;
SELECT 'canonical_generation_count' AS item,count(*) AS rows FROM fi.recorded_generation
UNION ALL SELECT 'canonical_journal_events',count(*) FROM fi.ingest_journal
UNION ALL SELECT 'canonical_source_records',count(*) FROM fi.source_record
UNION ALL SELECT 'pending_generation_control',count(*) FROM fi_c1_pending.generation_control
UNION ALL SELECT 'pending_source_records',count(*) FROM fi_c1_pending.source_record;
SQL

echo "FI C1 REAL SOR ROW DATA RESET COMPLETE: snapshot=$snapshot"
echo 'NO C1 RUN PERFORMED. Use the separately approved direct-canonical C1 writer only.'
