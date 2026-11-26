#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# FI C1 FreeBSD fi-sor direct-canonical SQL role cutover.
# Offline operator-controlled database *permissions* only, no FI rows cleared.
# A separate ZFS snapshot and fresh-data reset are prerequisites for the
# destructive integration test. The script itself never starts C1.
set -eu
umask 077

mode="${1:-}"
case "$mode" in
  --audit|--apply) test "$#" -eq 1 || exit 2 ;;
  *) echo 'usage: sh fi_c1_c220_direct_canonical_roles.sh --audit|--apply' >&2; exit 2;;
esac
snapshot=fast/data/fi/sor/pgdata@fi-c1-real-pretest-20261126
test "$(zfs list -H -t snapshot -o name "$snapshot")" = "$snapshot" || {
    echo 'STOP: real SoR pretest snapshot absent' >&2;exit 1;
}
test "$(df -P /fast/jails/roots/fi-sor/var/db/fi/sor/postgres | awk 'END{print $1}')" = /fast/data/fi/sor/pgdata || {
    echo 'STOP: not the verified real C220 database storage' >&2;exit 1;
}

echo "===== C1 DIRECT CANONICAL SQL ROLE AUDIT ====="
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -P pager=off \
    -h /var/db/fi/sor/run -p 5432 -d fi <<'SQL'
BEGIN READ ONLY;
DO $check$
DECLARE sid text; ct int; journal int;
BEGIN
 SELECT system_identifier::text INTO sid FROM pg_control_system();
 SELECT count(*) INTO ct FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi' AND c.relkind IN ('r','p') AND NOT c.relispartition;
 SELECT count(*) INTO journal FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi' AND c.relname='ingest_journal';
 IF sid<>'7690295447535908318' OR current_database()<>'fi' OR
    current_setting('data_directory')<>'/var/db/fi/sor/postgres' OR
    pg_is_in_recovery() OR ct<>49 OR journal<>1 OR
    NOT EXISTS(SELECT FROM pg_roles WHERE rolname='fi_ingest' AND NOT rolsuper) OR
    NOT EXISTS(SELECT FROM pg_roles WHERE rolname='fi_c1_publisher' AND NOT rolsuper) THEN
   RAISE EXCEPTION 'STOP: wrong FI PostgreSQL 18 C220 identity/schema/roles';
 END IF;
 RAISE NOTICE 'C1 direct canonical role target verified SID=% tables=%',sid,ct;
END $check$;
COMMIT;
SQL

if [ "$mode" = --audit ];then
    echo 'AUDIT COMPLETE. No privilege or record mutations.'
    exit 0
fi

echo "===== APPLY NARROW C1 DIRECT SQL PRIVILEGE CUTOVER ====="
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -P pager=off \
    -h /var/db/fi/sor/run -p 5432 -d fi <<'SQL'
BEGIN;
SET LOCAL lock_timeout='10s';
DO $check$
DECLARE n int;
BEGIN
 SELECT count(*) INTO n FROM pg_stat_activity
 WHERE datname='fi' AND pid<>pg_backend_pid();
 IF n<>0 THEN RAISE EXCEPTION 'STOP: % other FI SQL sessions active',n;END IF;
 IF (SELECT system_identifier::text FROM pg_control_system())<>'7690295447535908318' THEN
   RAISE EXCEPTION 'STOP: wrong PostgreSQL cluster'; END IF;
END $check$;

REVOKE CREATE ON SCHEMA fi FROM PUBLIC,fi_ingest,fi_c1_publisher;
GRANT USAGE ON SCHEMA fi TO fi_ingest,fi_c1_publisher;
-- Ordered parent and five typed-family C1 workers insert directly once.
GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA fi TO fi_ingest;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA fi TO fi_ingest;
REVOKE UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN
  ON ALL TABLES IN SCHEMA fi FROM fi_ingest;
REVOKE INSERT ON fi.ingest_journal FROM fi_ingest;
-- Only B-gated publisher records a journal event; it cannot remap rows.
REVOKE INSERT ON ALL TABLES IN SCHEMA fi FROM fi_c1_publisher;
GRANT SELECT,MAINTAIN ON ALL TABLES IN SCHEMA fi TO fi_c1_publisher;
GRANT INSERT ON fi.ingest_journal TO fi_c1_publisher;
COMMIT;
SQL

echo '===== VERIFY EXACT WORKER / PUBLISHER PERMISSIONS ====='
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 \
    -h /var/db/fi/sor/run -p 5432 -d fi -c "
SELECT
 has_table_privilege('fi_ingest','fi.source_record','INSERT') AS worker_insert,
 has_table_privilege('fi_ingest','fi.ingest_journal','INSERT') AS worker_cannot_publish,
 has_table_privilege('fi_c1_publisher','fi.source_record','INSERT') AS publisher_cannot_reinsert,
 has_table_privilege('fi_c1_publisher','fi.ingest_journal','INSERT') AS publisher_journal_insert"
echo 'C1 DIRECT CANONICAL ROLE CUTOVER COMPLETE — NO FI RECORDS DELETED OR INGESTED'
