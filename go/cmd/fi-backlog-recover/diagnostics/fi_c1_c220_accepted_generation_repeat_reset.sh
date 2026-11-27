#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# Repeat-test only: preserve real SoR PostgreSQL schema, indexes, roles and
# preexisting recovery snapshot, but erase the EXACT Accepted generation.
# NO snapshot creation; NO rollback. Leave signed receiver custody and cache.
# Never touch receiver custody, authenticated cache, READY, or FI services.
set -eu
umask 077
fail(){ echo "FI C1 ACCEPTED REPEAT RESET STOP: $*" >&2; exit 1; }
if [ "$#" -eq 1 ] && [ "$1" = --audit ];then
 mode=audit
elif [ "$#" -eq 2 ] && [ "$1" = --reset ] &&
     [ "$2" = I-ACKNOWLEDGE-ERASE-ACCEPTED-FI-SOR-GENERATION ];then
 mode=reset
else
 fail "usage: --audit OR --reset I-ACKNOWLEDGE-ERASE-ACCEPTED-FI-SOR-GENERATION"
fi
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
[ "$(id -u)" -eq 0 ] || fail "physical root@c220 required"
ds=fast/data/fi/sor/pgdata
snap=$ds@fi-c1-real-pretest-20261126
pg=/fast/jails/roots/fi-sor/var/db/fi/sor/postgres
[ "$(zfs list -H -t snapshot -o name "$snap")" = "$snap" ] ||
 fail "original ZFS rollback snapshot missing"
[ "$(zfs get -H -o value mountpoint "$ds")" = /fast/data/fi/sor/pgdata ] ||
 fail "unexpected real ZFS dataset"
[ "$(df -P "$pg" | awk 'END{print $1}')" = /fast/data/fi/sor/pgdata ] ||
 fail "PGDATA not on original ZFS dataset"
[ -d "$pg/base" ] && [ -d "$pg/global" ] && [ -d "$pg/pg_wal" ] &&
[ ! -L "$pg/pg_wal" ] || fail "unsafe original PostgreSQL PGDATA"
jls -j fi-sor >/dev/null 2>&1 || fail "fi-sor jail not running"
for svc in fi_c1_sor fi_c1_sor_local;do
 if jexec fi-sor service "$svc" onestatus >/dev/null 2>&1;then
   fail "C1 service $svc running; do not reset"
 fi
done
if jexec fi-sor pgrep -f 'fi-c1-sor-local|fi-c1-sor-direct-real|fi-c1-sor-worker' >/dev/null 2>&1;then
 fail "C1 native process still active"
fi
echo "===== ORIGINAL SNAPSHOT (PRESERVED; NOT ROLLED BACK) ====="
zfs list -t snapshot -o name,used,refer,creation "$snap"
sql(){
 jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 \
  -P pager=off -h /var/db/fi/sor/run -p 5432 -d fi
}
guard=$(cat <<'SQL'
DO $c1_guard$
DECLARE
 sid text; v int; tables_fi int; tables_pending int;
 generations bigint; exact_generation bigint; batches bigint;
 journal bigint; accepted_match bigint; source_records bigint;
 pending bigint; peers bigint;
BEGIN
 SELECT system_identifier::text INTO sid FROM pg_control_system();
 v:=current_setting('server_version_num')::int;
 SELECT count(*) INTO tables_fi FROM pg_class c
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='fi' AND c.relkind IN ('r','p');
 SELECT count(*) INTO tables_pending FROM pg_class c
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='fi_c1_pending' AND c.relkind IN ('r','p');
 SELECT count(*) INTO generations FROM fi.recorded_generation;
 SELECT count(*) INTO exact_generation FROM fi.recorded_generation
  WHERE source_id='iss-fs-22a.iss.local'
    AND generation_id='20261030T000032.061323100Z-3e38b2210771462c'
    AND record_count=15140785 AND batch_count=8399;
 SELECT count(*) INTO batches FROM fi.source_batch;
 SELECT count(*) INTO journal FROM fi.ingest_journal;
 SELECT count(*) INTO accepted_match FROM fi.ingest_journal j
 JOIN fi.recorded_generation g ON g.source_id=j.source_id
   AND g.generation_id=j.generation_id
 WHERE g.source_id='iss-fs-22a.iss.local'
   AND g.generation_id='20261030T000032.061323100Z-3e38b2210771462c'
   AND j.outcome='Accepted'
   AND j.transfer_sha256=g.transfer_sha256
   AND j.records_committed=g.record_count;
 SELECT count(*) INTO source_records FROM fi.source_record;
 SELECT count(*) INTO pending FROM fi_c1_pending.generation_control;
 SELECT count(*) INTO peers FROM pg_stat_activity
  WHERE datname='fi' AND pid<>pg_backend_pid();
 IF sid<>'7690295447535908318' OR v<180000 OR v>=190000 OR
  current_database()<>'fi' OR
  current_setting('data_directory')<>'/var/db/fi/sor/postgres' OR
  pg_is_in_recovery() OR tables_fi<>49 OR tables_pending<>50 OR
  generations<>1 OR exact_generation<>1 OR batches<>8399 OR
  source_records<>15140785 OR journal<>1 OR accepted_match<>1 OR
  pending<>0 OR peers<>0 THEN
   RAISE EXCEPTION 'FI C1 reset refused: sid=% PGver=% schemas=%/% generations=% matched=% batches=% source_records=% journal=% Accepted=% pending=% peers=%',
    sid,v,tables_fi,tables_pending,generations,exact_generation,batches,source_records,journal,accepted_match,pending,peers;
 END IF;
 RAISE NOTICE 'FI C1 EXACT ACCEPTED GENERATION GUARD PASS: sid=% fi_tables=% pending_tables=% batches=% source_records=% journal=1 Accepted=1 pending=0 peers=0',
  sid,tables_fi,tables_pending,batches,source_records;
END $c1_guard$;
SQL
)
echo "===== EXACT REAL PostgreSQL IDENTITY + ACCEPTED-GENERATION GUARD ====="
if [ "$mode" = audit ];then
 {
   printf 'BEGIN READ ONLY;\n%s\nCOMMIT;\n' "$guard"
 } | sql
 echo "FI C1 ACCEPTED REPEAT RESET AUDIT PASS read_only=true"
 exit 0
fi
echo "===== ATOMIC RESET: ALL CANONICAL + PENDING FI ROWS ====="
{
 cat <<'SQL'
BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = 0;
SQL
 printf '%s\n' "$guard"
 cat <<'SQL'
DO $reset$
DECLARE
 table_list text;
 root_count int;
 item record;
 remaining boolean;
BEGIN
 SELECT string_agg(format('%I.%I',n.nspname,c.relname),', ' ORDER BY n.nspname,c.relname),
        count(*)
 INTO table_list,root_count
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('fi','fi_c1_pending')
 AND c.relkind IN ('r','p') AND NOT c.relispartition;
 IF root_count<2 OR table_list IS NULL THEN
  RAISE EXCEPTION 'FI C1: canonical and Pending root table inventory missing';
 END IF;
 -- All original FI and Pending tables in ONE atomic command, with RESTRICT:
 -- unexpected cross-schema foreign keys abort rather than deleting more data.
 EXECUTE 'TRUNCATE TABLE ' || table_list || ' RESTART IDENTITY RESTRICT';
 FOR item IN
  SELECT n.nspname,c.relname FROM pg_class c
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname IN ('fi','fi_c1_pending') AND c.relkind IN ('r','p')
   AND NOT c.relispartition
 LOOP
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.%I)',item.nspname,item.relname)
   INTO remaining;
  IF remaining THEN
   RAISE EXCEPTION 'FI C1 reset incomplete: %.% has rows',item.nspname,item.relname;
  END IF;
 END LOOP;
 RAISE NOTICE 'FI C1 canonical and Pending tables empty; existing schemas, indexes, roles and constraints untouched';
END $reset$;
COMMIT;
SELECT 'recorded_generation' name,count(*) rows FROM fi.recorded_generation
UNION ALL SELECT 'source_batch',count(*) FROM fi.source_batch
UNION ALL SELECT 'source_record',count(*) FROM fi.source_record
UNION ALL SELECT 'ingest_journal',count(*) FROM fi.ingest_journal
UNION ALL SELECT 'pending_generation_control',count(*) FROM fi_c1_pending.generation_control;
SQL
} | sql
echo "FI C1 REAL SOR ACCEPTED REPEAT RESET PASS new_snapshot=false original_snapshot_preserved=true pgdata_retained=true fi_and_pending_rows_zero=true receiver_custody_untouched=true receiver_cache_untouched=true"
