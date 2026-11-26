#!/bin/sh
# Copyright (c) 2026 John Joseph Wood. All rights reserved.
# C220 real SoR direct C1 one-generation acceptance, after independently
# authorized fresh-data reset and role cutover. No implicit reset or rollback.
# Run only after this commit's native FreeBSD tests and acceptance review.
set -eu
umask 077
fail(){ echo "FI C1 REAL DIRECT STOP: $*" >&2;exit 1; }
[ "$(id -u)" = 0 ] && [ "$(uname -s)" = FreeBSD ] &&
[ "$(hostname -s)" = c220 ] || fail 'physical root@c220 FreeBSD required'
[ "$#" -eq 2 ] || fail 'usage: --audit|--run FULL_40_CHARACTER_COMMIT_SHA'
case "$1" in --audit|--run) mode=$1;;*) fail 'invalid mode';;esac
pin=$2
case "$pin" in *[!0123456789abcdef]*|'') fail 'invalid SHA';;esac
[ "${#pin}" -eq 40 ] || fail 'exact commit SHA required'

repo=/home/jwood/fi-c1-two-process-2a449f1a
branch=dev/c1-sor-single-jail-20261124
snapshot=fast/data/fi/sor/pgdata@fi-c1-real-pretest-20261126
data=/fast/jails/roots/fi-sor/var/db/fi/sor/postgres
sor=/fast/jails/roots/fi-sor
dev=/fast/jails/roots/fi-dev
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
root=/var/tmp/fi-c1-sor-local-scratch
socket=/var/db/fi/sor/run
target=/usr/local/sbin/fi-c1-sor-direct-real
hosttarget=$sor$target

[ "$(zfs list -H -t snapshot -o name "$snapshot")" = "$snapshot" ] ||
 fail 'original real-SoR ZFS rollback snapshot is absent'
[ "$(df -P "$data" | awk 'END {print $1}')" = /fast/data/fi/sor/pgdata ] ||
 fail 'PostgreSQL is not on original ZFS dataset'
[ -d "$data/base" ] && [ -d "$data/pg_wal" ] && [ ! -L "$data/pg_wal" ] ||
 fail 'real PostgreSQL data/WAL changed'
for j in fi-dev fi-sor fi-receiver;do jls -j "$j" >/dev/null 2>&1 ||
 fail "required jail $j is absent";done
for service in fi_c1_sor fi_c1_sor_local;do
  if jexec fi-sor service "$service" onestatus >/dev/null 2>&1;then
    fail "competing C1 service $service is active"
  fi
done
if jls -j fi-ingest >/dev/null 2>&1;then
  if jexec fi-ingest service fi_c1_ingest onestatus >/dev/null 2>&1;then
    fail 'competing C1 fi-ingest consumer running'
  fi
fi
if jexec fi-sor /usr/bin/pgrep -f 'fi-c1-sor-local|fi-c1-sor-direct-real' >/dev/null 2>&1;then
  fail 'another C1 direct runner is active'
fi
[ -d "$sor$root" ] && [ ! -L "$sor$root" ] ||
 fail 'original verified fi-sor local extraction scratch missing'

echo '===== EXACT REAL POSTGRESQL CLUSTER, FRESH DATA AND ROLE AUDIT ====='
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -P pager=off \
  -h "$socket" -p 5432 -d fi <<'SQL'
BEGIN READ ONLY;
DO $audit$
DECLARE sid text; generations bigint; accepted bigint; pending bigint;
        source_rows bigint; journal_allowed boolean; write_allowed boolean;
        publisher_allowed boolean; publisher_reinsert boolean; n int;
BEGIN
 SELECT system_identifier::text INTO sid FROM pg_control_system();
 SELECT count(*) INTO generations FROM fi.recorded_generation;
 SELECT count(*) INTO accepted FROM fi.ingest_journal;
 SELECT count(*) INTO pending FROM fi_c1_pending.generation_control;
 SELECT count(*) INTO source_rows FROM fi.source_record;
 SELECT count(*) INTO n FROM pg_stat_activity
   WHERE datname='fi' AND pid<>pg_backend_pid();
 SELECT has_table_privilege('fi_ingest','fi.ingest_journal','INSERT') INTO journal_allowed;
 SELECT has_table_privilege('fi_ingest','fi.source_record','INSERT') INTO write_allowed;
 SELECT has_table_privilege('fi_c1_publisher','fi.ingest_journal','INSERT') INTO publisher_allowed;
 SELECT has_table_privilege('fi_c1_publisher','fi.source_record','INSERT') INTO publisher_reinsert;
 IF sid<>'7690295447535908318' OR current_database()<>'fi'
    OR current_setting('data_directory')<>'/var/db/fi/sor/postgres'
    OR pg_is_in_recovery() OR generations<>0 OR accepted<>0 OR pending<>0
    OR source_rows<>0 OR n<>0 OR journal_allowed OR NOT write_allowed
    OR NOT publisher_allowed OR publisher_reinsert THEN
   RAISE EXCEPTION 'C1 real direct STOP: sid=% generations=% journal=% pending=% source=% other_sessions=% SQL_worker_insert=% worker_publish=% publisher_publish=% publisher_reinsert=%',
      sid,generations,accepted,pending,source_rows,n,write_allowed,journal_allowed,
      publisher_allowed,publisher_reinsert;
 END IF;
 RAISE NOTICE 'C1 REAL SOR DIRECT FRESH START PASS: canonical=0 Accepted=0 source_records=0 pending=0 proper_SQL_roles=true';
END $audit$;
COMMIT;
SQL

echo '===== ORIGINAL SIGNED RECEIVER CUSTODY ====='
for path in "$sor/var/db/fi/custody/generation" \
            "$sor/var/db/fi/custody/recorded";do
  [ -d "$path" ] && [ ! -L "$path" ] ||
    fail "original custody absent $path"
done
jexec -U fi-sor fi-sor /bin/test -r /var/db/fi/custody/generation ||
 fail 'fi-sor cannot access original signed receiver custody'
jexec -U fi-sor fi-sor /bin/test -r /var/db/fi/custody/recorded ||
 fail 'fi-sor cannot access original recorded receipts'

jexec -U jwood fi-dev git -C "$repo" fetch origin \
 "refs/heads/$branch:refs/remotes/origin/$branch" ||
 fail 'development source fetch failed'
[ "$(jexec -U jwood fi-dev git -C "$repo" rev-parse "refs/remotes/origin/$branch")" = "$pin" ] ||
 fail 'development branch moved; exact commit pin changed'
[ "$mode" = --run ] || {
  echo 'FI C1 REAL DIRECT AUDIT PASS (read-only). No SQL rows, services or executables modified.'
  exit 0
}
echo '===== BUILD FREEBSD EXACT PIN (NO BACKGROUND DEPLOY) ====='
build=$(jexec -U jwood fi-dev mktemp -d /home/jwood/fi-c1-direct-real.XXXXXXXX) ||
 fail 'cannot allocate isolated FreeBSD build'
jexec -U jwood fi-dev /bin/sh -c '
 set -eu
 repo=$1
 pin=$2
 build=$3
 git -C "$repo" archive "$pin" | tar -xf - -C "$build"
 cd "$build/go"
 go test -tags fi_c1_sor_dev -count=1 -run "^TestC1Direct|^TestC1NativeBDirect" ./internal/recordingest
 go build -trimpath -tags fi_c1_sor_dev -o "$build/fi-c1-sor-direct-real" ./cmd/fi-c1-sor-local
 test -s "$build/fi-c1-sor-direct-real"
' sh "$repo" "$pin" "$build" || fail 'direct canonical code did not pass local FreeBSD build/tests'
candidate="$dev$build/fi-c1-sor-direct-real"
[ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -s "$candidate" ] ||
 fail 'native executable unavailable'
if [ -e "$hosttarget" ];then
 [ -f "$hosttarget" ] && [ ! -L "$hosttarget" ] &&
 [ "$(sha256 -q "$candidate")" = "$(sha256 -q "$hosttarget")" ] ||
 fail 'old different live test executable exists (never overwrite)'
else
 install -o root -g wheel -m 0555 "$candidate" "$hosttarget" ||
 fail 'install direct canonical development executable failed'
fi
echo '===== ORIGINAL SIGNED RECEIPT / REAL SQL PREFLIGHT ====='
# Read normal service configuration from within fi-sor, not host environment.
# The test runner uses the same C1SoRService/P5/P6/B code as normal READY.
jexec -U fi-sor fi-sor /bin/sh -c '
  set -eu
  . /etc/rc.conf.d/fi_c1_sor
  : "${fi_c1_sor_postgres_local:?}"
  : "${fi_c1_sor_postgres_publisher_local:?}"
  : "${fi_c1_sor_custody_root:?}"
  : "${fi_c1_sor_recorded_root:?}"
  if [ -n "${fi_c1_sor_pgpass:-}" ];then
    PGPASSFILE=$fi_c1_sor_pgpass
    export PGPASSFILE
  fi
  set -- -source-id "$1" -generation-id "$2" \
    -custody-root "$fi_c1_sor_custody_root" \
    -recorded-root "$fi_c1_sor_recorded_root" \
    -postgres-local "$fi_c1_sor_postgres_local" \
    -postgres-publisher-local "$fi_c1_sor_postgres_publisher_local" \
    -sql-workers-max 32 -staging-root "$3"
  if [ "${fi_c1_sor_source_namespaces:-NO}" = YES ];then
    set -- "$@" -source-namespaces
  fi
  /usr/local/sbin/fi-c1-sor-direct-real "$@" -preflight
' sh "$source" "$generation" "$root" || fail 'original signed generation or real SQL preflight failed'

echo '===== RUN EXACT SIGNED GENERATION INTO REAL CANONICAL FI ====='
logdir=$(mktemp -d /root/fi-c1-real-canonical.XXXXXXXX) ||
 fail 'cannot allocate real acceptance log'
echo "FI_C1_REAL_ACCEPTANCE_LOG=$logdir/ingest.log"
if ! jexec -U fi-sor fi-sor /bin/sh -c '
  set -eu
  . /etc/rc.conf.d/fi_c1_sor
  if [ -n "${fi_c1_sor_pgpass:-}" ];then
    PGPASSFILE=$fi_c1_sor_pgpass
    export PGPASSFILE
  fi
  set -- -source-id "$1" -generation-id "$2" \
    -custody-root "$fi_c1_sor_custody_root" \
    -recorded-root "$fi_c1_sor_recorded_root" \
    -postgres-local "$fi_c1_sor_postgres_local" \
    -postgres-publisher-local "$fi_c1_sor_postgres_publisher_local" \
    -sql-workers-max 32 -staging-root "$3"
  if [ "${fi_c1_sor_source_namespaces:-NO}" = YES ];then
    set -- "$@" -source-namespaces
  fi
  exec /usr/local/sbin/fi-c1-sor-direct-real "$@"
' sh "$source" "$generation" "$root" > "$logdir/ingest.log" 2>&1;then
 tail -n 100 "$logdir/ingest.log" >&2 || :
 fail 'C1 did not complete with independent B and canonical Accepted; preserve evidence and assess ZFS rollback'
fi
tail -n 60 "$logdir/ingest.log"
echo '===== FINAL REAL CANONICAL ACCEPTED READBACK ====='
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 -P pager=off \
  -h "$socket" -p 5432 -d fi -c "
SELECT g.source_id,g.generation_id,g.record_count,g.batch_count,
 (SELECT count(*) FROM fi.source_batch b WHERE b.recorded_generation_id=g.recorded_generation_id) AS actual_batches,
 (SELECT count(*) FROM fi.ingest_journal j WHERE j.source_id=g.source_id AND j.generation_id=g.generation_id AND j.outcome='Accepted' AND j.transfer_sha256=g.transfer_sha256 AND j.records_committed=g.record_count) AS matching_accepted
FROM fi.recorded_generation g WHERE g.source_id='$source' AND g.generation_id='$generation'"
echo "FI C1 REAL DIRECT RUN FINISHED; verify full independent B, row counts and journal before promoting to routine service."
