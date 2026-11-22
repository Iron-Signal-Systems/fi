#!/bin/sh
# FI C1 read-only deployment gate for the EXISTING physical FreeBSD C220.
# Does not modify PostgreSQL, mount, custody, jails, rc.conf or services.
set -eu
umask 077
fail(){ echo "FI C1 C220 GOVERNED DEPLOY STOP: $*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'usage: --audit | --ready'
case "$1" in --audit) strict=0;; --ready) strict=1;; *) fail 'unknown gate mode';; esac
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
[ "$(id -u)" -eq 0 ] || fail 'physical C220 root FreeBSD host required'

echo '===== ACTUAL C220 FI JAIL INVENTORY ====='
for jail in fi-receiver fi-ingest fi-sor;do
  jls -j "$jail" jid >/dev/null 2>&1 ||
    fail "required existing FI jail not running: $jail"
  expected="/fast/jails/roots/$jail"
  actual=$(jls -h jid name path | awk -v name="$jail" '$2==name{print $3}')
  [ "$actual" = "$expected" ] ||
    fail "wrong existing jail root for $jail: $actual"
  echo "C1_JAIL=$jail path=$actual"
done
if jls -j fi-sor-db jid >/dev/null 2>&1;then
  fail 'second fi-sor-db running: PostgreSQL ownership ambiguous'
fi
jexec fi-ingest id fi-ingest >/dev/null || fail 'fi-ingest service identity absent'
[ "$(jexec fi-sor id -u fi-sor)" = 4100 ] &&
[ "$(jexec fi-sor id -g fi-sor)" = 4100 ] ||
  fail 'fi-sor runtime UID/GID changed from 4100'
jexec fi-sor id postgres >/dev/null || fail 'PostgreSQL identity absent'

echo '===== HOST TMPFS AND JAIL-ISOLATED HANDOFF ====='
ram=/var/run/fi-c1-handoff
ingest=/fast/jails/roots/fi-ingest
sor=/fast/jails/roots/fi-sor
options=$(mount -p | awk -v m="$ram" '$2==m && $3=="tmpfs"{print $4}')
irw=$(mount -p | awk -v m="$ingest$ram" '$2==m && $3=="nullfs"{print $4}')
sro=$(mount -p | awk -v m="$sor$ram" '$2==m && $3=="nullfs"{print $4}')
[ -n "$options" ] && [ -n "$irw" ] && [ -n "$sro" ] ||
  fail 'missing host tmpfs or isolated jail nullfs mount'
case ",$options," in *,noexec,*) :;; *) fail 'host RAM lacks noexec';; esac
case ",$options," in *,nosuid,*) :;; *) fail 'host RAM lacks nosuid';; esac
case ",$irw," in *,ro,*) fail 'fi-ingest RAM producer unexpectedly read-only';; esac
case ",$sro," in *,ro,*) :;; *) fail 'fi-sor RAM consumer has write authority';; esac
echo 'C1_RAM_ISOLATION=PASS host=tmpfs ingest=rw sor=ro'

echo '===== REAL FI POSTGRESQL 18 (READ-ONLY SQL) ====='
sock=/var/db/fi/sor/run
jexec -U postgres fi-sor pg_isready -h "$sock" -p 5432 >/dev/null ||
  fail 'real fi-sor Unix PostgreSQL socket not ready'
sql(){
  jexec -U postgres fi-sor psql -X -w -h "$sock" -p 5432 \
    -d fi -At -v ON_ERROR_STOP=1 -c "$1"
}
pgdata=$(sql 'SHOW data_directory') || fail 'cannot read real PGDATA'
[ "$pgdata" = /var/db/fi/sor/postgres ] ||
  fail "wrong physical FI SoR PGDATA $pgdata"
identity=$(sql "SELECT current_database()||'|'||
  current_setting('server_version_num')||'|'||
  pg_is_in_recovery()::text||'|'||current_setting('fsync')||'|'||
  current_setting('synchronous_commit')||'|'||
  current_setting('full_page_writes')") ||
    fail 'cannot query durable database identity'
case "$identity" in fi\|18????\|false\|on\|on\|on) :;;
  *) fail "not the expected writable durable PostgreSQL18: $identity";;
esac
canonical=$(sql "SELECT count(*) FROM information_schema.tables WHERE table_schema='fi'") ||
  fail 'cannot inspect canonical FI relational schema'
[ "$canonical" = 49 ] || fail "canonical FI 49-table graph changed: $canonical"
echo "C1_CANONICAL_FI_TABLES=$canonical PGDATA_VERIFIED=true"

echo '===== GOVERNED C1 PENDING / WORKER / PUBLISHER ====='
flags=$(sql "SELECT
 (to_regnamespace('fi_c1_pending') IS NOT NULL)::int||'|'||
 EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_ingest')::int||'|'||
 EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_c1_publisher')::int") ||
   fail 'cannot read governed Pending role presence'
echo "C1_PENDING_WORKER_PUBLISHER=$flags"
ready_sql=0
if [ "$flags" = '1|1|1' ];then
  count=$(sql "SELECT count(*) FROM information_schema.tables
    WHERE table_schema='fi_c1_pending'") || fail 'read pending tables'
  [ "$count" = 50 ] || fail "Pending 49 tables/control incomplete: $count"
  privileges=$(sql "SELECT
    has_table_privilege('fi_ingest','fi_c1_pending.source_record','INSERT')::int||'|'||
    has_table_privilege('fi_ingest','fi_c1_pending.ingest_journal','SELECT')::int||'|'||
    has_table_privilege('fi_ingest','fi_c1_pending.ingest_journal','INSERT')::int||'|'||
    has_table_privilege('fi_ingest','fi.source_record','INSERT')::int||'|'||
    has_table_privilege('fi_c1_publisher','fi.source_record','MAINTAIN')::int||'|'||
    has_table_privilege('fi_c1_publisher','fi.ingest_journal','INSERT')::int||'|'||
    has_table_privilege('fi_c1_publisher','fi.source_record','UPDATE')::int||'|'||
    has_table_privilege('fi_c1_publisher','fi.source_record','TRUNCATE')::int||'|'||
    has_table_privilege('fi_c1_publisher','fi_c1_pending.source_record','TRUNCATE')::int") ||
    fail 'read C1 local SQL-role authority'
  [ "$privileges" = '1|1|0|0|1|1|0|0|1' ] ||
    fail "unsafe C1 PostgreSQL-role separation: $privileges"
  canonical_writes=$(sql "SELECT count(*) FROM pg_class c
      JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='fi' AND c.relkind IN ('r','p') AND
        (has_table_privilege('fi_ingest',c.oid,'INSERT')
         OR has_table_privilege('fi_ingest',c.oid,'UPDATE')
         OR has_table_privilege('fi_ingest',c.oid,'DELETE')
         OR has_table_privilege('fi_ingest',c.oid,'TRUNCATE')
         OR has_table_privilege('fi_ingest',c.oid,'MAINTAIN'))") ||
    fail 'cannot verify fi_ingest canonical 49-table isolation'
  [ "$canonical_writes" = 0 ] ||
    fail "fi_ingest retains canonical insert/mutation authority on $canonical_writes FI tables"
  unresolved=$(sql "SELECT
    (SELECT count(*) FROM fi_c1_pending.recorded_generation)+
    (SELECT count(*) FROM fi_c1_pending.generation_control)+
    (SELECT count(*) FROM fi_c1_pending.source_record)") ||
    fail 'read Pending unresolved generation count'
  [ "$unresolved" = 0 ] ||
    fail "unresolved signed Pending SQL exists: $unresolved; audit original custody first"
  ready_sql=1
fi
echo "C1_GOVERNED_SQL_INSTALLED_AND_EMPTY=$ready_sql"

echo '===== DISABLED-BY-DEFAULT NATIVE C1 SERVICE ASSETS ====='
ready_rc=1
for jail in fi-ingest fi-sor;do
  service=fi_c1_ingest
  binary=fi-c1-ingest-worker
  [ "$jail" = fi-sor ] && service=fi_c1_sor
  [ "$jail" = fi-sor ] && binary=fi-c1-sor-worker
  if ! jexec "$jail" /bin/test -f "/etc/rc.conf.d/$service";then
    echo "C1_RC_$jail=NOT_STAGED"
    ready_rc=0
    continue
  fi
  jexec "$jail" /usr/bin/grep -Eq "^$service""_enable=\"NO\"$" \
    "/etc/rc.conf.d/$service" ||
    fail "existing $jail C1 rc service enabled or changed; no activation authorized"
  if ! jexec "$jail" /bin/test -x "/usr/local/sbin/$binary";then
    echo "C1_BINARY_$jail=NOT_STAGED"
    ready_rc=0
  else
    echo "C1_BINARY_$jail=STAGED"
  fi
done
if [ "$ready_rc" -eq 1 ];then
  if ! grep -Eq '^fi_c1_sor_postgres_local="[^"]+"' "$sor/etc/rc.conf.d/fi_c1_sor" ||
     ! grep -Eq '^fi_c1_sor_postgres_publisher_local="[^"]+"' "$sor/etc/rc.conf.d/fi_c1_sor";then
    echo 'C1_SOR_SQL_ROLE_DSN_CONFIG=INCOMPLETE'
    ready_rc=0
  fi
  if ! grep -Eq '^fi_c1_ingest_generation_id="[^"]+"' "$ingest/etc/rc.conf.d/fi_c1_ingest" &&
     ! grep -Eq '^fi_c1_ingest_ready_root="[^"]+"' "$ingest/etc/rc.conf.d/fi_c1_ingest";then
    echo 'C1_INGEST_SIGNED_SOURCE_CONFIG=INCOMPLETE'
    ready_rc=0
  fi
fi
echo "C1_NATIVE_RC_STAGING_READY=$ready_rc"

# An installed binary and valid-looking rc.conf are NOT a startup proof.
# Invoke BOTH actual unprivileged workers through their exact installed
# rc runners in read-only verification mode. Their Go preflight verifies
# the original receiver input/TLS/tmpfs and local PG18 worker/publisher roles,
# without a TCP listener, SQL write, B process or READY retirement.
verified_workers=0
if [ "$ready_rc" -eq 1 ] && [ "$ready_sql" -eq 1 ];then
  jexec -U fi-ingest fi-ingest /usr/local/libexec/fi-c1-ingest-run --verify ||
    fail 'actual jailed fi-ingest worker failed read-only C1 startup preflight'
  jexec -U fi-sor fi-sor /usr/local/libexec/fi-c1-sor-run --verify ||
    fail 'actual jailed fi-sor worker failed read-only C1 startup preflight'
  verified_workers=1
fi
echo "C1_NATIVE_UNPRIVILEGED_WORKER_PREFLIGHT=$verified_workers"
if [ "$strict" -eq 1 ];then
  [ "$ready_sql" -eq 1 ] && [ "$ready_rc" -eq 1 ] &&
  [ "$verified_workers" -eq 1 ] ||
    fail 'C1 worker startup, offline Pending/role installation or disabled service staging incomplete'
fi
echo "FI C1 C220 GOVERNED DEPLOY GATE COMPLETE mode=$1 read_only=true canonical_unchanged=true services_started=false"
