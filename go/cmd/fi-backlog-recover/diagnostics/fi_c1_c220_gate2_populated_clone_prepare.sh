#!/bin/sh
# FI C1 Gate 2 — COPY the existing populated FI development SoR into a
# NEW independent PostgreSQL 18 cluster, preserving real FI tables and data.
# This script NEVER changes the live cluster, runs ingestion, changes
# receiver custody/READY, or deletes any existing benchmark database.
# '--audit' is read-only; '--prepare <SYSTEM_ID> <GENERATIONS>' explicitly
# authorizes disk allocation and a read-only pg_dump of the live FI database.
# The 15,140,785-record signed generation is ALREADY Accepted in live SoR.
# Preserve it unchanged: this tool only copies the populated SoR; it does not
# re-run the accepted signed generation as new data.
# User must first review fi_c1_c220_gate2_populated_sor_inventory.sh output.
set -eu
umask 077
die(){ printf 'FI C1 POPULATED CLONE STOP: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
[ "$(id -u)" -eq 0 ] || die 'requires root on physical C220'
case "${1:-}" in
  --audit) [ "$#" -eq 1 ] || die 'usage: --audit'; mode=audit;;
  --prepare)
    [ "$#" -eq 3 ] || die 'usage: --prepare VERIFIED_LIVE_SYSTEM_ID VERIFIED_GENERATION_COUNT'
    mode=prepare
    expect_sid=$2
    expect_gens=$3
    case "$2:$3" in *[!0123456789:]*|:*) die 'invalid expected live identity/count';; esac ;;
  *) die 'usage: --audit | --prepare VERIFIED_LIVE_SYSTEM_ID VERIFIED_GENERATION_COUNT';;
esac
for jail in fi-sor fi-dev fi-receiver;do
  jls -j "$jail" jid >/dev/null 2>&1 || die "required jail absent: $jail"
done
sorroot=$(jls -j fi-sor path)
[ "$sorroot" = /fast/jails/roots/fi-sor ] ||
  die "unknown fi-sor root $sorroot"
real_socket=/var/db/fi/sor/run
real_pgdata=/var/db/fi/sor/postgres
pg_user=fi_c1_gate2_root
sql(){
  jexec -U postgres fi-sor /usr/local/bin/psql -X -w -At     -v ON_ERROR_STOP=1 -h "$real_socket" -p 5432 -U postgres -d fi -c "$1"
}
identity=$(sql "SELECT current_setting('data_directory')||'|'||
    current_setting('port')||'|'||
    current_setting('server_version_num')::int/10000||'|'||
    pg_is_in_recovery()::text||'|'||
    (SELECT system_identifier FROM pg_control_system())::text")
case "$identity" in
  "$real_pgdata|5432|18|false|"*) :;;
  *) die "unexpected LIVE SoR PostgreSQL identity $identity";;
esac
sid=${identity##*|}
case "$sid" in ''|*[!0123456789]*) die 'invalid LIVE PostgreSQL system ID';; esac
live=$(sql "SELECT (SELECT count(*) FROM fi.recorded_generation)::text||'|'||
    (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')::text||'|'||
    (SELECT count(*) FROM fi_c1_pending.generation_control)::text||'|'||
    (SELECT count(*) FROM pg_tables WHERE schemaname='fi')::text||'|'||
    (SELECT count(*) FROM pg_tables WHERE schemaname='fi_c1_pending')::text||'|'||
    (SELECT count(*) FROM fi.recorded_generation WHERE source_id='iss-fs-22a.iss.local' AND
      generation_id='20261030T000032.061323100Z-3e38b2210771462c')::text")
oldifs=$IFS
IFS='|'
set -- $live
IFS=$oldifs
gens=$1
accepted=$2
pending=$3
fi_tables=$4
pending_tables=$5
target=$6
[ "$gens" -gt 0 ] && [ "$accepted" -gt 0 ] && [ "$pending" = 0 ] &&
[ "$fi_tables" = 49 ] && [ "$pending_tables" = 50 ] && [ "$target" = 1 ] ||
  die "unexpected populated live baseline ($live); existing Accepted generation must be preserved"
[ "$(sql "SELECT count(*) FROM pg_subscription")" = 0 ] ||
  die 'live FI has logical subscriptions; clone startup cannot be assumed isolated'
[ "$(sql "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')")" = 0 ] ||
  die 'live FI uses custom tablespaces; separate manual restore plan required'
[ "$(sql "SELECT count(*) FROM pg_roles WHERE rolname='$pg_user'")" = 0 ] ||
  die "reserved clone-only PostgreSQL superuser already exists on live $pg_user"
# This generation was accepted on 2026-11-24 and is not a new-ingest test
# candidate. Require the exact signed count/batches and one matching Accepted
# journal entry BEFORE cloning; never mutate or delete existing history.
target_evidence=$(sql "SELECT g.record_count::text||'|'||g.batch_count::text||'|'||
 (SELECT count(*) FROM fi.ingest_journal j WHERE j.source_id=g.source_id AND
  j.generation_id=g.generation_id AND j.outcome='Accepted' AND
  j.records_committed=g.record_count AND j.transfer_sha256=g.transfer_sha256)::text
 FROM fi.recorded_generation g WHERE g.source_id='iss-fs-22a.iss.local' AND
 g.generation_id='20261030T000032.061323100Z-3e38b2210771462c'")
[ "$target_evidence" = '15140785|8399|1' ] ||
 die "expected prior signed canonical acceptance proof not found: $target_evidence"
echo "FI C1 GATE2 PRE-ACCEPTED HISTORY VERIFIED records=15140785 batches=8399 matching_accepted=1 preserve_existing=true"
for svc in fi_c1_sor fi_c1_sor_local;do
  if jexec fi-sor service "$svc" onestatus >/dev/null 2>&1;then
    die "C1 service already active: $svc"
  fi
done
db_bytes=$(sql "SELECT pg_database_size('fi')")
case "$db_bytes" in ''|*[!0123456789]*) die 'invalid FI database size';; esac
[ "$db_bytes" -gt 0 ] || die 'empty SoR does not qualify as populated clone'
db_kib=$(( (db_bytes+1023)/1024 ))
# Conservative reserve for dump+restored full data+large test-generation WAL.
need_kib=$((db_kib*3+157286400))
free_kib=$(df -Pk "$sorroot/var/tmp" | awk 'END{print $4}')
case "$free_kib" in ''|*[!0123456789]*) die 'invalid fast pool free space';; esac
[ "$free_kib" -gt "$need_kib" ] ||
  die "insufficient free storage: need_kib=$need_kib free_kib=$free_kib; no cleanup authorized"
echo "FI C1 GATE2 COPY AUDIT PASS live_sid=$sid live_generations=$gens live_accepted=$accepted live_source_present=$target existing_fi_tables=$fi_tables existing_pending_tables=$pending_tables database_bytes=$db_bytes free_kib=$free_kib minimum_kib=$need_kib independent_cluster_required=true"
if [ "$mode" = audit ];then
  echo 'FI C1 GATE2 AUDIT COMPLETE read_only=true no_clone_created=true no_sql_writes=true'
  exit 0
fi
[ "$sid" = "$expect_sid" ] && [ "$gens" = "$expect_gens" ] ||
  die "operator supplied identity/baseline differs (live_sid=$sid live_gens=$gens)"
# Fresh destination not derived from any previous benchmark path.
base=$sorroot/var/tmp
full=$(mktemp -d "$base/fi-c1-populated.XXXXXXXX") ||
  die 'cannot allocate unique new clone directory'
clone=${full#"$sorroot"}
[ "$clone" != "$full" ] || die 'clone path not jail-relative'
uid=$(jexec fi-sor id -u postgres)
gid=$(jexec fi-sor id -g fi-sor)
chown "$uid:$gid" "$full"
chmod 0770 "$full"
install -d -o "$uid" -g "$gid" -m 0770 "$full/socket"
echo "FI C1 GATE2 CLONE_ROOT=$clone"
cat > "$full/CLONE_MANIFEST.txt" <<EOF
source_pgdata=$real_pgdata
source_socket=$real_socket
source_system_id=$sid
source_generations=$gens
source_accepted=$accepted
source_canonical_tables=$fi_tables
source_pending_tables=$pending_tables
source_pg_database_size_bytes=$db_bytes
destination_pgdata=$clone/pgdata
destination_socket=$clone/socket
purpose=gate2_populated_development_sor_only
no_live_writes=true
no_c1_ingestion_authorized=true
signed_generation_already_accepted=true
EOF
chmod 0600 "$full/CLONE_MANIFEST.txt"
echo '===== INITIALIZE INDEPENDENT PG18 CLUSTER, NO TCP ====='
jexec -U postgres fi-sor /usr/local/bin/initdb -D "$clone/pgdata"   -U "$pg_user" -A trust --locale=C --encoding=UTF8 --no-instructions ||
  die 'fresh isolated PostgreSQL initdb failed'
[ ! -e "$full/socket/.s.PGSQL.5432" ] ||
  die 'new clone socket unexpectedly occupied'
jexec -U postgres fi-sor /usr/local/bin/pg_ctl -D "$clone/pgdata"   -l "$clone/postgres.log"   -o "-p 5432 -k $clone/socket -c listen_addresses= -c unix_socket_permissions=0777 -c fsync=on -c synchronous_commit=on -c full_page_writes=on -c max_connections=128 -c max_wal_size=8GB -c wal_buffers=16MB"   -w start || die 'fresh clone startup failed; preserve directory'
clonesql(){
  jexec -U postgres fi-sor /usr/local/bin/psql -X -w -At     -v ON_ERROR_STOP=1 -h "$clone/socket" -p 5432 -U "$pg_user"     -d postgres -c "$1"
}
cloneinfo=$(clonesql "SELECT current_setting('data_directory')||'|'||
    current_setting('unix_socket_directories')||'|'||
    current_setting('listen_addresses')||'|'||
    (SELECT system_identifier FROM pg_control_system())::text")
case "$cloneinfo" in "$clone/pgdata|$clone/socket||"*) :;; *)
  die "clone identity or TCP isolation changed: $cloneinfo";;
esac
clone_sid=${cloneinfo##*|}
[ -n "$clone_sid" ] && [ "$clone_sid" != "$sid" ] ||
  die 'clone and live PostgreSQL cluster system identifiers match'
echo "FI C1 GATE2 NEW CLUSTER VERIFIED system_id=$clone_sid independent_from_live=true tcp_disabled=true"
echo '===== RECREATE FI ROLE DEFINITIONS WITH NO CREDENTIALS ====='
jexec -U postgres fi-sor /usr/local/bin/pg_dumpall --roles-only   --no-role-passwords -w -h "$real_socket" -p 5432 -U postgres   -f "$clone/roles_without_passwords.sql" ||
  die 'read-only source PostgreSQL role export failed'
jexec -U postgres fi-sor /usr/local/bin/psql -X -w -v ON_ERROR_STOP=1   -h "$clone/socket" -p 5432 -U "$pg_user" -d postgres   -f "$clone/roles_without_passwords.sql" > "$full/restore_roles.log" 2>&1 ||
  die 'isolated role restoration failed; do not retry on same clone'
echo '===== CONSISTENT READ-ONLY DUMP OF POPULATED FI ====='
jexec -U postgres fi-sor /usr/local/bin/pg_dump -Fc -Z 6   --lock-wait-timeout=15s -w -h "$real_socket" -p 5432 -U postgres   -d fi -f "$clone/fi-populated.backup" ||
  die 'populated FI pg_dump failed; preserve diagnostic clone'
jexec -U postgres fi-sor /usr/local/bin/pg_restore -l   "$clone/fi-populated.backup" > "$full/archive.toc" ||
  die 'FI archive TOC integrity check failed'
echo '===== RESTORE INTO PHYSICALLY DISTINCT POSTGRESQL INSTANCE ====='
jexec -U postgres fi-sor /usr/local/bin/pg_restore -C -j 4   --exit-on-error --verbose -w -h "$clone/socket" -p 5432   -U "$pg_user" -d postgres "$clone/fi-populated.backup"   > "$full/restore_fi.log" 2>&1 ||
  die 'populated FI restore failed; leave clone, logs and archive untouched'
clfi(){
  jexec -U postgres fi-sor /usr/local/bin/psql -X -w -At -v ON_ERROR_STOP=1     -h "$clone/socket" -p 5432 -U "$pg_user" -d fi -c "$1"
}
clone_counts=$(clfi "SELECT (SELECT count(*) FROM fi.recorded_generation)::text||'|'||
   (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')::text||'|'||
   (SELECT count(*) FROM fi_c1_pending.generation_control)::text||'|'||
   (SELECT count(*) FROM pg_tables WHERE schemaname='fi')::text||'|'||
   (SELECT count(*) FROM pg_tables WHERE schemaname='fi_c1_pending')::text||'|'||
   (SELECT count(*) FROM fi.recorded_generation WHERE source_id='iss-fs-22a.iss.local' AND
    generation_id='20261030T000032.061323100Z-3e38b2210771462c')::text")
[ "$clone_counts" = "$live" ] ||
  die "populated clone counts not equal to live prestate; clone=$clone_counts live_prestate=$live"
clone_target_evidence=$(clfi "SELECT g.record_count::text||'|'||g.batch_count::text||'|'||
 (SELECT count(*) FROM fi.ingest_journal j WHERE j.source_id=g.source_id AND
  j.generation_id=g.generation_id AND j.outcome='Accepted' AND
  j.records_committed=g.record_count AND j.transfer_sha256=g.transfer_sha256)::text
 FROM fi.recorded_generation g WHERE g.source_id='iss-fs-22a.iss.local' AND
 g.generation_id='20261030T000032.061323100Z-3e38b2210771462c'")
[ "$clone_target_evidence" = "$target_evidence" ] ||
  die "pre-Accepted signed target changed in populated clone: $clone_target_evidence"
# Full source-record COUNT checks are deliberate on this 54M+ row SoR:
# a logically restored copy must contain every pre-existing canonical row.
source_rows_live=$(sql "SELECT count(*) FROM fi.source_record")
source_rows_clone=$(clfi "SELECT count(*) FROM fi.source_record")
[ "$source_rows_live" = "$source_rows_clone" ] ||
  die "canonical source_record count mismatch live=$source_rows_live cloned=$source_rows_clone"
schema_live=$(sql "SELECT (SELECT count(*) FROM pg_indexes WHERE schemaname='fi')::text||'|'||
  (SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='fi' AND c.contype='f')::text")
schema_clone=$(clfi "SELECT (SELECT count(*) FROM pg_indexes WHERE schemaname='fi')::text||'|'||
  (SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='fi' AND c.contype='f')::text")
[ "$schema_live" = "$schema_clone" ] ||
  die "FI index/FK layout mismatch live=$schema_live clone=$schema_clone"
echo "FI C1 GATE2 POPULATED DATA/DDL VERIFIED source_records=$source_rows_clone fi_indexes_and_fks=$schema_clone"
[ "$(clfi "SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='fi' AND c.contype='f' AND NOT c.convalidated")" = 0 ] ||
  die 'restored FI canonical constraints are NOT validated'
[ "$(sql "SELECT (SELECT count(*) FROM fi.recorded_generation)::text||'|'||
   (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')::text||'|'||
   (SELECT count(*) FROM fi_c1_pending.generation_control)::text||'|'||
   (SELECT count(*) FROM pg_tables WHERE schemaname='fi')::text||'|'||
   (SELECT count(*) FROM pg_tables WHERE schemaname='fi_c1_pending')::text||'|'||
   (SELECT count(*) FROM fi.recorded_generation WHERE source_id='iss-fs-22a.iss.local' AND
    generation_id='20261030T000032.061323100Z-3e38b2210771462c')::text")" = "$live" ] ||
  die 'real SoR baseline changed during clone; do not use this clone for acceptance'
echo "FI C1 GATE2 POPULATED CLONE READY clone_root=$clone clone_system_id=$clone_sid live_system_id=$sid original_generations=$gens original_accepted=$accepted canonical_tables=49 pending_tables=50 sql_archive=fi-populated.backup verified_fk=true ready_queue_untouched=true original_live_untouched=true prior_signed_generation_accepted=true NO_INGESTION_PERFORMED=true"
