#!/bin/sh
# FI DEV ONLY: compare signed-source identities rather than SQL-generated IDs.
# Never changes either database, and never reads original custody archives.
set -eu
umask 077
fail() { printf 'FI FIELD IDENTITY STOP: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'usage: sh diagnose_full_field_mismatch.sh /home/jwood/fi-window-bench-fieldpart-<timestamp>'
cluster=$1
case "$cluster" in
  /home/jwood/fi-window-bench-fieldpart-[0-9]*) ;;
  *) fail 'unapproved field-partition benchmark cluster path' ;;
esac
case "$cluster" in *..*|*' '*|*'*'*|*'?'*|*'['*|*']'*) fail 'unsafe cluster path';; esac
[ -d "$cluster/W32/socket" ] && [ -d "$cluster/W64/socket" ] || fail 'missing control/candidate sockets'
[ "$(id -un)" = jwood ] || fail 'run as jwood inside fi-dev'
[ "$(sysctl -n security.jail.jailed)" = 1 ] || fail 'must run inside fi-dev jail'
for bin in psql sha256 mktemp diff awk sed; do command -v "$bin" >/dev/null 2>&1 || fail "missing $bin"; done
work=$(mktemp -d /home/jwood/fi-field-identity-XXXXXXXX) || fail 'could not create report dir'
printf 'FI FIELD IDENTITY REPORT directory=%s\n' "$work"
dsn() {
  case "$1" in
    W32) port=55961 ;;
    W64) port=55962 ;;
    *) fail "unknown profile $1" ;;
  esac
  printf 'host=%s/%s/socket port=%s user=fi_ingest dbname=fi sslmode=disable' "$cluster" "$1" "$port"
}
sql() { profile=$1; shift; psql "$(dsn "$profile")" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
# Logical identity uses original batch ID + signed ordinal + field ordinal.
# SERIAL-generated PostgreSQL IDs are intentionally excluded.
logical_copy='COPY (
 SELECT b.batch_id, r.record_ordinal, f.field_ordinal, f.name, f.value
 FROM fi_recovery_projection.windows_security_event_field f
 JOIN fi_recovery_projection.source_record r ON r.source_record_id=f.source_record_id
 JOIN fi_recovery_projection.source_batch b ON b.source_batch_id=r.source_batch_id
 ORDER BY b.batch_id COLLATE "C", r.record_ordinal, f.field_ordinal
) TO STDOUT WITH (FORMAT csv, FORCE_QUOTE *)'
physical_copy='COPY (
 SELECT f.source_record_id, f.field_ordinal, f.name, f.value
 FROM fi_recovery_projection.windows_security_event_field f
 ORDER BY f.source_record_id, f.field_ordinal
) TO STDOUT WITH (FORMAT csv, FORCE_QUOTE *)'
for profile in W32 W64; do
  identity=$(sql "$profile" "SELECT current_database() || '|' || current_user || '|' || current_setting('port') || '|' || current_setting('fsync') || '|' || current_setting('synchronous_commit')") || fail "$profile connection"
  case "$identity" in
    "fi|fi_ingest|$(if [ "$profile" = W32 ]; then echo 55961; else echo 55962; fi)|on|on") ;;
    *) fail "$profile wrong database/port/durability: $identity" ;;
  esac
  sql "$profile" "SELECT window_index || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index" > "$work/$profile.checkpoints" || fail "$profile checkpoints"
  [ "$(wc -l < "$work/$profile.checkpoints" | tr -d ' ')" = 3 ] || fail "$profile expected seed plus two typed windows"
  sql "$profile" "SELECT count(*)::text || '|' || min(source_record_id)::text || '|' || max(source_record_id)::text FROM fi_recovery_projection.windows_security_event_field" > "$work/$profile.field-range" || fail "$profile field stats"
  sql "$profile" "SELECT count(*)::text FROM fi_recovery_projection.source_record" > "$work/$profile.source-count" || fail "$profile source count"
  [ "$(cat "$work/$profile.source-count")" = 390387 ] || fail "$profile source count mismatch"
  [ "$(cut -d '|' -f 1 "$work/$profile.field-range")" = 4838850 ] || fail "$profile field count mismatch"
  sql "$profile" "SELECT count(*)::text FROM fi.recorded_generation" > "$work/$profile.authoritative-count" || fail "$profile canonical check"
  [ "$(cat "$work/$profile.authoritative-count")" = 0 ] || fail "$profile authoritative data present"
  sql "$profile" "SELECT count(*)::text FROM fi.ingest_journal WHERE outcome='Accepted'" > "$work/$profile.accepted-count" || fail "$profile acceptance check"
  [ "$(cat "$work/$profile.accepted-count")" = 0 ] || fail "$profile Accepted journal present"
  printf 'FI FIELD IDENTITY CHECK profile=%s fields=%s source_records=%s checkpoints=3 authoritative=0 accepted=0\n' "$profile" "$(cat "$work/$profile.field-range")" "$(cat "$work/$profile.source-count")"
  for mode in physical logical; do
    case "$mode" in physical) query=$physical_copy ;; logical) query=$logical_copy ;; esac
    sql "$profile" "$query" > "$work/$profile.$mode.csv" || fail "$profile $mode export failed"
    sha256 -q "$work/$profile.$mode.csv" > "$work/$profile.$mode.sha256" || fail "$profile $mode hash failed"
    rm "$work/$profile.$mode.csv"
    printf 'FI FIELD IDENTITY HASH profile=%s mode=%s sha256=%s\n' "$profile" "$mode" "$(cat "$work/$profile.$mode.sha256")"
  done
done
# Count every private projection table under the same catalog-derived query.
count_sql=$(sql W32 "SELECT 'SELECT name,n FROM (' || string_agg(format('SELECT %L::text AS name,count(*)::bigint AS n FROM %I.%I',tablename,schemaname,tablename),' UNION ALL ' ORDER BY tablename) || ') AS t ORDER BY name' FROM pg_tables WHERE schemaname='fi_recovery_projection'") || fail 'cannot construct 49-table verification'
[ -n "$count_sql" ] || fail 'empty table-count query'
for profile in W32 W64; do
  sql "$profile" "$count_sql" > "$work/$profile.49table-counts" || fail "$profile table-count query"
  [ "$(wc -l < "$work/$profile.49table-counts" | tr -d ' ')" = 49 ] || fail "$profile expected exactly 49 private tables"
done
diff -u "$work/W32.checkpoints" "$work/W64.checkpoints" > "$work/checkpoints.diff" || fail 'typed checkpoint chain differs'
diff -u "$work/W32.49table-counts" "$work/W64.49table-counts" > "$work/table-counts.diff" || fail '49-table counts differ'
if cmp -s "$work/W32.physical.sha256" "$work/W64.physical.sha256"; then
  printf 'FI FIELD IDENTITY PHYSICAL MATCH source_record_ids_equal=true\n'
else
  printf 'FI FIELD IDENTITY PHYSICAL DIFFER source_record_ids_equal=false (rollback sequence drift is possible)\n'
fi
if ! cmp -s "$work/W32.logical.sha256" "$work/W64.logical.sha256"; then
  printf 'FI FIELD IDENTITY FAIL signed_source_field_contents_differ=true report=%s\n' "$work" >&2
  exit 1
fi
printf 'FI FIELD IDENTITY PASS signed_source_field_contents_match=true physical_ids_may_differ=true table_counts=49 checkpoints=3 report=%s\n' "$work"
