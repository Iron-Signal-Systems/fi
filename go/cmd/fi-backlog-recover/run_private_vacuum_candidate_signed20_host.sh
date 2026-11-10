#!/bin/sh
# FI PRIVATE W128 candidate: 20 new durable signed windows W3-W22.
# Pinned optimized Go source, verified signed cache and private-clone database.
# Apply candidate leaf-only insert-vacuum threshold, global settings unchanged.
# Collect process high-water RSS and Go GC trace as resource evidence.
# GC tracing and PostgreSQL sampling enabled, may affect absolute timing.
# Exactly one private PostgreSQL fixture: clone-11-08-26.
# The 32,768-record processing chunk is still active. Never touches fi-sor-db.
set -eu
umask 077

fail() { printf 'FI CLONE STOP: %s\n' "$*" >&2; exit 1; }

[ "$(id -un)" = root ] || fail 'run as root on fi-backend-b'
[ -x /usr/bin/time ] && [ -x /usr/bin/env ] && [ -x /usr/bin/true ] || fail 'FreeBSD resource-usage tools are missing'
/usr/bin/time -l /usr/bin/true >/dev/null 2>&1 || fail 'FreeBSD time -l rusage unsupported'
for command in jexec jls ps awk grep find wc sha256 iostat vmstat tar; do
    command -v "$command" >/dev/null 2>&1 || fail "missing $command"
done

[ "$#" -eq 0 ] || fail 'usage: sh run_private_vacuum_candidate_signed20_host.sh (no arguments)'
mode=candidate
short=c
name=clone-11-08-26
ddlref=dc556813d450f7ab79121d05e10e54c6d2732d01
ddlpath=go/cmd/fi-backlog-recover/testdata/private_field_insert_vacuum_candidate.sql
ref=b01ff0d8cb6559797de052f34b18bd84a395dc4c
seed=/home/jwood/fi-window-bench-fieldpart-20261104T091019Z/W64
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root=/home/jwood/fi-window-bench-optfield-v20-$short-$stamp
out=/var/tmp/fi-window-chunks-v20-$short-$stamp
# Fail before touching the seed if either AF_UNIX socket would exceed FreeBSD sun_path.
private_socket="$root/$name/socket/.s.PGSQL.55981"
relay_socket="$out/pg-$name/.s.PGSQL.55981"
[ "${#private_socket}" -le 103 ] || fail "private socket path too long: ${#private_socket}"
[ "${#relay_socket}" -le 103 ] || fail "relay socket path too long: ${#relay_socket}"
printf 'FI EFFICIENCY SOCKET PASS private_bytes=%s relay_bytes=%s\n' "${#private_socket}" "${#relay_socket}"
jailroot=$(jls -j fi-dev path) || fail 'fi-dev missing'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev JID missing'
sorjid=$(jls -j fi-sor-db jid) || fail 'fi-sor-db missing'
[ "$devjid" != "$sorjid" ] || fail 'SoR and development JIDs match'

# Detect actual PostgreSQL postmasters, not background process names.
existing=$(ps -axww -o pid,jid,user,rss,command | awk -v jid="$devjid" '
    $2 == jid && $5 == "/usr/local/bin/postgres" && $6 == "-D" { n++ }
    END { print n + 0 }
')
[ "$existing" -eq 0 ] || fail "$existing PostgreSQL postmasters already running in fi-dev; no benchmark started"

jexec fi-sor-db service postgresql status >/dev/null 2>&1 || fail 'real SoR PostgreSQL not running'
[ -d "$jailroot$seed/data" ] && [ -d "$jailroot$seed/socket" ] || fail 'original validated seed missing'
[ ! -e "$jailroot$root" ] && [ ! -e "$out" ] || fail 'disposable output collision'
[ -d "$cache" ] && [ ! -L "$cache" ] || fail 'verified signed cache missing or symlink'
[ "$(find "$cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')" -eq 8399 ] || fail 'not exactly 8,399 signed cached batches'
[ "$(find "$cache" -type f -name 'verified.json' | wc -l | tr -d ' ')" -eq 1 ] || fail 'verified cache receipt not unique'
[ "$(sysctl -n vfs.zfs.bclone_enabled)" -eq 1 ] || fail 'required ZFS block clone is disabled'
[ "$(zpool get -H -o value feature@block_cloning zroot)" = active ] || fail 'ZFS block-clone feature not active'

relaypid=
iostatpid=
vmstatpid=
pgwatchpid=
stop_host_monitors() {
    for monitor in "$iostatpid" "$vmstatpid" "$pgwatchpid"; do
        if [ -n "$monitor" ]; then
            kill -TERM "$monitor" 2>/dev/null || :
            wait "$monitor" 2>/dev/null || :
        fi
    done
    iostatpid=
    vmstatpid=
}
cleanup() {
    code=$?
    trap - 0 1 2 15
    stop_host_monitors
    if [ -n "$relaypid" ]; then
        kill -TERM "$relaypid" 2>/dev/null || :
        wait "$relaypid" 2>/dev/null || :
    fi
    for data in "$root/$name/data" "$seed/data"; do
        if jexec -U jwood fi-dev pg_ctl -D "$data" status >/dev/null 2>&1; then
            printf 'FI CLONE CLEANUP stopping PostgreSQL %s\n' "$data"
            jexec -U jwood fi-dev pg_ctl -D "$data" -m fast -w -t 60 stop || {
                printf 'FI CLONE CLEANUP WARNING: shutdown failed: %s\n' "$data" >&2
                code=1
            }
        fi
    done
    printf 'FI EFFICIENCY FINISHED exit=%s outputs=%s database=%s/%s\n' "$code" "$out" "$root" "$name"
    exit "$code"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15

printf 'FI CLONE PRECHECK PASS dev_postmasters=0 real_sor=running signed_batches=8399 source_ref=%s\n' "$ref"

# Provision one and only one isolated PostgreSQL instance inside fi-dev.
# Use git archive to preserve the historical code without moving any branch,
# editing the active worktree, or pulling newer changes.
jexec -U jwood fi-dev sh -s "$root" "$seed" "$name" "$ref" "$mode" "$ddlref" "$ddlpath" <<'JAIL'
set -eu
umask 077
fail() { printf 'FI CLONE JAIL STOP: %s\n' "$*" >&2; exit 1; }
root=$1
seed=$2
name=$3
ref=$4
mode=$5
ddlref=$6
ddlpath=$7
repo=/home/jwood/fi-deferred-experiment
src="$root/optimized-source"
pgroot="$root/$name"
socket="$pgroot/socket"
port=55981
[ "$(id -un)" = jwood ] || fail 'expected jwood in fi-dev'
[ "$(sysctl -n security.jail.jailed)" -eq 1 ] || fail 'not jailed'
[ "$(psql --version)" = 'psql (PostgreSQL) 18.6' ] || fail 'unexpected PostgreSQL version'
# Respect the source go.mod (Go 1.27.3); permit the jailed jwood Go toolchain
# to select a version via the configured Go proxy, before touching seed or clone.
(cd "$repo/go" && GOTOOLCHAIN=auto go version) || fail 'Go 1.27.3 toolchain is unavailable in fi-dev'
[ ! -e "$root" ] || fail 'fixture path already exists'
git -C "$repo" cat-file -e "$ref^{commit}" || fail 'pinned optimized source commit is not available locally'
mkdir -m 700 "$root" "$src" "$pgroot" "$socket"
git -C "$repo" archive --format=tar -o "$root/source.tar" "$ref" || fail 'cannot archive historical source'
tar -xf "$root/source.tar" -C "$src" || fail 'cannot extract historical source'

main="$src/go/cmd/fi-backlog-recover/main_freebsd.go"
relay="$src/go/cmd/fi-backlog-recover/optfield/relay.go"
[ "$(grep -Fc 'testStopAfterWindows > 2 || !continuousPrivate' "$main")" -eq 1 ] || fail 'optimized exact-window patch anchor changed'
[ "$(grep -Fc 'var profiles = []string{"K32", "K64"}' "$relay")" -eq 1 ] || fail 'optimized relay profile anchor changed'

# Patch only the archived private CLI: permit N=20 after a durable
# window callback; retain the original 1-2 window stop modes elsewhere.
sed 's/testStopAfterWindows > 2 || !continuousPrivate/(testStopAfterWindows > 2 \&\& testStopAfterWindows != 20) || !continuousPrivate/' "$main" > "$main.new"
mv "$main.new" "$main"
grep -Fq 'testStopAfterWindows != 20' "$main" || fail 'window-stop patch missing'

# The database is named clone-11-08-26, not K32. K32 still describes a
# genuine 32,768-source-record processing chunk, not the cluster identity.
sed 's/var profiles = \[\]string{"K32", "K64"}/var profiles = []string{"clone-11-08-26"}/' "$relay" > "$relay.new"
mv "$relay.new" "$relay"
grep -Fq 'var profiles = []string{"clone-11-08-26"}' "$relay" || fail 'relay single-cluster patch missing'

(cd "$src/go" && GOTOOLCHAIN=auto go build -o "$root/fi-optfield-recover" ./cmd/fi-backlog-recover) || fail 'optimized Go build failed'
(cd "$src/go/cmd/fi-backlog-recover/optfield" && GOTOOLCHAIN=auto go build -o "$root/fi-optfield-relay" ./relay.go) || fail 'single-fixture relay build failed'
sha256 -q "$root/fi-optfield-recover" > "$root/recover.sha256"
sha256 -q "$root/fi-optfield-relay" > "$root/relay.sha256"
printf '%s\n' "$ref" > "$root/SOURCE_COMMIT"

# The seed was deliberately stopped after the 88-cluster cleanup.
# Start it only long enough for a consistent PostgreSQL logical dump.
if pg_ctl -D "$seed/data" status >/dev/null 2>&1; then fail 'seed unexpectedly running'; fi
pg_ctl -D "$seed/data" -l "$seed/postgres.log" \
    -o "-p 55962 -k $seed/socket -c listen_addresses= -c unix_socket_permissions=0700" \
    -w start || fail 'validated seed start failed'
seedconn="host=$seed/socket port=55962 user=fi_m1_admin dbname=fi sslmode=disable"
qseed() { psql "$seedconn" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
[ "$(qseed 'SELECT count(*) FROM fi_recovery.typed_window')" = 3 ] || fail 'seed checkpoint count differs'
[ "$(qseed 'SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window')" = 390387 ] || fail 'seed records differ'
[ "$(qseed 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 4838850 ] || fail 'seed Security fields differ'
[ "$(qseed 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || fail 'seed contains canonical SoR rows'
[ "$(qseed "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || fail 'seed contains accepted records'
pg_dump "$seedconn" -Fc -Z 1 -f "$root/accepted-prefix.dump" > "$root/dump.log" 2>&1 || fail 'seed dump failed'
[ -s "$root/accepted-prefix.dump" ] || fail 'seed dump is empty'
sha256 -q "$root/accepted-prefix.dump" > "$root/accepted-prefix.sha256"
pg_ctl -D "$seed/data" -m fast -w -t 60 stop || fail 'seed shutdown after dump failed'
printf 'FI CLONE VERIFIED SEED DUMP source=real_signed three_windows=3 records=390387 fields=4838850 seed_stopped=true\n'

initdb -D "$pgroot/data" -U fi_m1_admin -A trust --no-instructions > "$pgroot/initdb.log" 2>&1 || fail 'clone initdb failed'
pg_ctl -D "$pgroot/data" -l "$pgroot/postgres.log" \
    -o "-p $port -k $socket -c listen_addresses= -c unix_socket_permissions=0700" \
    -w start > "$pgroot/start.log" 2>&1 || fail 'clone start failed'
admin_postgres="host=$socket port=$port user=fi_m1_admin dbname=postgres sslmode=disable"
psql "$admin_postgres" -X -q -v ON_ERROR_STOP=1 \
    -c 'CREATE ROLE fi_owner NOLOGIN' -c 'CREATE ROLE fi_ingest LOGIN' \
    > "$pgroot/roles.log" 2>&1 || fail 'clone roles failed'
createdb -h "$socket" -p "$port" -U fi_m1_admin -O fi_owner fi || fail 'clone database create failed'
admin="host=$socket port=$port user=fi_m1_admin dbname=fi sslmode=disable"
pg_restore --no-owner --exit-on-error --single-transaction \
    --dbname="$admin" "$root/accepted-prefix.dump" > "$pgroot/restore.log" 2>&1 || fail 'clone restore failed'
conn="host=$socket port=$port user=fi_ingest dbname=fi sslmode=disable"
qclone() { psql "$conn" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
[ "$(qclone "SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window")" = '3|390387|2' ] || fail 'clone checkpoint differs'
[ "$(qclone 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 4838850 ] || fail 'clone Security field count differs'
[ "$(qclone 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || fail 'clone contains canonical rows'
[ "$(qclone "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || fail 'clone has Accepted journal'
[ "$(qclone "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 1024 ] || fail 'clone WAL differs from original 1GiB'
for setting in fsync synchronous_commit full_page_writes; do
    [ "$(qclone "SHOW $setting")" = on ] || fail "clone durability $setting is not on"
done
[ "$(qclone 'SHOW autovacuum')" = on ] || fail 'autovacuum globally disabled on trial clone'
[ "$(qclone 'SHOW track_counts')" = on ] || fail 'PostgreSQL statistics tracking is disabled'
[ "$(qclone 'SHOW autovacuum_vacuum_insert_threshold')" = 1000 ] ||
    fail 'unexpected global insert-vacuum threshold; paired pilot invalid'
# Alter only the SECURITY DEFINER fixture in the NEW private clone.
# A restored existing function retains owner, EXECUTE ACL and security mode.
# No fixture function or original seed is modified in either variant.
before_meta=$(psql "$admin" -X -qAt -v ON_ERROR_STOP=1 -c "
SELECT pg_get_userbyid(proowner) || '|' || prosecdef::text || '|' ||
       coalesce(proacl::text, '<none>')
FROM pg_proc
WHERE oid='fi_recovery_projection.begin_security_field_window(integer)'::regprocedure")
[ -n "$before_meta" ] || fail 'private field fixture function missing'
echo "$before_meta" | grep -Fq '|true|' || fail 'field fixture was not SECURITY DEFINER'
if [ "$mode" = candidate ]; then
    git -C "$repo" cat-file -e "$ddlref^{commit}" ||
        fail 'pinned candidate SQL fixture commit missing'
    git -C "$repo" show "$ddlref:$ddlpath" > "$root/leaf-insert-vacuum.sql" ||
        fail 'cannot extract pinned candidate SQL fixture'
    [ -s "$root/leaf-insert-vacuum.sql" ] || fail 'candidate SQL fixture empty'
    psql "$admin" -X -q -v ON_ERROR_STOP=1 -f "$root/leaf-insert-vacuum.sql" \
        > "$root/leaf-insert-vacuum-apply.log" 2>&1 ||
        fail 'candidate leaf-only threshold function replacement failed'
fi
after_meta=$(psql "$admin" -X -qAt -v ON_ERROR_STOP=1 -c "
SELECT pg_get_userbyid(proowner) || '|' || prosecdef::text || '|' ||
       coalesce(proacl::text, '<none>')
FROM pg_proc
WHERE oid='fi_recovery_projection.begin_security_field_window(integer)'::regprocedure")
[ "$before_meta" = "$after_meta" ] ||
    fail 'private fixture function owner/security/ACL changed'
body=$(psql "$admin" -X -qAt -v ON_ERROR_STOP=1 -c "
SELECT pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure)")
echo "$body" | grep -Fq 'INCLUDING ALL' || fail 'private field CREATE TABLE behavior changed'
echo "$body" | grep -Fq 'GRANT INSERT, SELECT' || fail 'private field role grant changed'
if [ "$mode" = candidate ]; then
    echo "$body" | grep -Fq 'autovacuum_vacuum_insert_threshold = -1' ||
        fail 'candidate threshold missing in private function'
else
    if echo "$body" | grep -Fq 'autovacuum_vacuum_insert_threshold = -1'; then
        fail 'control fixture contaminated by candidate reloption'
    fi
fi
printf 'FI VACUUM FUNCTION GATE PASS mode=%s owner_security_acl_unchanged=true\n' "$mode"
printf 'FI CLONE PROVISION PASS name=%s port=55981 ref=%s windows=3 source_records=390387 signed_fields=4838850 max_wal_size_mb=1024\n' "$name" "$ref"
JAIL

recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || fail 'new binaries missing'
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] || fail 'recovery binary hash mismatch'
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] || fail 'relay binary hash mismatch'

mkdir -m 700 "$out" "$out/$name" "$out/$name/private"
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI PRIVATE VACUUM A/B PILOT: REAL SIGNED, EXACTLY TWENTY DURABLE WINDOWS
experiment=private_insert_vacuum_candidate_signed20
source_commit=$ref
vacuum_variant=$mode
candidate_ddl_commit=$ddlref
baseline_commit=9e0e6e236c95d9af91bc67a065efb47ce2318579
source_instrumentation=none
vacuum_experiment_scope=only_new_private_security_field_leaves
PostgreSQL_global_autovacuum=unchanged
manual_vacuum_after_timed_replay=not_yet_performed
optimizations=reusable_security_event_scope_source_file_rows_and_envelope_scan
GODEBUG_gctrace=enabled_for_recover_only
process_rusage=FreeBSD_time_l_peak_RSS
GC_trace_overhead=both_variants_traced_identically
checkpoint_log_override=none
host_iostat_sample_seconds=5
host_vmstat_sample_seconds=5
postgres_stats=before_and_after
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
verified_cache=$cache
signed_batches=8399
validated_seed=3|390387|2
clone_database_root=$root/$name
clone_postgresql_port=55981
outer_window=W128
processing_chunk_records=32768
security_profile=P3
file_profile=F3
max_wal_size_mb=1024
fsync=on
synchronous_commit=on
full_page_writes=on
start_window_index=3
number_of_new_windows=20
max_runtime=none
authoritative_writes=prohibited
canonical_publication=disabled
recover_sha256=$(sha256 -q "$recover")
relay_sha256=$(sha256 -q "$relay")
EOF

"$relay" -cluster-root="$root" -output-root="$out" \
    -base-port=55981 -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
ready=0
tries=0
while [ "$tries" -lt 30 ]; do
    if grep -Fq "FI PG RELAY READY profile=$name port=55981" "$out/relay.log" 2>/dev/null; then
        ready=1
        break
    fi
    kill -0 "$relaypid" 2>/dev/null || fail "relay stopped: $(tail -n 5 "$out/relay.log")"
    tries=$((tries+1))
    sleep 1
done
[ "$ready" -eq 1 ] || fail 'relay did not become ready'
cat "$out/relay.log"

sql() {
    jexec -U jwood fi-dev psql \
        "host=$root/$name/socket port=55981 user=fi_ingest dbname=fi sslmode=disable" \
        -X -qAt -v ON_ERROR_STOP=1 -c "$1"
}
# Snapshot read-only counters on the fresh clone outside the replay timer.
# Full-column raw rows preserve PostgreSQL 18 semantics for later comparison.
snapshot_pg() {
    phase=$1
    {
        sql 'SELECT * FROM pg_stat_wal'
        sql 'SELECT * FROM pg_stat_checkpointer'
        sql 'SELECT * FROM pg_stat_io'
    } > "$out/$name/pg_${phase}.txt" || fail "PostgreSQL ${phase} stats snapshot failed"
    # JSON objects retain PG18 counter column names and units for offline
    # before/after deltas. All are read-only and sampled outside the replay.
    sql 'SELECT row_to_json(s)::text FROM (SELECT * FROM pg_stat_wal) s' \
        > "$out/$name/pg_stat_wal_${phase}.jsonl" || fail "WAL statistics snapshot failed"
    sql 'SELECT row_to_json(s)::text FROM (SELECT * FROM pg_stat_checkpointer) s' \
        > "$out/$name/pg_stat_checkpointer_${phase}.jsonl" || fail "checkpointer snapshot failed"
    sql 'SELECT row_to_json(s)::text FROM (SELECT * FROM pg_stat_io) s' \
        > "$out/$name/pg_stat_io_${phase}.jsonl" || fail "I/O statistics snapshot failed"
}
snapshot_pg before
# Record per-relation vacuum/analyze work, including every populated private
# Security field partition. Snapshot both variants immediately before replay.
snapshot_relations() {
    phase=$1
    sql "SELECT row_to_json(r)::text FROM (
      SELECT clock_timestamp() AS observed_at,s.schemaname,s.relname,
             s.n_tup_ins,s.n_tup_upd,s.n_tup_del,s.n_dead_tup,
             s.autovacuum_count,s.autoanalyze_count,
             s.total_autovacuum_time,s.total_autoanalyze_time,
             c.reloptions,pg_relation_size(s.relid) AS heap_bytes
      FROM pg_stat_all_tables s JOIN pg_class c ON c.oid=s.relid
      WHERE s.schemaname IN ('fi_recovery','fi_recovery_projection')
      ORDER BY s.schemaname,s.relname
    ) r" > "$out/$name/relations_${phase}.jsonl" ||
        fail "private relation statistics ${phase} snapshot failed"
}
snapshot_relations before

{
    printf 'source_sha=%s\n' "$ref"
    for setting in shared_buffers wal_buffers max_wal_size checkpoint_timeout checkpoint_completion_target fsync synchronous_commit full_page_writes track_io_timing track_wal_io_timing; do
        printf '%s=%s\n' "$setting" "$(sql "SHOW $setting")"
    done
} > "$out/$name/pg_settings.txt" || fail 'PostgreSQL settings capture failed'

# The observers read host-wide counters; they do not trace or modify FI,
# PostgreSQL or the replay process. The first sample may be since boot.
# Go GC trace is enabled only for the replay process; host monitors are passive.
iostat -x -w 5 > "$out/$name/host-iostat.txt" 2>&1 &
iostatpid=$!
vmstat -w 5 > "$out/$name/host-vmstat.txt" 2>&1 &
vmstatpid=$!
kill -0 "$iostatpid" 2>/dev/null || fail 'iostat failed to start'
kill -0 "$vmstatpid" 2>/dev/null || fail 'vmstat failed to start'
# Preflight the sampling query synchronously. If PG permissions or syntax
# differ from our expectation, reject BEFORE starting the signed replay.
# Restarting a worker later is not acceptable: incomplete metrics skew A/B.
pg_sample_sql="SELECT json_build_object(
  'observed_at',clock_timestamp(),
  'wal',(SELECT row_to_json(w) FROM pg_stat_wal w),
  'checkpointer',(SELECT row_to_json(c) FROM pg_stat_checkpointer c),
  'active_vacuum',(SELECT coalesce(json_agg(row_to_json(v)),'[]'::json)
                    FROM pg_stat_progress_vacuum v),
  'autovacuum_workers',(SELECT coalesce(json_agg(row_to_json(a)),'[]'::json)
                    FROM (SELECT pid,wait_event_type,wait_event,query
                          FROM pg_stat_activity
                          WHERE backend_type='autovacuum worker') a)
)::text"
sql "$pg_sample_sql" > "$out/$name/pg_5sec_samples.jsonl" ||
    fail 'PG vacuum/WAL observer query failed preflight'
[ -s "$out/$name/pg_5sec_samples.jsonl" ] ||
    fail 'PG observer preflight produced empty result'

# Same five-second observer for each isolated variant; both capture WAL
# counters, checkpoint counts and in-flight VACUUM/worker wait detail.
(
    while :; do
        sleep 5
        sql "$pg_sample_sql" >> "$out/$name/pg_5sec_samples.jsonl" \
            2>> "$out/$name/pg_samples_errors.log" || break
    done
) &
pgwatchpid=$!
kill -0 "$pgwatchpid" 2>/dev/null || fail 'PostgreSQL watcher failed to start'


# The recovery executable runs on the host, connects to the jail through the
# private AF_UNIX relay, and reads the already-authenticated real signed cache.
printf 'FI EFFICIENCY START name=%s source=real_signed_8399 source_commit=%s start_index=3 windows=20\n' "$name" "$ref" | tee "$out/SUMMARY.txt"
# Trace only the Go recovery process; PostgreSQL and relay remain unchanged.
# FreeBSD time -l records process high-water resident memory on completion.
# GC trace adds timing overhead; compare memory evidence before timing.
if ! /usr/bin/time -l /usr/bin/env GODEBUG=gctrace=1 "$recover" \
    -source=iss-fs-22a.iss.local \
    -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
    -postgres="host=$out/pg-$name port=55981 user=fi_ingest dbname=fi sslmode=disable" \
    -custody-root=/var/db/fi/custody/generation \
    -recorded-root=/var/db/fi/custody/recorded \
    -source-namespaces=false -private-root="$out/$name/private" \
    -private-writes -private-field-partitions \
    -security-profile=P3 -file-profile=F3 -window-profile=W128 \
    -processing-chunk-records=32768 -continuous-private -start-window=3 \
    -max-windows=0 -max-runtime=0 -test-stop-after-windows=20 \
    -deferred-verified-clone -verified-cache-root="$cache" \
    > "$out/$name/recover.log" 2>&1; then
    tail -n 80 "$out/$name/recover.log" >&2 || :
    fail '20-window private vacuum candidate recovery failed'
fi

stop_host_monitors
[ -s "$out/$name/pg_5sec_samples.jsonl" ] ||
    fail 'PostgreSQL vacuum/WAL observer did not collect samples'
[ "$(wc -l < "$out/$name/pg_5sec_samples.jsonl" | tr -d ' ')" -ge 3 ] ||
    fail 'PostgreSQL vacuum/WAL observer coverage incomplete'
[ ! -s "$out/$name/pg_samples_errors.log" ] ||
    fail 'PostgreSQL vacuum/WAL observer reported errors'
snapshot_pg after
snapshot_relations after
printf 'FI EFFICIENCY HOST OBSERVERS captured iostat=%s vmstat=%s\n' \
    "$(wc -l < "$out/$name/host-iostat.txt" | tr -d ' ')" \
    "$(wc -l < "$out/$name/host-vmstat.txt" | tr -d ' ')" | tee -a "$out/SUMMARY.txt"

log="$out/$name/recover.log"
# Reject SQL tracing from old experiments; GC trace is expected here.
if grep -q '^FI FIELD COPY TRACE ' "$log"; then
    fail 'unexpected field-COPY instrumentation in optimized replay'
fi
gc_lines=$(grep -c '^gc [0-9]' "$log" || :)
peak_rss_kib=$(awk '/maximum resident set size/ { value=$1 } END { if (value!="") print value; else print "unavailable" }' "$log")
printf 'FI EFFICIENCY RESOURCES gc_trace_lines=%s peak_rss_kib=%s\n' "$gc_lines" "$peak_rss_kib" |
    tee "$out/$name/process_resources.txt"
grep '^FI PRIVATE EXACT WINDOW STOP start=3 windows=20 last=22 ' "$log" > "$out/$name/result.txt" || fail 'exact twenty-window durable stop not verified'
grep '^FI REAL BACKLOG DURABLE ' "$log" > "$out/$name/windows.txt" || fail 'no durable window records'
grep '^FI PRIVATE STAGE PROFILE ' "$log" > "$out/$name/stages.txt" || fail 'missing per-window stage profiles'
grep '^FI DEFERRED ARTIFACT PUBLISHED ' "$log" > "$out/$name/deferred.txt" || fail 'missing deferred artifacts'
for f in windows stages deferred; do
    [ "$(wc -l < "$out/$name/$f.txt" | tr -d ' ')" -eq 20 ] || fail "$f: expected exactly 20 committed windows"
done
state=$(sql "SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window")
[ "${state%%|*}" = 23 ] || fail "unexpected SQL checkpoint count $state"
[ "${state##*|}" = 22 ] || fail "unexpected last window $state"
# Known W0-W17 prefix from independently verified signed W3-W17 replay.
# New W18-W22 totals must be measured, not guessed.
prefix=$(sql "SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index <= 17")
[ "$prefix" = 2338918 ] || fail "W0-W17 signed prefix differs: $prefix"
new_records=$(sql "SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index BETWEEN 3 AND 22")
[ "$new_records" -gt 1948531 ] || fail "W3-W22 must extend W3-W17 verified records: $new_records"
printf 'FI CANDIDATE PREFIX PASS W0_W17=%s W3_W22=%s checkpoint=%s\n' "$prefix" "$new_records" "$state" | tee -a "$out/SUMMARY.txt"

integrity=$(sql "
SELECT CASE WHEN
 (SELECT count(*) FROM fi_recovery.verified_artifact_window)=(SELECT count(*) FROM fi_recovery.source_window)
 AND (SELECT count(*) FROM fi_recovery.source_window)=(SELECT count(*) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi_recovery.pending_source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi_recovery_projection.source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM pg_inherits WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass)=(SELECT count(*) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi.recorded_generation)=0
 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0
 AND NOT EXISTS (
 SELECT 1 FROM fi_recovery.typed_window t
 JOIN fi_recovery.source_window s USING(receipt_sha256,window_index)
 JOIN fi_recovery.verified_artifact_window a USING(receipt_sha256,window_index)
 WHERE t.descriptor_sha256<>s.descriptor_sha256 OR t.descriptor_sha256<>a.descriptor_sha256
 )
 THEN 'PASS' ELSE 'FAIL' END") || fail 'SQL integrity query failed'
[ "$integrity" = PASS ] || fail 'SQL integrity FAIL'
printf 'FI CLONE SQL INTEGRITY PASS checkpoint=%s canonical=0 accepted=0\n' "$state" | tee -a "$out/SUMMARY.txt"
# Verify exactly 20 new W3-W22 leaf partitions carry the candidate setting.
leaf_config=$(sql "SELECT count(*)::text || '|' ||
    count(*) FILTER (WHERE 'autovacuum_vacuum_insert_threshold=-1' =
                       ANY(coalesce(c.reloptions,ARRAY[]::text[])))::text
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='fi_recovery_projection'
AND c.relname ~ '^windows_security_event_field_w0000(0[3-9]|1[0-9]|2[0-2])$'")
[ "$leaf_config" = '20|20' ] || fail "new private leaf options expected 20|20 got $leaf_config"
# The three restored seed field partitions may not be changed.
seed_config=$(sql "SELECT count(*)::text || '|' ||
    count(*) FILTER (WHERE 'autovacuum_vacuum_insert_threshold=-1' =
                       ANY(coalesce(c.reloptions,ARRAY[]::text[])))::text
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='fi_recovery_projection'
AND c.relname ~ '^windows_security_event_field_w00000[0-2]$'")
[ "$seed_config" = '3|0' ] || fail "seed leaf options were changed: $seed_config"
printf 'FI VACUUM LEAF OPTIONS PASS new=%s seed=%s\n' "$leaf_config" "$seed_config" |
    tee "$out/$name/leaf_options.txt"

# Independent signed artifact readback is AFTER the benchmark timing.
expected=$(sql "SELECT coalesce(sum(end_batch-start_batch),0)::text FROM fi_recovery.verified_artifact_window WHERE window_index>=3")
checked=0
for windowdir in "$out/$name/private"/receipt-*/window-*; do
    [ -d "$windowdir" ] || fail 'missing signed artifact window'
    receipt=$(basename "$(dirname "$windowdir")")
    for batch in "$windowdir"/batch-*.data; do
        [ -f "$batch" ] || fail 'missing published batch'
        base=$(basename "$batch")
        original="$cache/$receipt/$base"
        [ -f "$original" ] || fail "missing original signed cached data $base"
        cmp -s "$batch" "$original" || fail "signed data differs $base"
        cmp -s "${batch%.data}.manifest" "${original%.data}.manifest" || fail "signed manifest differs $base"
        checked=$((checked+1))
    done
done
[ "$checked" -eq "$expected" ] || fail "signed artifact count mismatch $checked/$expected"
# The five-window batch count is derived from SQL verified-artifact
# custody and ALL published files are compared to signed-cache originals.
[ "$checked" -gt 0 ] || fail "five-window signed readback is empty: $checked"
printf 'FI CLONE SIGNED READBACK PASS batch_files=%s byte_identical=true manifests_identical=true\n' "$checked" | tee -a "$out/SUMMARY.txt"

# Real per-window throughput: difference in durable record positions divided
# by that window's own duration, never a ten-minute or provisioning clock.
awk '
function seconds(x, y,a,b) {
    y=x
    if (y ~ /ms$/) {sub(/ms$/, "", y); return (y+0)/1000}
    if (index(y,"h")) {split(y,a,"h"); return (a[1]+0)*3600+seconds(a[2])}
    if (index(y,"m")) {split(y,a,"m"); return (a[1]+0)*60+seconds(a[2])}
    sub(/s$/, "", y)
    return y+0
}
BEGIN {
    previous=390387
    printf "%-9s %-12s %-14s %-14s\n", "WINDOW", "RECORDS", "DURATION", "RECORDS/SEC"
}
/^FI REAL BACKLOG DURABLE / {
    idx=-1; through=-1; elapsed=""
    for (i=1; i<=NF; i++) {
        if ($i ~ /^window=[0-9]+\/[0-9]+$/) {
            split($i,a,"="); split(a[2],b,"/"); idx=b[1]-1
        } else if ($i ~ /^records_through=/) {
            split($i,a,"="); split(a[2],b,"/"); through=b[1]+0
        } else if ($i ~ /^window=[0-9.]+(h|m|s)/) {
            split($i,a,"="); elapsed=a[2]
        }
    }
    duration=seconds(elapsed)
    records=through-previous
    if (idx != count+3 || through<=previous || duration<=0) {
        print "FI CLONE RESULT ERROR inconsistent window order/count/duration" > "/dev/stderr"
        exit 1
    }
    previous=through
    totalrecords+=records
    totaltime+=duration
    printf "%-9d %-12d %-14s %-14.1f\n", idx, records, elapsed, records/duration
    count++
}
END {
    if (count!=20 || totaltime<=0) exit 1
    printf "TWENTY-WINDOW TOTAL: records=%d window_seconds=%.3f committed_rate=%.1f records/sec\n", totalrecords, totaltime, totalrecords/totaltime
}' "$log" > "$out/$name/WINDOW_RATES.txt" ||
    fail 'five-window rate extraction failed'
cat "$out/$name/WINDOW_RATES.txt"


# Export one row per durable W3..W22 stage profile. Preserve raw duration
# strings as well as a derived sum, without conflating nested stage counters
# with mutually exclusive wall-clock phases.
awk -v totals="$out/$name/STAGE_TOTALS.tsv" '
function seconds(s, h,m,a) {
    if (s ~ /ms$/) { sub(/ms$/, "", s); return (s+0)/1000 }
    h=0; m=0
    if (index(s,"h")) { split(s,a,"h"); h=a[1]+0; s=a[2] }
    if (index(s,"m")) { split(s,a,"m"); m=a[1]+0; s=a[2] }
    if (s ~ /ms$/) { sub(/ms$/, "", s); return h*3600+m*60+(s+0)/1000 }
    sub(/s$/, "", s)
    return h*3600+m*60+(s+0)
}
BEGIN {
    columns="index records joined typed_total setup batch_ingest joined_finish deferred_flush verification verify_counts verify_coverage marker_commit source_read batch_hash envelope_prepare security_prepare security_child_prepare source_sql projection_total file_projection_inclusive security_projection_inclusive other_projection_inclusive security_id_lookup security_source_copy security_event_copy security_scope_copy security_field_copy security_single_pass_rows"
    n=split(columns,col," ")
    for (i=1; i<=n; i++) printf "%s%s", col[i], (i<n ? "\t" : "\n")
}
/^FI PRIVATE STAGE PROFILE / {
    for (k in values) delete values[k]
    for (i=5; i<=NF; i++) {
        p=index($i,"=")
        if (p>0) values[substr($i,1,p-1)]=substr($i,p+1)
    }
    if (!("index" in values)) { bad=1; exit 2 }
    window=values["index"]+0
    if (window<3 || window>22 || seen[window]++) { bad=1; exit 2 }
    for (i=1; i<=n; i++) {
        if (!(col[i] in values)) { bad=1; exit 2 }
        printf "%s%s", values[col[i]], (i<n ? "\t" : "\n")
        if (i>=4 && col[i]!="security_single_pass_rows")
            duration[i] += seconds(values[col[i]])
    }
    total_single_pass+=values["security_single_pass_rows"]+0
    rows++
}
END {
    if (bad || rows!=20 || total_single_pass<=0) {
        printf "FI EFFICIENCY STAGE MATRIX FAIL rows=%d single_pass=%d bad=%d\n", rows,total_single_pass,bad > "/dev/stderr"
        exit 3
    }
    print "stage_key\ttotal_seconds\tavg_seconds\tinterpretation" > totals
    for (i=4; i<=n; i++) {
        if (col[i]=="security_single_pass_rows") continue
        printf "%s\t%.3f\t%.3f\t%s\n", col[i], duration[i], duration[i]/20,
            (col[i]=="typed_total" ? "outer_wall" : "nested_or_component_do_not_sum") >> totals
    }
    printf "FI EFFICIENCY SINGLE PASS PASS windows=%d selected_rows=%d\n", rows,total_single_pass > "/dev/stderr"
}' "$log" > "$out/$name/PER_WINDOW_STAGES.tsv" ||
    fail 'stage timing matrix or active single-pass selection acceptance failed'
[ "$(wc -l < "$out/$name/PER_WINDOW_STAGES.tsv" | tr -d ' ')" -eq 21 ] ||
    fail 'stage timing matrix does not contain a header plus 20 windows'

# Join typed Security counters, File validation counters, and field partition
# finalization records by canonical window index. No new SQL or per-record logs.
awk '
function parse_fields(   i,p,key,val) {
    for (key in fields) delete fields[key]
    for (i=2; i<=NF; i++) {
        p=index($i,"=")
        if (p>0) fields[substr($i,1,p-1)]=substr($i,p+1)
    }
}
BEGIN { print "window\trecords\tsecurity_events\tsecurity_fields\tfamilies\tfile_source_validated\tfile_bulk_reused\tfile_bulk_validated\tpartition_field_rows\tpartition_begin\tpartition_validate_attach" }
/^FI REAL TYPED WINDOW / {
    parse_fields()
    w=fields["index"]+0
    if (w>=3 && w<=22) {
        count[w]++
        records[w]=fields["records"]; events[w]=fields["security_events"]
        secfields[w]=fields["security_fields"]; families[w]=fields["families"]
    }
}
/^FI FILE VALIDATION WINDOW / {
    parse_fields(); w=fields["index"]+0
    if (w>=3 && w<=22) {
        file_seen[w]++
        file_valid[w]=fields["source_validated"]
        file_reused[w]=fields["bulk_reused"]
        file_bulk[w]=fields["bulk_validated"]
    }
}
/^FI PRIVATE FIELD PARTITION COMMITTED / {
    parse_fields(); w=fields["window"]+0
    if (w>=3 && w<=22) {
        partition_seen[w]++
        partition_rows[w]=fields["rows"]
        partition_begin[w]=fields["begin"]
        partition_finish[w]=fields["validate_attach"]
    }
}
END {
    for (w=3; w<=22; w++) {
        if (count[w]!=1 || file_seen[w]!=1 || partition_seen[w]!=1) {
            printf "FI EFFICIENCY FAMILY MATRIX incomplete window=%d typed=%d file=%d partition=%d\n",
                w,count[w],file_seen[w],partition_seen[w] > "/dev/stderr"
            exit 2
        }
        printf "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
            w, records[w], events[w], secfields[w], families[w],
            file_valid[w], file_reused[w], file_bulk[w],
            partition_rows[w], partition_begin[w], partition_finish[w]
    }
}' "$log" > "$out/$name/PER_WINDOW_FAMILIES.tsv" ||
    fail 'per-window Security/File/field counts missing'
[ "$(wc -l < "$out/$name/PER_WINDOW_FAMILIES.tsv" | tr -d ' ')" -eq 21 ] ||
    fail 'family matrix does not contain a header plus 20 windows'

# Copy all observed processing chunks, including unusually slow chunks.
awk '
BEGIN { print "window\tchunk\tlimit\tbatches\trecords\tprocessing" }
/^FI TYPED CHUNK COMMITTED / {
    for (k in f) delete f[k]
    for (i=2; i<=NF; i++) {
        p=index($i,"=")
        if (p>0) f[substr($i,1,p-1)]=substr($i,p+1)
    }
    if (f["window"]+0>=3 && f["window"]+0<=7)
        printf "%s\t%s\t%s\t%s\t%s\t%s\n", f["window"],f["chunk"],f["limit"],f["batches"],f["records"],f["processing"]
}' "$log" > "$out/$name/PROCESSING_CHUNKS.tsv" ||
    fail 'processing chunk timing extraction failed'

# Cross-check durable SQL identity and record counts outside replay timing.
{
    printf 'window_index\tcommitted_records\n'
    sql "SELECT window_index::text || chr(9) || committed_records::text
         FROM fi_recovery.typed_window WHERE window_index BETWEEN 3 AND 22
         ORDER BY window_index"
} > "$out/$name/SQL_WINDOW_COUNTS.tsv" ||
    fail 'SQL committed-window record matrix failed'
[ "$(wc -l < "$out/$name/SQL_WINDOW_COUNTS.tsv" | tr -d ' ')" -eq 21 ] ||
    fail 'SQL committed-window matrix not exactly 20 rows'

grep '^gc [0-9]' "$log" > "$out/$name/GC_EVENTS.txt" || :
cat > "$out/$name/METRICS_README.txt" <<'FI_METRICS'
Private signed W128 window indexes 3..22; 20 fully durable windows.
PER_WINDOW_STAGES.tsv: source-reported Go stage durations and fast-path counts;
  columns named *_inclusive, COPY and source_sql are nested/overlapping.
STAGE_TOTALS.tsv: sum across the 20 windows of EACH individual stage ONLY;
  DO NOT ADD different stages together to infer elapsed wall clock.
PER_WINDOW_FAMILIES.tsv: Security event/field counts, File validation reuse,
  and private field-partition finish/attach durations by window.
PROCESSING_CHUNKS.tsv: per-processing-chunk duration, records, signed batches.
SQL_WINDOW_COUNTS.tsv: post-run PostgreSQL durable source-record positions.
WINDOW_RATES.txt: per-window records and actual durable-window durations.
GC_EVENTS.txt: Go runtime GC trace, enabled on replay only; instrumented
  elapsed time must not be confused with untraced baseline throughput.
process_resources.txt: FreeBSD rusage peak replay-process resident memory;
  this is not PostgreSQL RSS or total host memory.
pg_stat_wal_{before,after}.jsonl: named PostgreSQL 18 WAL counters.
pg_stat_checkpointer_{before,after}.jsonl: named checkpoint counters.
pg_stat_io_{before,after}.jsonl: named PostgreSQL IO records.
host-iostat.txt and host-vmstat.txt: 5-second HOST-WIDE observations.
recover.log: exact complete authoritative source of the profile and GC lines.
signed_artifact comparisons and fi_recovery SQL integrity: acceptance gates.
FI_METRICS
printf 'FI EFFICIENCY METRIC EXPORT PASS stage_windows=20 source_rows=%s\n' "$new_records" |
    tee -a "$out/SUMMARY.txt"

# Maintenance debt acceptance: both variants pay the same explicit
# VACUUM (ANALYZE) of their five newly attached private field leaves, only
# AFTER committed-window timing, SQL integrity and signed custody checks.
# This is NOT a PostgreSQL global or production vacuum change.
# Comparing ingest+repayment helps expose deferred versus eliminated work.
maint_log="$out/$name/MAINTENANCE_REPAYMENT.tsv"
printf 'window\telapsed_seconds\n' > "$maint_log"
maint_start=$(date -u '+%s')
for w in 3 4 5 6 7; do
    table=$(printf 'windows_security_event_field_w%06d' "$w")
    started=$(date -u '+%s')
    jexec -U jwood fi-dev psql \
        "host=$root/$name/socket port=55981 user=fi_m1_admin dbname=fi sslmode=disable" \
        -X -q -v ON_ERROR_STOP=1 -c "VACUUM (ANALYZE) fi_recovery_projection.$table" \
        > "$out/$name/vacuum_manual_w$w.log" 2>&1 ||
        fail "postrun private leaf VACUUM ANALYZE failed window=$w"
    stopped=$(date -u '+%s')
    printf '%s\t%s\n' "$w" "$((stopped-started))" >> "$maint_log"
done
maint_stop=$(date -u '+%s')
printf 'FI VACUUM REPAYMENT COMPLETE mode=%s leaf_windows=5 elapsed_seconds=%s\n' \
    "$mode" "$((maint_stop-maint_start))" | tee "$out/$name/MAINTENANCE_REPAYMENT_SUMMARY.txt"
snapshot_pg maintenance_after
snapshot_relations maintenance_after

cat "$out/$name/result.txt" | tee -a "$out/SUMMARY.txt"
cat "$out/$name/process_resources.txt" | tee -a "$out/SUMMARY.txt"
printf 'FI VACUUM CANDIDATE20 ACCEPTED mode=%s output=%s source_commit=%s signed_data=real authoritative=0 accepted=0\n' "$mode" "$out" "$ref" | tee -a "$out/SUMMARY.txt"

# Shareable diagnostics only. Deliberately EXCLUDE private/ copied signed
# data, source.tar, PostgreSQL dump/cluster, and credentials. Every source
# observation remains available in the local directory for later audit.
bundle="$out/fi-vacuum-candidate20-$stamp.tar.gz"
(
    cd "$out" || exit 1
    tar -czf "$bundle" \
        RUN_MANIFEST.txt SUMMARY.txt relay.log \
        "$name/recover.log" "$name/result.txt" "$name/windows.txt" \
        "$name/stages.txt" "$name/deferred.txt" \
        "$name/WINDOW_RATES.txt" "$name/PER_WINDOW_STAGES.tsv" \
        "$name/STAGE_TOTALS.tsv" "$name/PER_WINDOW_FAMILIES.tsv" \
        "$name/PROCESSING_CHUNKS.tsv" "$name/SQL_WINDOW_COUNTS.tsv" \
        "$name/GC_EVENTS.txt" "$name/process_resources.txt" \
        "$name/METRICS_README.txt" "$name/pg_settings.txt" \
        "$name/pg_before.txt" "$name/pg_after.txt" \
        "$name/pg_stat_wal_before.jsonl" "$name/pg_stat_wal_after.jsonl" \
        "$name/pg_stat_checkpointer_before.jsonl" "$name/pg_stat_checkpointer_after.jsonl" \
        "$name/pg_stat_io_before.jsonl" "$name/pg_stat_io_after.jsonl" \
        "$name/host-iostat.txt" "$name/host-vmstat.txt" \
        "$name/relations_before.jsonl" "$name/relations_after.jsonl" \
        "$name/pg_5sec_samples.jsonl" "$name/leaf_options.txt" \
        "$name/MAINTENANCE_REPAYMENT.tsv" "$name/MAINTENANCE_REPAYMENT_SUMMARY.txt" \
        "$name/pg_stat_wal_maintenance_after.jsonl" \
        "$name/pg_stat_checkpointer_maintenance_after.jsonl" \
        "$name/pg_stat_io_maintenance_after.jsonl" \
        "$name/relations_maintenance_after.jsonl"
) || fail 'cannot package complete metrics-only archive'
[ -s "$bundle" ] || fail 'metrics archive empty'
printf 'FI EFFICIENCY METRICS BUNDLE PASS path=%s\n' "$bundle"
