#!/bin/sh
# FI private fifteen-window combined efficiency acceptance (real signed W128).
# Pinned candidate source, one disposable PostgreSQL clone, verified signed cache.
# Based on the proven clean baseline runner. Retains PostgreSQL settings.
# Collect process high-water RSS and Go GC trace as resource evidence.
# GC tracing adds overhead; this run is NOT a clean timing comparison.
# Exactly one private PostgreSQL fixture: clone-11-08-26.
# The 32,768-record processing chunk is still active. Never touches fi-sor-db.
set -eu
umask 077

fail() { printf 'FI CLONE STOP: %s\n' "$*" >&2; exit 1; }

[ "$(id -un)" = root ] || fail 'run as root on fi-backend-b'
[ -x /usr/bin/time ] && [ -x /usr/bin/env ] && [ -x /usr/bin/true ] || fail 'FreeBSD resource-usage tools are missing'
/usr/bin/time -l /usr/bin/true >/dev/null 2>&1 || fail 'FreeBSD time -l rusage unsupported'
for command in jexec jls ps awk grep find wc sha256 iostat vmstat; do
    command -v "$command" >/dev/null 2>&1 || fail "missing $command"
done

name=clone-11-08-26
ref=b01ff0d8cb6559797de052f34b18bd84a395dc4c
seed=/home/jwood/fi-window-bench-fieldpart-20261104T091019Z/W64
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root=/home/jwood/fi-window-bench-optfield-e15-$stamp
out=/var/tmp/fi-window-chunks-eff15-$stamp
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
stop_host_monitors() {
    for monitor in "$iostatpid" "$vmstatpid"; do
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
jexec -U jwood fi-dev sh -s "$root" "$seed" "$name" "$ref" <<'JAIL'
set -eu
umask 077
fail() { printf 'FI CLONE JAIL STOP: %s\n' "$*" >&2; exit 1; }
root=$1
seed=$2
name=$3
ref=$4
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

# Patch only the archived private candidate CLI: permit N=15 after a durable
# window callback; retain the original 1-2 window stop modes elsewhere.
sed 's/testStopAfterWindows > 2 || !continuousPrivate/(testStopAfterWindows > 2 \&\& testStopAfterWindows != 15) || !continuousPrivate/' "$main" > "$main.new"
mv "$main.new" "$main"
grep -Fq 'testStopAfterWindows != 15' "$main" || fail 'window-stop patch missing'

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
printf 'FI CLONE PROVISION PASS name=%s port=55981 ref=%s windows=3 source_records=390387 signed_fields=4838850 max_wal_size_mb=1024\n' "$name" "$ref"
JAIL

recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || fail 'new binaries missing'
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] || fail 'recovery binary hash mismatch'
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] || fail 'relay binary hash mismatch'

mkdir -m 700 "$out" "$out/$name" "$out/$name/private"
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI PRIVATE EFFICIENCY TRIAL: REAL SIGNED, EXACTLY FIFTEEN DURABLE WINDOWS
experiment=private_combined_efficiency_w128_15_windows
source_commit=$ref
baseline_commit=9e0e6e236c95d9af91bc67a065efb47ce2318579
source_instrumentation=none
optimizations=reusable_security_event_scope_source_file_rows_and_envelope_scan
GODEBUG_gctrace=enabled_for_recover_only
process_rusage=FreeBSD_time_l_peak_RSS
GC_trace_overhead=not_comparable_to_untraced_baseline
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
number_of_new_windows=15
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
}
snapshot_pg before
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


# The recovery executable runs on the host, connects to the jail through the
# private AF_UNIX relay, and reads the already-authenticated real signed cache.
printf 'FI EFFICIENCY START name=%s source=real_signed_8399 source_commit=%s start_index=3 windows=15\n' "$name" "$ref" | tee "$out/SUMMARY.txt"
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
    -max-windows=0 -max-runtime=0 -test-stop-after-windows=15 \
    -deferred-verified-clone -verified-cache-root="$cache" \
    > "$out/$name/recover.log" 2>&1; then
    tail -n 80 "$out/$name/recover.log" >&2 || :
    fail 'optimized fifteen-window private recovery failed'
fi

stop_host_monitors
snapshot_pg after
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
grep '^FI PRIVATE EXACT WINDOW STOP start=3 windows=15 last=17 ' "$log" > "$out/$name/result.txt" || fail 'exact fifteen-window durable stop not verified'
grep '^FI REAL BACKLOG DURABLE ' "$log" > "$out/$name/windows.txt" || fail 'no durable window records'
grep '^FI PRIVATE STAGE PROFILE ' "$log" > "$out/$name/stages.txt" || fail 'missing per-window stage profiles'
grep '^FI DEFERRED ARTIFACT PUBLISHED ' "$log" > "$out/$name/deferred.txt" || fail 'missing deferred artifacts'
for f in windows stages deferred; do
    [ "$(wc -l < "$out/$name/$f.txt" | tr -d ' ')" -eq 15 ] || fail "$f: expected exactly 15 committed windows"
done
state=$(sql "SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window")
[ "${state%%|*}" = 18 ] || fail "unexpected SQL checkpoint count $state"
[ "${state##*|}" = 17 ] || fail "unexpected last window $state"
# Preserve the historically proven W0-W12 prefix, but obtain the new
# W13-W17 counts from the verified signed source instead of guessing.
prefix=$(sql "SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index <= 12")
[ "$prefix" = 1688152 ] || fail "historical W0-W12 record prefix mismatch $prefix"
new_records=$(sql "SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index BETWEEN 3 AND 17")
[ "$new_records" -gt 1297765 ] || fail "W3-W17 did not extend verified W3-W12: $new_records"
printf 'FI EFFICIENCY PREFIX PASS cumulative_W0_W12=%s new_W3_W17=%s checkpoint=%s\n' "$prefix" "$new_records" "$state" | tee -a "$out/SUMMARY.txt"

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
# The fifteen-window batch count is derived from SQL verified-artifact
# custody and ALL published files are compared to signed-cache originals.
[ "$checked" -gt 566 ] || fail "fifteen-window readback did not exceed historical 566 files: $checked"
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
    if (count!=15 || totaltime<=0) exit 1
    printf "FIFTEEN-WINDOW TOTAL: records=%d window_seconds=%.3f committed_rate=%.1f records/sec\n", totalrecords, totaltime, totalrecords/totaltime
}' "$log" | tee "$out/$name/WINDOW_RATES.txt"

cat "$out/$name/result.txt" | tee -a "$out/SUMMARY.txt"
cat "$out/$name/process_resources.txt" | tee -a "$out/SUMMARY.txt"
printf 'FI EFFICIENCY FIFTEEN-WINDOW ACCEPTED output=%s source_commit=%s signed_data=real authoritative=0 accepted=0\n' "$out" "$ref" | tee -a "$out/SUMMARY.txt"
