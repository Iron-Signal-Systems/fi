#!/bin/sh
# FI DEV ONLY. Four PostgreSQL WAL configurations, ONE FIXED Go ingest path:
# W128 outer private atomic checkpoints, 32K inner source chunks, P3/F3.
# Reuses a previous fully verified 8,399-batch cache and W128 seed pg_dump.
# Does not open original custody; never deletes/modifies prior test results.
set -eu
umask 077

stop() { printf 'FI CACHED WAL BENCH STOP: %s\n' "$*" >&2; exit 1; }
for tool in jexec sha256 pgrep ps date grep tail cp mkdir sleep find sed awk wc; do
    command -v "$tool" >/dev/null 2>&1 || stop "missing $tool"
done
: "$FI_BENCH_BINARY"
: "$FI_BENCH_BINARY_SHA256"
: "$FI_BENCH_RELAY_BINARY"
: "$FI_BENCH_RELAY_SHA256"
: "$FI_BENCH_JAIL_RELAY_BINARY"
: "$FI_BENCH_OUTPUT_ROOT"
: "$FI_BENCH_SOURCE_GIT_SHA"
: "$FI_BENCH_W32_DSN"
: "$FI_BENCH_W64_DSN"
: "$FI_BENCH_W96_DSN"
: "$FI_BENCH_W128_DSN"
: "$FI_BENCH_W32_PORT"
: "$FI_BENCH_W64_PORT"
: "$FI_BENCH_W96_PORT"
: "$FI_BENCH_W128_PORT"
: "$FI_BENCH_PSQL_JAIL"
: "$FI_BENCH_ISOLATED_CLUSTERS_CONFIRMED"
: "$FI_BENCH_PG_WAL_COMPARE"
: "$FI_BENCH_PRIOR_OUTPUT_ROOT"
: "$FI_BENCH_PRIOR_SEED_DUMP"

[ "$FI_BENCH_ISOLATED_CLUSTERS_CONFIRMED" = YES ] || stop "new isolated clusters not confirmed"
[ "$FI_BENCH_PG_WAL_COMPARE" = YES ] || stop "new clusters not provisioned in 2x2 WAL compare mode"
[ "$FI_BENCH_PSQL_JAIL" = fi-dev ] || stop "fi-dev only"
case "$FI_BENCH_OUTPUT_ROOT" in
  /var/tmp/fi-window-chunks-*) ;;
  *) stop "fresh output must be /var/tmp/fi-window-chunks-*";;
esac
[ ! -e "$FI_BENCH_OUTPUT_ROOT" ] || stop "new output root already exists"
case "$FI_BENCH_PRIOR_OUTPUT_ROOT" in
  /var/tmp/fi-window-chunks-*) ;;
  *) stop "prior output must be an existing FI chunk benchmark";;
esac
[ -d "$FI_BENCH_PRIOR_OUTPUT_ROOT/verified-cache" ] || stop "verified cache missing"
[ -f "$FI_BENCH_PRIOR_OUTPUT_ROOT/RUN_MANIFEST.txt" ] || stop "previous run manifest missing"
grep '^source_id=iss-fs-22a.iss.local$' "$FI_BENCH_PRIOR_OUTPUT_ROOT/RUN_MANIFEST.txt" >/dev/null ||
    stop "wrong cached source"
grep '^signed_source_records=15140785$' "$FI_BENCH_PRIOR_OUTPUT_ROOT/RUN_MANIFEST.txt" >/dev/null ||
    stop "wrong cached record count"
grep '^FI VERIFIED CACHE SINGLE SCAN COMPLETE ' "$FI_BENCH_PRIOR_OUTPUT_ROOT/SUMMARY.txt" >/dev/null ||
    stop "previous authenticated full FIGT cache not completed"
[ -d "$FI_BENCH_PRIOR_OUTPUT_ROOT/W128/private" ] || stop "previous W128 private seed missing"
marker_count=$(find "$FI_BENCH_PRIOR_OUTPUT_ROOT/verified-cache" -name verified.json -type f | wc -l | tr -d ' ')
[ "$marker_count" = 1 ] || stop "verified receipt marker count must equal one"
cache_batches=$(find "$FI_BENCH_PRIOR_OUTPUT_ROOT/verified-cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')
[ "$cache_batches" = 8399 ] || stop "original verified cache incomplete"
case "$FI_BENCH_PRIOR_SEED_DUMP" in
  /home/jwood/fi-window-bench-*/single-w128-seed.dump) ;;
  *) stop "seed dump is not from an isolated FI W128 benchmark";;
esac
jexec -U jwood fi-dev test -s "$FI_BENCH_PRIOR_SEED_DUMP" ||
    stop "old seed snapshot not available inside fi-dev"
[ -x "$FI_BENCH_BINARY" ] || stop "recover binary missing"
[ -x "$FI_BENCH_RELAY_BINARY" ] || stop "relay binary missing"
[ "$(sha256 -q "$FI_BENCH_BINARY")" = "$FI_BENCH_BINARY_SHA256" ] || stop "recover binary SHA wrong"
[ "$(sha256 -q "$FI_BENCH_RELAY_BINARY")" = "$FI_BENCH_RELAY_SHA256" ] || stop "relay binary SHA wrong"
[ "$(jexec -U jwood fi-dev git -C /home/jwood/src/fi rev-parse HEAD)" = "$FI_BENCH_SOURCE_GIT_SHA" ] ||
    stop "fi-dev commit differs from provisioned source"
[ "$(jexec -U jwood fi-dev sha256 -q "$FI_BENCH_JAIL_RELAY_BINARY")" = "$FI_BENCH_RELAY_SHA256" ] ||
    stop "jail relay SHA differs from host relay"
if pgrep -f 'run_fixed_w128_chunk_benchmarks[.]sh' >/dev/null 2>&1; then
    stop "earlier runner still active"
fi

get_profile() {
    case "$1" in
      W32) profile_dsn=$FI_BENCH_W32_DSN; port=$FI_BENCH_W32_PORT; wal_label=baseline-default ;;
      W64) profile_dsn=$FI_BENCH_W64_DSN; port=$FI_BENCH_W64_PORT; wal_label=wal-buffers-64MB ;;
      W96) profile_dsn=$FI_BENCH_W96_DSN; port=$FI_BENCH_W96_PORT; wal_label=max-wal-size-8GB ;;
      W128) profile_dsn=$FI_BENCH_W128_DSN; port=$FI_BENCH_W128_PORT; wal_label=both-64MB-and-8GB ;;
      *) stop "invalid profile $1";;
    esac
    jail_dsn=$(printf '%s\n' "$profile_dsn" | sed 's@host=/usr/local/jails/containers/fi-dev/@host=/@')
    case "$jail_dsn" in
      host=/home/jwood/fi-window-bench-*" user=fi_ingest dbname=fi sslmode=disable") ;;
      *) stop "unexpected isolated database DSN for $1";;
    esac
}
psql_check() {
    jexec -U jwood fi-dev psql "$jail_dsn" -X -qAt -v ON_ERROR_STOP=1 -c "$1"
}
[ "$FI_BENCH_W32_PORT" = 55931 ] || stop "new WAL benchmark must use fresh 55931 port family"
[ "$FI_BENCH_W64_PORT" = 55932 ] || stop "expected 55932"
[ "$FI_BENCH_W96_PORT" = 55933 ] || stop "expected 55933"
[ "$FI_BENCH_W128_PORT" = 55934 ] || stop "expected 55934"
get_profile W32
jail_cluster_root=$(printf '%s\n' "$jail_dsn" | sed 's/^host=//;s@/W32/socket .*@@')
case "$jail_cluster_root" in
  /home/jwood/fi-window-bench-*) ;;
  *) stop "unsafe new isolated cluster root";;
esac
[ -d "/usr/local/jails/containers/fi-dev$jail_cluster_root" ] ||
    stop "missing new isolated cluster root"
for profile in W32 W64 W96 W128; do
    get_profile "$profile"
    [ "$(psql_check "SELECT current_setting('port')")" = "$port" ] || stop "$profile wrong port"
    [ "$(psql_check "SELECT count(*) FROM fi_recovery.typed_window")" = 0 ] ||
        stop "$profile private typed data not empty"
    [ "$(psql_check "SELECT count(*) FROM fi_recovery_projection.recorded_generation")" = 0 ] ||
        stop "$profile recovery already populated"
    [ "$(psql_check "SHOW fsync")" = on ] || stop "$profile fsync disabled"
    [ "$(psql_check "SHOW synchronous_commit")" = on ] || stop "$profile synchronous commit disabled"
    case "$profile" in
      W32) : ;;
      W64)
        [ "$(psql_check "SHOW wal_buffers")" = 64MB ] || stop "W64 wrong wal_buffers";;
      W96)
        [ "$(psql_check "SHOW max_wal_size")" = 8GB ] || stop "W96 wrong max_wal_size";;
      W128)
        [ "$(psql_check "SHOW wal_buffers")" = 64MB ] || stop "W128 wrong wal_buffers"
        [ "$(psql_check "SHOW max_wal_size")" = 8GB ] || stop "W128 wrong max_wal_size";;
    esac
    printf 'FI WAL PREFLIGHT profile=%s port=%s label=%s empty=yes durability=on\n' "$profile" "$port" "$wal_label"
done

mkdir -m 700 "$FI_BENCH_OUTPUT_ROOT"
{
    printf 'FI CACHED WAL 2x2 BENCH - ONE VERIFICATION, NO CUSTODY SCANS\n'
    printf 'cache=%s\nseed_dump=%s\n' "$FI_BENCH_PRIOR_OUTPUT_ROOT/verified-cache" "$FI_BENCH_PRIOR_SEED_DUMP"
    printf 'source_git=%s\nrecover_binary_sha256=%s\nrelay_sha256=%s\n' "$FI_BENCH_SOURCE_GIT_SHA" "$FI_BENCH_BINARY_SHA256" "$FI_BENCH_RELAY_SHA256"
    printf 'source_id=iss-fs-22a.iss.local\ngeneration_id=20261030T000032.061323100Z-3e38b2210771462c\n'
    printf 'source_records=15140785\nsource_batches=8399\n'
    printf 'outer_window=W128/1GiB\ninner_chunk_records=32768\nsecurity=P3\nfile=F3\n'
    printf 'profiles=W32:base,W64:wal_buffers_64MB,W96:max_wal_size_8GB,W128:both\n'
    printf 'each_run=10m\npublication=disabled\nstarted_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'seed_dump_sha256=%s\n' "$(jexec -U jwood fi-dev sha256 -q "$FI_BENCH_PRIOR_SEED_DUMP")"
} > "$FI_BENCH_OUTPUT_ROOT/RUN_MANIFEST.txt"
printf 'FI CACHED WAL BENCH SOURCE cache=%s batches=8399 original_figt_scans=0\n' "$FI_BENCH_PRIOR_OUTPUT_ROOT/verified-cache" | tee "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
# Restore the exact SAME signed W128 seed into four new databases. Do not
# touch the previous run's data, dump, cache, or committed checkpoints.
seed_hash=
for profile in W32 W64 W96 W128; do
    get_profile "$profile"
    admin_dsn=$(printf '%s\n' "$jail_dsn" | sed 's/user=fi_ingest/user=fi_m1_admin/')
    mkdir -m 700 "$FI_BENCH_OUTPUT_ROOT/$profile" "$FI_BENCH_OUTPUT_ROOT/$profile/private"
    jexec -U jwood fi-dev pg_restore --data-only --exit-on-error --single-transaction \
        --dbname="$admin_dsn" "$FI_BENCH_PRIOR_SEED_DUMP" \
        > "$FI_BENCH_OUTPUT_ROOT/$profile/restore.log" 2>&1 ||
        stop "$profile seed restore failed"
    [ "$(psql_check "SELECT count(*) FROM fi_recovery.typed_window")" = 1 ] ||
        stop "$profile must contain exactly seed window zero"
    [ "$(psql_check "SELECT count(*) FROM fi_recovery_projection.source_batch")" = 8399 ] ||
        stop "$profile missing original signed metadata index"
    [ "$(psql_check "SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window")" = 129470 ] ||
        stop "$profile seed record count mismatch"
    current_hash=$(psql_check "SELECT encode(descriptor_sha256,'hex') FROM fi_recovery.typed_window WHERE window_index=0")
    [ -n "$current_hash" ] || stop "$profile missing seed hash"
    if [ -n "$seed_hash" ]; then
        [ "$current_hash" = "$seed_hash" ] || stop "$profile source checkpoint fingerprint differs"
    else
        seed_hash=$current_hash
    fi
    cp -Rp "$FI_BENCH_PRIOR_OUTPUT_ROOT/W128/private/." "$FI_BENCH_OUTPUT_ROOT/$profile/private/" ||
        stop "$profile seed artifact copy failed"
    psql_check "SELECT name || '=' || setting || coalesce(unit,'') FROM pg_settings WHERE name IN ('wal_buffers','max_wal_size','shared_buffers','fsync','synchronous_commit','full_page_writes','checkpoint_timeout') ORDER BY name" \
        > "$FI_BENCH_OUTPUT_ROOT/$profile/pg-settings.txt" ||
        stop "$profile cannot record PostgreSQL settings"
    printf 'FI CACHED WAL SEED profile=%s label=%s prefix=129470 fingerprint=%s\n' "$profile" "$wal_label" "$current_hash" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
done

# One verified relay for new jailed clusters; no TCP listener.
"$FI_BENCH_RELAY_BINARY" \
    -cluster-root="$jail_cluster_root" -output-root="$FI_BENCH_OUTPUT_ROOT" \
    -base-port=55931 -jail-binary="$FI_BENCH_JAIL_RELAY_BINARY" \
    > "$FI_BENCH_OUTPUT_ROOT/relay.log" 2>&1 &
relay_pid=$!
relay_cleanup() {
    if [ -n "$relay_pid" ]; then
        kill "$relay_pid" 2>/dev/null || :
        wait "$relay_pid" 2>/dev/null || :
        relay_pid=
    fi
}
monitor_cleanup() {
    for pid in $mon_vm $mon_io $mon_ps $mon_pg; do
        kill "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    done
    mon_vm=; mon_io=; mon_ps=; mon_pg=
}
mon_vm=; mon_io=; mon_ps=; mon_pg=
trap 'monitor_cleanup; relay_cleanup' 0
trap 'exit 130' 2
trap 'exit 143' 15
tries=0
while [ "$tries" -lt 30 ]; do
    ready_count=$(grep -c '^FI PG RELAY READY profile=' "$FI_BENCH_OUTPUT_ROOT/relay.log" || :)
    if [ "$ready_count" -eq 4 ]; then break; fi
    if ! kill -0 "$relay_pid" 2>/dev/null; then
        tail -n 25 "$FI_BENCH_OUTPUT_ROOT/relay.log" >&2 || :
        stop "PostgreSQL relay failed to start"
    fi
    sleep 1
    tries=$((tries+1))
done
[ "$ready_count" -eq 4 ] || stop "PostgreSQL relay handshakes incomplete"
cat "$FI_BENCH_OUTPUT_ROOT/relay.log"

for profile in W32 W64 W96 W128; do
    get_profile "$profile"
    profile_dir="$FI_BENCH_OUTPUT_ROOT/$profile"
    host_dsn="host=$FI_BENCH_OUTPUT_ROOT/pg-$profile port=$port user=fi_ingest dbname=fi sslmode=disable"
    [ "$(psql_check "SELECT count(*) FROM fi_recovery.typed_window")" = 1 ] ||
        stop "$profile seed modified before timed test"
    if command -v vmstat >/dev/null 2>&1; then
        vmstat -w 15 > "$profile_dir/vmstat.log" 2>&1 & mon_vm=$!
    fi
    if command -v iostat >/dev/null 2>&1; then
        iostat -x -w 15 > "$profile_dir/iostat.log" 2>&1 & mon_io=$!
    fi
    (
        while :; do
            date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
            ps -axo pid,ppid,%cpu,%mem,rss,comm | awk 'NR==1 || /fi-backlog-recover|postgres|postmaster/' || :
            # Per-core CPU ticks for capacity and saturation comparisons.
            sysctl -n kern.cp_times || :
            sleep 15
        done
    ) > "$profile_dir/process.log" 2>&1 & mon_ps=$!
    (
        while :; do
            date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
            psql_check "SELECT coalesce(wait_event_type,'running') || ':' || coalesce(wait_event,'CPU-or-idle') || ':' || state FROM pg_stat_activity WHERE usename='fi_ingest' ORDER BY pid" || :
            sleep 15
        done
    ) > "$profile_dir/pg-waits.log" 2>&1 & mon_pg=$!
    before_wal=$(psql_check "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal") ||
        stop "$profile WAL baseline missing"
    before_ckpt=$(psql_check "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer") ||
        stop "$profile checkpoint baseline missing"
    printf '%s FI CACHED WAL TIMED START profile=%s label=%s inner_chunk=32768 window=W128\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$profile" "$wal_label" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    if ! "$FI_BENCH_BINARY" \
        -source=iss-fs-22a.iss.local \
        -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
        -postgres="$host_dsn" \
        -custody-root=/var/db/fi/custody/generation \
        -recorded-root=/var/db/fi/custody/recorded \
        -source-namespaces=false \
        -private-root="$profile_dir/private" -private-writes \
        -security-profile=P3 -file-profile=F3 -window-profile=W128 \
        -processing-chunk-records=32768 -continuous-private \
        -start-window=1 -max-windows=0 -max-runtime=10m \
        -verified-cache-root="$FI_BENCH_PRIOR_OUTPUT_ROOT/verified-cache" \
        > "$profile_dir/timed.log" 2>&1; then
        monitor_cleanup
        tail -n 45 "$profile_dir/timed.log" >&2 || :
        stop "$profile cached WAL test failed"
    fi
    monitor_cleanup
    grep '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$profile_dir/timed.log" > "$profile_dir/result.txt" ||
        stop "$profile no timed result"
    cat "$profile_dir/result.txt" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    after_wal=$(psql_check "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal") ||
        stop "$profile WAL closing counters missing"
    after_ckpt=$(psql_check "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer") ||
        stop "$profile checkpoint closing counters missing"
    printf 'FI CACHED WAL COUNTERS profile=%s label=%s wal_before=%s wal_after=%s ckpt_before=%s ckpt_after=%s\n' \
        "$profile" "$wal_label" "$before_wal" "$after_wal" "$before_ckpt" "$after_ckpt" \
        | tee "$profile_dir/postgres-counters.txt" >> "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    fingerprint_sql="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' ||
        md5(coalesce(string_agg(window_index::text || ':' || encode(descriptor_sha256,'hex') || ':' ||
        committed_records::text,'|' ORDER BY window_index),'')) FROM fi_recovery.typed_window"
    checkpoint=$(psql_check "$fingerprint_sql") || stop "$profile SQL checkpoint unreadable"
    printf 'FI CACHED WAL SQL CHECKPOINT profile=%s label=%s count_records_digest=%s\n' \
        "$profile" "$wal_label" "$checkpoint" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    integrity=$(psql_check "SELECT CASE WHEN
        (SELECT count(*) FROM fi_recovery.source_window) = (SELECT count(*) FROM fi_recovery.typed_window)
        AND (SELECT count(*) FROM fi_recovery.pending_source_record) =
            (SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
        AND (SELECT count(*) FROM fi_recovery_projection.source_record) =
            (SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
        AND NOT EXISTS(SELECT 1 FROM fi.recorded_generation WHERE source_id='iss-fs-22a.iss.local')
        AND NOT EXISTS(SELECT 1 FROM fi.ingest_journal WHERE outcome='Accepted')
        THEN 'PASS' ELSE 'FAIL' END") || stop "$profile SQL integrity query failed"
    [ "$integrity" = PASS ] || stop "$profile private SQL integrity failed"
    grep '^FI PRIVATE STAGE PROFILE' "$profile_dir/timed.log" > "$profile_dir/stages.txt" ||
        stop "$profile lacks committed-window stage profiles"
done
printf '%s FI CACHED WAL 2x2 COMPLETE original_custody_scans=0 output=%s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$FI_BENCH_OUTPUT_ROOT" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
