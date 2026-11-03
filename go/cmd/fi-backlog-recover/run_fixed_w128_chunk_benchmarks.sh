#!/bin/sh
# One verified W128/1GiB seed, four isolated tests of internal joined-source
# COPY chunks (32/64/96/128Ki records) inside UNCHANGED W128 atomic windows.
# Run on the FreeBSD HOST as root; PostgreSQL utilities execute inside fi-dev.
# NO DROP/TRUNCATE/DELETE. Requires FOUR fresh isolated clusters.
set -eu
umask 077

stop() { printf 'FI W128 CHUNK BENCH STOP: %s\n' "$*" >&2; exit 1; }
for n in jexec sha256 pgrep ps date grep tail cp mkdir sleep openssl; do
    command -v "$n" >/dev/null 2>&1 || stop "missing $n"
done
: "${FI_BENCH_BINARY:?missing executable}"
: "${FI_BENCH_BINARY_SHA256:?missing executable SHA}"
: "${FI_BENCH_SOURCE_GIT_SHA:?missing optimized source Git commit}"
: "${FI_BENCH_RUN_LABEL:?missing dev test run label}"
: "${FI_BENCH_RELAY_BINARY:?missing verified host-to-jail PostgreSQL relay}"
: "${FI_BENCH_RELAY_SHA256:?missing host-to-jail relay SHA256}"
: "${FI_BENCH_JAIL_RELAY_BINARY:=/home/jwood/fi-w128-chunk-build/fi-backlog-pg-relay}"
: "${FI_BENCH_OUTPUT_ROOT:?missing fresh output root}"
: "${FI_BENCH_CUSTODY_ROOT:?missing custody root}"
: "${FI_BENCH_RECORDED_ROOT:?missing recorded receipt root}"
: "${FI_BENCH_W32_DSN:?missing W32 cluster}"
: "${FI_BENCH_W64_DSN:?missing W64 cluster}"
: "${FI_BENCH_W96_DSN:?missing W96 cluster}"
: "${FI_BENCH_W128_DSN:?missing W128 cluster}"
: "${FI_BENCH_W32_PORT:?missing W32 port}"
: "${FI_BENCH_W64_PORT:?missing W64 port}"
: "${FI_BENCH_W96_PORT:?missing W96 port}"
: "${FI_BENCH_W128_PORT:?missing W128 port}"
[ "${FI_BENCH_ISOLATED_CLUSTERS_CONFIRMED:-}" = YES ] || stop "four disposable instances must be reviewed and confirmed"
case "$FI_BENCH_SOURCE_GIT_SHA" in *[!a-f0-9]*|'') stop "invalid source Git SHA";; esac
[ "${#FI_BENCH_SOURCE_GIT_SHA}" -eq 40 ] || stop "source Git SHA must contain 40 hexadecimal characters"
actual_source_commit=$(jexec -U jwood fi-dev git -C /home/jwood/src/fi rev-parse HEAD) ||
    stop "cannot inspect fi-dev source commit"
[ "$actual_source_commit" = "$FI_BENCH_SOURCE_GIT_SHA" ] ||
    stop "fi-dev source commit differs from the provisioned optimized build"
[ "${FI_BENCH_PSQL_JAIL:-}" = fi-dev ] || stop "requires fi-dev PostgreSQL client jail"
jexec -U jwood fi-dev sh -c 'command -v psql >/dev/null && command -v pg_dump >/dev/null && command -v pg_restore >/dev/null' ||
    stop "fi-dev requires psql, pg_dump, and pg_restore before any custody scan"
for trust_file in \
    /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem \
    /usr/local/etc/fi/sources/iss-fs-22a.iss.local.conf; do
    [ -r "$trust_file" ] || stop "missing installed host FI trust: $trust_file"
done
# The Go signed loader remains authoritative for expiration/revocation.
# Preflight additionally checks that host's installed CRL signature is
# authentic (do not use receiver-jail CRLs for this test).
openssl crl -in /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem \
    -noout -verify -CAfile /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem \
    >/dev/null || stop "host-installed batch CRL signature invalid"
case "$FI_BENCH_BINARY" in /*) ;; *) stop "binary requires absolute path";; esac
case "$FI_BENCH_OUTPUT_ROOT" in /var/tmp/fi-window-chunks-*) ;; *) stop "new output root must start /var/tmp/fi-window-chunks-";; esac
[ ! -e "$FI_BENCH_OUTPUT_ROOT" ] || stop "output root already exists; cannot reuse"
[ -x "$FI_BENCH_BINARY" ] || stop "binary missing/unexecutable"
[ "$(sha256 -q "$FI_BENCH_BINARY")" = "$FI_BENCH_BINARY_SHA256" ] || stop "wrong build SHA"
[ -x "$FI_BENCH_RELAY_BINARY" ] || stop "missing host-to-jail relay executable"
[ "$(sha256 -q "$FI_BENCH_RELAY_BINARY")" = "$FI_BENCH_RELAY_SHA256" ] ||
    stop "wrong host-to-jail relay executable SHA"
jexec -U jwood fi-dev test -x "$FI_BENCH_JAIL_RELAY_BINARY" ||
    stop "fi-dev must have the built relay executable (run build in separate fi-dev SSH)"
for f in "$FI_BENCH_CUSTODY_ROOT" "$FI_BENCH_RECORDED_ROOT"; do
    [ -d "$f" ] || stop "missing custody/recorded root $f"
done

namespace_flag=${FI_BENCH_SOURCE_NAMESPACES:-false}
case "$namespace_flag" in true|false) ;; *) stop "invalid source namespace value";; esac
# Do not run two benchmark runners concurrently.
if pgrep -f 'run_four_window_benchmarks[.]sh' >/dev/null 2>&1; then
    stop "old window-size benchmark still running; stop it before starting chunk comparison"
fi

get_profile() {
    case "$1" in
      W32) dsn=$FI_BENCH_W32_DSN; expected=$FI_BENCH_W32_PORT; chunk=32768;;
      W64) dsn=$FI_BENCH_W64_DSN; expected=$FI_BENCH_W64_PORT; chunk=65536;;
      W96) dsn=$FI_BENCH_W96_DSN; expected=$FI_BENCH_W96_PORT; chunk=98304;;
      W128) dsn=$FI_BENCH_W128_DSN; expected=$FI_BENCH_W128_PORT; chunk=131072;;
      *) stop "invalid profile";;
    esac
    case "$expected" in 5553[1-4]|5563[1-4]|5573[1-4]|5583[1-4]) ;; *) stop "unexpected disposable cluster port $expected";; esac
    jail_dsn=$(printf '%s\n' "$dsn" | sed 's@host=/usr/local/jails/containers/fi-dev/@host=/@')
    case "$jail_dsn" in
       host=/home/jwood/fi-window-bench-*" user=fi_ingest dbname=fi sslmode=disable") ;;
       *) stop "invalid test database DSN for $1";;
    esac
    # Only the original jail_dsn goes to in-jail PostgreSQL clients.
    # The host recovery executable connects to a real host-owned Unix
    # listener. The relay enters fi-dev for each PG connection; no
    # symlinks, TCP services, database restarts or jail networking changes.
    if [ "${host_relay_ready:-NO}" = YES ]; then
        dsn="host=$FI_BENCH_OUTPUT_ROOT/pg-$1 port=$expected user=fi_ingest dbname=fi sslmode=disable"
    fi
}
psql_check() {
    jexec -U jwood fi-dev psql "$jail_dsn" -X -qAt -v ON_ERROR_STOP=1 -c "$1"
}
schema_sql="SELECT CASE WHEN current_database()='fi' AND current_user='fi_ingest'
 AND to_regclass('fi_recovery.verified_artifact_window') IS NOT NULL
 AND to_regclass('fi_recovery.typed_window') IS NOT NULL
 AND to_regclass('fi_recovery_projection.recorded_generation') IS NOT NULL
 AND to_regclass('fi_recovery_projection.source_batch') IS NOT NULL
 AND to_regclass('fi.recorded_generation') IS NOT NULL
 THEN 'READY' ELSE 'MISSING' END"
empty_sql="SELECT CASE WHEN
 NOT EXISTS(SELECT 1 FROM fi_recovery.verified_artifact_window)
 AND NOT EXISTS(SELECT 1 FROM fi_recovery.source_window)
 AND NOT EXISTS(SELECT 1 FROM fi_recovery.typed_window)
 AND NOT EXISTS(SELECT 1 FROM fi_recovery_projection.recorded_generation)
 AND NOT EXISTS(SELECT 1 FROM fi.recorded_generation)
 THEN 'EMPTY' ELSE 'DIRTY' END"
seen_ports=
for profile in W32 W64 W96 W128; do
    get_profile "$profile"
    [ "$(psql_check "$schema_sql")" = READY ] || stop "$profile schema incomplete"
    [ "$(psql_check "SELECT current_setting('port')")" = "$expected" ] || stop "$profile wrong PostgreSQL instance"
    case "|$seen_ports|" in *"|$expected|"*) stop "$profile reused PostgreSQL port";; esac
    seen_ports="$seen_ports|$expected"
    [ "$(psql_check "$empty_sql")" = EMPTY ] || stop "$profile not empty; no changes made"
    printf 'FI CHUNK BENCH PREFLIGHT profile=%s port=%s schema=ready private_state=empty\n' "$profile" "$expected"
done

# The seed dump and the jail-owned PostgreSQL clusters must all belong to
# the SAME configured disposable root; the archive never contains passwords.
get_profile W128
jail_cluster_root=${jail_dsn#host=}
jail_cluster_root=${jail_cluster_root%%/W128/socket*}
case "$jail_cluster_root" in /home/jwood/fi-window-bench-*) ;; *) stop "invalid jail cluster root";; esac
jail_archive="$jail_cluster_root/single-w128-seed.dump"
host_jail_archive="/usr/local/jails/containers/fi-dev$jail_archive"
[ ! -e "$host_jail_archive" ] || stop "bootstrap snapshot already exists"
[ -d "/usr/local/jails/containers/fi-dev$jail_cluster_root" ] || stop "jail cluster root missing"

mkdir -m 700 "$FI_BENCH_OUTPUT_ROOT" || stop "cannot create new output root"
# One complete original signed transfer is verified at seed time; preserve
# every checked batch in this shared, receipt-bound cache for ALL four tests.
cache_root="$FI_BENCH_OUTPUT_ROOT/verified-cache"
mkdir -m 700 "$cache_root" || stop "cannot create verified cache"
df -h "$cache_root" > "$FI_BENCH_OUTPUT_ROOT/cache-filesystem-before.txt" ||
    stop "cannot inspect cache disk capacity"
{
    printf 'FI REAL SIGNED BACKLOG - OPTIMIZED SINGLE-WORKER EXPERIMENT\n'
    printf 'label=%s\n' "$FI_BENCH_RUN_LABEL"
    printf 'git_commit=%s\n' "$FI_BENCH_SOURCE_GIT_SHA"
    printf 'recover_binary_sha256=%s\n' "$FI_BENCH_BINARY_SHA256"
    printf 'relay_binary_sha256=%s\n' "$FI_BENCH_RELAY_SHA256"
    printf 'source_id=iss-fs-22a.iss.local\n'
    printf 'generation_id=20261030T000032.061323100Z-3e38b2210771462c\n'
    printf 'signed_source_records=15140785\nsigned_batches=8399\n'
    printf 'preparation=one complete signed custody scan, persists verified original batch data; first W128 durable seed\n'
    printf 'verified_cache=shared receipt-bound source reused for four timed profiles\n'
    printf 'four_tests=independent cloned seed, 10 minutes each, serial W32 W64 W96 W128\n'
    printf 'atomic_window_records=131072\natomic_window_bytes=1073741824\n'
    printf 'security_profile=P3\nfile_profile=F3\n'
    printf 'inner_chunk_records=32768,65536,98304,131072\n'
    printf 'publication=disabled; private durable throughput only\n'
    printf 'start_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'host=%s\n' "$(hostname)"
    printf 'crl_sha256=%s\n' "$(sha256 -q /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem)"
    openssl crl -in /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem \
        -noout -lastupdate -nextupdate -crlnumber
} > "$FI_BENCH_OUTPUT_ROOT/RUN_MANIFEST.txt"
# A separate, verified helper bridges private host AF_UNIX endpoints into
# fi-dev by entering the jail for each PostgreSQL connection. Unlike a
# symlink to a jailed PostgreSQL socket, the host endpoints are created by
# the host process itself. Startup sends a real PostgreSQL SSLRequest over
# every relay and requires an N/S response BEFORE the signed-custody seed.
relay_pid=
relay_cleanup() {
    if [ -n "$relay_pid" ]; then
        kill "$relay_pid" 2>/dev/null || :
        wait "$relay_pid" 2>/dev/null || :
        relay_pid=
    fi
}
trap relay_cleanup 0
"$FI_BENCH_RELAY_BINARY" \
    -cluster-root="$jail_cluster_root" \
    -output-root="$FI_BENCH_OUTPUT_ROOT" \
    -base-port="$FI_BENCH_W32_PORT" \
    -jail-binary="$FI_BENCH_JAIL_RELAY_BINARY" \
    > "$FI_BENCH_OUTPUT_ROOT/relay.log" 2>&1 &
relay_pid=$!
tries=0
while [ "$tries" -lt 30 ]; do
    ready_count=$(grep -c '^FI PG RELAY READY profile=' "$FI_BENCH_OUTPUT_ROOT/relay.log" || :)
    if [ "$ready_count" -eq 4 ]; then break; fi
    if ! kill -0 "$relay_pid" 2>/dev/null; then
        tail -n 30 "$FI_BENCH_OUTPUT_ROOT/relay.log" >&2 || :
        stop "host-to-jail relay exited before confirming four PostgreSQL wire handshakes"
    fi
    sleep 1
    tries=$((tries + 1))
done
[ "$ready_count" -eq 4 ] || {
    tail -n 30 "$FI_BENCH_OUTPUT_ROOT/relay.log" >&2 || :
    stop "host-to-jail relay failed PostgreSQL wire handshake preflight"
}
host_relay_ready=YES
cat "$FI_BENCH_OUTPUT_ROOT/relay.log"
printf 'fixed_window_records=131072 fixed_window_bytes=1073741824 original_signed_generation=yes source_git=%s run_label=%s\n' \
    "$FI_BENCH_SOURCE_GIT_SHA" "$FI_BENCH_RUN_LABEL" > "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
printf 'binary_sha256=%s\n' "$FI_BENCH_BINARY_SHA256" >> "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
printf 'relay_sha256=%s\n' "$FI_BENCH_RELAY_SHA256" >> "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
source_id=iss-fs-22a.iss.local
generation_id=20261030T000032.061323100Z-3e38b2210771462c
seed_root="$FI_BENCH_OUTPUT_ROOT/W128/private"
mkdir -m 700 "$FI_BENCH_OUTPUT_ROOT/W128" "$seed_root"

get_profile W128
printf '%s FI CHUNK BENCH W128 one-time signed-custody seed started\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
# One complete signed-custody scan authenticates all original source batches
# and creates 1 committed W128 window before any 10-minute timed trial.
if ! "$FI_BENCH_BINARY" \
    -source="$source_id" -generation-id="$generation_id" -postgres="$dsn" \
    -custody-root="$FI_BENCH_CUSTODY_ROOT" -recorded-root="$FI_BENCH_RECORDED_ROOT" \
    -source-namespaces="$namespace_flag" -private-root="$seed_root" \
    -private-writes -security-profile=P3 -file-profile=F3 \
    -window-profile=W128 -stream-loader -start-window=0 -max-windows=1 \
    -verified-cache-root="$cache_root" \
    > "$FI_BENCH_OUTPUT_ROOT/W128/seed.log" 2>&1; then
    tail -n 35 "$FI_BENCH_OUTPUT_ROOT/W128/seed.log" >&2 || :
    stop "W128 initial signed seed failed; other clusters remain empty"
fi
grep 'FI REAL BACKLOG PAUSED completed_to_window=1' "$FI_BENCH_OUTPUT_ROOT/W128/seed.log" >/dev/null ||
  stop "W128 seed did not report committed first window"
[ "$(psql_check "SELECT count(*) FROM fi_recovery.typed_window")" = 1 ] ||
  stop "W128 database first typed window not durable"
[ "$(psql_check "SELECT count(*) FROM fi_recovery_projection.source_batch")" = 8399 ] ||
  stop "W128 database source-batch index not complete"
seed_hash=$(psql_check "SELECT encode(descriptor_sha256,'hex') FROM fi_recovery.typed_window WHERE window_index=0")
[ "${#seed_hash}" -eq 64 ] || stop "W128 seed descriptor fingerprint missing"
cache_batches=$(find "$cache_root" -type f -name '*.data' | wc -l | tr -d ' ')
[ "$cache_batches" = 8399 ] || stop "verified signed cache has $cache_batches data batches, expected 8399"
printf '%s FI VERIFIED CACHE SINGLE SCAN COMPLETE root=%s batches=8399\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$cache_root" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
printf '%s FI CHUNK BENCH W128 initial private checkpoint durable\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"

# Make one consistent source snapshot, then restore to three NEW, empty
# PostgreSQL databases. Signed source identities and checkpoint hashes match.
admin_dsn=$(printf '%s\n' "$jail_dsn" | sed 's/user=fi_ingest/user=fi_m1_admin/')
jexec -U jwood fi-dev pg_dump "$admin_dsn" \
    --format=custom --data-only --no-owner --no-acl --file="$jail_archive" ||
    stop "one-time W128 PostgreSQL source snapshot failed"
[ -s "$host_jail_archive" ] || stop "empty W128 seed dump"

for profile in W32 W64 W96; do
    get_profile "$profile"
    [ "$(psql_check "$empty_sql")" = EMPTY ] || stop "$profile changed before restore"
    admin_dsn=$(printf '%s\n' "$jail_dsn" | sed 's/user=fi_ingest/user=fi_m1_admin/')
    jexec -U jwood fi-dev pg_restore \
       --data-only --exit-on-error --single-transaction \
       --dbname="$admin_dsn" "$jail_archive" \
       > "$FI_BENCH_OUTPUT_ROOT/restore-$profile.log" 2>&1 ||
       stop "$profile PostgreSQL restore failed; see restore-$profile.log"
    [ "$(psql_check "SELECT count(*) FROM fi_recovery.typed_window")" = 1 ] ||
       stop "$profile missing cloned W128 committed checkpoint"
    [ "$(psql_check "SELECT count(*) FROM fi_recovery_projection.source_batch")" = 8399 ] ||
       stop "$profile incomplete authenticated source-batch index after clone"
    clone_hash=$(psql_check "SELECT encode(descriptor_sha256,'hex') FROM fi_recovery.typed_window WHERE window_index=0")
    [ "$clone_hash" = "$seed_hash" ] || stop "$profile seed descriptor differs from W128"
    mkdir -m 700 "$FI_BENCH_OUTPUT_ROOT/$profile" "$FI_BENCH_OUTPUT_ROOT/$profile/private"
    cp -Rp "$seed_root/." "$FI_BENCH_OUTPUT_ROOT/$profile/private/" ||
        stop "$profile private artifact seed copy failed"
    printf '%s FI CHUNK BENCH %s cloned same durable W128 seed\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$profile" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
done

monitor_cleanup() {
    for p in "${mon_vm:-}" "${mon_io:-}" "${mon_ps:-}"; do
        if [ -n "$p" ]; then kill "$p" 2>/dev/null || :; wait "$p" 2>/dev/null || :; fi
    done
    mon_vm=; mon_io=; mon_ps=
}
trap 'monitor_cleanup; relay_cleanup' 0
trap 'exit 130' 2
trap 'exit 143' 15
for profile in W32 W64 W96 W128; do
    get_profile "$profile"
    profile_dir="$FI_BENCH_OUTPUT_ROOT/$profile"
    mon_vm=; mon_io=; mon_ps=
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
        sleep 15
      done
    ) > "$profile_dir/process.log" 2>&1 & mon_ps=$!
    before_wal=$(psql_check "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal") ||
        stop "$profile WAL baseline read failed"
    before_checkpoints=$(psql_check "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer") ||
        stop "$profile checkpoint baseline read failed"
    printf '%s FI CHUNK BENCH profile=%s chunk_records=%s timed-start\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$profile" "$chunk" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    if ! "$FI_BENCH_BINARY" \
        -source="$source_id" -generation-id="$generation_id" -postgres="$dsn" \
        -custody-root="$FI_BENCH_CUSTODY_ROOT" -recorded-root="$FI_BENCH_RECORDED_ROOT" \
        -source-namespaces="$namespace_flag" -private-root="$profile_dir/private" \
        -private-writes -security-profile=P3 -file-profile=F3 \
        -window-profile=W128 -processing-chunk-records="$chunk" \
        -continuous-private -start-window=1 -max-windows=0 -max-runtime=10m \
        -verified-cache-root="$cache_root" \
        > "$profile_dir/timed.log" 2>&1; then
        monitor_cleanup
        tail -n 30 "$profile_dir/timed.log" >&2 || :
        stop "$profile failed; later tests not run"
    fi
    monitor_cleanup
    grep '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$profile_dir/timed.log" > "$profile_dir/result.txt" ||
       stop "$profile did not produce a ten-minute terminal checkpoint"
    cat "$profile_dir/result.txt" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    after_wal=$(psql_check "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal") ||
        stop "$profile ending WAL counters unreadable"
    after_checkpoints=$(psql_check "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer") ||
        stop "$profile ending checkpoint counters unreadable"
    printf 'FI PG COUNTERS profile=%s WAL_before=%s WAL_after=%s checkpoints_before=%s checkpoints_after=%s\n' \
       "$profile" "$before_wal" "$after_wal" "$before_checkpoints" "$after_checkpoints" \
       | tee "$profile_dir/postgres-counters.txt" >> "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    grep '^FI TYPED CHUNK COMMITTED ' "$profile_dir/timed.log" > "$profile_dir/typed-chunks.txt" ||
        stop "$profile did not exercise typed processing chunks"
    # Validate actual SQL state rather than trusting the terminal log's
    # 'authoritative=0 accepted=0' fields. Every profile has its own empty
    # disposable cluster; a mismatch is a HARD test failure.
    integrity_sql="SELECT CASE WHEN
      (SELECT count(*) FROM fi_recovery.source_window)
       = (SELECT count(*) FROM fi_recovery.typed_window)
      AND (SELECT count(*) FROM fi_recovery.pending_source_record)
       = (SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
      AND (SELECT count(*) FROM fi_recovery_projection.source_record)
       = (SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
      AND NOT EXISTS(SELECT 1 FROM fi.recorded_generation
        WHERE source_id='$source_id' AND generation_id='$generation_id')
      AND NOT EXISTS(SELECT 1 FROM fi.ingest_journal WHERE outcome='Accepted')
      THEN 'PASS' ELSE 'FAIL' END"
    [ "$(psql_check "$integrity_sql")" = PASS ] ||
        stop "$profile private source/typed markers, source rows, or canonical isolation failed"
    # Each descriptor was previously signed and independently verified.
    # Capture a comparable fingerprint of exactly the durable prefix actually
    # completed: profiles may commit DIFFERENT numbers of windows by 10 min.
    fingerprint_sql="SELECT
      'FI CHUNK BENCH SQL CHECKPOINT profile=$profile windows=' || count(*) ||
      ' durable_records=' || coalesce(sum(committed_records),0) ||
      ' last_window=' || coalesce(max(window_index),-1) ||
      ' descriptor_chain_md5=' ||
      md5(coalesce(string_agg(window_index::text || ':' ||
        encode(descriptor_sha256,'hex') || ':' || committed_records::text,
        '|' ORDER BY window_index),''))
      FROM fi_recovery.typed_window"
    psql_check "$fingerprint_sql" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt" ||
        stop "$profile could not read verified private SQL checkpoint"
done
printf '%s FI CHUNK BENCH COMPLETE: four timed W128/1GiB runs, output=%s\n' \
   "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$FI_BENCH_OUTPUT_ROOT" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
df -h "$cache_root" > "$FI_BENCH_OUTPUT_ROOT/cache-filesystem-after.txt" || :
printf 'completed_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$FI_BENCH_OUTPUT_ROOT/RUN_MANIFEST.txt"
