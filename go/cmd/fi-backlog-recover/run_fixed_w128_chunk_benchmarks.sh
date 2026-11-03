#!/bin/sh
# One verified W128/1GiB seed, four isolated tests of internal joined-source
# COPY chunks (32/64/96/128Ki records) inside UNCHANGED W128 atomic windows.
# Run on the FreeBSD HOST as root; PostgreSQL utilities execute inside fi-dev.
# NO DROP/TRUNCATE/DELETE. Requires FOUR fresh isolated clusters.
set -eu
umask 077

stop() { printf 'FI W128 CHUNK BENCH STOP: %s\n' "$*" >&2; exit 1; }
for n in jexec sha256 pgrep ps date grep tail cp mkdir ln nc; do
    command -v "$n" >/dev/null 2>&1 || stop "missing $n"
done
: "${FI_BENCH_BINARY:?missing executable}"
: "${FI_BENCH_BINARY_SHA256:?missing executable SHA}"
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
case "$FI_BENCH_BINARY" in /*) ;; *) stop "binary requires absolute path";; esac
case "$FI_BENCH_OUTPUT_ROOT" in /var/tmp/fi-window-chunks-*) ;; *) stop "new output root must start /var/tmp/fi-window-chunks-";; esac
[ ! -e "$FI_BENCH_OUTPUT_ROOT" ] || stop "output root already exists; cannot reuse"
[ -x "$FI_BENCH_BINARY" ] || stop "binary missing/unexecutable"
[ "$(sha256 -q "$FI_BENCH_BINARY")" = "$FI_BENCH_BINARY_SHA256" ] || stop "wrong build SHA"
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
    case "$expected" in 5553[1-4]|5563[1-4]|5573[1-4]) ;; *) stop "unexpected disposable cluster port $expected";; esac
    jail_dsn=$(printf '%s\n' "$dsn" | sed 's@host=/usr/local/jails/containers/fi-dev/@host=/@')
    case "$jail_dsn" in
       host=/home/jwood/fi-window-bench-*" user=fi_ingest dbname=fi sslmode=disable") ;;
       *) stop "invalid test database DSN for $1";;
    esac
    # Host-visible jail paths can exceed FreeBSD's AF_UNIX sun_path limit
    # (104 bytes). Keep original jail_dsn for PostgreSQL utilities inside
    # fi-dev; only the host recovery process uses short symlink DSNs.
    if [ "${host_socket_links_ready:-NO}" = YES ]; then
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
# Postgres socket path seen by the HOST, including .s.PGSQL.NNNNN, must
# fit FreeBSD sockaddr_un.sun_path. The original path can be too long even
# though the same socket works inside fi-dev. Use test-owned short links;
# never reconfigure databases or expose a TCP port for this benchmark.
for profile in W32 W64 W96 W128; do
    get_profile "$profile"
    socket_dir=${dsn#host=}
    socket_dir=${socket_dir%% port=*}
    case "$socket_dir" in
      /usr/local/jails/containers/fi-dev/home/jwood/fi-window-bench-*/"$profile"/socket) ;;
      *) stop "$profile unexpected jail socket path";;
    esac
    original_socket="$socket_dir/.s.PGSQL.$expected"
    short_dir="$FI_BENCH_OUTPUT_ROOT/pg-$profile"
    ln -s "$socket_dir" "$short_dir" || stop "$profile could not create short host socket path"
    socket="$short_dir/.s.PGSQL.$expected"
    [ "${#socket}" -lt 104 ] || stop "$profile host Unix socket path still too long"
    [ -S "$socket" ] || stop "$profile PostgreSQL Unix socket missing through short path"
    nc -z -U -w 3 "$socket" </dev/null >/dev/null 2>&1 ||
        stop "$profile host cannot connect through short Unix socket; no custody scan started"
    printf 'FI CHUNK BENCH HOST SOCKET profile=%s original_bytes=%s short_bytes=%s connect=ok\n' \
        "$profile" "${#original_socket}" "${#socket}"
done
host_socket_links_ready=YES
printf 'fixed_window_records=131072 fixed_window_bytes=1073741824 original_signed_generation=yes\n' > "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
printf 'binary_sha256=%s\n' "$FI_BENCH_BINARY_SHA256" >> "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
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
trap monitor_cleanup 0
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
    printf '%s FI CHUNK BENCH profile=%s chunk_records=%s timed-start\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$profile" "$chunk" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    if ! "$FI_BENCH_BINARY" \
        -source="$source_id" -generation-id="$generation_id" -postgres="$dsn" \
        -custody-root="$FI_BENCH_CUSTODY_ROOT" -recorded-root="$FI_BENCH_RECORDED_ROOT" \
        -source-namespaces="$namespace_flag" -private-root="$profile_dir/private" \
        -private-writes -security-profile=P3 -file-profile=F3 \
        -window-profile=W128 -processing-chunk-records="$chunk" \
        -continuous-private -start-window=1 -max-windows=0 -max-runtime=10m \
        > "$profile_dir/timed.log" 2>&1; then
        monitor_cleanup
        tail -n 30 "$profile_dir/timed.log" >&2 || :
        stop "$profile failed; later tests not run"
    fi
    monitor_cleanup
    grep '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$profile_dir/timed.log" > "$profile_dir/result.txt" ||
       stop "$profile did not produce a ten-minute terminal checkpoint"
    cat "$profile_dir/result.txt" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
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
