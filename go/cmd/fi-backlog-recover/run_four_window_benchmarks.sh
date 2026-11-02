#!/bin/sh
# FI PRIVATE recovery window comparison. Never resets or edits existing state.
# Each profile requires its own PREINSTALLED, EMPTY, ISOLATED PostgreSQL cluster
# with the original FI schema + private recovery schema and permissions.
set -eu
umask 077

fail() { printf '%s\n' "FI BENCHMARK STOP: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing executable $1"; }

: "${FI_BENCH_BINARY:?set an absolute path to the fi-backlog-recover FreeBSD binary}"
: "${FI_BENCH_BINARY_SHA256:?set the expected SHA256 of that binary}"
: "${FI_BENCH_OUTPUT_ROOT:?set a NEW absolute output directory that does not yet exist}"
: "${FI_BENCH_CUSTODY_ROOT:?set the immutable custody directory}"
: "${FI_BENCH_RECORDED_ROOT:?set the immutable recorded-receipt directory}"
: "${FI_BENCH_W32_DSN:?set the independent W32 isolated PostgreSQL DSN}"
: "${FI_BENCH_W64_DSN:?set the independent W64 isolated PostgreSQL DSN}"
: "${FI_BENCH_W96_DSN:?set the independent W96 isolated PostgreSQL DSN}"
: "${FI_BENCH_W128_DSN:?set the independent W128 isolated PostgreSQL DSN}"
[ "${FI_BENCH_ISOLATED_CLUSTERS_CONFIRMED:-}" = "YES" ] || fail "set FI_BENCH_ISOLATED_CLUSTERS_CONFIRMED=YES after checking four separate disposable PostgreSQL instances"

need sha256
need psql
need grep
need date
case "$FI_BENCH_BINARY" in /*) ;; *) fail "FI_BENCH_BINARY must be absolute";; esac
case "$FI_BENCH_OUTPUT_ROOT" in /*) ;; *) fail "FI_BENCH_OUTPUT_ROOT must be absolute";; esac
case "$FI_BENCH_CUSTODY_ROOT" in /*) ;; *) fail "FI_BENCH_CUSTODY_ROOT must be absolute";; esac
case "$FI_BENCH_RECORDED_ROOT" in /*) ;; *) fail "FI_BENCH_RECORDED_ROOT must be absolute";; esac
[ -x "$FI_BENCH_BINARY" ] || fail "binary not executable"
[ -d "$FI_BENCH_CUSTODY_ROOT" ] || fail "custody directory unavailable"
[ -d "$FI_BENCH_RECORDED_ROOT" ] || fail "recorded directory unavailable"
[ ! -e "$FI_BENCH_OUTPUT_ROOT" ] || fail "output directory already exists; never reuse a recovery root"
actual_sha=$(sha256 -q "$FI_BENCH_BINARY") || fail "could not hash executable"
[ "$actual_sha" = "$FI_BENCH_BINARY_SHA256" ] || fail "wrong executable SHA256"
[ "$FI_BENCH_W32_DSN" != "$FI_BENCH_W64_DSN" ] || fail "duplicate W32/W64 DSN"
[ "$FI_BENCH_W32_DSN" != "$FI_BENCH_W96_DSN" ] || fail "duplicate W32/W96 DSN"
[ "$FI_BENCH_W32_DSN" != "$FI_BENCH_W128_DSN" ] || fail "duplicate W32/W128 DSN"
[ "$FI_BENCH_W64_DSN" != "$FI_BENCH_W96_DSN" ] || fail "duplicate W64/W96 DSN"
[ "$FI_BENCH_W64_DSN" != "$FI_BENCH_W128_DSN" ] || fail "duplicate W64/W128 DSN"
[ "$FI_BENCH_W96_DSN" != "$FI_BENCH_W128_DSN" ] || fail "duplicate W96/W128 DSN"

namespace_flag="${FI_BENCH_SOURCE_NAMESPACES:-false}"
case "$namespace_flag" in true|false) ;; *) fail "FI_BENCH_SOURCE_NAMESPACES must be true or false";; esac

get_dsn() {
    case "$1" in
        W32) dsn=$FI_BENCH_W32_DSN;;
        W64) dsn=$FI_BENCH_W64_DSN;;
        W96) dsn=$FI_BENCH_W96_DSN;;
        W128) dsn=$FI_BENCH_W128_DSN;;
        *) fail "unsupported profile $1";;
    esac
}

# A preflight is deliberately read-only. Each connection must be the private
# 'fi_ingest' role in an empty FI test database. No DROP/TRUNCATE/DELETE occurs.
# Existing 32K recovery, even when unfinished, MUST fail this gate.
ready_sql="SELECT CASE WHEN
 current_database()='fi' AND current_user='fi_ingest' AND
 to_regclass('fi_recovery.verified_artifact_window') IS NOT NULL AND
 to_regclass('fi_recovery.source_window') IS NOT NULL AND
 to_regclass('fi_recovery.typed_window') IS NOT NULL AND
 to_regclass('fi_recovery_projection.recorded_generation') IS NOT NULL AND
 to_regclass('fi_recovery_projection.source_batch') IS NOT NULL AND
 to_regclass('fi.recorded_generation') IS NOT NULL AND
 to_regclass('fi.ingest_journal') IS NOT NULL
 THEN 'SCHEMA_READY' ELSE 'SCHEMA_MISSING' END"
empty_sql="SELECT CASE WHEN
 NOT EXISTS (SELECT 1 FROM fi_recovery.verified_artifact_window) AND
 NOT EXISTS (SELECT 1 FROM fi_recovery.source_window) AND
 NOT EXISTS (SELECT 1 FROM fi_recovery.typed_window) AND
 NOT EXISTS (SELECT 1 FROM fi_recovery_projection.recorded_generation) AND
 NOT EXISTS (SELECT 1 FROM fi.recorded_generation) AND
 NOT EXISTS (SELECT 1 FROM fi.ingest_journal)
 THEN 'EMPTY' ELSE 'NOT_EMPTY' END"

printf 'FI BENCHMARK preflight: four unique disposable database connections, one binary=%s\n' "$actual_sha"
for profile in W32 W64 W96 W128; do
    get_dsn "$profile"
    schema=$(psql "$dsn" -X -qAt -v ON_ERROR_STOP=1 -c "$ready_sql") || fail "$profile schema preflight failed"
    [ "$schema" = "SCHEMA_READY" ] || fail "$profile schema is not installed or wrong DB role"
    empty=$(psql "$dsn" -X -qAt -v ON_ERROR_STOP=1 -c "$empty_sql") || fail "$profile empty-state query failed"
    [ "$empty" = "EMPTY" ] || fail "$profile recovery state is not empty; no changes made"
    printf 'FI BENCHMARK preflight profile=%s status=isolated-empty\n' "$profile"
done

mkdir -m 700 "$FI_BENCH_OUTPUT_ROOT" || fail "cannot create new output root"
: > "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
printf 'binary_sha256=%s\n' "$actual_sha" >> "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
printf 'four profiles; P3 Security; F3 File; 10 minute timed continuous resume per profile\n' >> "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"

# Exactly the immutable signed generation used in the 2026-11-02 tests.
source_id=iss-fs-22a.iss.local
generation_id=20261030T000032.061323100Z-3e38b2210771462c
mon_vm=
mon_io=
mon_ps=
cleanup_monitors() {
    for p in "$mon_vm" "$mon_io" "$mon_ps"; do
        if [ -n "$p" ]; then
            kill "$p" 2>/dev/null || :
            wait "$p" 2>/dev/null || :
        fi
    done
    mon_vm=; mon_io=; mon_ps=
}
trap cleanup_monitors 0
trap 'exit 130' 2
trap 'exit 143' 15

for profile in W32 W64 W96 W128; do
    get_dsn "$profile"
    profile_dir="$FI_BENCH_OUTPUT_ROOT/$profile"
    private_root="$profile_dir/private"
    mkdir -m 700 "$profile_dir" "$private_root" || fail "$profile private directories"
    printf '%s profile=%s seed-start\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$profile" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"

    # Full signed-custody verification and initial private window happen BEFORE
    # the timed 10-minute run. This creates the complete indexed batch metadata
    # required for the subsequent continuous-private stream.
    if ! "$FI_BENCH_BINARY" \
      -source="$source_id" -generation-id="$generation_id" -postgres="$dsn" \
      -custody-root="$FI_BENCH_CUSTODY_ROOT" -recorded-root="$FI_BENCH_RECORDED_ROOT" \
      -source-namespaces="$namespace_flag" -private-root="$private_root" \
      -private-writes -security-profile=P3 -file-profile=F3 \
      -window-profile="$profile" -stream-loader -start-window=0 -max-windows=1 \
      > "$profile_dir/seed.log" 2>&1; then
        tail -n 25 "$profile_dir/seed.log" >&2 || :
        fail "$profile initial window failed: see seed.log; later profiles NOT started"
    fi
    grep 'FI REAL BACKLOG PAUSED completed_to_window=1' "$profile_dir/seed.log" >/dev/null ||
      fail "$profile did not establish durable window-0 checkpoint"

    # The timers begin only for the 10-minute continuous-phase comparison.
    # Monitor system, disk and process counters without logging command args
    # (which can contain connection credentials).
    if command -v vmstat >/dev/null 2>&1; then
        vmstat -w 15 > "$profile_dir/vmstat.log" 2>&1 & mon_vm=$!
    fi
    if command -v iostat >/dev/null 2>&1; then
        iostat -x -w 15 > "$profile_dir/iostat.log" 2>&1 & mon_io=$!
    fi
    (
        while :; do
            date -u '+UTC %Y-%m-%dT%H:%M:%SZ'
            ps -axo pid,ppid,%cpu,%mem,rss,comm 2>/dev/null |
              awk 'NR == 1 || /fi-backlog-recover|postgres|postmaster/' || :
            sleep 15
        done
    ) > "$profile_dir/process.log" 2>&1 & mon_ps=$!

    printf '%s profile=%s timed-start\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$profile" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    if ! "$FI_BENCH_BINARY" \
      -source="$source_id" -generation-id="$generation_id" -postgres="$dsn" \
      -custody-root="$FI_BENCH_CUSTODY_ROOT" -recorded-root="$FI_BENCH_RECORDED_ROOT" \
      -source-namespaces="$namespace_flag" -private-root="$private_root" \
      -private-writes -security-profile=P3 -file-profile=F3 \
      -window-profile="$profile" -continuous-private -start-window=1 -max-windows=0 \
      -max-runtime=10m > "$profile_dir/timed.log" 2>&1; then
        cleanup_monitors
        tail -n 25 "$profile_dir/timed.log" >&2 || :
        fail "$profile timed run failed: see timed.log; later profiles NOT started"
    fi
    cleanup_monitors
    grep '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$profile_dir/timed.log" > "$profile_dir/result.txt" ||
      fail "$profile lacks a 10-minute terminal checkpoint report"
    printf '%s profile=%s timed-end\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$profile" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
    cat "$profile_dir/result.txt" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
done

printf 'FI BENCHMARK COMPLETE: all four isolated 10-minute runs finished; logs=%s\n' "$FI_BENCH_OUTPUT_ROOT" | tee -a "$FI_BENCH_OUTPUT_ROOT/SUMMARY.txt"
