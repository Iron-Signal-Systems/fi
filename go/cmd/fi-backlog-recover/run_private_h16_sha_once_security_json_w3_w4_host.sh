#!/bin/sh
# FI H16 W3-W4 SHA-once + Security JSON-boundary development candidate.
# Reuse the authenticated batch digest across the isolated private COW handoff.
# All record hashes, byte/record counts, row digests, and SQL gates remain.
# The accepted H16 source/runner, signed cache, seed, and real SoR stay untouched.
# Source runner: go/cmd/fi-backlog-recover/run_private_hash_h16_ab10_host.sh at bbe90168ed6807d348a9550a4a282fdce89c33d1.
# The relay executable guard is patched to the exact isolated cluster path
# (the proven fix already present in the accepted locally tested runner).
# One pinned H16 source, with SHA-once plus Security JSON-boundary overlay.
# Preserve the accepted field-leaf VACUUM policy and read-only host samples.
# No CPU profiler or Go GC tracing in the candidate to minimize observer cost.
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

case "${1:-}" in
    h16) hashmode=h16 ;;
    *) fail 'usage: sh run_private_h16_sha_once_security_json_w3_w4_host.sh h16' ;;
esac
[ "$#" -eq 1 ] || fail 'exactly one H16 argument required'
mode=candidate
name=clone-11-08-26
ddlref=dc556813d450f7ab79121d05e10e54c6d2732d01
ddlpath=go/cmd/fi-backlog-recover/testdata/private_field_insert_vacuum_candidate.sql
ref=b01ff0d8cb6559797de052f34b18bd84a395dc4c
h16ref=e47b5383e19140090d691b7c20e8d6ef6e0113fa
seed=/home/jwood/fi-window-bench-fieldpart-20261104T091019Z/W64
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root=/home/jwood/fi-window-bench-json2-$stamp
out=/var/tmp/fi-window-chunks-json2-$stamp
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
jexec -U jwood fi-dev sh -s "$root" "$seed" "$name" "$ref" "$mode" "$ddlref" "$ddlpath" "$h16ref" <<'JAIL'
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
h16ref=$8
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
# Overlay precisely two Go files from the pinned experiment commit onto the
# accepted optimized source; include the independent test file for an on-host
# unit gate. This avoids unrelated changes from the long-lived dev branch.
git -C "$repo" cat-file -e "$h16ref^{commit}" || fail 'H16 source commit missing'
for relpath in \
    go/cmd/fi-backlog-recover/main_freebsd.go \
    go/internal/recordingest/file_bulk_profiles.go \
    go/internal/recordingest/private_file_hash_h16_test.go; do
    git -C "$repo" show "$h16ref:$relpath" > "$src/$relpath" ||
        fail "cannot extract pinned H16 source $relpath"
done
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^(TestPrivateHashH16|TestFileBulkProfilesAreContextScoped|TestFIContentHashCopyChunk|TestHashCopyLatency)' -count=1) > "$root/h16-unit-tests.log" 2>&1 ||
    { cat "$root/h16-unit-tests.log" >&2; fail 'H16 unit tests failed'; }
printf 'FI HASH H16 GO TEST PASS pinned_overlay=%s\n' "$h16ref"


main="$src/go/cmd/fi-backlog-recover/main_freebsd.go"
relay="$src/go/cmd/fi-backlog-recover/optfield/relay.go"
[ "$(grep -Fc 'testStopAfterWindows > 2 || !continuousPrivate' "$main")" -eq 1 ] || fail 'optimized exact-window patch anchor changed'
[ "$(grep -Fc 'var profiles = []string{"K32", "K64"}' "$relay")" -eq 1 ] || fail 'optimized relay profile anchor changed'

# The original pinned CLI already accepts two-window durable-stop tests.
# Do not alter its stop-mode contract.
grep -Fq 'testStopAfterWindows > 2 || !continuousPrivate' "$main" ||
    fail 'pinned two-window stop-contract changed'

# The database is named clone-11-08-26, not K32. K32 still describes a
# genuine 32,768-source-record processing chunk, not the cluster identity.
sed 's/var profiles = \[\]string{"K32", "K64"}/var profiles = []string{"clone-11-08-26"}/' "$relay" > "$relay.new"
mv "$relay.new" "$relay"
grep -Fq 'var profiles = []string{"clone-11-08-26"}' "$relay" || fail 'relay single-cluster patch missing'

# The pinned relay rejects the hash10 fixture path under its older optfield-only
# prefix rule. Bind the jailed relay binary to THIS verified isolated cluster.
# Same correctness fix used by the accepted H16 run; no broadened executable path.
grep -Fq '!strings.HasPrefix(jailBinary,"/home/jwood/fi-window-bench-optfield-")' "$relay" ||
    fail 'pinned relay guard differs from reviewed source'
sed 's|!strings.HasPrefix(jailBinary,"/home/jwood/fi-window-bench-optfield-")|jailBinary != filepath.Join(clusterRoot,"fi-optfield-relay")|' "$relay" > "$relay.new"
mv "$relay.new" "$relay"
grep -Fq 'jailBinary != filepath.Join(clusterRoot,"fi-optfield-relay")' "$relay" ||
    fail 'private relay executable path guard patch missing'



# Trust reuse is available ONLY in the disposable historical source archive.
# Fail before starting the private PostgreSQL seed if the staged assets are
# missing, changed or compiled against a different source.
assets=/home/jwood/fi-h16-batch-once-assets
[ -d "$assets" ] && [ ! -L "$assets" ] || fail 'SHA-once assets directory missing'
for spec in \
  "fi_private_batch_hash_once_freebsd.go 704ad5ae6d93f036fc821724834747d35f5ab7d2" \
  "fi_private_batch_hash_once_test.go fc437741ab4d7ae4a45099c1aa45f85a19735f10" \
  "patch_private_batch_hash_once.go bff7343872bbca3c214bce0a79c92ec2b8039d0f"; do
    set -- $spec
    [ -f "$assets/$1" ] && [ ! -L "$assets/$1" ] || fail "SHA-once asset absent: $1"
    [ "$(git hash-object "$assets/$1")" = "$2" ] ||
        fail "SHA-once asset changed: $1"
done
cp "$assets/fi_private_batch_hash_once_freebsd.go" \
    "$src/go/internal/recordingest/private_batch_hash_once.go"
cp "$assets/fi_private_batch_hash_once_test.go" \
    "$src/go/internal/recordingest/private_batch_hash_once_test.go"
(cd "$src/go" && GOTOOLCHAIN=auto go run "$assets/patch_private_batch_hash_once.go" "$src") ||
    fail 'SHA-once pinned-source patch rejected'
(cd "$src/go" && gofmt -w \
    ./internal/recordingest/private_batch_hash_once.go \
    ./internal/recordingest/private_batch_hash_once_test.go \
    ./internal/recordingest/postgres_ingest.go \
    ./internal/recordingest/backlog_typed_window_postgres.go) ||
    fail 'SHA-once Go formatting failed'
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^(TestPrivateBatchHashOnce|TestPrivateHashH16|TestFIContentHashCopyChunk)' \
    -count=1) > "$root/hash-once-go-tests.log" 2>&1 ||
    { cat "$root/hash-once-go-tests.log" >&2; fail 'private SHA-once tests failed'; }
printf 'FI HASH ONCE GO GATE PASS pinned_source=true private_tests=true historical_ref=%s\n' "$ref"

# Private Security JSON candidate: source patch and independent equivalence tests
# MUST succeed before the signed seed or private PostgreSQL clone is touched.
jsonassets=/home/jwood/fi-h16-json-boundary-assets
[ -d "$jsonassets" ] && [ ! -L "$jsonassets" ] || fail 'JSON boundary assets missing'
for spec in \
 "fi_private_security_payload_boundary.go 7982863f24470d839763221de1940a06233e27d7" \
 "fi_private_security_payload_boundary_test.go 64932172d69750eec0d1d523beafe15d92df3785" \
 "patch_private_security_payload_boundary.go fddad808d77194b9f71817a4d7745b50ea8e10fe"; do
    set -- $spec
    [ -f "$jsonassets/$1" ] && [ ! -L "$jsonassets/$1" ] ||
        fail "missing private Security JSON asset: $1"
    [ "$(git hash-object "$jsonassets/$1")" = "$2" ] ||
        fail "Security JSON asset blob differs: $1"
done
cp "$jsonassets/fi_private_security_payload_boundary.go" \
    "$src/go/internal/recordingest/private_security_payload_boundary.go"
cp "$jsonassets/fi_private_security_payload_boundary_test.go" \
    "$src/go/internal/recordingest/private_security_payload_boundary_test.go"
(cd "$src/go" && GOTOOLCHAIN=auto go run \
    "$jsonassets/patch_private_security_payload_boundary.go" "$src") ||
    fail 'Security JSON boundary patch rejected'
(cd "$src/go" && gofmt -w \
    ./internal/recordingest/private_security_payload_boundary.go \
    ./internal/recordingest/private_security_payload_boundary_test.go \
    ./internal/recordingest/security_single_pass_candidate.go) ||
    fail 'private JSON boundary Go formatting failed'
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^(TestPrivateSecurityPayloadBoundary|TestSinglePassSecurity|TestFIJSONOneShot)' \
    -count=1) > "$root/security-json-tests.log" 2>&1 ||
    { cat "$root/security-json-tests.log" >&2; fail 'Security JSON equivalence failed'; }
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^$' -bench '^BenchmarkPrivateSecurityPayloadBoundary$' \
    -benchtime=1s -count=2 -benchmem) \
    > "$root/security-json-benchmark.log" 2>&1 ||
    { cat "$root/security-json-benchmark.log" >&2; fail 'Security JSON microbenchmark failed'; }
printf 'FI SECURITY JSON BOUNDARY GO GATE PASS strict_decode=unchanged malformed_equivalence=12000 original_SHA_once=retained\n'

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
[ "$(qclone "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 1024 ] || fail 'private clone max WAL not 1GiB'
[ "$(qclone "SHOW wal_buffers")" = 4MB ] || fail 'private clone wal_buffers not 4MB'
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
printf 'FI CLONE PROVISION PASS name=%s port=55981 ref=%s windows=3 source_records=390387 signed_fields=4838850 max_wal_size_mb=1024 wal_buffers_mb=4\n' "$name" "$ref"
JAIL

recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || fail 'new binaries missing'
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] || fail 'recovery binary hash mismatch'
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] || fail 'relay binary hash mismatch'

mkdir -m 700 "$out" "$out/$name" "$out/$name/private"
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI PRIVATE H16 SIGNED BATCH HASH ONCE: W3-W4
experiment=private_h16_sha_once_security_json_w3_w4
source_commit=$ref
hash_overlay_commit=$h16ref
hash_variant=$hashmode
vacuum_variant=$mode
candidate_ddl_commit=$ddlref
baseline_commit=9e0e6e236c95d9af91bc67a065efb47ce2318579
source_instrumentation=pinned_H16_plus_COW_SHA_once_plus_Security_JSON_boundary
vacuum_experiment_scope=only_new_private_security_field_leaves
PostgreSQL_global_autovacuum=unchanged
manual_vacuum_after_timed_replay=not_part_of_two_window_candidate
optimizations=reusable_security_event_scope_source_file_rows_and_envelope_scan
GODEBUG_gctrace=disabled_for_SHA_once_trial
process_rusage=FreeBSD_time_l_peak_RSS
CPU_pprof_overhead=none
checkpoint_log_override=none
verified_cache_handoff=clone_from_receipt_bound_authenticated_cache
batch_SHA_recomputed_during_private_ingest=no_for_trusted_COW
typed_record_SHA256=unchanged
metadata_identity_check=both_before_and_after_ingest
postrun_signed_byte_readback=required
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
wal_buffers_mb=4
cpu_profile=off
batch_hash_once=private_verified_COW_only
security_json_boundary=lightweight_with_legacy_fallback
fsync=on
synchronous_commit=on
full_page_writes=on
start_window_index=3
number_of_new_windows=2
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
# The Go recovery worker uses the candidate private SHA-once code; host monitors are passive.
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
  'last_durable_window',(SELECT max(window_index) FROM fi_recovery.typed_window),
  'io',(SELECT coalesce(json_agg(row_to_json(i)),'[]'::json) FROM pg_stat_io i),
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



printf 'FI H16 HASH ONCE START source=real_signed_8399 start_index=3 windows=2 wal_limit=1GB wal_buffers=4MB\n' |
    tee "$out/SUMMARY.txt"
if ! /usr/bin/time -l "$recover" -private-hash-h16 \
    -source=iss-fs-22a.iss.local \
    -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
    -postgres="host=$out/pg-$name port=55981 user=fi_ingest dbname=fi sslmode=disable" \
    -custody-root=/var/db/fi/custody/generation \
    -recorded-root=/var/db/fi/custody/recorded \
    -source-namespaces=false -private-root="$out/$name/private" \
    -private-writes -private-field-partitions \
    -security-profile=P3 -file-profile=F3 -window-profile=W128 \
    -processing-chunk-records=32768 -continuous-private -start-window=3 \
    -max-windows=0 -max-runtime=0 -test-stop-after-windows=2 \
    -deferred-verified-clone -verified-cache-root="$cache" \
    > "$out/$name/recover.log" 2>&1; then
    tail -n 100 "$out/$name/recover.log" >&2 || :
    fail 'private two-window SHA-once replay failed'
fi
stop_host_monitors
snapshot_pg after
snapshot_relations after
log="$out/$name/recover.log"
grep -q '^FI PRIVATE EXACT WINDOW STOP start=3 windows=2 last=4 records=259178 ' "$log" ||
    fail 'durable exact two-window stop failed'
[ "$(grep -c '^FI REAL BACKLOG DURABLE ' "$log")" -eq 2 ] ||
    fail 'expected exactly two durable windows'
[ "$(grep -c '^FI PRIVATE STAGE PROFILE ' "$log")" -eq 2 ] ||
    fail 'expected two stage profiles'
[ "$(grep -c '^FI PRIVATE BATCH HASH ONCE window=' "$log")" -eq 2 ] ||
    fail 'SHA-once evidence counters absent'
reused=$(awk '
    /^FI PRIVATE BATCH HASH ONCE window=/ {
        for (i=1;i<=NF;i++) if ($i ~ /^trusted_batches=/) {
            split($i,parts,"="); count += parts[2]+0
        }
    }
    END {print count+0}
' "$log")
[ "$reused" = 111 ] || fail "expected SHA-once evidence reuse in all 111 signed W3-W4 batches; got $reused"
printf 'FI H16 HASH ONCE PROOF PASS trusted_batches=%s rehashed_batch_data=0 per_record_hashes=unchanged\n' "$reused" |
    tee -a "$out/SUMMARY.txt"
state=$(sql "SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' ||
       max(window_index)::text FROM fi_recovery.typed_window")
[ "$state" = '5|649565|4' ] || fail "private SQL checkpoint failed: $state"
new_records=$(sql "SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index BETWEEN 3 AND 4")
[ "$new_records" = 259178 ] || fail "new signed W3-W4 records differ: $new_records"
integrity=$(sql "
SELECT CASE WHEN
  (SELECT count(*) FROM fi_recovery.verified_artifact_window)=5
  AND (SELECT count(*) FROM fi_recovery.source_window)=5
  AND (SELECT count(*) FROM fi_recovery.typed_window)=5
  AND (SELECT count(*) FROM fi_recovery_projection.source_record)=649565
  AND (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field)=8111457
  AND (SELECT count(*) FROM fi.recorded_generation)=0
  AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0
  AND NOT EXISTS (
    SELECT 1 FROM fi_recovery.typed_window t
    JOIN fi_recovery.source_window s USING(receipt_sha256,window_index)
    JOIN fi_recovery.verified_artifact_window a USING(receipt_sha256,window_index)
    WHERE t.descriptor_sha256<>s.descriptor_sha256 OR t.descriptor_sha256<>a.descriptor_sha256)
  THEN 'PASS' ELSE 'FAIL' END")
[ "$integrity" = PASS ] || fail 'signed private SQL integrity failed'
printf 'FI H16 HASH ONCE SQL INTEGRITY PASS checkpoint=%s new_records=%s authoritative=0 accepted=0\n' "$state" "$new_records" |
    tee -a "$out/SUMMARY.txt"
expected=$(sql "SELECT coalesce(sum(end_batch-start_batch),0)::text
  FROM fi_recovery.verified_artifact_window WHERE window_index BETWEEN 3 AND 4")
checked=0
for directory in "$out/$name/private"/receipt-*/window-*; do
    [ -d "$directory" ] || fail 'signed window directory absent'
    receipt=$(basename "$(dirname "$directory")")
    for batch in "$directory"/batch-*.data; do
        [ -f "$batch" ] || fail 'signed batch absent'
        filename=$(basename "$batch")
        original="$cache/$receipt/$filename"
        [ -f "$original" ] || fail "cached original missing $filename"
        cmp -s "$batch" "$original" || fail "signed data differs $filename"
        manifest=$(printf '%s\n' "$batch" | sed 's/\.data$/.manifest/')
        origmanifest=$(printf '%s\n' "$original" | sed 's/\.data$/.manifest/')
        cmp -s "$manifest" "$origmanifest" || fail "signed manifest differs $filename"
        checked=$((checked+1))
    done
done
[ "$checked" -gt 0 ] && [ "$checked" -eq "$expected" ] && [ "$checked" -eq "$reused" ] ||
    fail "signed readback count mismatch $checked/$expected trusted=$reused"
printf 'FI H16 HASH ONCE SIGNED READBACK PASS batch_files=%s byte_identical=true manifests_identical=true\n' "$checked" |
    tee -a "$out/SUMMARY.txt"
grep '^FI PRIVATE STAGE PROFILE ' "$log" > "$out/$name/STAGES.txt"
grep '^FI PRIVATE BATCH HASH ONCE ' "$log" > "$out/$name/HASH_ONCE.txt"
grep '^FI REAL BACKLOG DURABLE ' "$log" > "$out/$name/WINDOWS.txt"
grep '^FI PRIVATE EXACT WINDOW STOP ' "$log" > "$out/$name/RESULT.txt"
printf 'FI H16 HASH ONCE ACCEPTED windows=2 new_records=259178 trusted_batches=111 authoritative=0 accepted=0\n' |
    tee -a "$out/SUMMARY.txt"
bundle="$out/fi-h16-sha-once-json-w3-w4-$stamp.tar.gz"
(
 cd "$out" || exit 1
 tar -czf "$bundle" RUN_MANIFEST.txt SUMMARY.txt \
   "$name/HASH_ONCE.txt" "$name/STAGES.txt" "$name/WINDOWS.txt" "$name/RESULT.txt" \
   "$name/pg_settings.txt" "$name/pg_before.txt" "$name/pg_after.txt" \
   "$name/pg_stat_wal_before.jsonl" "$name/pg_stat_wal_after.jsonl" \
   "$name/pg_stat_checkpointer_before.jsonl" "$name/pg_stat_checkpointer_after.jsonl" \
   "$name/pg_stat_io_before.jsonl" "$name/pg_stat_io_after.jsonl" \
   "$name/relations_before.jsonl" "$name/relations_after.jsonl" \
   "$name/pg_5sec_samples.jsonl" "$name/host-iostat.txt" "$name/host-vmstat.txt"
) || fail 'SHA-once diagnostics bundle creation failed'
[ -s "$bundle" ] || fail 'SHA-once diagnostics bundle missing'
printf 'FI H16 HASH ONCE METRICS BUNDLE PASS path=%s\n' "$bundle"
