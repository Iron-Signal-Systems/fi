#!/bin/sh
# FI W512/2GiB: build pinned Candidate A and establish ONE NEW private signed seed (window 0).
 # Fresh W512 signed source seed; no inherited W128 checkpoint descriptors.
 # Two preparation workers are preserved for the later W512 private replay.
# FI H16 (frozen 89.931s source) plus private combined Security/coverage buffering.
# Reuse the authenticated batch digest across the isolated private COW handoff.
# All record hashes, byte/record counts, row digests, and SQL gates remain.
# The accepted H16 source/runner, signed cache, seed, and real SoR stay untouched.
# Source runner: go/cmd/fi-backlog-recover/run_private_hash_h16_ab10_host.sh at bbe90168ed6807d348a9550a4a282fdce89c33d1.
# The relay executable guard is patched to the exact isolated cluster path
# (the proven fix already present in the accepted locally tested runner).
# Frozen H16 SHA-once overlay plus isolated Security JSON-once source patch.
# Preserve the accepted field-leaf VACUUM policy and read-only host samples.
# No CPU profiler or Go GC tracing in the candidate to minimize observer cost.
# Exactly one private PostgreSQL fixture: clone-w512-2g.
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
    *) fail 'usage: sh run_private_h16_parallel_a_w512_seed_host.sh h16' ;;
esac
[ "$#" -eq 1 ] || fail 'exactly one H16 argument required'
mode=candidate
name=clone-w512-2g
combinedref=58f5d7341ba728b4696d05ba31199cb38226befc
parallelref=54e7ad82abb9e90402ee90a15f6a726f97e7ef0a
w512ref=f0617de20f61b5f8826a4e2b0a38316b47ec2455
ddlref=dc556813d450f7ab79121d05e10e54c6d2732d01
ddlpath=go/cmd/fi-backlog-recover/testdata/private_field_insert_vacuum_candidate.sql
ref=b01ff0d8cb6559797de052f34b18bd84a395dc4c
h16ref=e47b5383e19140090d691b7c20e8d6ef6e0113fa
seed=UNUSED_NO_W128_SEED_ACCESS
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root=/home/jwood/fi-window-bench-w512-$stamp
out=/var/tmp/fi-window-chunks-h16-w512-seed-$stamp
# Fail before touching the seed if either AF_UNIX socket would exceed FreeBSD sun_path.
private_socket="$root/$name/socket/.s.PGSQL.55983"
relay_socket="$out/pg-$name/.s.PGSQL.55983"
[ "${#private_socket}" -le 103 ] || fail "private socket path too long: ${#private_socket}"
# The historical, pinned relay strictly allows only this output subtree.
# Keep the relay's original allowlist unchanged; reject a bad runner path
# before provisioning a disposable database or compiling any source.
case "$out" in
    /var/tmp/fi-window-chunks-*) ;;
    *) fail 'output root rejected by historical FI PostgreSQL relay allowlist' ;;
esac
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
[ -d "$jailroot" ] || fail 'fi-dev jail filesystem missing'
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
    pgwatchpid=
}
cleanup() {
    code=$?
    trap - 0 1 2 15
    stop_host_monitors
    if [ -n "$relaypid" ]; then
        kill -TERM "$relaypid" 2>/dev/null || :
        wait "$relaypid" 2>/dev/null || :
    fi
    for data in "$root/$name/data"; do
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
jexec -U jwood fi-dev sh -s "$root" "$seed" "$name" "$ref" "$mode" "$ddlref" "$ddlpath" "$h16ref" "$combinedref" "$parallelref" "$w512ref" <<'JAIL'
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
combinedref=$9
parallelref=${10}
w512ref=${11}
repo=/home/jwood/fi-deferred-experiment
combinedrepo=/home/jwood/src/fi
src="$root/optimized-source"
pgroot="$root/$name"
socket="$pgroot/socket"
port=55983
[ "$(id -un)" = jwood ] || fail 'expected jwood in fi-dev'
[ "$(sysctl -n security.jail.jailed)" -eq 1 ] || fail 'not jailed'
[ "$(psql --version)" = 'psql (PostgreSQL) 18.6' ] || fail 'unexpected PostgreSQL version'
# Respect the source go.mod (Go 1.27.3); permit the jailed jwood Go toolchain
# to select a version via the configured Go proxy, before touching seed or clone.
(cd "$repo/go" && GOTOOLCHAIN=auto go version) || fail 'Go 1.27.3 toolchain is unavailable in fi-dev'
[ ! -e "$root" ] || fail 'fixture path already exists'
git -C "$repo" cat-file -e "$ref^{commit}" || fail 'pinned optimized source commit is not available locally'
# Preflight all historical mixed/dependency assets BEFORE allocating the
# fixture or restoring PostgreSQL. Their exact blob SHA-1 is an immutable
# source-pin invariant; do not accept an older local staged test file.
git -C "$combinedrepo" cat-file -e "$combinedref^{commit}" ||
  fail 'FI H16 combined source pin missing: fetch the development branch in fi-dev'
for blob in \
 a1170aa8f7e3e40ee8f4702a54c6ced006386a23 \
 a841233fcaa176b49448434795141263ca163bae \
 3f29c387c190ffdf8c6a331ceb4dc6a2b8d6609a \
 089bbf0af7ef50d1c5815cbd59e13833068236c2 \
 c9f4466364c1a5b6b1a0ae1f7b7f4dfbdf344866 \
 ec72725173fd97e961b82de1e5890b6ed47654f1 \
 3548edb0945eb7213974b0edfa78e6f21efbf8f7 \
 b081f1c928e217d82e37ebbfb48025a863fbe3a7; do
    git -C "$combinedrepo" cat-file -e "$blob^{blob}" ||
      fail "FI H16 pinned source asset unavailable: $blob (fetch branch in fi-dev)"
done
printf 'FI H16 PINNED ASSET PREFLIGHT PASS mixed=3 dependency=5 source=git_objects staging=disposable\n'
# Candidate A source is pinned by immutable Git SHA objects. Fail BEFORE
# the first private PostgreSQL seed clone or SQL writer.
git -C "$combinedrepo" cat-file -e "$parallelref^{commit}" ||
  fail 'FI Candidate A exact reviewed source commit missing; fetch dev branch'
for blob in a31d62e95b6a37a0aa2ca739a6ca00e0cb95e071 d946c69e0a580cb0e959654116ed7ebbe2401c37 e65aaa7cddd1beacd724a697af06dc5da53f7594; do
  git -C "$combinedrepo" cat-file -e "$blob^{blob}" ||
    fail "FI Candidate A signed-source prep asset missing: $blob"
done
printf 'FI CANDIDATE A PINNED SOURCE PREFLIGHT PASS workers=2 assets=3 writer=1\n'

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

# Verify the original pinned two-window guard before applying source overlays.
# After Candidate A overlays, only the DISPOSABLE archive is extended to N=10.
grep -Fq 'testStopAfterWindows > 2 || !continuousPrivate' "$main" ||
    fail 'pinned two-window stop-contract changed'

# The database is named clone-w512-2g, not K32. K32 still describes a
# genuine 32,768-source-record processing chunk, not the cluster identity.
sed 's/var profiles = \[\]string{"K32", "K64"}/var profiles = []string{"clone-w512-2g"}/' "$relay" > "$relay.new"
mv "$relay.new" "$relay"
grep -Fq 'var profiles = []string{"clone-w512-2g"}' "$relay" || fail 'relay single-cluster patch missing'

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

# Directly install the exact reviewed Security JSON-once source and its
# tests into the disposable H16 archive. No Go source patcher or wrapper.
# The normal SHA-once input and transaction code stay unchanged.
jsonassets=/home/jwood/fi-h16-json-once-assets
[ -d "$jsonassets" ] && [ ! -L "$jsonassets" ] || fail 'JSON-once source assets missing'
for spec in \
 "security_single_pass_candidate.go 9d7ba5fd99dc79d859023885810a95e869b8c1f1" \
 "security_json_once_test.go d8b7603774f91209471ce42e311caf45f3d3fd9e" \
 "security_json_once_signed_cache_test.go e2926386e039f05ce52d9cd44b75c56e81133d53"; do
    set -- $spec
    [ -f "$jsonassets/$1" ] && [ ! -L "$jsonassets/$1" ] ||
        fail "JSON-once asset missing: $1"
    [ "$(git hash-object "$jsonassets/$1")" = "$2" ] ||
        fail "JSON-once asset changed: $1"
done
cp "$jsonassets/security_single_pass_candidate.go" \
    "$src/go/internal/recordingest/security_single_pass_candidate.go"
cp "$jsonassets/security_json_once_test.go" \
    "$src/go/internal/recordingest/security_json_once_test.go"
cp "$jsonassets/security_json_once_signed_cache_test.go" \
    "$src/go/internal/recordingest/security_json_once_signed_cache_test.go"
(cd "$src/go" && gofmt -w \
    ./internal/recordingest/security_single_pass_candidate.go \
    ./internal/recordingest/security_json_once_test.go \
    ./internal/recordingest/security_json_once_signed_cache_test.go) ||
    fail 'JSON-once source formatting failed'
# Apply private-only pinned mixed buffering after SHA-once and JSON-once.
# Materialize exact immutable original Git objects into disposable fixture.
# Fail BEFORE any SQL replay when source or test anchors diverge.
# Build the exact original mixed-buffer patch assets from immutable Git
# objects IN THIS disposable source fixture. Do not trust or overwrite
# previously staged /home/jwood/*-assets files, which can belong to an
# older experiment and may have different test hashes.
mixedassets="$root/h16-mixed-assets"
mkdir -m 700 "$mixedassets" || fail 'cannot create disposable mixed assets'
for spec in \
 "private_mixed_family_buffers.go a1170aa8f7e3e40ee8f4702a54c6ced006386a23" \
 "private_mixed_family_buffers_test.go a841233fcaa176b49448434795141263ca163bae" \
 "patch_mixed_family_buffers.go 3f29c387c190ffdf8c6a331ceb4dc6a2b8d6609a"; do
    set -- $spec
    git -C "$combinedrepo" cat-file -e "$2^{blob}" ||
      fail "pinned mixed Git object not fetched: $1 ($2)"
    git -C "$combinedrepo" cat-file blob "$2" > "$mixedassets/$1" ||
      fail "cannot materialize pinned mixed asset: $1"
    [ "$(git -C "$combinedrepo" hash-object "$mixedassets/$1")" = "$2" ] ||
      fail "pinned mixed Git object hash mismatch: $1"
done
cp "$mixedassets/private_mixed_family_buffers.go" "$src/go/internal/recordingest/private_mixed_family_buffers.go"
cp "$mixedassets/private_mixed_family_buffers_test.go" "$src/go/internal/recordingest/private_mixed_family_buffers_test.go"
(cd "$src/go" && GOTOOLCHAIN=auto go run "$mixedassets/patch_mixed_family_buffers.go" "$src") ||
    fail 'mixed buffer source patch rejected the pinned H16 code'
# Apply the additional pinned dependency-buffer experiment only to the
# disposable H16 code archive, after the original mixed-family patch.
# The pinned dependency-buffer tests and patcher MUST be the exact
# reviewed Git blobs, not leftovers from a prior staged experiment. An old
# private_dependency_buffers_test.go caused the 2026-11-13 12:19Z stop.
depassets="$root/h16-dependency-assets"
mkdir -m 700 "$depassets" || fail 'cannot create disposable dependency assets'
for spec in \
 "private_dependency_buffers.go 089bbf0af7ef50d1c5815cbd59e13833068236c2" \
 "private_dependency_buffers_test.go c9f4466364c1a5b6b1a0ae1f7b7f4dfbdf344866" \
 "private_mixed_family_buffers.go ec72725173fd97e961b82de1e5890b6ed47654f1" \
 "private_mixed_family_buffers_test.go 3548edb0945eb7213974b0edfa78e6f21efbf8f7" \
 "patch_private_dependency_buffers.go b081f1c928e217d82e37ebbfb48025a863fbe3a7"; do
    set -- $spec
    git -C "$combinedrepo" cat-file -e "$2^{blob}" ||
      fail "pinned dependency Git object not fetched: $1 ($2)"
    git -C "$combinedrepo" cat-file blob "$2" > "$depassets/$1" ||
      fail "cannot materialize pinned dependency asset: $1"
    [ "$(git -C "$combinedrepo" hash-object "$depassets/$1")" = "$2" ] ||
      fail "pinned dependency Git object hash mismatch: $1"
done
cp "$depassets/private_dependency_buffers.go" "$src/go/internal/recordingest/private_dependency_buffers.go"
cp "$depassets/private_dependency_buffers_test.go" "$src/go/internal/recordingest/private_dependency_buffers_test.go"
cp "$depassets/private_mixed_family_buffers.go" "$src/go/internal/recordingest/private_mixed_family_buffers.go"
cp "$depassets/private_mixed_family_buffers_test.go" "$src/go/internal/recordingest/private_mixed_family_buffers_test.go"
(cd "$src/go" && GOTOOLCHAIN=auto go run "$depassets/patch_private_dependency_buffers.go" "$src") ||
  fail 'dependency patch rejected pinned H16 source'

# Apply ONLY the two original-H16 K32 buffer-drain edits from a precise
# development commit. All ordinary H16 source, COPY, decoder, SHA-once and
# PostgreSQL window transaction logic remain historically pinned.
git -C "$combinedrepo" cat-file -e "$combinedref^{commit}" ||
  fail 'pinned H16 combined-buffer patch unavailable; fetch branch in fi-dev first'
patcher_rel=go/cmd/fi-backlog-recover/patchers/h16_combined_buffer/main.go
test_rel=go/internal/recordingest/h16_combined_family_buffers_test.go
mkdir -p "$src/go/cmd/fi-backlog-recover/patchers/h16_combined_buffer" ||
  fail 'could not create isolated H16 patcher directory'
git -C "$combinedrepo" show "$combinedref:$patcher_rel" > "$src/$patcher_rel" ||
  fail 'cannot recover exact H16 combined patcher from branch commit'
git -C "$combinedrepo" show "$combinedref:$test_rel" > "$src/$test_rel" ||
  fail 'cannot recover exact H16 combined-buffer tests from branch commit'
(cd "$src/go" && GOTOOLCHAIN=auto go run "./cmd/fi-backlog-recover/patchers/h16_combined_buffer/main.go" "$src") ||
  fail 'frozen H16 combined-buffer source patch refused historical code'
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest -run '^TestH16Combined' -count=1 -v) \
  > "$root/h16-combined-test.log" 2>&1 ||
  { cat "$root/h16-combined-test.log" >&2; fail 'H16 combined-buffer unit gates failed'; }
printf 'FI H16 COMBINED BUFFER SOURCE GATE PASS source=frozen_89.931s k32_partial_drains=disabled w128_tx=unchanged\n'
# Add exactly one private two-worker preparation overlay after the frozen
# combined-buffer patch. Do NOT edit the authoritative FI source worktree.
parallelpatch=go/cmd/fi-backlog-recover/patchers/h16_parallel_a/main.go
mkdir -p "$src/go/cmd/fi-backlog-recover/patchers/h16_parallel_a" \
  "$src/go/cmd/fi-backlog-recover/testdata/h16-parallel-a" ||
  fail 'Candidate A disposable source asset directories unavailable'
for spec in \
 "a31d62e95b6a37a0aa2ca739a6ca00e0cb95e071 $parallelpatch" \
 "d946c69e0a580cb0e959654116ed7ebbe2401c37 go/cmd/fi-backlog-recover/testdata/h16-parallel-a/private_parallel_preparation.go" \
 "e65aaa7cddd1beacd724a697af06dc5da53f7594 go/cmd/fi-backlog-recover/testdata/h16-parallel-a/private_parallel_preparation_test.go"; do
  set -- $spec
  git -C "$combinedrepo" show "$parallelref:$2" > "$src/$2" ||
    fail "Candidate A pinned source file cannot be recovered: $2"
  [ "$(git -C "$combinedrepo" hash-object "$src/$2")" = "$1" ] ||
    fail "Candidate A pinned source blob mismatch: $2"
done
(cd "$src/go" && GOTOOLCHAIN=auto go run \
  ./cmd/fi-backlog-recover/patchers/h16_parallel_a/main.go "$src") ||
  fail 'Candidate A exact-source patch refused frozen H16'
# The historical Go CLI permits only 1 or 2 exact-stop windows. Extend it
# inside THIS disposable archived source only, retaining all other restrictions.
# This is the same narrowly scoped N=10 condition used by the historical H16
# ten-window runner. Never change the active source tree or authoritative SoR.
[ "$(grep -Fc 'testStopAfterWindows > 2 || !continuousPrivate' "$main")" -eq 1 ] ||
  fail 'Candidate A exact-stop Go guard changed after source overlays'
sed 's/testStopAfterWindows > 2 || !continuousPrivate/(testStopAfterWindows > 2 \&\& testStopAfterWindows != 10) || !continuousPrivate/' "$main" > "$main.ten" ||
  fail 'disposable ten-window guard patch failed'
mv "$main.ten" "$main" || fail 'cannot install ten-window guard in disposable source'
[ "$(grep -Fc 'testStopAfterWindows != 10' "$main")" -eq 1 ] ||
  fail 'disposable Go exact-stop N=10 proof missing'
printf 'FI PRIVATE EXACT STOP 10 GO SOURCE GATE PASS only_disposable=true allowed=1,2,10\n'
(cd "$src/go" && gofmt -w \
  ./internal/recordingest/private_parallel_preparation.go \
  ./internal/recordingest/private_parallel_preparation_test.go \
  ./internal/recordingest/postgres_ingest.go \
  ./cmd/fi-backlog-recover/main_freebsd.go) ||
  fail 'Candidate A source formatting failed'
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
  -run '^(TestPrivateParallelA|TestH16Combined|TestPrivateDependency|TestPrivateMixed)' \
  -count=1 -timeout=60s -v) > "$root/parallel-a-go-tests.log" 2>&1 ||
  { cat "$root/parallel-a-go-tests.log" >&2; fail 'Candidate A two-worker regression tests failed'; }
printf 'FI H16 CANDIDATE A GO GATE PASS workers=2 original_W128=true signed_order=true no_second_sql_writer=true\n'

(cd "$src/go" && gofmt -w \
  ./internal/recordingest/private_dependency_buffers.go \
  ./internal/recordingest/private_dependency_buffers_test.go \
  ./internal/recordingest/private_mixed_family_buffers.go \
  ./internal/recordingest/postgres_ingest.go \
  ./internal/recordingest/backlog_typed_chunks.go \
  ./internal/recordingest/backlog_typed_window_postgres.go \
  ./cmd/fi-backlog-recover/main_freebsd.go) || fail 'dependency gofmt failed'
for check in \
 'flushPrivateDependencies(ctx, tx, sourceID, pendingDependencies, profile)' \
 'privateDependencyAppend(pendingDependencies, pendingDependencyBytes,' \
 'privateDependencyBuffersEnabled(ctx)' \
 'FI PRIVATE DEPENDENCY BUFFER PROOF'; do
    grep -Fq "$check" "$src/go/internal/recordingest/"*.go ||
      fail "dependency source wiring missing: $check"
done
grep -Fq 'recordingest.WithPrivateDependencyBuffers(ctx)' "$src/go/cmd/fi-backlog-recover/main_freebsd.go" ||
  fail 'dependency CLI context not wired'
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
  -run '^(TestPrivateDependency|TestPrivateMixed|TestMixedBulk|TestUSNBoundaryLegacyAndCaptureContracts|TestUSNCaptureBindingScopeSourceGenerationAndCounts)' -count=1 -v) \
  > "$root/dependency-buffer-go-tests.log" 2>&1 ||
  { cat "$root/dependency-buffer-go-tests.log" >&2; fail 'dependency/mixed regression tests failed'; }
printf 'FI PRIVATE DEPENDENCY BUFFER GO GATE PASS source_wired=true signed_source_order=true coverage_independent=true\n'

(cd "$src/go" && gofmt -w \
 ./internal/recordingest/private_mixed_family_buffers.go \
 ./internal/recordingest/private_mixed_family_buffers_test.go \
 ./internal/recordingest/postgres_ingest.go \
 ./internal/recordingest/backlog_typed_chunks.go \
 ./internal/recordingest/file_source_bulk.go \
 ./cmd/fi-backlog-recover/main_freebsd.go) || fail 'mixed buffer gofmt failed'
for check in \
 'decision := securityFileFlushBeforeKind(ctx, prepared.Record.RecordKind)' \
 'bulkSourceIDsAreContiguousSingleBatch(batchIDs, ordinals)' \
 'fileOrdinalInvalidForBatch(ctx, item.ordinal, pending[i-1].ordinal)'; do
  grep -Fq "$check" "$src/go/internal/recordingest/"*.go ||
      fail "mixed buffer function missing: $check"
done
grep -Fq 'recordingest.WithPrivateMixedFamilyBuffers(ctx)' "$src/go/cmd/fi-backlog-recover/main_freebsd.go" ||
    fail 'mixed buffer CLI selector is missing'
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^(TestPrivateMixed|TestMixedBulk)' -count=1 -v) > "$root/mixed-buffer-go-tests.log" 2>&1 ||
    { cat "$root/mixed-buffer-go-tests.log" >&2; fail 'mixed buffer or source ID tests failed'; }
printf 'FI PRIVATE MIXED BUFFER GO GATE PASS active_ingest=true exact_keys=true usn_fences=true\n'



(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^(TestSecurityJSONOnce|TestSinglePassSecurity|TestFIJSONOneShot|TestPrivateBatchHashOnce|TestSecurityEventReusableCOPY|TestSecurityScopeReusableCOPY|TestSourceRecordReusableCOPY)' \
    -count=1) > "$root/json-once-go-tests.log" 2>&1 ||
    { cat "$root/json-once-go-tests.log" >&2; fail 'JSON-once strict equivalence tests failed'; }
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^$' -bench '^(BenchmarkSecurityJSONOnceWholeRecord|BenchmarkSecuritySourceEnvelopeAndPayloadOnePass|BenchmarkSecurityEventCOPYRowsLegacyVsReusable|BenchmarkSecurityScopeCOPYRowsLegacyVsReusable|BenchmarkSecuritySourceRecordCOPYLegacyVsReusable|BenchmarkFileSourceRecordCOPYLegacyVsReusable)$' \
    -benchtime=1s -count=2 -benchmem) > "$root/json-once-benchmark.log" 2>&1 ||
    { cat "$root/json-once-benchmark.log" >&2; fail 'JSON-once microbenchmark failed'; }
printf 'FI SECURITY JSON ONCE GO GATE PASS source=exact_reviewed_blob strict_decoder=unchanged nested_scope_version_test=true seeded_mutations=12000 no_explicit_json_valid_checks=true\n'
(cd "$src/go" && GOTOOLCHAIN=auto go test -c \
    -o "$root/fi-security-json-preflight.test" ./internal/recordingest) \
    > "$root/security-json-preflight-build.log" 2>&1 ||
    { cat "$root/security-json-preflight-build.log" >&2; fail 'Security JSON preflight build failed'; }
sha256 -q "$root/fi-security-json-preflight.test" > "$root/fi-security-json-preflight.sha256"

# W512 source is patched AFTER the pinned SHA-once/JSON-once/H16/Candidate A
# gates, and ONLY in the disposable archive.
w512patch=go/cmd/fi-backlog-recover/patchers/w512_2g/main.go
w512test=go/internal/recordingest/backlog_window_plan_w512_test.go
mkdir -p "$src/go/cmd/fi-backlog-recover/patchers/w512_2g"
for spec in \
  "b63c4674158691b10473641ac5c8ab660118d77a $w512patch" \
  "7a2049a3a62464e336f33387877bf072dfd6ec55 $w512test"; do
  set -- $spec
  git -C "$combinedrepo" show "$w512ref:$2" > "$src/$2" ||
    fail "W512 pinned Go asset not available: $2"
  [ "$(git -C "$combinedrepo" hash-object "$src/$2")" = "$1" ] ||
    fail "W512 Go asset changed: $2"
done
(cd "$src/go" && GOTOOLCHAIN=auto go run "./cmd/fi-backlog-recover/patchers/w512_2g/main.go" "$src") ||
  fail 'W512 disposable Go source overlay failed'
(cd "$src/go" && gofmt -w ./cmd/fi-backlog-recover/main_freebsd.go \
    ./internal/recordingest/backlog_continuous_private.go \
    ./internal/recordingest/backlog_stream_load.go \
    ./internal/recordingest/backlog_window_plan_w512_test.go) ||
  fail 'W512 Go source formatting failed'
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^(TestBacklogWindowsW512TwoGiB|TestBacklogWindows128K|TestPrivateParallelA|TestH16Combined)' \
    -count=1 -timeout=180s) > "$root/w512-unit-tests.log" 2>&1 ||
  { cat "$root/w512-unit-tests.log" >&2; fail 'W512 planner/H16 unit gate failed'; }
(cd "$src/go" && GOTOOLCHAIN=auto go test ./cmd/fi-backlog-recover -count=1) \
  > "$root/w512-cli-tests.log" 2>&1 ||
  { tail -n 100 "$root/w512-cli-tests.log" >&2; fail 'W512 CLI source tests failed'; }
# The relay port family remains a precise test-fixture allowlist.
grep -Fq 'if basePort != 55981 {' "$relay" ||
  fail 'pinned relay port-family guard changed'
sed 's/if basePort != 55981 {/if basePort != 55983 {/' "$relay" > "$relay.w512"
mv "$relay.w512" "$relay"
[ "$(grep -Fc 'if basePort != 55983 {' "$relay")" -eq 1 ] ||
  fail 'W512 relay fixed-port proof missing'
printf 'FI W512 SOURCE GATE PASS limit_records=524288 limit_bytes=2147483648 original_H16=true workers=2 K32_unchanged=true\n'

(cd "$src/go" && GOTOOLCHAIN=auto go build -o "$root/fi-optfield-recover" ./cmd/fi-backlog-recover) || fail 'optimized Go build failed'
(cd "$src/go/cmd/fi-backlog-recover/optfield" && GOTOOLCHAIN=auto go build -o "$root/fi-optfield-relay" ./relay.go) || fail 'single-fixture relay build failed'
sha256 -q "$root/fi-optfield-recover" > "$root/recover.sha256"
sha256 -q "$root/fi-optfield-relay" > "$root/relay.sha256"
printf '%s\n' "$ref" > "$root/SOURCE_COMMIT"


# A W512 immutable descriptor chain must start from EMPTY SQL; the validated
# W128 three-window seed is deliberately neither opened nor dumped.
git -C "$combinedrepo" cat-file -e "$w512ref^{commit}" ||
  fail 'new W512 private source commit not fetched'
for spec in \
  "c68f1ab270e473a3f279310868efbfb45bfbbf8f go/cmd/fi-backlog-recover/testdata/w512_2g_private_field_bootstrap.sql" \
  "e55e316d470280b04211bc6013f0c06aaa765c40 go/cmd/fi-backlog-recover/testdata/w512_2g_private_field_postseed.sql"; do
  set -- $spec
  git -C "$combinedrepo" show "$w512ref:$2" > "$root/${2##*/}" ||
    fail "W512 SQL fixture unavailable: $2"
  [ "$(git -C "$combinedrepo" hash-object "$root/${2##*/}")" = "$1" ] ||
    fail "W512 SQL fixture changed: $2"
done
git -C "$combinedrepo" show "$w512ref:go/cmd/fi-backlog-recover/testdata/private_field_partitions_isolated.sql" \
  > "$root/private-field-functions.raw.sql" || fail 'source field functions missing'
# Historical field-function snapshot has two closing dollar quotes but lacks
# SQL statement terminators. Normalize only the fresh test fixture copy.
[ "$(grep -Fc '$function$' "$root/private-field-functions.raw.sql")" = 4 ] ||
  fail 'W512 historical function delimiters differ'
awk '{ if ($0=="$function$") {print "$function$;"; next} print }' \
  "$root/private-field-functions.raw.sql" > "$root/private-field-functions.sql" ||
  fail 'W512 historical function SQL normalization failed'
[ "$(grep -Fc '$function$;' "$root/private-field-functions.sql")" = 2 ] ||
  fail 'W512 historical field function terminators absent'
git -C "$repo" show "$ddlref:$ddlpath" \
  > "$root/leaf-insert-vacuum.sql" || fail 'pinned leaf-only vacuum fixture missing'

# Use immutable archived source migrations, not the fi-dev active worktree.
schema="$src/database/schema"
ledger="$src/go/internal/recordingest/backlog_artifact_ledger_schema.sql"
for file in 0001_relational.sql 0002_source_families.sql 0003_usn_relational_identity.sql \
            0004_security_field_name_index.sql 0005_usn_capture_binding.sql; do
  [ -s "$schema/$file" ] || fail "frozen FI schema migration missing: $file"
done
(cd "$src/go" && GOTOOLCHAIN=auto go run ./cmd/fi-backlog-recovery-schema \
    -ledger-sql="$ledger" -migrations-dir="$schema") \
    > "$root/private-schema.sql" || fail 'private schema generation failed'
grep -Fq 'CREATE SCHEMA fi_recovery;' "$root/private-schema.sql" ||
  fail 'private schema emitter output invalid'
[ ! -e "$pgroot/data" ] || fail 'fresh W512 PostgreSQL data directory already exists'
initdb -D "$pgroot/data" -U fi_m1_admin -A trust --no-instructions \
    > "$pgroot/initdb.log" 2>&1 || fail 'W512 private initdb failed'
pg_ctl -D "$pgroot/data" -l "$pgroot/postgres.log" \
    -o "-p $port -k $socket -c listen_addresses= -c unix_socket_permissions=0700" \
    -w start > "$pgroot/start.log" 2>&1 || fail 'W512 private PostgreSQL start failed'
adminpg="host=$socket port=$port user=fi_m1_admin dbname=postgres sslmode=disable"
psql "$adminpg" -X -q -v ON_ERROR_STOP=1 \
    -c 'CREATE ROLE fi_owner NOLOGIN' -c 'CREATE ROLE fi_ingest LOGIN' \
    > "$pgroot/roles.log" 2>&1 || fail 'W512 private role setup failed'
createdb -h "$socket" -p "$port" -U fi_m1_admin -O fi_owner fi ||
    fail 'W512 private fi database create failed'
admin="host=$socket port=$port user=fi_m1_admin dbname=fi sslmode=disable"
for file in 0001_relational.sql 0002_source_families.sql 0003_usn_relational_identity.sql \
            0004_security_field_name_index.sql 0005_usn_capture_binding.sql; do
  psql "$admin" -X -q -v ON_ERROR_STOP=1 -f "$schema/$file" \
     >> "$pgroot/canonical-schema.log" 2>&1 || fail "W512 clone schema $file failed"
done
psql "$admin" -X -q -v ON_ERROR_STOP=1 -f "$root/private-schema.sql" \
  > "$pgroot/private-schema.log" 2>&1 || fail 'W512 new private projection schema failed'
# Bootstrap a real partitioned field parent, seed partition 0, and the
# original private SECURITY DEFINER helpers only in the new empty clone.
psql "$admin" -X -q -v ON_ERROR_STOP=1 \
  -f "$root/w512_2g_private_field_bootstrap.sql" \
  > "$pgroot/w512-field-bootstrap.log" 2>&1 ||
    { tail -n 30 "$pgroot/w512-field-bootstrap.log" >&2; fail 'W512 private field partition bootstrap failed'; }
psql "$admin" -X -q -v ON_ERROR_STOP=1 \
  -f "$root/private-field-functions.sql" \
  > "$pgroot/field-functions.log" 2>&1 || fail 'W512 original field functions failed'
psql "$admin" -X -q -v ON_ERROR_STOP=1 \
  -f "$root/leaf-insert-vacuum.sql" \
  > "$pgroot/leaf-insert-vacuum.log" 2>&1 || fail 'W512 pinned leaf vacuum SQL failed'
function_count=$(psql "$admin" -X -qAt -v ON_ERROR_STOP=1 -c "
SELECT count(*) FROM pg_proc WHERE oid IN
('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure,
 'fi_recovery_projection.finish_security_field_window(integer,bigint)'::regprocedure)
AND prosecdef") || fail 'W512 private function metadata query failed'
[ "$function_count" = 2 ] || fail 'W512 SECURITY DEFINER helper functions missing'
conn="host=$socket port=$port user=fi_ingest dbname=fi sslmode=disable"
q() { psql "$conn" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
[ "$(q "SELECT count(*) FROM pg_tables WHERE schemaname='fi'")" = 49 ] ||
  fail 'W512 fresh clone canonical schema count invalid'
[ "$(q "SELECT count(*) FROM fi_recovery.typed_window")" = 0 ] ||
  fail 'W512 fresh clone unexpectedly contains W128 typed checkpoints'
[ "$(q "SELECT count(*) FROM fi_recovery_projection.source_record")" = 0 ] ||
  fail 'W512 fresh clone unexpectedly contains source projections'
[ "$(q "SELECT count(*) FROM fi.recorded_generation")" = 0 ] ||
  fail 'W512 clone contains canonical SoR rows'
[ "$(q "SHOW max_wal_size")" = 1GB ] || fail 'W512 max_wal_size not 1GB'
[ "$(q "SHOW wal_buffers")" = 4MB ] || fail 'W512 wal_buffers not 4MB'
for setting in fsync synchronous_commit full_page_writes; do
  [ "$(q "SHOW $setting")" = on ] || fail "W512 durability $setting not enabled"
done
printf 'FI W512 FRESH CLONE PASS source=original_authenticated_custody windows=0 records=0 postgres_writers=1 authoritative=0 accepted=0\n'

JAIL

recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || fail 'W512 pinned build binaries absent'
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] ||
  fail 'W512 recovery executable hash mismatch'
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] ||
  fail 'W512 relay executable hash mismatch'
mkdir -m 700 "$out" "$out/$name" "$out/$name/private"
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI CANDIDATE A W512/2GiB FRESH PRIVATE SIGNED SEED
status=seed_only_no_performance_claim
outer_records=524288
outer_signed_source_data_bytes=2147483648
seed_window_index=0
seed_checkpoint_source=original_8399_receiver_signed_batches
original_W128_seed_reused=false
source_ref=$ref
W512_overlay_ref=$w512ref
parallel_ref=$parallelref
verified_cache_existing=$cache
canonical_authoritative_writes=forbidden
server_jail=fi-dev
host=fi-backend-b
private_postgresql_port=55983
private_root=$root
fresh_field_schema=true
W512_first_partition=w000000
active_test_workers=seed_ingest_only
future_worker_count=2
K32_future_chunk=32768
future_sql_writers=1
WAL_max_size=1GB
WAL_buffers=4MB
recover_sha256=$(sha256 -q "$recover")
relay_sha256=$(sha256 -q "$relay")
EOF

"$relay" -cluster-root="$root" -output-root="$out" \
    -base-port=55983 -jail-binary="$root/fi-optfield-relay" \
    > "$out/relay.log" 2>&1 &
relaypid=$!
ready=0
tries=0
while [ "$tries" -lt 30 ]; do
  if grep -Fq "FI PG RELAY READY profile=$name port=55983" "$out/relay.log" 2>/dev/null; then
    ready=1
    break
  fi
  kill -0 "$relaypid" 2>/dev/null || fail "W512 relay exited: $(tail -n 8 "$out/relay.log")"
  tries=$((tries+1))
  sleep 1
done
[ "$ready" = 1 ] || fail 'W512 private relay did not become ready'
cat "$out/relay.log"
sql() {
  jexec -U jwood fi-dev psql \
    "host=$root/$name/socket port=55983 user=fi_ingest dbname=fi sslmode=disable" \
    -X -qAt -v ON_ERROR_STOP=1 -c "$1"
}
[ "$(sql 'SELECT count(*) FROM fi_recovery.typed_window')" = 0 ] ||
  fail 'W512 SQL seed database already has typed checkpoints'

# The first W512 seed must be fully authenticated by the existing signed
# transport loader; never substitute inherited W128 descriptor or field rows.
# This full original-custody admission can fail on trust state; fail closed
# rather than silently bypassing a current verification failure.
printf 'FI W512 SIGNED FIRST-WINDOW SEED START records_max=524288 bytes_max=2147483648 signed_batches=8399\n' |
  tee "$out/SUMMARY.txt"
if ! /usr/bin/time -l "$recover" -private-w512-2g \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="host=$out/pg-$name port=55983 user=fi_ingest dbname=fi sslmode=disable" \
  -custody-root=/var/db/fi/custody/generation \
  -recorded-root=/var/db/fi/custody/recorded \
  -source-namespaces=false -private-root="$out/$name/private" \
  -private-writes -stream-loader -start-window=0 -max-windows=1 \
  -security-profile=P3 -file-profile=F3 -window-profile=W512 \
  -max-runtime=0 > "$out/$name/seed-recover.log" 2>&1; then
  tail -n 100 "$out/$name/seed-recover.log" >&2 || :
  fail 'new signed W512 seed rejected; no benchmark or W128 seed modification'
fi

grep -Fq 'window_profile=W512 max_window_records=524288 max_window_data_bytes=2147483648' \
    "$out/$name/seed-recover.log" || fail 'W512 runtime source window limit proof absent'
grep -Fq 'FI REAL BACKLOG verified signed receipt records=15140785 batches=8399' \
    "$out/$name/seed-recover.log" || fail 'full signed source receipt was not verified'
[ "$(sql "SELECT count(*)::text || '|' || min(window_index)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window")" = '1|0|0' ] ||
  fail 'W512 first window checkpoint count/index invalid'
[ "$(sql 'SELECT count(*) FROM fi_recovery.source_window')" = 1 ] ||
  fail 'W512 source checkpoint not durable'
[ "$(sql 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 1 ] ||
  fail 'W512 signed artifact checkpoint not durable'
[ "$(sql 'SELECT count(*) FROM fi_recovery_projection.source_batch')" = 8399 ] ||
  fail 'W512 private source metadata missing original 8399 batches'
[ "$(sql 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] ||
  fail 'W512 seed unexpectedly modified authoritative generation'
[ "$(sql "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] ||
  fail 'W512 seed unexpectedly marked Accepted'
records=$(sql 'SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window') ||
  fail 'W512 seed checkpoint record query failed'
case "$records" in ''|*[!0-9]*) fail 'W512 seed record count malformed';; esac
[ "$records" -gt 0 ] && [ "$records" -le 524288 ] ||
  fail "W512 seed original signed record cap invalid: $records"
fields_before=$(sql 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field') ||
  fail 'W512 seed private field readback failed'
[ "$fields_before" -gt 0 ] || fail 'W512 seed had no Security fields'
printf 'FI W512 SIGNED SEED SQL PASS windows=1 index=0 records=%s security_fields=%s signed_batches=8399 authoritative=0 accepted=0\n' \
  "$records" "$fields_before" | tee -a "$out/SUMMARY.txt"

# Reattach the initial field partition with a finite verified source-id upper
# bound. This is outside the future W512 performance timer.
jexec -U jwood fi-dev psql \
  "host=$root/$name/socket port=55983 user=fi_m1_admin dbname=fi sslmode=disable" \
  -X -v ON_ERROR_STOP=1 -f "$root/w512_2g_private_field_postseed.sql" \
  > "$out/$name/w512-field-postseed.log" 2>&1 ||
  { tail -n 50 "$out/$name/w512-field-postseed.log" >&2; fail 'W512 field postseed range/row conservation rejected'; }
[ "$(sql "SELECT count(*) FROM fi_recovery_projection.windows_security_event_field")" = "$fields_before" ] ||
  fail 'W512 Security field row conservation mismatch after partition reattach'
[ "$(sql "SELECT count(*) FROM pg_inherits WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass")" = 1 ] ||
  fail 'W512 seeded field parent partition count invalid'
sql "SELECT window_index::text || '|' || committed_records::text || '|' || encode(descriptor_sha256,'hex')
     FROM fi_recovery.typed_window ORDER BY window_index" > "$out/$name/W512_SEED_CHECKPOINT.tsv" ||
  fail 'W512 checkpoint descriptor readback failed'
cat "$out/$name/W512_SEED_CHECKPOINT.tsv"
printf 'FI W512 FIELD PARTITION GATE PASS fields=%s leaf=1 seed_index=0\n' "$fields_before" |
  tee -a "$out/SUMMARY.txt"
[ "$(sql 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] ||
  fail 'W512 authoritative SoR changed after postseed'
printf 'FI W512/2G FRESH SIGNED SEED ACCEPTED windows=1 typed_records=%s fields=%s authoritative=0 accepted=0\n' \
  "$records" "$fields_before" | tee -a "$out/SUMMARY.txt"
bundle="$out/fi-w512-private-seed-$stamp.tar.gz"
tar -C "$out" -czf "$bundle" RUN_MANIFEST.txt SUMMARY.txt relay.log "$name/seed-recover.log" \
  "$name/w512-field-postseed.log" "$name/W512_SEED_CHECKPOINT.tsv" ||
  fail 'W512 seed diagnostics bundle creation failed'
[ -s "$bundle" ] || fail 'W512 seed diagnostics missing'
printf 'FI W512 SEED METRICS BUNDLE PASS path=%s sha256=%s\n' "$bundle" "$(sha256 -q "$bundle")"
