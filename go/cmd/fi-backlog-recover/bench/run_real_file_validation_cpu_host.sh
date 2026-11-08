#!/bin/sh
# FI isolated real-signed FileObservation validator-cost benchmark.
# One immutable historical source snapshot; one Go test binary; NO PostgreSQL.
# Reads only the 566 source artifacts already byte-compared with original signed
# cache during the clean Nov 8 baseline. Does not modify fi-dev worktree or SoR.
set -eu
umask 077
fail() { printf 'FI VALIDATOR BENCH STOP: %s\n' "$*" >&2; exit 1; }

[ "$(id -un)" = root ] || fail 'must run on fi-backend-b host as root'
for command in jexec jls find wc date grep ps; do
    command -v "$command" >/dev/null 2>&1 || fail "missing $command"
done

base=9e0e6e236c95d9af91bc67a065efb47ce2318579
testcommit=f12fd6d4585ec8cb635aec4779ccbae4f6fc82f0
testpath=go/cmd/fi-backlog-recover/bench/real_file_validation_cpu_test.go
data=/var/tmp/fi-window-chunks-clone-11-08-26-20261108T150115Z/clone-11-08-26/private
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root=/home/jwood/fi-validator-cpu-$stamp
out=/var/tmp/fi-validator-cpu-$stamp
jailroot=$(jls -j fi-dev path) || fail 'development jail is missing'
devjid=$(jls -j fi-dev jid) || fail 'development jail JID is missing'
sorjid=$(jls -j fi-sor-db jid) || fail 'authoritative jail is missing'
[ "$devjid" != "$sorjid" ] || fail 'development and authoritative jail JIDs match'
[ -d "$data" ] && [ ! -L "$data" ] || fail 'clean baseline signed artifacts missing'
[ "$(find "$data" -type f -name 'batch-*.data' | wc -l | tr -d ' ')" -eq 566 ] || fail 'expected exactly 566 verified baseline batch artifacts'
[ ! -e "$jailroot$root" ] && [ ! -e "$out" ] || fail 'benchmark destination already exists'
jexec fi-sor-db service postgresql status >/dev/null 2>&1 || fail 'authoritative PostgreSQL status changed'
mkdir -m 700 "$out"
cat > "$out/MANIFEST.txt" <<EOF
FI CPU benchmark for original signed FileObservation validation
go_source_commit=$base
test_harness_commit=$testcommit
signed_baseline_artifacts=$data
baseline_signed_byte_readback=PASS_566_files_2026-11-08
database_started=false
sql_connections=false
one_versus_two_validator_calls=same_go_test_process_balanced_ABBA
EOF

# The original historical source and experimental test are staged together
# in a fresh private jail directory. This does not change the active branch.
jexec -U jwood fi-dev sh -s "$root" "$base" "$testcommit" "$testpath" <<'JAIL'
set -eu
umask 077
fail() { printf 'FI VALIDATOR JAIL STOP: %s\n' "$*" >&2; exit 1; }
root=$1
base=$2
testcommit=$3
testpath=$4
repo=/home/jwood/fi-deferred-experiment
src=$root/historical-source
[ "$(id -un)" = jwood ] || fail 'expected non-root jwood inside fi-dev'
git -C "$repo" cat-file -e "$base^{commit}" || fail 'original source commit unavailable'
git -C "$repo" cat-file -e "$testcommit^{commit}" || fail 'harness commit unavailable; fetch experiment branch first'
[ ! -e "$root" ] || fail 'destination already exists'
mkdir -m 700 "$root" "$src"
git -C "$repo" archive --format=tar -o "$root/original-source.tar" "$base" || fail 'cannot archive original source'
tar -xf "$root/original-source.tar" -C "$src" || fail 'cannot extract historical source'
git -C "$repo" show "$testcommit:$testpath" > "$src/go/internal/recordingest/real_file_validation_cpu_test.go" || fail 'cannot stage benchmark harness'
[ -s "$src/go/internal/recordingest/real_file_validation_cpu_test.go" ] || fail 'benchmark harness empty'
(cd "$src/go" && GOTOOLCHAIN=auto go version) || fail 'historical Go toolchain missing'
(cd "$src/go" && GOTOOLCHAIN=auto go test -c -o "$root/validator.test" ./internal/recordingest) || fail 'original source test binary failed to compile'
[ -x "$root/validator.test" ] || fail 'test binary missing'
printf 'FI VALIDATOR HISTORICAL BUILD PASS ref=%s test_commit=%s postgres=not_started\n' "$base" "$testcommit"
JAIL

binary="$jailroot$root/validator.test"
[ -x "$binary" ] || fail 'compiled benchmark not accessible from host'
printf 'FI VALIDATOR BENCH START source=real_signed_baseline files=566 database=none gomaxprocs=1\n'
if ! env FI_SIGNED_DATA_ROOT="$data" FI_VALIDATOR_SAMPLES=4096 GOMAXPROCS=1 \
    "$binary" -test.run '^TestRealSignedFileValidatorCost$' -test.v > "$out/measurements.log" 2>&1; then
    cat "$out/measurements.log" >&2 || :
    fail 'signed-data Go benchmark did not pass'
fi
cat "$out/measurements.log"
grep -q '^FI REAL VALIDATION COMPLETE status=PASS ' "$out/measurements.log" || fail 'benchmark missing completion marker'
printf 'FI VALIDATOR BENCH COMPLETE output=%s source=real_signed postgresql=untouched\n' "$out"
