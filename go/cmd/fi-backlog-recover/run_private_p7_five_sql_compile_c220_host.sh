#!/bin/sh
# FI P7 Five Actual SQL Writers — private C220 compile/race regression.
# This is NOT the full W512 multi-writer integration replay.
# No postgres starts. No source/receiver cache changes. No trusted paths edit.
set -eu
umask 077
fail(){ echo "FI P7 FIVE-WRITER STOP: $*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] &&
    [ "$#" -eq 1 ] || fail 'root@c220 required; mode preflight|tests'
case "$1" in preflight|tests) mode=$1;; *) fail 'unknown mode';; esac
repo=/home/jwood/fi-w512-c220-stage
sourcepin=907b74759f7465c7c9a7b15560a63f61d771b1d2
p6pin=be622cf547f750ba20b111720219e82a44eaa56c
anchor=/var/tmp/fi-window-chunks-family-p3-20261116T230127Z
bundle="$anchor/fi-w512-family-p3-pilot2-20261116T230127Z.tar.gz"
checksum=f8b28076c610f26bab85959db17d3ce3dae4d30753dfed622764f8da20edaa91
[ -s "$bundle" ] && [ "$(sha256 -q "$bundle")" = "$checksum" ] ||
    fail 'accepted P6 signed SQL clone archive missing or checksum mismatched'
[ -s "$anchor/SUMMARY.txt" ] &&
grep -Fqx 'FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true' "$anchor/SUMMARY.txt" &&
grep -Fqx 'FI C220 W512 ATOMIC FAMILY P6 TWO-WINDOW ACCEPTED windows=2 new_records=997434 elapsed=4m7.626s min_workers=2 max_workers=16 max_slots=80 credits=32 writer=1 authoritative=0 accepted=0' "$anchor/SUMMARY.txt" ||
    fail 'accepted P6 parent/child and signed source baseline unavailable'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}" ||
    fail 'pinned P7 source unavailable in fi-dev Git checkout'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$p6pin^{commit}" ||
    fail 'pinned accepted P6 source unavailable'
printf 'FI P7 READ-ONLY FIVE SQL PREFLIGHT PASS p7_source=%s accepted_p6=%s clone_immutable=true postgres_started=false\n' "$sourcepin" "$p6pin"
[ "$mode" = preflight ] && exit 0
jexec -U jwood fi-dev sh -s "$repo" "$sourcepin" "$p6pin" <<'JAIL'
set -eu
umask 077
repo=$1
sourcepin=$2
p6pin=$3
base=/home/jwood/fi-window-bench-w512-family-p3-20261116T230127Z/optimized-source
[ -f "$base/go/go.mod" ] &&
[ -f "$base/go/internal/recordingest/private_p6_sql_ntfs.go" ] &&
[ -f "$base/go/internal/recordingest/private_p6_family_buffers_test.go" ] ||
    { echo 'FI P7: accepted P6 source overlay missing; STOP' >&2; exit 1; }
# Confirm the cached working source really matches the accepted P6 pin.
for item in private_p6_sql_ntfs.go private_p6_family_buffers.go private_p6_file_proof_test.go; do
    git -C "$repo" show \
      "$p6pin:go/cmd/fi-backlog-recover/testdata/family-p6/$item" |
      cmp -s - "$base/go/internal/recordingest/$item" ||
        { echo "FI P7: historical P6 source differs: $item" >&2; exit 1; }
done
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
dst="/home/jwood/fi-p7-five-writer-go-tests-$stamp"
[ ! -e "$dst" ] && [ ! -L "$dst" ] ||
    { echo 'FI P7: test destination already exists' >&2; exit 1; }
mkdir -m 0700 "$dst"
cp -R "$base" "$dst/optimized-source"
files='private_p7_five_writer_handoff.go private_p7_five_writer_handoff_test.go private_p7_postgres_writers.go private_p7_atomic_publish.go private_p7_window_setup.go private_p7_window_session.go private_p7_typed_window.go'
for item in $files; do
    test ! -e "$dst/optimized-source/go/internal/recordingest/$item" ||
        { echo "FI P7: source unexpectedly preexisting $item" >&2; exit 1; }
    git -C "$repo" show \
      "$sourcepin:go/cmd/fi-backlog-recover/testdata/family-p7/$item" \
      > "$dst/optimized-source/go/internal/recordingest/$item" ||
        { echo "FI P7: missing pinned source $item" >&2; exit 1; }
done
# Include P7's modified completion barrier; the accepted P6 file
# alone still assumes one synchronous SQL writer.
git -C "$repo" show \
  "$sourcepin:go/cmd/fi-backlog-recover/testdata/family-p6/private_p6_family_buffers.go" \
  > "$dst/optimized-source/go/internal/recordingest/private_p6_family_buffers.go" ||
  { echo 'FI P7: pinned atomic five-writer completion barrier missing' >&2; exit 1; }
# Apply the SAME exact-anchor P7 preparer gate in this test-only source
# that the SQL pilot will install after the inherited family P3 patch.
bridge="$dst/optimized-source/go/cmd/fi-backlog-recover/patchers/p7_parallel_bridge"
mkdir -p "$bridge"
git -C "$repo" show "$sourcepin:go/cmd/fi-backlog-recover/patchers/p7_parallel_bridge/main.go" \
    > "$bridge/main.go" ||
    { echo 'FI P7: pinned Candidate A bridge missing' >&2; exit 1; }
(cd "$dst/optimized-source/go" &&
 GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 run \
   ./cmd/fi-backlog-recover/patchers/p7_parallel_bridge "$dst/optimized-source") ||
    { echo 'FI P7: signed reader preparer bridge failed' >&2; exit 1; }
cd "$dst/optimized-source/go"
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
unset FI_W512_P7_SQL_WRITERS FI_W512_P6_FAMILY_SQL FI_W512_P5_PERSISTENT
echo '===== P7 NO-POSTGRES GO TEST ====='
go127 test ./internal/recordingest -run '^TestPrivateP7' -count=1 \
    > "$dst/p7-test.log" 2>&1 ||
    { tail -n 100 "$dst/p7-test.log"; echo "FI P7 GO TEST FAIL log=$dst/p7-test.log"; exit 1; }
echo '===== P7 NO-POSTGRES RACE TEST ====='
go127 test -race ./internal/recordingest -run '^TestPrivateP7' -count=1 \
    > "$dst/p7-race.log" 2>&1 ||
    { tail -n 100 "$dst/p7-race.log"; echo "FI P7 RACE FAIL log=$dst/p7-race.log"; exit 1; }
echo '===== ACCEPTED P6 REGRESSION GATE ====='
go127 test ./internal/recordingest -run '^TestPrivateP6' -count=1 \
    > "$dst/p6-regression.log" 2>&1 ||
    { tail -n 100 "$dst/p6-regression.log"; echo "FI P7 BROKE P6 REGRESSION log=$dst/p6-regression.log"; exit 1; }
echo 'FI P7 FIVE-WRITER CODE TEST PASS lanes=5 distinct_backend_adapter=compiled source_parent_guard=compiled sql_marker_gate=compiled race=true unchanged_p6=true'
echo "FI P7 FIVE-WRITER TEST LOGS path=$dst"
JAIL
