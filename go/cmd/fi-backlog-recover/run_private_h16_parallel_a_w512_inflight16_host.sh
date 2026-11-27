#!/bin/sh
# FI W512 Candidate A: private in-flight 16 experiment, same 2 workers.
# Repeat the accepted W512 windows 1 and 2 from a NEW offline seed copy.
# Accepted four-credit control = /var/tmp/fi-window-chunks-h16-w512-p2-20261113T211329Z.
# No WAL/PG tuning, no production writes, no W128 chain, no trust bypass.
set -eu
umask 077
fail(){ printf 'FI W512 INFLIGHT16 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$#" -eq 1 ] && [ "$1" = h16 ] ||
    fail 'run as root on fi-backend-b with exactly h16'
for exe in jexec jls ps sha256 grep awk; do
    command -v "$exe" >/dev/null 2>&1 || fail "required command missing: $exe"
done
jailroot=$(jls -j fi-dev path) || fail 'fi-dev jail missing'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev JID missing'
sorjid=$(jls -j fi-sor-db jid) || fail 'fi-sor-db JID missing'
[ "$devjid" != "$sorjid" ] || fail 'dev and SoR jails match'
jexec fi-sor-db service postgresql status >/dev/null 2>&1 || fail 'SoR PostgreSQL unavailable'
existing=$(ps -axww -o pid,jid,user,rss,command | awk -v jid="$devjid" '
    $2==jid&&$5=="/usr/local/bin/postgres"&&$6=="-D"{n++} END{print n+0}')
[ "$existing" = 0 ] || fail 'fi-dev PostgreSQL postmaster already running'
seed=/home/jwood/fi-window-bench-w512-20261113T205026Z
seedout=/var/tmp/fi-window-chunks-h16-w512-seed-20261113T205026Z
control=/var/tmp/fi-window-chunks-h16-w512-p2-20261113T211329Z
[ -d "$jailroot$seed/optimized-source/go/internal/recordingest" ] ||
    fail 'accepted disposable W512 Go source missing'
[ -d "$jailroot$seed/clone-w512-2g/data" ] ||
    fail 'accepted W512 PostgreSQL seed missing'
[ "$(sha256 -q "$seedout/fi-w512-private-seed-20261113T205026Z.tar.gz")" = \
  77d378fad4fd8a4cb0cee6e4f9c46bce644590de1fda7d818a5ab8891e6489ce ] ||
    fail 'accepted W512 seed bundle changed'
[ "$(cat "$seedout/clone-w512-2g/W512_SEED_CHECKPOINT.tsv")" = \
  '0|493478|ff58478b40ca35f1f6cc5e52aa0300de6371ed58243c41f34e4f20ad6d61a319' ] ||
    fail 'accepted W512 checkpoint descriptor/count changed'
[ -f "$control/clone-w512-2g/RESULT.txt" ] ||
    fail 'accepted 4-credit control proof missing'
grep -Fq 'FI W512 TWO-WINDOW PILOT ACCEPTED windows=2 new_records=997434 elapsed=5m12.63s workers=2 authoritative=0 accepted=0' \
  "$control/SUMMARY.txt" || fail 'accepted four-credit baseline changed'
jexec -U jwood fi-dev pg_ctl -D "$seed/clone-w512-2g/data" status >/dev/null 2>&1 &&
    fail 'accepted W512 seed must remain stopped'
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
stage=/home/jwood/fi-window-bench-w512-inflight16-$stamp
[ ! -e "$jailroot$stage" ] || fail 'in-flight 16 build stage already exists'
# Only this isolated Go source archive is patched. The W512 accepted executable
# and original pilot script are copied, never modified or reused as writable.
jexec -U jwood fi-dev sh -s "$seed" "$stage" <<'JAIL'
set -eu
umask 077
seed=$1
stage=$2
[ "$(id -un)" = jwood ] || exit 1
repo=/home/jwood/src/fi
ref=bb42b229f157b1527a702499e04ee3b562380610
baseline=a75e18661b070e9c76cd00e18cf35ee8fd6d3d0a
patcher=go/cmd/fi-backlog-recover/patchers/w512_inflight16/main.go
pilot=go/cmd/fi-backlog-recover/run_private_h16_parallel_a_w512_pilot2_host.sh
[ ! -e "$stage" ] || exit 1
git -C "$repo" cat-file -e "$ref^{commit}" || exit 1
git -C "$repo" cat-file -e "$baseline^{commit}" || exit 1
[ "$(git -C "$repo" rev-parse "$ref:$patcher")" = \
  5cabf84a9449072bc65366a915a5a08a16d012a0 ] || exit 1
[ "$(git -C "$repo" rev-parse "$baseline:$pilot")" = \
  86a7543e4379f62209013ddd161bf6532c48f171 ] || exit 1
mkdir -m 700 "$stage" || exit 1
cp -R "$seed/optimized-source" "$stage/optimized-source" || exit 1
git -C "$repo" show "$baseline:$pilot" > "$stage/pilot-inflight16.sh" || exit 1
[ "$(git -C "$repo" hash-object "$stage/pilot-inflight16.sh")" = \
  86a7543e4379f62209013ddd161bf6532c48f171 ] || exit 1
mkdir -p "$stage/optimized-source/go/cmd/fi-backlog-recover/patchers/w512_inflight16"
git -C "$repo" show "$ref:$patcher" \
  > "$stage/optimized-source/$patcher" || exit 1
[ "$(git -C "$repo" hash-object "$stage/optimized-source/$patcher")" = \
  5cabf84a9449072bc65366a915a5a08a16d012a0 ] || exit 1
(cd "$stage/optimized-source/go" &&
  GOTOOLCHAIN=auto go run "./cmd/fi-backlog-recover/patchers/w512_inflight16/main.go" "$stage") ||
  { echo 'FI W512 INFLIGHT16 source patch rejected' >&2; exit 1; }
(cd "$stage/optimized-source/go" &&
  gofmt -w ./internal/recordingest/private_parallel_preparation.go \
    ./internal/recordingest/postgres_ingest.go \
    ./cmd/fi-backlog-recover/main_freebsd.go) || exit 1
(cd "$stage/optimized-source/go" &&
  GOTOOLCHAIN=auto go test ./internal/recordingest \
    -run '^TestPrivateParallelA' -count=1 -timeout=180s) ||
  { echo 'FI W512 INFLIGHT16 two-worker ordering and bounded-credit tests failed' >&2; exit 1; }
(cd "$stage/optimized-source/go" &&
  GOTOOLCHAIN=auto go build -o "$stage/fi-optfield-recover-16" ./cmd/fi-backlog-recover) ||
  { echo 'FI W512 INFLIGHT16 candidate build rejected' >&2; exit 1; }
sha256 -q "$stage/fi-optfield-recover-16" > "$stage/fi-optfield-recover-16.sha256"
sh -n "$stage/pilot-inflight16.sh" || exit 1
grep -Fq 'privateParallelAMaxInFlight = 16' \
  "$stage/optimized-source/go/internal/recordingest/private_parallel_preparation.go" || exit 1
grep -Fq 'FI PRIVATE PARALLEL PREP BATCH batch=%s workers=2 inflight_limit=16 writers=1' \
  "$stage/optimized-source/go/internal/recordingest/postgres_ingest.go" || exit 1
grep -Fq 'workers=2 inflight=16 postgres_writers=1 source_window=%s atomic=true' \
  "$stage/optimized-source/go/cmd/fi-backlog-recover/main_freebsd.go" || exit 1
grep -Fq 'f["inflight_limit"]!=16' "$stage/pilot-inflight16.sh" || exit 1
grep -Fq 'f["reorder_peak"]+0>15' "$stage/pilot-inflight16.sh" || exit 1
printf 'FI W512 INFLIGHT16 BUILD GATE PASS source=copy_of_accepted_W512 workers=2 credits=16 sql_writers=1 seed_unchanged=true candidate_sha256=%s\n' \
  "$(cat "$stage/fi-optfield-recover-16.sha256")"
JAIL
# The approved two-window pilot verifies the seed, copies it while offline,
# enforces SQL checkpoint lineage, reads back signed bytes, and stops PG.
pilot="$jailroot$stage/pilot-inflight16.sh"
[ -f "$pilot" ] && [ ! -L "$pilot" ] || fail 'patched pilot missing'
grep -Fq 'FI W512 INFLIGHT16 PILOT START' "$pilot" ||
    fail 'W512 in-flight 16 pilot start marker missing'
grep -Fq 'FI W512 INFLIGHT16 PILOT ACCEPTED' "$pilot" ||
    fail 'W512 in-flight 16 pilot acceptance gate missing'
printf 'FI W512 INFLIGHT16 COMPARISON CONTROL records=997434 duration=312.630s throughput=3190.46rec/s workers=2 credits=4\n'
sh "$pilot" h16 || fail 'W512 in-flight 16 pilot did not pass signed SQL and readback acceptance'
