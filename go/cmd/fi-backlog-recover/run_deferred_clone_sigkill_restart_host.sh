#!/bin/sh
# Development-only FI SIGKILL acceptance: real signed W128, disposable DB.
# Host root on fi-backend-b. Never touch the canonical FI instance/cache.
set -eu
umask 077
die(){ echo "FI DEFERRED SIGKILL STOP: $*" >&2; exit 1; }
[ "$(id -un)" = root ] || die "host root required"
jail_root=$(jls -j fi-dev path) || die "fi-dev jail unavailable"
work=/home/jwood/fi-deferred-experiment
provision="$work/go/cmd/fi-backlog-recover/deferred_clone_provision_jail.sh"
[ -f "$jail_root$provision" ] || die "experimental source worktree missing"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$cache" ] || die "signed source cache missing"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root="/home/jwood/fi-window-bench-optfield-$stamp"
out="/var/tmp/fi-window-chunks-deferred-sigkill-$stamp"
[ ! -e "$jail_root$root" ] && [ ! -e "$out" ] || die "disposable fixture collision"
jexec -U jwood fi-dev sh "$provision" "$root" || die "isolated PostgreSQL provisioning failed"
recover="$jail_root$root/fi-optfield-recover"
relay="$jail_root$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || die "experimental binaries missing"
[ "$(sha256 -q "$recover")" = "$(cat "$jail_root$root/recover.sha256")" ] || die "binary digest differs from fixture"
mkdir -m 700 "$out" "$out/K32" "$out/K32/private"
sql(){
 case "$1" in K32) port=55981;;K64) port=55982;;*)die "unknown isolated database";;esac
 jexec -U jwood fi-dev psql \
  "host=$root/$1/socket port=$port user=fi_ingest dbname=fi sslmode=disable" \
  -X -qAt -v ON_ERROR_STOP=1 -c "$2"
}
ckpt="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window"
seed(){
 [ "$(sql "$1" "$ckpt")" = '3|390387|2' ] || die "$1 checkpoint not initial signed seed"
 [ "$(sql "$1" 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 3 ] || die "$1 artifact count diverged"
 [ "$(sql "$1" 'SELECT count(*) FROM fi_recovery.source_window')" = 3 ] || die "$1 source marker count diverged"
 [ "$(sql "$1" 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "$1 canonical source unexpectedly populated"
 [ "$(sql "$1" "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "$1 accepted outcome present"
}
seed K32
seed K64
"$relay" -cluster-root="$root" -output-root="$out" -base-port=55981 \
 -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
trap 'kill "$relaypid" 2>/dev/null || :; wait "$relaypid" 2>/dev/null || :' 0
n=0
while :;do
 [ "$(grep -c '^FI PG RELAY READY profile=' "$out/relay.log" 2>/dev/null || :)" = 2 ] && break
 kill -0 "$relaypid" 2>/dev/null || die "relay process exited"
 n=$((n+1))
 [ "$n" -lt 30 ] || die "relay failed readiness"
 sleep 1
done
run(){
 fault=$1
 log=$2
 if [ "$fault" = none ];then extra="";else extra="-test-deferred-fault=$fault";fi
 "$recover" \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="host=$out/pg-K32 port=55981 user=fi_ingest dbname=fi sslmode=disable" \
  -custody-root=/var/db/fi/custody/generation \
  -recorded-root=/var/db/fi/custody/recorded \
  -source-namespaces=false -private-root="$out/K32/private" \
  -private-writes -private-field-partitions \
  -security-profile=P3 -file-profile=F3 -window-profile=W128 \
  -processing-chunk-records=32768 -continuous-private \
  -start-window=3 -max-windows=0 -max-runtime=5m \
  -test-stop-after-windows=1 -deferred-verified-clone \
  -verified-cache-root="$cache" ${extra:+"$extra"} > "$log" 2>&1
}
echo "FI DEFERRED SIGKILL START window=3 phase=after_durable_publish_before_SQL_commit"
# Signal 9 MUST kill just this dedicated FI recovery child. A normal
# returned error or a normal completion is a FAIL, not acceptable evidence.
set +e
run kill-after-publish "$out/K32/killed.log"
status=$?
set -e
[ "$status" -eq 137 ] || {
 tail -n 60 "$out/K32/killed.log" >&2 || :
 die "expected real SIGKILL status=137, observed=$status"
}
grep '^FI INJECTED PRIVATE DEFERRED SIGKILL AFTER-PUBLISH window=3 ' "$out/K32/killed.log" >/dev/null || die "missing exact after-publication kill proof"
ready="$out/K32/private/receipt-29891703eea7bef6e21b84374c49193a9b1d58666665d418267e418e3414c7ed/window-00000003"
[ -d "$ready" ] || die "durable published orphan missing"
seed K32
seed K64
echo "FI DEFERRED SIGKILL ROLLBACK PASS terminated_signal=9 artifact_orphan=true committed_markers_unchanged=true canonical=0 accepted=0"

# After SIGKILL there are no Go defers. The SAME published directory and
# SAME DB are reused; no fresh ZFS clone is permitted for this window.
echo "FI DEFERRED SIGKILL RESTART START existing_orphan_full_hash_required=true"
if ! run none "$out/K32/restart.log";then
 tail -n 65 "$out/K32/restart.log" >&2 || :
 die "real signed artifact restart failed"
fi
grep '^FI PRIVATE EXACT WINDOW STOP start=3 windows=1 last=3 ' "$out/K32/restart.log" >/dev/null || die "missing durable restart stop"
if grep '^FI DEFERRED ARTIFACT PUBLISHED window=3 ' "$out/K32/restart.log" >/dev/null;then
 die "restart improperly used new-clone fast path"
fi
[ "$(sql K32 "$ckpt")" = '4|519822|3' ] || die "restart durable checkpoint not 519822"
[ "$(sql K32 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 4 ] || die "restart artifact marker missing"
[ "$(sql K32 'SELECT count(*) FROM fi_recovery.source_window')" = 4 ] || die "restart source marker missing"
[ "$(sql K32 'SELECT count(*) FROM fi_recovery.pending_source_record')" = 519822 ] || die "private source count mismatch"
[ "$(sql K32 'SELECT count(*) FROM fi_recovery_projection.source_record')" = 519822 ] || die "private typed source count mismatch"
[ "$(sql K32 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "authoritative row introduced"
[ "$(sql K32 "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "Accepted journal introduced"
seed K64
orig="$cache/receipt-29891703eea7bef6e21b84374c49193a9b1d58666665d418267e418e3414c7ed"
count=0
for f in "$ready"/batch-*.data;do
 [ -f "$f" ] || die "signed batch missing"
 name=$(basename "$f")
 cmp -s "$f" "$orig/$name" || die "recovered signed data differs: $name"
 cmp -s "${f%.data}.manifest" "$orig/${name%.data}.manifest" || die "recovered signed manifest differs: $name"
 count=$((count+1))
done
[ "$count" = 54 ] || die "expected 54 original signed batches, observed $count"
echo "FI DEFERRED SIGKILL RESTART PASS durable_records=519822 signed_batches=54 byte_identical=true full_hash_fallback=true authoritative=0 accepted=0"
echo "FI DEFERRED SIGKILL ACCEPTANCE COMPLETE output=$out"
