#!/bin/sh
# Isolated signed-real-data failure acceptance. HOST fi-backend-b root only.
# K32: altered PRIVATE clone must fail without SQL commit or cache mutation.
# K64: fail AFTER durable artifact publication but BEFORE SQL commit, then
# restart against the SAME private root and verify full-hash replay.
# All DB clusters are cloned from the original immutable 3-window seed.
set -eu
umask 077
die(){ echo "FI DEFERRED FAULT STOP: $*" >&2;exit 1; }
[ "$(id -un)" = root ] || die "FreeBSD host root required"
jail_root=$(jls -j fi-dev path) || die "fi-dev jail missing"
work=/home/jwood/fi-deferred-experiment
provision="$work/go/cmd/fi-backlog-recover/deferred_clone_provision_jail.sh"
[ -f "$jail_root$provision" ] || die "experiment source not refreshed in fi-dev"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$cache" ] || die "real signed cache missing"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root="/home/jwood/fi-window-bench-optfield-$stamp"
out="/var/tmp/fi-window-chunks-deferred-fault-$stamp"
[ ! -e "$jail_root$root" ] && [ ! -e "$out" ] || die "fresh disposable trial root exists"
echo "FI DEFERRED FAULT PROVISION source=real_signed_W128 original_seed=read_only"
jexec -U jwood fi-dev sh "$provision" "$root" || die "fresh cloned PostgreSQL fixtures failed"
recover="$jail_root$root/fi-optfield-recover"
relay="$jail_root$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || die "fixture binaries missing"
[ "$(sha256 -q "$recover")" = "$(cat "$jail_root$root/recover.sha256")" ] || die "fixture binary hash changed"
mkdir -m 700 "$out" "$out/K32" "$out/K32/private" "$out/K64" "$out/K64/private"
sql(){
 case "$1" in K32) port=55981;;K64) port=55982;;*)die "unsupported isolated fixture";;esac
 jexec -U jwood fi-dev psql \
 "host=$root/$1/socket port=$port user=fi_ingest dbname=fi sslmode=disable" -X -qAt -v ON_ERROR_STOP=1 -c "$2"
}
checkpoint="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window"
check_seed(){
 [ "$(sql "$1" "$checkpoint")" = '3|390387|2' ] || die "$1 checkpoint moved unexpectedly"
 [ "$(sql "$1" 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 3 ] || die "$1 artifact marker moved"
 [ "$(sql "$1" 'SELECT count(*) FROM fi_recovery.source_window')" = 3 ] || die "$1 source marker moved"
 [ "$(sql "$1" 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "$1 canonical SoR not empty"
 [ "$(sql "$1" "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "$1 Accepted journal not empty"
}
check_seed K32
check_seed K64
"$relay" -cluster-root="$root" -output-root="$out" -base-port=55981 \
 -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || :;wait "$pid" 2>/dev/null || :' 0
n=0
while :;do
 [ "$(grep -c '^FI PG RELAY READY profile=' "$out/relay.log" 2>/dev/null || :)" = 2 ] && break
 kill -0 "$pid" 2>/dev/null || { tail -n 25 "$out/relay.log" >&2; die "relay failed"; }
 n=$((n+1));[ "$n" -lt 30 ] || die "relay handshake timeout";sleep 1
done
run(){
 name=$1; fault=$2; destination=$3
 case "$name" in K32) port=55981;;K64) port=55982;;*)die "invalid profile";;esac
 if [ "$fault" != none ];then fault_flag="-test-deferred-fault=$fault";else fault_flag="";fi
 # Exactly one signed W128 private window per invocation; deliberately
 # not against the original FI database or the accepted custody archive.
 "$recover" \
 -source=iss-fs-22a.iss.local \
 -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
 -postgres="host=$out/pg-$name port=$port user=fi_ingest dbname=fi sslmode=disable" \
 -custody-root=/var/db/fi/custody/generation \
 -recorded-root=/var/db/fi/custody/recorded \
 -source-namespaces=false -private-root="$out/$name/private" \
 -private-writes -private-field-partitions \
 -security-profile=P3 -file-profile=F3 -window-profile=W128 \
 -processing-chunk-records=32768 -continuous-private -start-window=3 -max-windows=0 \
 -max-runtime=5m -test-stop-after-windows=1 -deferred-verified-clone \
 -verified-cache-root="$cache" ${fault_flag:+"$fault_flag"} > "$destination" 2>&1
}
echo "FI DEFERRED FAULT K32 START mode=corrupt-clone"
if run K32 corrupt-clone "$out/K32/corrupt.log";then
 die "tampered unpublished private clone unexpectedly committed"
fi
grep '^FI INJECTED PRIVATE DEFERRED CLONE CORRUPTION ' "$out/K32/corrupt.log" >/dev/null || {
 tail -n 45 "$out/K32/corrupt.log";die "corruption was not injected"; }
check_seed K32
[ "$(find "$out/K32/private" -name 'window-00000003' -type d | wc -l | tr -d ' ')" = 0 ] || die "corrupt unverified clone was published"
echo "FI DEFERRED FAULT CORRUPTION PASS sql_rollback=true unpublished=true source_cache_untouched=true"

echo "FI DEFERRED FAULT K64 START mode=after-publish"
if run K64 after-publish "$out/K64/interrupted.log";then
 die "injected failure after durable publication unexpectedly committed"
fi
grep '^FI INJECTED PRIVATE DEFERRED AFTER-PUBLISH window=3 ' "$out/K64/interrupted.log" >/dev/null || {
 tail -n 45 "$out/K64/interrupted.log";die "after-publish fault did not fire"; }
check_seed K64
ready="$out/K64/private/receipt-29891703eea7bef6e21b84374c49193a9b1d58666665d418267e418e3414c7ed/window-00000003"
[ -d "$ready" ] || die "published orphan artifact missing after injected failure"
echo "FI DEFERRED FAULT AFTER-PUBLISH PASS sql_rollback=true durable_orphan_present=true"

# The SAME database and SAME ready directory, with the fault flag REMOVED.
# The baseline MaterializeBacklogWindow + RecordVerifiedBacklogArtifactWindow
# route MUST fully hash this already published artifact before joined SQL COPY.
echo "FI DEFERRED RESTART K64 START original_ready_artifact=existing"
if ! run K64 none "$out/K64/restart.log";then
 tail -n 70 "$out/K64/restart.log"
 die "existing-artifact full-hash restart failed"
fi
grep '^FI PRIVATE EXACT WINDOW STOP start=3 windows=1 last=3 ' "$out/K64/restart.log" >/dev/null || die "restart did not commit exactly one signed window"
if grep '^FI DEFERRED ARTIFACT PUBLISHED window=3 ' "$out/K64/restart.log" >/dev/null;then
 die "restart incorrectly used fast unpublished clone path"
fi
[ "$(sql K64 "$checkpoint")" = "4|519822|3" ] || die "restart SQL checkpoint wrong"
[ "$(sql K64 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 4 ] || die "restart artifact marker count wrong"
[ "$(sql K64 'SELECT count(*) FROM fi_recovery.source_window')" = 4 ] || die "restart source marker count wrong"
[ "$(sql K64 'SELECT count(*) FROM fi_recovery.pending_source_record')" = 519822 ] || die "restart source rows wrong"
[ "$(sql K64 'SELECT count(*) FROM fi_recovery_projection.source_record')" = 519822 ] || die "restart typed source rows wrong"
[ "$(sql K64 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "restart touched SoR"
[ "$(sql K64 "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "restart wrote Accepted journal"
# Independent on-disk comparison of ALL resumed window-3 signed data pairs.
count=0
cache_receipt="$cache/receipt-29891703eea7bef6e21b84374c49193a9b1d58666665d418267e418e3414c7ed"
for f in "$ready"/batch-*.data;do
 [ -f "$f" ] || die "no ready signed data"
 base=$(basename "$f")
 cmp -s "$f" "$cache_receipt/$base" || die "restart source data changed from signed cache: $base"
 cmp -s "${f%.data}.manifest" "$cache_receipt/${base%.data}.manifest" || die "restart signed manifest changed: $base"
 count=$((count+1))
done
[ "$count" = 54 ] || die "unexpected W128 window 3 batch count: $count"
echo "FI DEFERRED RESTART PASS signed_batches=54 data_and_manifest_byte_identical=true durable_records=519822 authoritative=0 accepted=0"
printf 'FI DEFERRED FAILURE ACCEPTANCE COMPLETE output=%s\n' "$out"
