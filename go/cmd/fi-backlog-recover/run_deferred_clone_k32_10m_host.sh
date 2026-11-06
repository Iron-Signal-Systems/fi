#!/bin/sh
# FI DEVELOPMENT ONLY. Fresh clone of real signed 3-window PostgreSQL seed;
# single K32/P3/F3 W128 deferred-clone 10-minute REAL source trial.
# Run as root on FreeBSD fi-backend-b. No GitHub connectivity from the host.
set -eu
umask 077
die(){ echo "FI DEFERRED K32 10M STOP: $*" >&2; exit 1; }
[ "$(id -un)" = root ] || die "host root required"
command -v jexec >/dev/null 2>&1 || die "FreeBSD jexec missing"
[ "$(sysctl -n vfs.zfs.bclone_enabled)" = 1 ] || die "ZFS block cloning disabled"
[ "$(zpool get -H -o value feature@block_cloning zroot)" = active ] || die "zroot block-cloning feature not active"
jailroot=$(jls -j fi-dev path) || die "fi-dev jail not running"
work=/home/jwood/fi-deferred-experiment
provision="$work/go/cmd/fi-backlog-recover/deferred_clone_provision_jail.sh"
[ -f "$jailroot$provision" ] || die "experiment provisioner not built/fetched in fi-dev"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root="/home/jwood/fi-window-bench-optfield-$stamp"
out="/var/tmp/fi-window-chunks-deferred10m-$stamp"
[ ! -e "$jailroot$root" ] || die "disposable database root already exists"
[ ! -e "$out" ] || die "result directory collision"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$cache" ] || die "verified source cache missing"
[ "$(find "$cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')" = 8399 ] || die "signed cache does not contain all 8399 batches"
[ "$(find "$cache" -type f -name 'verified.json' | wc -l | tr -d ' ')" = 1 ] || die "verified cache receipt marker missing/ambiguous"
echo "FI DEFERRED K32 10M PROVISION start=$stamp source=existing_signed_cache original_seed=read_only"
jexec -U jwood fi-dev sh "$provision" "$root" || die "fresh PostgreSQL clone provision FAILED"
recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || die "fresh experimental binaries missing"
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] || die "recovery binary checksum mismatch"
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] || die "relay checksum mismatch"
sql(){
 name=$1
 q=$2
 case "$name" in K32) port=55981;;K64) port=55982;;*)die "unknown fixture";;esac
 jexec -U jwood fi-dev psql \
  "host=$root/$name/socket port=$port user=fi_ingest dbname=fi sslmode=disable" \
  -X -qAt -v ON_ERROR_STOP=1 -c "$q"
}
checkpoint="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window"
for name in K32 K64;do
 [ "$(sql "$name" "$checkpoint")" = '3|390387|2' ] || die "$name not at validated 3-window seed"
 [ "$(sql "$name" 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 4838850 ] || die "$name wrong Security field count"
 [ "$(sql "$name" 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "$name canonical SoR unexpectedly populated"
 [ "$(sql "$name" "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "$name accepted journal unexpectedly populated"
 for setting in fsync synchronous_commit full_page_writes;do
  [ "$(sql "$name" "SHOW $setting")" = on ] || die "$name PostgreSQL durability $setting is not on"
 done
done
mkdir -m 700 "$out" "$out/K32" "$out/K64" "$out/K32/private"
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI PRIVATE REAL SIGNED DEFERRED VERIFIED CLONE K32 10 MINUTES
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
verified_cache=$cache
seed=3|390387|2
database_clones=$root
candidate_database=K32 port=55981
untouched_control_database=K64 port=55982
outer_window=W128
processing_chunk=32768
security=P3
file=F3
duration=10m
publication=disabled
authoritative_writes=prohibited
recover_sha256=$(sha256 -q "$recover")
relay_sha256=$(sha256 -q "$relay")
previous_committed_rate=2300.2_records_per_second
EOF
"$relay" -cluster-root="$root" -output-root="$out" \
 -base-port=55981 -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
vm=;io=;proc=;pgmon=
stopmon(){
 for pid in $vm $io $proc $pgmon;do
  kill "$pid" 2>/dev/null || :
  wait "$pid" 2>/dev/null || :
 done
 vm=;io=;proc=;pgmon=
}
cleanup(){ stopmon;kill "$relaypid" 2>/dev/null || :;wait "$relaypid" 2>/dev/null || :; }
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15
n=0
while :;do
 if [ "$(grep -c '^FI PG RELAY READY profile=' "$out/relay.log" 2>/dev/null || :)" = 2 ];then break;fi
 kill -0 "$relaypid" 2>/dev/null || { tail -n 25 "$out/relay.log" >&2;die "PG relay died"; }
 n=$((n+1))
 [ "$n" -lt 30 ] || die "PG relay handshake timed out"
 sleep 1
done
cat "$out/relay.log"
if command -v vmstat >/dev/null 2>&1;then vmstat -w 15 > "$out/K32/vmstat.log" 2>&1 &vm=$!;fi
if command -v iostat >/dev/null 2>&1;then iostat -x -w 15 > "$out/K32/iostat.log" 2>&1 &io=$!;fi
(while :;do date -u '+UTC %Y-%m-%dT%H:%M:%SZ'; ps -axo pid,ppid,%cpu,%mem,rss,comm | awk 'NR==1 || /fi-optfield-recover|postgres|postmaster/';sysctl -n kern.cp_times || :;sleep 15;done) > "$out/K32/process.log" 2>&1 &proc=$!
(while :;do date -u '+UTC %Y-%m-%dT%H:%M:%SZ';sql K32 "SELECT pid::text || '|' || coalesce(state,'-') || '|' || coalesce(wait_event_type,'CPU') || ':' || coalesce(wait_event,'-') FROM pg_stat_activity WHERE backend_type='client backend' AND usename='fi_ingest' AND pid<>pg_backend_pid() ORDER BY pid" || :;sleep 15;done) > "$out/K32/pg-waits.log" 2>&1 &pgmon=$!
beforewal=$(sql K32 "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal")
beforeckpt=$(sql K32 "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer")
printf '%s FI DEFERRED K32 10M START source=signed_8399_batches start_window=3 original_archive_scans=0\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee "$out/SUMMARY.txt"
if ! "$recover" \
 -source=iss-fs-22a.iss.local \
 -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
 -postgres="host=$out/pg-K32 port=55981 user=fi_ingest dbname=fi sslmode=disable" \
 -custody-root=/var/db/fi/custody/generation -recorded-root=/var/db/fi/custody/recorded \
 -source-namespaces=false -private-root="$out/K32/private" \
 -private-writes -private-field-partitions \
 -security-profile=P3 -file-profile=F3 -window-profile=W128 \
 -processing-chunk-records=32768 -continuous-private -start-window=3 \
 -max-windows=0 -max-runtime=10m -deferred-verified-clone \
 -verified-cache-root="$cache" > "$out/K32/recover.log" 2>&1;then
 stopmon
 tail -n 60 "$out/K32/recover.log" >&2 || :
 die "signed-cache continuous PRIVATE recovery rejected"
fi
stopmon
grep '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$out/K32/recover.log" > "$out/K32/result.txt" || die "missing 10-minute durable completion record"
cat "$out/K32/result.txt" | tee -a "$out/SUMMARY.txt"
grep '^FI REAL BACKLOG DURABLE ' "$out/K32/recover.log" > "$out/K32/windows.txt" || die "no completed durable windows"
grep '^FI PRIVATE STAGE PROFILE ' "$out/K32/recover.log" > "$out/K32/stages.txt" || die "missing typed stage evidence"
grep '^FI DEFERRED ARTIFACT PUBLISHED ' "$out/K32/recover.log" > "$out/K32/deferred.txt" || die "no deferred artifact publication"
windows=$(wc -l < "$out/K32/windows.txt" | tr -d ' ')
stages=$(wc -l < "$out/K32/stages.txt" | tr -d ' ')
deferred=$(wc -l < "$out/K32/deferred.txt" | tr -d ' ')
[ "$windows" = "$stages" ] && [ "$windows" = "$deferred" ] || die "partial profiles or deferred checkpoints $windows/$stages/$deferred"
state=$(sql K32 "$checkpoint") || die "durable checkpoint unavailable"
rows=$(sql K32 "SELECT coalesce(sum(committed_records),0)::text FROM fi_recovery.typed_window") || die "missing SQL committed rows"
test "$rows" -gt 390387 || die "no new committed source records"
integrity=$(sql K32 "
SELECT CASE WHEN
 (SELECT count(*) FROM fi_recovery.verified_artifact_window)=(SELECT count(*) FROM fi_recovery.source_window)
 AND (SELECT count(*) FROM fi_recovery.source_window)=(SELECT count(*) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi_recovery.pending_source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi_recovery_projection.source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM pg_inherits WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass)=(SELECT count(*) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi.recorded_generation)=0
 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0
 AND NOT EXISTS(
 SELECT 1 FROM fi_recovery.typed_window t
 JOIN fi_recovery.source_window s USING(receipt_sha256,window_index)
 JOIN fi_recovery.verified_artifact_window a USING(receipt_sha256,window_index)
 WHERE t.descriptor_sha256<>s.descriptor_sha256 OR t.descriptor_sha256<>a.descriptor_sha256
 )
 THEN 'PASS' ELSE 'FAIL' END") || die "SQL integrity query failed"
[ "$integrity" = PASS ] || die "SQL integrity FAILED"
[ "$(sql K64 "$checkpoint")" = '3|390387|2' ] || die "untouched K64 control changed unexpectedly"
afterwal=$(sql K32 "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal")
afterckpt=$(sql K32 "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer")
# Independent post-run readback; outside the 10-minute performance clock.
# Compare every published signed data file AND original manifest with the
# fully authenticated immutable source cache. This does not modify custody.
expected_batches=$(sql K32 "SELECT coalesce(sum(end_batch-start_batch),0)::text FROM fi_recovery.verified_artifact_window WHERE window_index>=3") || die "signed batch range count unavailable"
checked_batches=0
for ready in "$out/K32/private"/receipt-*/window-*;do
 [ -d "$ready" ] || die "missing newly published window"
 receipt_name=$(basename "$(dirname "$ready")")
 for dest in "$ready"/batch-*.data;do
  [ -f "$dest" ] || die "published signed batch missing"
  base_name=$(basename "$dest")
  original="$cache/$receipt_name/$base_name"
  [ -f "$original" ] || die "original signed batch missing: $base_name"
  cmp -s "$dest" "$original" || die "published bytes changed: $base_name"
  cmp -s "${dest%.data}.manifest" "${original%.data}.manifest" || die "signed manifest changed: $base_name"
  checked_batches=$((checked_batches+1))
 done
done
[ "$checked_batches" -eq "$expected_batches" ] || die "published batch count mismatch: $checked_batches/$expected_batches"
printf 'FI DEFERRED K32 10M ARTIFACT READBACK PASS original_signed_batches=%s byte_identical=true manifest_identical=true\n' "$checked_batches" | tee -a "$out/SUMMARY.txt"
printf 'FI DEFERRED K32 10M INTEGRITY PASS checkpoint=%s durable_records=%s windows=%s canonical=0 accepted=0 control_unchanged=true\n' "$state" "$rows" "$windows" | tee -a "$out/SUMMARY.txt"
printf 'FI DEFERRED K32 10M IO wal_before=%s wal_after=%s ckpt_before=%s ckpt_after=%s\n' "$beforewal" "$afterwal" "$beforeckpt" "$afterckpt" | tee -a "$out/SUMMARY.txt"
printf 'FI DEFERRED K32 10M COMPLETE output=%s\n' "$out" | tee -a "$out/SUMMARY.txt"
