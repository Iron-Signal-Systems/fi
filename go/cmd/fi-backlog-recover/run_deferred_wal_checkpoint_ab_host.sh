#!/bin/sh
# FI DEVELOPMENT ONLY: real signed W128 K32/P3/F3 deferred-clone WAL A/B.
# Control 1 GiB max_wal_size vs candidate 8 GiB, same Go build,
# same 3-window seed, unchanged durability, independent PostgreSQL clusters.
# Run as root on FreeBSD fi-backend-b. Never touches production SoR.
set -eu
umask 077
die(){ printf 'FI WAL AB STOP: %s\n' "$*" >&2;exit 1; }
[ "$#" -le 3 ] || die "usage: $0 [normal|reverse] [on|off] [wal|indexed-count]"
order=${1:-normal}
timing=${2:-on}
experiment=${3:-wal}
case "$experiment" in wal|indexed-count) ;; *) die "invalid benchmark experiment" ;; esac
[ "$experiment" != indexed-count ] || [ "$timing" = off ] || die "indexed-count requires I/O timing off"
case "$order" in normal|reverse) ;; *) die "usage: $0 [normal|reverse] [on|off]" ;; esac
case "$timing" in on|off) ;; *) die "timing must be on or off" ;; esac
[ "$(id -un)" = root ] || die "FreeBSD host root required"
command -v jexec >/dev/null 2>&1 || die "jexec unavailable"
jailroot=$(jls -j fi-dev path) || die "fi-dev jail missing"
work=/home/jwood/fi-deferred-experiment
provision="$work/go/cmd/fi-backlog-recover/deferred_clone_provision_jail.sh"
[ -f "$jailroot$provision" ] || die "experiment provisioner absent"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$cache" ] || die "verified signed cache missing"
[ "$(find "$cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')" = 8399 ] || die "signed cache batch count changed"
[ "$(find "$cache" -type f -name verified.json | wc -l | tr -d ' ')" = 1 ] || die "verified receipt ambiguous"
[ "$(sysctl -n vfs.zfs.bclone_enabled)" = 1 ] || die "ZFS block clone disabled"
[ "$(zpool get -H -o value feature@block_cloning zroot)" = active ] || die "ZFS clone feature not active"
available_kb=$(df -Pk "$jailroot/home/jwood" | awk 'NR==2{print $4}')
case "$available_kb" in ''|*[!0-9]*) die "cannot establish PostgreSQL filesystem headroom";;esac
[ "$available_kb" -ge 50331648 ] || die "less than 48 GiB free for two independent PostgreSQL clusters"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root="/home/jwood/fi-window-bench-optfield-$stamp"
out="/var/tmp/fi-window-chunks-$experiment-ab-$stamp"
[ ! -e "$jailroot$root" ] && [ ! -e "$out" ] || die "experiment path already exists"
printf 'FI WAL AB PROVISION source=real_signed_W128 baseline_max_wal=1GB candidate_max_wal=8GB free_kib=%s\n' "$available_kb"
jexec -U jwood fi-dev sh "$provision" "$root" || die "disposable fixture provisioning failed"
recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || die "experiment binary or relay absent"
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] || die "experiment binary checksum mismatch"
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] || die "relay binary checksum mismatch"
sql(){
 name=$1; query=$2
 case "$name" in K32) port=55981;;K64) port=55982;;*)die "unknown DB";;esac
 jexec -U jwood fi-dev psql "host=$root/$name/socket port=$port user=fi_ingest dbname=fi sslmode=disable" \
 -X -qAt -v ON_ERROR_STOP=1 -c "$query"
}
admin(){
 name=$1; query=$2
 case "$name" in K32) port=55981;;K64) port=55982;;*)die "unknown admin DB";;esac
 jexec -U jwood fi-dev psql "host=$root/$name/socket port=$port user=fi_m1_admin dbname=fi sslmode=disable" \
 -X -qAt -v ON_ERROR_STOP=1 -c "$query"
}
checkpoint="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window"
for name in K32 K64;do
 [ "$(sql "$name" "$checkpoint")" = '3|390387|2' ] || die "$name initial signed checkpoint mismatch"
 [ "$(sql "$name" 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 4838850 ] || die "$name seed Security rows mismatch"
 [ "$(sql "$name" 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 3 ] || die "$name seed artifact marker mismatch"
 [ "$(sql "$name" 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "$name authoritative SoR not empty"
 [ "$(sql "$name" "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "$name Accepted journal not empty"
 for setting in fsync synchronous_commit full_page_writes;do
  [ "$(sql "$name" "SHOW $setting")" = on ] || die "$name durability $setting not enabled"
 done
 [ "$(sql "$name" "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 1024 ] || die "$name baseline max_wal_size not 1GiB"
 # Both arms use identical instrumentation; choose off to establish
 # performance without extra per-I/O time measurements.
 admin "$name" "ALTER SYSTEM SET track_io_timing='$timing'" >/dev/null
 admin "$name" "ALTER SYSTEM SET track_wal_io_timing='$timing'" >/dev/null
done
# Exactly one performance variable differs.
admin K64 "ALTER SYSTEM SET max_wal_size='8GB'" >/dev/null
if [ "$experiment" = indexed-count ]; then admin K32 "ALTER SYSTEM SET max_wal_size='8GB'" >/dev/null; fi
for name in K32 K64;do
 [ "$(admin "$name" 'SELECT pg_reload_conf()')" = t ] || die "$name config reload rejected"
done
sleep 1
expected_control_wal=1024
[ "$experiment" != indexed-count ] || expected_control_wal=8192
[ "$(sql K32 "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = "$expected_control_wal" ] || die "baseline WAL changed"
[ "$(sql K64 "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 8192 ] || die "candidate WAL did not reach 8GiB"
for name in K32 K64;do
 [ "$(sql "$name" "SELECT current_setting('track_io_timing') || '|' || current_setting('track_wal_io_timing')")" = "$timing|$timing" ] || die "$name timing instrumentation differs"
 for setting in fsync synchronous_commit full_page_writes;do
  [ "$(sql "$name" "SHOW $setting")" = on ] || die "$name durability disabled after reload"
 done
done
mkdir -m 700 "$out"
for name in K32 K64;do mkdir -m 700 "$out/$name" "$out/$name/private";done
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI SIGNED W128 DEFERRED CLONE WAL CHECKPOINT A/B
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
verified_cache=$cache
original_immutable_seed=3|390387|2
fixture_root=$root
control=K32 port=55981 max_wal_size=1024MB
candidate=K64 port=55982 max_wal_size=8192MB
both=window_W128 chunk_32768 P3 F3, 10m serial, same binary
both=fsync_on synchronous_commit_on full_page_writes_on
both=track_io_timing_$timing track_wal_io_timing_$timing
run_order=$order
experiment=$experiment
control_wal_mb=$expected_control_wal
wal_buffers=unchanged
checkpoint_timeout=unchanged
published_and_authoritative_source=prohibited
experiment_binary_sha256=$(sha256 -q "$recover")
relay_sha256=$(sha256 -q "$relay")
EOF
"$relay" -cluster-root="$root" -output-root="$out" -base-port=55981 \
 -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
vm=;io=;proc=;waitmon=
stopmon(){
 for pid in $vm $io $proc $waitmon;do
  kill "$pid" 2>/dev/null || :
  wait "$pid" 2>/dev/null || :
 done
 vm=;io=;proc=;waitmon=
}
cleanup(){ stopmon; kill "$relaypid" 2>/dev/null || :; wait "$relaypid" 2>/dev/null || :; }
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15
tries=0
while :;do
 [ "$(grep -c '^FI PG RELAY READY profile=' "$out/relay.log" 2>/dev/null || :)" = 2 ] && break
 kill -0 "$relaypid" 2>/dev/null || { tail -n 25 "$out/relay.log" >&2;die "relay process stopped"; }
 tries=$((tries+1))
 [ "$tries" -lt 30 ] || die "relay readiness timed out"
 sleep 1
done
cat "$out/relay.log"
snapshot(){
 name=$1
 # Cumulative counters are sampled independently around each run.
 sql "$name" "SELECT num_requested || '|' || num_timed || '|' || num_done || '|' || write_time || '|' || sync_time || '|' || buffers_written FROM pg_stat_checkpointer"
 sql "$name" "SELECT wal_bytes || '|' || wal_fpi || '|' || wal_buffers_full FROM pg_stat_wal"
 sql "$name" "SELECT coalesce(sum(writes),0)::text || '|' || coalesce(sum(write_time),0)::text || '|' || coalesce(sum(fsyncs),0)::text || '|' || coalesce(sum(fsync_time),0)::text FROM pg_stat_io WHERE object='wal'"
}
integrity(){
 name=$1
 sql "$name" "SELECT CASE WHEN
 (SELECT count(*) FROM fi_recovery.verified_artifact_window)=(SELECT count(*) FROM fi_recovery.source_window)
 AND (SELECT count(*) FROM fi_recovery.source_window)=(SELECT count(*) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi_recovery.pending_source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi_recovery_projection.source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM pg_inherits WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass)=(SELECT count(*) FROM fi_recovery.typed_window)
 AND (SELECT count(*) FROM fi.recorded_generation)=0
 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0
 AND NOT EXISTS(SELECT 1 FROM fi_recovery.typed_window t
 JOIN fi_recovery.source_window s USING(receipt_sha256,window_index)
 JOIN fi_recovery.verified_artifact_window a USING(receipt_sha256,window_index)
 WHERE t.descriptor_sha256<>s.descriptor_sha256 OR t.descriptor_sha256<>a.descriptor_sha256)
 THEN 'PASS' ELSE 'FAIL' END"
}
readback(){
 name=$1
 expected=$(sql "$name" "SELECT coalesce(sum(end_batch-start_batch),0)::text FROM fi_recovery.verified_artifact_window WHERE window_index>=3")
 actual=0
 for ready in "$out/$name/private"/receipt-*/window-*;do
  [ -d "$ready" ] || die "$name missing published artifact"
  receipt=$(basename "$(dirname "$ready")")
  for dest in "$ready"/batch-*.data;do
   [ -f "$dest" ] || die "$name missing signed batch data"
   base=$(basename "$dest")
   original="$cache/$receipt/$base"
   [ -f "$original" ] || die "$name signed cache source missing"
   cmp -s "$dest" "$original" || die "$name published signed data differ: $base"
   cmp -s "${dest%.data}.manifest" "${original%.data}.manifest" || die "$name published signed manifest differs: $base"
   actual=$((actual+1))
  done
 done
 [ "$actual" -eq "$expected" ] || die "$name artifact readback count mismatch $actual/$expected"
 printf 'FI WAL AB ARTIFACT READBACK PASS arm=%s batches=%s identical=true\n' "$name" "$actual" | tee -a "$out/SUMMARY.txt"
}
run_arm(){
 name=$1
 case "$name" in K32) port=55981;;K64) port=55982;;*)die "unknown trial arm";;esac
 dir="$out/$name"
 # Read cumulative counters just before and just after the timed test.
 snapshot "$name" > "$dir/before.stats"
 if command -v vmstat >/dev/null 2>&1;then vmstat -w 15 > "$dir/vmstat.log" 2>&1 &vm=$!;fi
 if command -v iostat >/dev/null 2>&1;then iostat -x -w 15 > "$dir/iostat.log" 2>&1 &io=$!;fi
 (while :;do date -u '+UTC %Y-%m-%dT%H:%M:%SZ';ps -axo pid,ppid,%cpu,%mem,rss,comm | awk 'NR==1 || /fi-optfield-recover|postgres|postmaster/' || :;sleep 15;done) > "$dir/process.log" 2>&1 &proc=$!
 (while :;do date -u '+UTC %Y-%m-%dT%H:%M:%SZ';sql "$name" "SELECT pid::text || '|' || coalesce(state,'-') || '|' || coalesce(wait_event_type,'CPU') || ':' || coalesce(wait_event,'-') FROM pg_stat_activity WHERE backend_type='client backend' AND usename='fi_ingest' AND pid<>pg_backend_pid() ORDER BY pid" || :;sleep 15;done) > "$dir/pg-waits.log" 2>&1 &waitmon=$!
 wal=$(sql "$name" "SELECT setting FROM pg_settings WHERE name='max_wal_size'")
 printf 'FI WAL AB START arm=%s max_wal_size_mb=%s duration=10m source=real_signed_cache\n' "$name" "$wal" | tee -a "$out/SUMMARY.txt"
 set --
 if [ "$experiment" = indexed-count ] && [ "$name" = K64 ]; then set -- -private-indexed-count-verify; fi
 if ! "$recover" \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="host=$out/pg-$name port=$port user=fi_ingest dbname=fi sslmode=disable" \
  -custody-root=/var/db/fi/custody/generation \
  -recorded-root=/var/db/fi/custody/recorded -source-namespaces=false \
  -private-root="$dir/private" -private-writes -private-field-partitions \
  -security-profile=P3 -file-profile=F3 -window-profile=W128 \
  -processing-chunk-records=32768 -continuous-private -start-window=3 \
  -max-windows=0 -max-runtime=10m -deferred-verified-clone \
  -verified-cache-root="$cache" "$@" > "$dir/recover.log" 2>&1;then
  stopmon;tail -n 65 "$dir/recover.log" >&2 || :;die "$name recovery failed"
 fi
 stopmon
 snapshot "$name" > "$dir/after.stats"
 grep '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$dir/recover.log" > "$dir/result.txt" || die "$name 10m result missing"
 grep '^FI PRIVATE STAGE PROFILE ' "$dir/recover.log" > "$dir/stages.txt" || die "$name no stage profile"
 grep '^FI REAL BACKLOG DURABLE ' "$dir/recover.log" > "$dir/windows.txt" || die "$name no durable windows"
 grep '^FI DEFERRED ARTIFACT PUBLISHED ' "$dir/recover.log" > "$dir/deferred.txt" || die "$name no deferred checkpoint evidence"
 nw=$(wc -l < "$dir/windows.txt" | tr -d ' ')
 [ "$nw" = "$(wc -l < "$dir/stages.txt" | tr -d ' ')" ] || die "$name stage count mismatch"
 [ "$nw" = "$(wc -l < "$dir/deferred.txt" | tr -d ' ')" ] || die "$name artifact count mismatch"
 [ "$(integrity "$name")" = PASS ] || die "$name full SQL integrity failed"
 count=$(sql "$name" "SELECT coalesce(sum(committed_records),0)::text FROM fi_recovery.typed_window")
 [ "$count" -gt 390387 ] || die "$name committed no new records"
 printf 'FI WAL AB SQL PASS arm=%s checkpoint=%s new_windows=%s authoritative=0 accepted=0\n' "$name" "$(sql "$name" "$checkpoint")" "$nw" | tee -a "$out/SUMMARY.txt"
 cat "$dir/result.txt" | tee -a "$out/SUMMARY.txt"
}
: > "$out/SUMMARY.txt"
# Explicit trial order: independent fresh database clones and the exact same
# binary, signed cache and K32/P3/F3 W128 settings in both arms.
# The reverse trial controls for OS cache warming and order effects.
printf 'FI WAL AB ORDER %s timing=%s experiment=%s\n' "$order" "$timing" "$experiment" | tee -a "$out/SUMMARY.txt"
if [ "$order" = reverse ];then
 run_arm K64
 run_arm K32
else
 run_arm K32
 run_arm K64
fi
# Readback is deliberately AFTER BOTH timed tests. Reading every source
# batch after the control but before the candidate would artificially warm
# the candidate source cache and bias the A/B comparison.
readback K32
readback K64
# Compare the signed descriptor chain for every COMMON completed window,
# independent of K32/K64's differing completion counts in ten minutes.
descriptor="SELECT window_index::text || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index"
sql K32 "$descriptor" > "$out/K32/checkpoints.tsv"
sql K64 "$descriptor" > "$out/K64/checkpoints.tsv"
last32=$(tail -n 1 "$out/K32/checkpoints.tsv" | cut -d '|' -f1)
last64=$(tail -n 1 "$out/K64/checkpoints.tsv" | cut -d '|' -f1)
common=$last32
[ "$last64" -lt "$common" ] && common=$last64
awk -F '|' -v limit="$common" '$1<=limit' "$out/K32/checkpoints.tsv" > "$out/K32/common.tsv"
awk -F '|' -v limit="$common" '$1<=limit' "$out/K64/checkpoints.tsv" > "$out/K64/common.tsv"
diff -u "$out/K32/common.tsv" "$out/K64/common.tsv" > "$out/common.diff" || die "common signed source checkpoint chain differs"
printf 'FI WAL AB COMMON PREFIX PASS through_window=%s descriptors_identical=true\n' "$common" | tee -a "$out/SUMMARY.txt"
# Calculate exact per-run cumulative PostgreSQL 18 counters.
awk -F '|' '
FNR==1 {
 arm=(FILENAME ~ /\/K32\// ? "K32" : "K64")
 sample=(FILENAME ~ /\/before\.stats$/ ? "before" : "after")
}
{for(i=1;i<=NF;i++) metric[arm,sample,FNR,i]=$i+0}
END{
 names[1,1]="checkpoints_requested"
 names[1,2]="checkpoints_timed"
 names[1,3]="checkpoints_done"
 names[1,4]="checkpoint_write_ms"
 names[1,5]="checkpoint_sync_ms"
 names[1,6]="checkpoint_buffers_written"
 names[2,1]="wal_bytes"
 names[2,2]="wal_full_page_images"
 names[2,3]="wal_buffers_full"
 names[3,1]="wal_io_writes"
 names[3,2]="wal_io_write_ms"
 names[3,3]="wal_io_fsyncs"
 names[3,4]="wal_io_fsync_ms"
 print "FI WAL AB COUNTER DELTAS (control=1GB candidate=8GB)"
 printf "%-29s %17s %17s %12s\n","METRIC","K32 CONTROL","K64 CANDIDATE","DELTA"
 for(j=1;j<=3;j++){
  count=(j==1?6:j==2?3:4)
  for(i=1;i<=count;i++){
   a=metric["K32","after",j,i]-metric["K32","before",j,i]
   b=metric["K64","after",j,i]-metric["K64","before",j,i]
   printf "%-29s %17.0f %17.0f %+12.0f\n",names[j,i],a,b,b-a
  }
 }
}' "$out/K32/before.stats" "$out/K32/after.stats" \
 "$out/K64/before.stats" "$out/K64/after.stats" | tee "$out/COUNTERS_DELTA.txt"
grep '^FI TEN MINUTE STOP ' "$out/K32/result.txt" "$out/K64/result.txt" | tee "$out/THROUGHPUT_COMPARISON.txt"
printf 'FI WAL AB COMPLETE output=%s experiment=%s order=%s timing=%s control_wal_mb=%s candidate_wal_mb=8192 signed_data=identical independent_real_db=true\n' "$out" "$experiment" "$order" "$timing" "$expected_control_wal" | tee -a "$out/SUMMARY.txt"
printf 'FI WAL AB COUNTER FILES: %s/K32/{before,after}.stats and %s/K64/{before,after}.stats\n' "$out" "$out"
