#!/bin/sh
# FI DEVELOPMENT ONLY: real signed W128 K32/P3/F3 deferred-clone WAL A/B.
# Control 1 GiB max_wal_size vs candidate 8 GiB, same Go build,
# same 3-window seed, unchanged durability, independent PostgreSQL clusters.
# Run as root on FreeBSD fi-backend-b. Never touches production SoR.
set -eu
umask 077
die(){ printf 'FI WAL AB STOP: %s\n' "$*" >&2;exit 1; }
[ "$#" -le 3 ] || die "usage: $0 [normal|reverse] [on|off] [wal|indexed-count|single30|profile30|bulk-index|bulk-full]"
order=${1:-normal}
timing=${2:-on}
experiment=${3:-wal}
case "$experiment" in wal|indexed-count|single30|profile30|bulk-index|bulk-full) ;; *) die "invalid benchmark experiment" ;; esac
case "$experiment" in
 single30|profile30) [ "$order" = normal ] && [ "$timing" = off ] || die "30m probe requires normal off";;
esac
case "$experiment" in indexed-count|bulk-index|bulk-full) [ "$timing" = off ] || die "$experiment requires I/O timing off";; esac
[ "$experiment" != bulk-full ] || { [ "$order" = normal ] || die 'bulk-full requires normal order'; }
case "$order" in normal|reverse) ;; *) die "usage: $0 [normal|reverse] [on|off]" ;; esac
case "$timing" in on|off) ;; *) die "timing must be on or off" ;; esac
[ "$(id -un)" = root ] || die "FreeBSD host root required"
command -v jexec >/dev/null 2>&1 || die "jexec unavailable"
jailroot=$(jls -j fi-dev path) || die "fi-dev jail missing"
work=/home/jwood/fi-deferred-experiment
provision="$work/go/cmd/fi-backlog-recover/deferred_clone_provision_jail.sh"
profile_sql="$work/go/cmd/fi-backlog-recover/testdata/private_field_finish_profile_isolated.sql"
bulk_sql="$work/go/cmd/fi-backlog-recover/testdata/private_field_bulk_index_isolated.sql"
case "$experiment" in
 bulk-index|bulk-full)
  [ -f "$jailroot$bulk_sql" ] || die "bulk-index SQL missing";;
esac
if [ "$experiment" = profile30 ]; then
 [ -f "$jailroot$profile_sql" ] || die "private field profiler source missing"
fi
[ -f "$jailroot$provision" ] || die "experiment provisioner absent"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$cache" ] || die "verified signed cache missing"
[ "$(find "$cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')" = 8399 ] || die "signed cache batch count changed"
[ "$(find "$cache" -type f -name verified.json | wc -l | tr -d ' ')" = 1 ] || die "verified receipt ambiguous"
[ "$(sysctl -n vfs.zfs.bclone_enabled)" = 1 ] || die "ZFS block clone disabled"
[ "$(zpool get -H -o value feature@block_cloning zroot)" = active ] || die "ZFS clone feature not active"
available_kb=$(df -Pk "$jailroot/home/jwood" | awk 'NR==2{print $4}')
case "$available_kb" in ''|*[!0-9]*) die "cannot establish PostgreSQL filesystem headroom";;esac
[ "$available_kb" -ge 50331648 ] || die "less than 48 GiB free for private PostgreSQL fixtures"
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root="/home/jwood/fi-window-bench-optfield-$stamp"
out="/var/tmp/fi-window-chunks-$experiment-ab-$stamp"
[ ! -e "$jailroot$root" ] && [ ! -e "$out" ] || die "experiment path already exists"
printf 'FI PRIVATE BENCH PROVISION experiment=%s source=real_signed_W128 K64_max_wal=8GB free_kib=%s\n' "$experiment" "$available_kb"
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
if [ "$experiment" = profile30 ]; then
 # FI-DEV DISPOSABLE K64 ONLY: pg_ctl -l captures stderr, not syslog.
 # Keep the jail's and the host's global syslog policy unchanged.
 admin K64 "ALTER SYSTEM SET log_destination='stderr'" >/dev/null
fi
case "$experiment" in indexed-count|bulk-index|bulk-full) admin K32 "ALTER SYSTEM SET max_wal_size='8GB'" >/dev/null;; esac
for name in K32 K64;do
 [ "$(admin "$name" 'SELECT pg_reload_conf()')" = t ] || die "$name config reload rejected"
done
sleep 1
expected_control_wal=1024
case "$experiment" in indexed-count|bulk-index|bulk-full) expected_control_wal=8192;; esac
[ "$(sql K32 "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = "$expected_control_wal" ] || die "baseline WAL changed"
[ "$(sql K64 "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 8192 ] || die "candidate WAL did not reach 8GiB"
for name in K32 K64;do
 [ "$(sql "$name" "SELECT current_setting('track_io_timing') || '|' || current_setting('track_wal_io_timing')")" = "$timing|$timing" ] || die "$name timing instrumentation differs"
 for setting in fsync synchronous_commit full_page_writes;do
  [ "$(sql "$name" "SHOW $setting")" = on ] || die "$name durability disabled after reload"
 done
done
if [ "$experiment" = profile30 ]; then
 # Fail BEFORE any timed recovery if RAISE LOG does not reach the exact
 # file consumed by the finalization-stage parser.
 [ "$(sql K64 'SHOW log_destination')" = stderr ] ||
   die "K64 PostgreSQL profile log_destination is not stderr"
 pglog="$jailroot$root/K64/postgres.log"
 [ -f "$pglog" ] || die "K64 PostgreSQL stderr log file is missing"
 smoke="FI_PROFILE_LOG_SMOKE_${stamp}_$$"
 admin K64 "DO \$fi_profile_smoke\$ BEGIN RAISE LOG '$smoke'; END \$fi_profile_smoke\$;" >/dev/null ||
   die "K64 PostgreSQL RAISE LOG smoke query failed"
 grep -Fq "$smoke" "$pglog" ||
   die "K64 RAISE LOG not captured by postgres.log; refusing 30-minute profile"
 printf 'FI PROFILE LOG PREFLIGHT PASS cluster=K64 destination=stderr marker=%s\n' "$smoke"
fi
mkdir -m 700 "$out"
for name in K32 K64;do mkdir -m 700 "$out/$name" "$out/$name/private";done
case "$experiment" in bulk-index|bulk-full)
 # Install only in the K64 disposable candidate; K32 retains indexed COPY.
 jexec -U jwood fi-dev psql \
  "host=$root/K64/socket port=55982 user=fi_m1_admin dbname=fi sslmode=disable" \
  -X -v ON_ERROR_STOP=1 -f "$bulk_sql" > "$out/K64/bulk-index-install.log" 2>&1 ||
  { tail -n 25 "$out/K64/bulk-index-install.log" >&2 || :; die "K64 bulk-index installation failed"; }
 [ "$(sql K64 "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))>0")" = t ] ||
  die "K64 bulk-index begin function missing"
 [ "$(sql K32 "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))=0")" = t ] ||
  die "K32 control begin function changed"
 if [ "$experiment" = bulk-full ]; then
   printf 'FI BULK FULL PRECHECK PASS target=K64 mode=full_generation indexed_copy=false all_checks=enabled\n'
 else
   printf 'FI BULK INDEX INSTALLED K32=incremental_indexes K64=post_COPY_indexes windows=2\n'
 fi
;; esac
if [ "$experiment" = profile30 ]; then
  # Replace the private finalizer only in this fresh K64 disposable cluster.
  # The signed three-window seed and canonical fi.* schema are untouched.
  jexec -U jwood fi-dev psql     "host=$root/K64/socket port=55982 user=fi_m1_admin dbname=fi sslmode=disable"     -X -v ON_ERROR_STOP=1 -f "$profile_sql" > "$out/K64/profile-install.log" 2>&1 ||
    { tail -n 25 "$out/K64/profile-install.log" >&2 || :; die "isolated SQL finalizer profiler installation failed"; }
  [ "$(sql K64 "SELECT position('FI_PRIVATE_FIELD_PROFILE' in pg_get_functiondef('fi_recovery_projection.finish_security_field_window(integer,bigint)'::regprocedure))>0")" = t ] ||
    die "private profile finalizer not installed"
  printf 'FI PRIVATE FIELD PROFILE INSTALLED cluster=K64 constraints=unchanged duration=30m\n'
fi
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI SIGNED W128 DEFERRED CLONE WAL CHECKPOINT A/B
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
verified_cache=$cache
original_immutable_seed=3|390387|2
fixture_root=$root
control=K32 port=55981 max_wal_size=${expected_control_wal}MB
candidate=K64 port=55982 max_wal_size=8192MB indexed_count_verify_selected=${experiment}
both=window_W128 chunk_32768 P3 F3, serial, same binary
single30=K64_only original_count_sql 30m no_AB
profile30=K64_only isolated_SQL_finalizer_telemetry no_AB
profile_sql_sha256=$( [ "$experiment" = profile30 ] && sha256 -q "$jailroot$profile_sql" || echo none )
bulk_index_sql_sha256=$( case "$experiment" in bulk-index|bulk-full) sha256 -q "$jailroot$bulk_sql";; *) echo none;; esac )
bulk_full=K64_only full_117_windows_15140785_records no_timeout original_verifier onprem_no_Accepted
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
 duration=10m
 case "$experiment" in
  single30|profile30) duration=30m;;
  bulk-full) duration=0s;; # Go uses an unbounded context until entire generation completes.
 esac
 printf 'FI PRIVATE AB START experiment=%s arm=%s max_wal_size_mb=%s duration=%s source=real_signed_cache\n' "$experiment" "$name" "$wal" "$duration" | tee -a "$out/SUMMARY.txt"
 set --
 if [ "$experiment" = indexed-count ] && [ "$name" = K64 ]; then set -- -private-indexed-count-verify; fi
 if [ "$experiment" = bulk-index ]; then set -- "$@" -test-stop-after-windows=2; fi
 case "$experiment:$name" in
  single30:K64|profile30:K64) set -- -private-30m-probe;;
 esac
 if ! "$recover" \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="host=$out/pg-$name port=$port user=fi_ingest dbname=fi sslmode=disable" \
  -custody-root=/var/db/fi/custody/generation \
  -recorded-root=/var/db/fi/custody/recorded -source-namespaces=false \
  -private-root="$dir/private" -private-writes -private-field-partitions \
  -security-profile=P3 -file-profile=F3 -window-profile=W128 \
  -processing-chunk-records=32768 -continuous-private -start-window=3 \
  -max-windows=0 -max-runtime="$duration" -deferred-verified-clone \
  -verified-cache-root="$cache" "$@" > "$dir/recover.log" 2>&1;then
  stopmon;tail -n 65 "$dir/recover.log" >&2 || :;die "$name recovery failed"
 fi
 stopmon
 snapshot "$name" > "$dir/after.stats"
 if [ "$experiment" = indexed-count ]; then
  if [ "$name" = K64 ]; then
   grep -q '^FI PRIVATE INDEXED COUNT VERIFY mode=per_signed_batch_lateral scope=private_only' "$dir/recover.log" || die "$name candidate did not enable indexed count verifier"
  else
   if grep -q '^FI PRIVATE INDEXED COUNT VERIFY ' "$dir/recover.log"; then die "$name legacy verifier unexpectedly changed"; fi
  fi
 fi
 stoplabel='FI TEN MINUTE STOP'
 case "$experiment" in single30|profile30) stoplabel='FI THIRTY MINUTE STOP';; bulk-index) stoplabel='FI PRIVATE EXACT WINDOW STOP';; esac
 if [ "$experiment" = bulk-full ]; then
  # No timer stop is acceptable. The complete authenticated source must pass
  # the Go loader's end-of-generation verification and report exact totals.
  grep '^FI REAL BACKLOG PRIVATE COMPLETE windows=117 records=15140785 ' "$dir/recover.log" > "$dir/result.txt" ||
   die "$name complete private generation verification missing"
 else
  grep "^$stoplabel .*authoritative=0 accepted=0" "$dir/recover.log" > "$dir/result.txt" ||
   die "$name $duration result missing"
 fi
 grep '^FI PRIVATE STAGE PROFILE ' "$dir/recover.log" > "$dir/stages.txt" || die "$name no stage profile"
 grep '^FI REAL BACKLOG DURABLE ' "$dir/recover.log" > "$dir/windows.txt" || die "$name no durable windows"
 grep '^FI DEFERRED ARTIFACT PUBLISHED ' "$dir/recover.log" > "$dir/deferred.txt" || die "$name no deferred checkpoint evidence"
 nw=$(wc -l < "$dir/windows.txt" | tr -d ' ')
 [ "$nw" = "$(wc -l < "$dir/stages.txt" | tr -d ' ')" ] || die "$name stage count mismatch"
 [ "$nw" = "$(wc -l < "$dir/deferred.txt" | tr -d ' ')" ] || die "$name artifact count mismatch"
 if [ "$experiment" = bulk-full ]; then
  [ "$name" = K64 ] || die "full-generation run may use only K64"
  [ "$nw" = 114 ] || die "full-generation run did not durably commit all 114 new W128 windows: $nw"
  [ "$(sql K64 "$checkpoint")" = '117|15140785|116' ] ||
   die "full-generation durable checkpoint is not exactly 117|15140785|116"
 fi
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
case "$experiment" in
bulk-full)
 # The K32 cluster is the unchanged three-window source-prefix control.
 # Only K64 processes the complete remainder: 114 real signed W128 windows.
 # A zero runtime is intentional: do not misreport a time-limited partial
 # ingestion as successful full-generation verification.
 [ "$(sql K64 "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 8192 ] ||
   die "K64 full-generation WAL is not 8 GiB"
 [ "$(sql K64 "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))>0")" = t ] ||
   die "K64 full-generation optimized begin function is not installed"
 [ "$(sql K64 "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.finish_security_field_window(integer,bigint)'::regprocedure))=0")" = t ] ||
   die "K64 full-generation finalization function changed unexpectedly"
 printf 'FI BULK FULL OPTIMIZATION ACTIVE arm=K64 indexes=built_on_attach source_records=15140785 windows=117 wal_mb=8192 runtime=until_complete\n' |
   tee -a "$out/SUMMARY.txt"
 run_arm K64
 # Full source, relational, and SQL integrity gates have passed in run_arm.
 # Preserve the entire descriptor chain plus independently check that the
 # signed original three-window prefix is unmodified by the experiment.
 descriptor="SELECT window_index::text || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index"
 sql K64 "$descriptor" > "$out/K64/checkpoints.tsv"
 sql K32 "$descriptor" > "$out/K32/checkpoints.tsv"
 awk -F '|' '$1<3' "$out/K64/checkpoints.tsv" > "$out/K64/seed-prefix.tsv"
 cmp -s "$out/K64/seed-prefix.tsv" "$out/K32/checkpoints.tsv" ||
   die "full-generation original signed three-window prefix changed"
 [ "$(wc -l < "$out/K64/checkpoints.tsv" | tr -d ' ')" = 117 ] ||
   die "full-generation descriptor chain length not 117"
 # Confirm all 114 new field partitions retain validated PK, FK, CHECK,
 # plus attached versions of every parent index. This is a metadata query:
 # it never recounts 180+ million Security field rows.
 full_constraints=$(sql K64 "
 WITH expected AS (
  SELECT window_index FROM fi_recovery.typed_window WHERE window_index>=3
 ), child AS (
  SELECT e.window_index, i.inhrelid AS relid
  FROM expected e
  LEFT JOIN pg_class c
    ON c.relname='windows_security_event_field_w'||lpad(e.window_index::text,6,'0')
   AND c.relnamespace='fi_recovery_projection'::regnamespace
  LEFT JOIN pg_inherits i ON i.inhrelid=c.oid
   AND i.inhparent='fi_recovery_projection.windows_security_event_field'::regclass
 )
 SELECT CASE WHEN (SELECT count(*) FROM expected)=114
  AND NOT EXISTS (
   SELECT 1 FROM child
   WHERE relid IS NULL
    OR NOT EXISTS (SELECT 1 FROM pg_constraint
      WHERE conrelid=child.relid AND contype='p' AND convalidated)
    OR NOT EXISTS (SELECT 1 FROM pg_constraint
      WHERE conrelid=child.relid AND contype='f' AND convalidated)
    OR NOT EXISTS (SELECT 1 FROM pg_constraint
      WHERE conrelid=child.relid AND contype='c'
       AND conname LIKE '%_range' AND convalidated)
    OR EXISTS (
     SELECT 1 FROM pg_index parentidx
     WHERE parentidx.indrelid='fi_recovery_projection.windows_security_event_field'::regclass
       AND NOT EXISTS (
        SELECT 1 FROM pg_index childidx
        JOIN pg_inherits idxattach ON idxattach.inhrelid=childidx.indexrelid
        WHERE childidx.indrelid=child.relid
          AND childidx.indisvalid AND childidx.indisready
          AND idxattach.inhparent=parentidx.indexrelid))
  )
 THEN 'PASS' ELSE 'FAIL' END")
 [ "$full_constraints" = PASS ] ||
   die "full-generation PK/FK/CHECK/index attachment verification failed"
 printf 'FI BULK FULL CONSTRAINTS PASS new_windows=114 primary_key=validated foreign_key=validated range_check=validated parent_indexes=attached\n' |
   tee -a "$out/SUMMARY.txt"
 readback K64
 # Readback is AFTER the timed processing, so it does not bias throughput.
 printf 'FI BULK FULL PASS output=%s checkpoint=117|15140785|116 sql_integrity=PASS signed_batches=identical source_prefix=unchanged authoritative=0 accepted=0 full_generation_verified=true\n' "$out" |
   tee -a "$out/SUMMARY.txt"
 exit 0
;;
single30|profile30)
 [ "$(sql K64 "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 8192 ] || die "30m WAL not 8GB"
 run_arm K64
 readback K64
 sql K64 "SELECT window_index::text || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index" > "$out/K64/checkpoints.tsv"
 if [ "$experiment" = profile30 ]; then
  pglog="$jailroot$root/K64/postgres.log"
  [ -f "$pglog" ] || die "private PostgreSQL server log missing"
  # Extract only the finalizer's own PostgreSQL RAISE LOG records. The
  # earlier preflight marker deliberately does not match this prefix.
  awk '
    /FI_PRIVATE_FIELD_PROFILE window=/ {
      line = $0
      sub(/^.*FI_PRIVATE_FIELD_PROFILE /, "FI_PRIVATE_FIELD_PROFILE ", line)
      print line
    }
  ' "$pglog" > "$out/K64/field-finalize-stages.log" ||
    die "private finalizer telemetry extraction failed"
  committed=$(wc -l < "$out/K64/stages.txt" | tr -d ' ')
  # Compare explicit window identities against the durable checkpoint
  # table, not just the number of log lines. A rolled-back attempt can
  # emit RAISE LOG; its marker must never count as a committed window.
  # Do not pipe the validator into tee: POSIX /bin/sh cannot pipefail.
  if ! awk -v committed="$committed" '
    function reject(message) {
      printf "FI PROFILE VALIDATION FAIL %s\n", message
      failures++
    }
    function number(x) {
      return x ~ /^[0-9]+([.][0-9]+)?$/
    }
    BEGIN {
      keys[1]="rows"
      keys[2]="count_ms"
      keys[3]="check_add_ms"
      keys[4]="check_validate_ms"
      keys[5]="fk_add_ms"
      keys[6]="fk_validate_ms"
      keys[7]="attach_ms"
      keys[8]="total_ms"
    }
    FNR == NR {
      parts_n=split($0, parts, /\|/)
      if (parts_n != 3 || parts[1] !~ /^[0-9]+$/) {
        reject("invalid checkpoint row: " $0)
        next
      }
      w=parts[1]+0
      if (w >= 3) {
        if (w in expected) reject("duplicate durable checkpoint window=" w)
        else { expected[w]=1; expected_n++ }
      }
      next
    }
    {
      raw_n++
      if ($1 != "FI_PRIVATE_FIELD_PROFILE") {
        reject("invalid sample prefix at line=" FNR)
        next
      }
      record_id++
      for (i=2;i<=NF;i++) {
        nv=split($i, pair, "=")
        if (nv != 2 || pair[1] == "" || pair[2] == "") {
          reject("invalid key=value at profile line=" FNR)
          continue
        }
        if (key_record[pair[1]] == record_id)
          reject("duplicate field " pair[1] " at profile line=" FNR)
        key_record[pair[1]]=record_id
        value[pair[1]]=pair[2]
      }
      if (key_record["window"] != record_id ||
          value["window"] !~ /^[0-9]+$/) {
        reject("missing or invalid window at profile line=" FNR)
        next
      }
      w=value["window"]+0
      if (!(w in expected)) {
        reject("uncommitted or unexpected profiler window=" w)
        next
      }
      sample[w]++
      if (sample[w] != 1) {
        reject("duplicate profiler window=" w)
        next
      }
      valid=1
      for (i=1;i<=8;i++) {
        k=keys[i]
        if (key_record[k] != record_id || !number(value[k])) {
          reject("invalid " k " for window=" w)
          valid=0
        }
      }
      if (!valid) next
      if (value["rows"] !~ /^[0-9]+$/)
        reject("invalid integer rows for window=" w)
      g=(w<=12 ? 1 : w<=22 ? 2 : 3)
      n[g]++
      count[g]+=value["count_ms"]+0
      check_add[g]+=value["check_add_ms"]+0
      check[g]+=value["check_validate_ms"]+0
      fk_add[g]+=value["fk_add_ms"]+0
      fk[g]+=value["fk_validate_ms"]+0
      attach[g]+=value["attach_ms"]+0
      total[g]+=value["total_ms"]+0
    }
    END {
      if (expected_n != committed)
        reject("durable checkpoint windows=" expected_n " stage profiles=" committed)
      if (raw_n != committed)
        reject("captured profiler messages=" raw_n " committed windows=" committed)
      for (w in expected)
        if (sample[w] != 1)
          reject("missing or duplicated committed window=" w " samples=" sample[w]+0)
      if (failures) exit 1
      print "FI PRIVATE FIELD FINALIZE COHORTS seconds per window"
      print "COHORT WINDOWS COUNT CHECK_ADD CHECK_VALIDATE FK_ADD FK_VALIDATE ATTACH TOTAL"
      for (g=1;g<=3;g++) {
        cohort=(g==1 ? "EARLY" : g==2 ? "MIDDLE" : "LATE")
        if (n[g])
          printf "%s %d %.3f %.3f %.3f %.3f %.3f %.3f %.3f\n",
            cohort,n[g],count[g]/n[g]/1000,check_add[g]/n[g]/1000,
            check[g]/n[g]/1000,fk_add[g]/n[g]/1000,
            fk[g]/n[g]/1000,attach[g]/n[g]/1000,total[g]/n[g]/1000
      }
    }
  ' "$out/K64/checkpoints.tsv" "$out/K64/field-finalize-stages.log" > "$out/K64/field-finalize-summary.txt"; then
    tail -n 50 "$out/K64/field-finalize-summary.txt" >&2 || :
    die "private finalizer telemetry does not match committed checkpoints"
  fi
  cat "$out/K64/field-finalize-summary.txt"
 fi
 printf 'FI PRIVATE 30M PASS output=%s experiment=%s sql_and_signed_readback=PASS original_count_verifier=true authoritative=0 accepted=0\n' "$out" "$experiment" | tee -a "$out/SUMMARY.txt"
 printf 'FI PRIVATE 30M FILES: %s/K64/{result,stages,windows,pg-waits,iostat,vmstat,process}.txt_or_log\n' "$out" | tee -a "$out/SUMMARY.txt"
 exit 0
;;
esac
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
if [ "$experiment" = bulk-index ]; then
 # Confirm no essential DB property vanished when indexes were delayed.
 for arm in K32 K64; do
  for window in 3 4; do
   child=$(printf 'fi_recovery_projection.windows_security_event_field_w%06d' "$window")
   result=$(sql "$arm" "SELECT
    EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='$child'::regclass AND contype='p' AND convalidated)
    AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='$child'::regclass AND contype='f' AND convalidated)
    AND EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='$child'::regclass AND contype='c'
      AND conname LIKE '%_range' AND convalidated)
    AND NOT EXISTS (
      SELECT 1 FROM pg_index pi
      WHERE pi.indrelid='fi_recovery_projection.windows_security_event_field'::regclass
      AND NOT EXISTS (
        SELECT 1 FROM pg_index ci JOIN pg_inherits inh ON inh.inhrelid=ci.indexrelid
        WHERE ci.indrelid='$child'::regclass AND ci.indisvalid AND ci.indisready
          AND inh.inhparent=pi.indexrelid
      )
    )")
   [ "$result" = t ] || die "$arm window=$window missing validated PK/FK/range or attached parent index"
  done
 done
 printf 'FI BULK INDEX CONSTRAINTS PASS arms=K32,K64 windows=3,4 PK=valid FK=validated range=validated parent_indexes=attached\n' | tee -a "$out/SUMMARY.txt"
fi
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
 print "FI AB POSTGRES COUNTER DELTAS"
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
grep -E '^FI (TEN MINUTE STOP|PRIVATE EXACT WINDOW STOP) ' "$out/K32/result.txt" "$out/K64/result.txt" | tee "$out/THROUGHPUT_COMPARISON.txt"
printf 'FI WAL AB COMPLETE output=%s experiment=%s order=%s timing=%s control_wal_mb=%s candidate_wal_mb=8192 signed_data=identical independent_real_db=true\n' "$out" "$experiment" "$order" "$timing" "$expected_control_wal" | tee -a "$out/SUMMARY.txt"
printf 'FI WAL AB COUNTER FILES: %s/K32/{before,after}.stats and %s/K64/{before,after}.stats\n' "$out" "$out"
