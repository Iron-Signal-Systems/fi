#!/bin/sh
# FI DEVELOPMENT ONLY: independent real-signed W128/P3/F3 optimization A/B.
# CONTROL/CANDIDATE are experiment arms, NOT processing chunk sizes.
# Both use 32768-record chunks; signed prefix and SQL durability unchanged.
# Run as root on FreeBSD fi-backend-b. Never touches production SoR.
set -eu
umask 077
die(){ printf 'FI BENCH AB STOP: %s\n' "$*" >&2;exit 1; }
[ "$#" -le 3 ] || die "usage: $0 [normal|reverse] [on|off] [wal|indexed-count|single30|profile30|bulk-index|bulk-event|profile10|fk-memory|bulk-full]"
order=${1:-normal}
timing=${2:-on}
experiment=${3:-wal}
case "$experiment" in wal|indexed-count|single30|profile30|bulk-index|bulk-event|profile10|fk-memory|bulk-full) ;; *) die "invalid benchmark experiment" ;; esac
case "$experiment" in
 single30|profile30) [ "$order" = normal ] && [ "$timing" = off ] || die "30m probe requires normal off";;
 profile10) [ "$order" = normal ] && [ "$timing" = off ] || die "profile10 requires normal off";;
esac
case "$experiment" in indexed-count|bulk-index|bulk-event|profile10|fk-memory|bulk-full) [ "$timing" = off ] || die "$experiment requires I/O timing off";; esac
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
 bulk-index|bulk-event|profile10|fk-memory|bulk-full)
  [ -f "$jailroot$bulk_sql" ] || die "bulk-index SQL missing";;
esac
if [ "$experiment" = profile30 ] || [ "$experiment" = profile10 ] || [ "$experiment" = fk-memory ]; then
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
printf 'FI PRIVATE BENCH PROVISION experiment=%s source=real_signed_W128 CANDIDATE_max_wal=8GB free_kib=%s\n' "$experiment" "$available_kb"
jexec -U jwood fi-dev sh "$provision" "$root" || die "disposable fixture provisioning failed"
recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || die "experiment binary or relay absent"
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] || die "experiment binary checksum mismatch"
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] || die "relay binary checksum mismatch"
sql(){
 name=$1; query=$2
 case "$name" in CONTROL) port=55981;;CANDIDATE) port=55982;;*)die "unknown DB";;esac
 jexec -U jwood fi-dev psql "host=$root/$name/socket port=$port user=fi_ingest dbname=fi sslmode=disable" \
 -X -qAt -v ON_ERROR_STOP=1 -c "$query"
}
admin(){
 name=$1; query=$2
 case "$name" in CONTROL) port=55981;;CANDIDATE) port=55982;;*)die "unknown admin DB";;esac
 jexec -U jwood fi-dev psql "host=$root/$name/socket port=$port user=fi_m1_admin dbname=fi sslmode=disable" \
 -X -qAt -v ON_ERROR_STOP=1 -c "$query"
}
checkpoint="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window"
for name in CONTROL CANDIDATE;do
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
admin CANDIDATE "ALTER SYSTEM SET max_wal_size='8GB'" >/dev/null
if [ "$experiment" = profile30 ] || [ "$experiment" = profile10 ] || [ "$experiment" = fk-memory ]; then
 # FI-DEV DISPOSABLE CANDIDATE ONLY: pg_ctl -l captures stderr, not syslog.
 # Keep the jail's and the host's global syslog policy unchanged.
 admin CANDIDATE "ALTER SYSTEM SET log_destination='stderr'" >/dev/null
fi
if [ "$experiment" = fk-memory ]; then
 admin CONTROL "ALTER SYSTEM SET log_destination='stderr'" >/dev/null
fi
case "$experiment" in indexed-count|bulk-index|bulk-event|profile10|fk-memory|bulk-full) admin CONTROL "ALTER SYSTEM SET max_wal_size='8GB'" >/dev/null;; esac
for name in CONTROL CANDIDATE;do
 [ "$(admin "$name" 'SELECT pg_reload_conf()')" = t ] || die "$name config reload rejected"
done
sleep 1
expectedControlWal=1024
case "$experiment" in indexed-count|bulk-index|bulk-event|profile10|fk-memory|bulk-full) expectedControlWal=8192;; esac
[ "$(sql CONTROL "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = "$expectedControlWal" ] || die "baseline WAL changed"
[ "$(sql CANDIDATE "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 8192 ] || die "candidate WAL did not reach 8GiB"
for name in CONTROL CANDIDATE;do
 [ "$(sql "$name" "SELECT current_setting('track_io_timing') || '|' || current_setting('track_wal_io_timing')")" = "$timing|$timing" ] || die "$name timing instrumentation differs"
 for setting in fsync synchronous_commit full_page_writes;do
  [ "$(sql "$name" "SHOW $setting")" = on ] || die "$name durability disabled after reload"
 done
done
if [ "$experiment" = profile30 ] || [ "$experiment" = profile10 ] || [ "$experiment" = fk-memory ]; then
 # Fail BEFORE any timed recovery if RAISE LOG does not reach the exact
 # file consumed by the finalization-stage parser.
 [ "$(sql CANDIDATE 'SHOW log_destination')" = stderr ] ||
   die "CANDIDATE PostgreSQL profile log_destination is not stderr"
 pglog="$jailroot$root/CANDIDATE/postgres.log"
 [ -f "$pglog" ] || die "CANDIDATE PostgreSQL stderr log file is missing"
 smoke="FI_PROFILE_LOG_SMOKE_${stamp}_$$"
 admin CANDIDATE "DO \$fi_profile_smoke\$ BEGIN RAISE LOG '$smoke'; END \$fi_profile_smoke\$;" >/dev/null ||
   die "CANDIDATE PostgreSQL RAISE LOG smoke query failed"
 grep -Fq "$smoke" "$pglog" ||
   die "CANDIDATE RAISE LOG not captured by postgres.log; refusing 30-minute profile"
 printf 'FI PROFILE LOG PREFLIGHT PASS cluster=CANDIDATE destination=stderr marker=%s\n' "$smoke"
fi
mkdir -m 700 "$out"
for name in CONTROL CANDIDATE;do mkdir -m 700 "$out/$name" "$out/$name/private";done
case "$experiment" in bulk-index|bulk-event|profile10|fk-memory|bulk-full)
 # bulk-index: CONTROL uses incremental field indexes, CANDIDATE deferred.
 # bulk-event: BOTH arms use deferred field indexes; only the event
 # row source differs. Both run independently for the same 10-minute
 # deadline over the real verified signed backlog.
 jexec -U jwood fi-dev psql \
  "host=$root/CANDIDATE/socket port=55982 user=fi_m1_admin dbname=fi sslmode=disable" \
  -X -v ON_ERROR_STOP=1 -f "$bulk_sql" > "$out/CANDIDATE/bulk-index-install.log" 2>&1 ||
  { tail -n 25 "$out/CANDIDATE/bulk-index-install.log" >&2 || :; die "CANDIDATE bulk-index installation failed"; }
 [ "$(sql CANDIDATE "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))>0")" = t ] ||
  die "CANDIDATE bulk-index begin function missing"
 if [ "$experiment" = bulk-event ] || [ "$experiment" = fk-memory ]; then
  jexec -U jwood fi-dev psql \
   "host=$root/CONTROL/socket port=55981 user=fi_m1_admin dbname=fi sslmode=disable" \
   -X -v ON_ERROR_STOP=1 -f "$bulk_sql" > "$out/CONTROL/bulk-index-install.log" 2>&1 ||
   { tail -n 25 "$out/CONTROL/bulk-index-install.log" >&2 || :; die "CONTROL bulk-index installation failed"; }
  [ "$(sql CONTROL "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))>0")" = t ] ||
   die "CONTROL field-index strategy differs from CANDIDATE"
  if [ "$experiment" = bulk-event ]; then
   printf 'FI EVENT COPY AB PRECHECK PASS CONTROL=legacy CANDIDATE=reusable both=deferred_field_indexes processing_chunk_records=32768 duration=10m_per_arm\n'
  else
   printf 'FI FK MEMORY PRECHECK both=original_copy both=deferred_field_indexes\n'
  fi
 else
  [ "$(sql CONTROL "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))=0")" = t ] ||
   die "CONTROL control begin function changed"
 fi
 if [ "$experiment" = bulk-full ]; then
   printf 'FI BULK FULL PRECHECK PASS target=CANDIDATE mode=full_generation indexed_copy=false all_checks=enabled\n'
 elif [ "$experiment" = bulk-index ]; then
   printf 'FI BULK INDEX INSTALLED CONTROL=incremental_indexes CANDIDATE=post_COPY_indexes windows=2\n'
 fi
;; esac
if [ "$experiment" = profile30 ] || [ "$experiment" = profile10 ] || [ "$experiment" = fk-memory ]; then
  # Replace the private finalizer only in this fresh CANDIDATE disposable cluster.
  # The signed three-window seed and canonical fi.* schema are untouched.
  jexec -U jwood fi-dev psql     "host=$root/CANDIDATE/socket port=55982 user=fi_m1_admin dbname=fi sslmode=disable"     -X -v ON_ERROR_STOP=1 -f "$profile_sql" > "$out/CANDIDATE/profile-install.log" 2>&1 ||
    { tail -n 25 "$out/CANDIDATE/profile-install.log" >&2 || :; die "isolated SQL finalizer profiler installation failed"; }
  [ "$(sql CANDIDATE "SELECT position('FI_PRIVATE_FIELD_PROFILE' in pg_get_functiondef('fi_recovery_projection.finish_security_field_window(integer,bigint)'::regprocedure))>0")" = t ] ||
    die "private profile finalizer not installed"
  printf 'FI PRIVATE FIELD PROFILE INSTALLED cluster=CANDIDATE constraints=unchanged experiment=%s\n' "$experiment"
fi
if [ "$experiment" = fk-memory ]; then
 # Both clones have identical SQL, signed seeds, durability, COPY, indexes,
 # WAL and PostgreSQL timing logs. Only finalizer work_mem differs.
 jexec -U jwood fi-dev psql \
  "host=$root/CONTROL/socket port=55981 user=fi_m1_admin dbname=fi sslmode=disable" \
  -X -v ON_ERROR_STOP=1 -f "$profile_sql" > "$out/CONTROL/profile-install.log" 2>&1 ||
  { tail -n 25 "$out/CONTROL/profile-install.log" >&2 || :; die "CONTROL profiler SQL failed"; }
 [ "$(sql CONTROL "SELECT position('FI_PRIVATE_FIELD_PROFILE' in pg_get_functiondef('fi_recovery_projection.finish_security_field_window(integer,bigint)'::regprocedure))>0")" = t ] ||
  die "CONTROL finalizer profiler missing"
 for arm in CONTROL CANDIDATE; do
  [ "$(sql "$arm" 'SHOW work_mem')" = '4MB' ] || die "$arm baseline work_mem is not 4MB"
  [ "$(sql "$arm" 'SHOW hash_mem_multiplier')" = 2 ] || die "$arm hash_mem_multiplier differs"
 done
 admin CANDIDATE "ALTER FUNCTION fi_recovery_projection.finish_security_field_window(integer,bigint) SET work_mem TO '64MB'" >/dev/null ||
  die "CANDIDATE function-local memory setting failed"
 config_sql="SELECT coalesce(array_to_string(proconfig,','),'') FROM pg_proc WHERE oid='fi_recovery_projection.finish_security_field_window(integer,bigint)'::regprocedure"
 cfg_control=$(sql CONTROL "$config_sql")
 cfg_candidate=$(sql CANDIDATE "$config_sql")
 case "$cfg_control" in *work_mem=*) die "CONTROL unexpected function memory override";; esac
 case "$cfg_candidate" in *work_mem=64MB*) :;; *) die "CANDIDATE 64MB function setting not installed";; esac
 [ "$(sql CANDIDATE 'SHOW work_mem')" = 4MB ] || die "CANDIDATE memory setting leaked outside function"
 printf 'FI FK MEMORY PRECHECK PASS control=4MB candidate=64MB scope=finish_security_field_window\n'
fi
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI SIGNED W128 DEFERRED CLONE EXPERIMENT A/B
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
verified_cache=$cache
original_immutable_seed=3|390387|2
fixture_root=$root
control=CONTROL port=55981 max_wal_size=${expectedControlWal}MB
candidate=CANDIDATE port=55982 max_wal_size=8192MB indexed_count_verify_selected=${experiment}
both=window_W128 processing_chunk_records_32768 P3 F3, serial, same_binary
arm_labels=CONTROL,CANDIDATE ports=55981,55982 labels_are_not_chunk_sizes
single30=CANDIDATE_only original_count_sql 30m no_AB
profile30=CANDIDATE_only isolated_SQL_finalizer_telemetry no_AB
profile_sql_sha256=$( case "$experiment" in profile30|profile10|fk-memory) sha256 -q "$jailroot$profile_sql";; *) echo none;; esac )
bulk_index_sql_sha256=$( case "$experiment" in bulk-index|bulk-event|profile10|fk-memory|bulk-full) sha256 -q "$jailroot$bulk_sql";; *) echo none;; esac )
bulk_full=CANDIDATE_only full_117_windows_15140785_records no_timeout original_verifier onprem_no_Accepted
bulk_event_ab=CONTROL_legacy_CANDIDATE_reusable both_deferred_field_indexes both_chunk_32768 wall_deadline_10m_per_arm
profile10=CANDIDATE_only ten_minute_signed_backlog Go_CPU_profile PG_SQL_finalizer_phase_profile
fk_memory_ab=CONTROL_4MB CANDIDATE_64MB work_mem_function_local both_original_copy both_deferred_indexes both_profiled duration_10m_each
bulk_full_event_copy=legacy
both=fsync_on synchronous_commit_on full_page_writes_on
both=track_io_timing_$timing track_wal_io_timing_$timing
run_order=$order
experiment=$experiment
control_wal_mb=$expectedControlWal
wal_buffers=unchanged
checkpoint_timeout=unchanged
published_and_authoritative_source=prohibited
experiment_binary_sha256=$(sha256 -q "$recover")
relay_sha256=$(sha256 -q "$relay")
EOF
"$relay" -cluster-root="$root" -output-root="$out" -base-port=55981 \
 -profiles=CONTROL,CANDIDATE -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
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
 printf 'FI BENCH AB ARTIFACT READBACK PASS arm=%s batches=%s identical=true\n' "$name" "$actual" | tee -a "$out/SUMMARY.txt"
}
run_arm(){
 name=$1
 case "$name" in CONTROL) port=55981;;CANDIDATE) port=55982;;*)die "unknown trial arm";;esac
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
 printf 'FI PRIVATE AB START experiment=%s arm=%s processing_chunk_records=32768 window_profile=W128 max_wal_size_mb=%s duration=%s source=real_signed_cache\n' "$experiment" "$name" "$wal" "$duration" | tee -a "$out/SUMMARY.txt"
 set --
 if [ "$experiment" = indexed-count ] && [ "$name" = CANDIDATE ]; then set -- -private-indexed-count-verify; fi
 if [ "$experiment" = bulk-index ]; then set -- "$@" -test-stop-after-windows=2; fi
 if [ "$experiment" = profile10 ] && [ "$name" = CANDIDATE ]; then
  set -- "$@" "-private-cpu-profile=$dir/cpu.pprof"
  printf 'FI PROFILE10 ARMED 10m_signed_backlog=true event_copy=legacy chunk_records=32768 CPU_profile=true SQL_finalizer_profile=true\n' |
   tee -a "$out/SUMMARY.txt"
 fi
 if [ "$experiment" = bulk-event ] && [ "$name" = CANDIDATE ]; then
  set -- "$@" -private-reusable-event-copy
  printf 'FI PRIVATE EVENT COPY CANDIDATE ARMED arm=CANDIDATE mode=reusable_40_columns max_runtime=10m private_only=true\n' |
   tee -a "$out/SUMMARY.txt"
 fi
 case "$experiment:$name" in
  single30:CANDIDATE|profile30:CANDIDATE) set -- -private-30m-probe;;
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
 if [ "$experiment" = profile10 ]; then
  [ -s "$dir/cpu.pprof" ] || die "Go CPU profile missing or empty"
  grep -q '^FI PRIVATE CPU PROFILE START mode=profile10 ' "$dir/recover.log" ||
   die "Go CPU profile was not activated"
 fi
 if [ "$experiment" = bulk-event ]; then
  if [ "$name" = CANDIDATE ]; then
   grep -q '^FI PRIVATE SECURITY EVENT COPY SOURCE mode=reusable_40_columns scope=private_only production=unchanged$' "$dir/recover.log" ||
    die "CANDIDATE reusable event COPY was not enabled"
  elif grep -q '^FI PRIVATE SECURITY EVENT COPY SOURCE ' "$dir/recover.log"; then
   die "CONTROL legacy control unexpectedly selected the candidate"
  fi
 fi
 snapshot "$name" > "$dir/after.stats"
 if [ "$experiment" = indexed-count ]; then
  if [ "$name" = CANDIDATE ]; then
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
  [ "$name" = CANDIDATE ] || die "full-generation run may use only CANDIDATE"
  [ "$nw" = 114 ] || die "full-generation run did not durably commit all 114 new W128 windows: $nw"
  [ "$(sql CANDIDATE "$checkpoint")" = '117|15140785|116' ] ||
   die "full-generation durable checkpoint is not exactly 117|15140785|116"
 fi
 [ "$(integrity "$name")" = PASS ] || die "$name full SQL integrity failed"
 count=$(sql "$name" "SELECT coalesce(sum(committed_records),0)::text FROM fi_recovery.typed_window")
 [ "$count" -gt 390387 ] || die "$name committed no new records"
 printf 'FI BENCH AB SQL PASS arm=%s checkpoint=%s new_windows=%s authoritative=0 accepted=0\n' "$name" "$(sql "$name" "$checkpoint")" "$nw" | tee -a "$out/SUMMARY.txt"
 cat "$dir/result.txt" | tee -a "$out/SUMMARY.txt"
}
: > "$out/SUMMARY.txt"
# Explicit trial order: independent fresh database clones and the exact same
# binary, signed cache and CONTROL/P3/F3 W128 settings in both arms.
# The reverse trial controls for OS cache warming and order effects.
printf 'FI BENCH AB ORDER %s timing=%s experiment=%s\n' "$order" "$timing" "$experiment" | tee -a "$out/SUMMARY.txt"
case "$experiment" in
profile10)
 [ "$(sql CANDIDATE "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 8192 ] ||
  die "profile10 WAL size changed"
 [ "$(sql CANDIDATE "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))>0")" = t ] ||
  die "profile10 deferred-index COPY path missing"
 [ "$(sql CANDIDATE "SELECT position('FI_PRIVATE_FIELD_PROFILE' in pg_get_functiondef('fi_recovery_projection.finish_security_field_window(integer,bigint)'::regprocedure))>0")" = t ] ||
  die "profile10 SQL finalizer profiler missing"
 run_arm CANDIDATE
 readback CANDIDATE
 pglog="$jailroot$root/CANDIDATE/postgres.log"
 [ -f "$pglog" ] || die "profile10 PostgreSQL stderr log missing"
 awk '/FI_PRIVATE_FIELD_PROFILE window=/ {v=$0;sub(/^.*FI_PRIVATE_FIELD_PROFILE /,"FI_PRIVATE_FIELD_PROFILE ",v); print v}' "$pglog" > "$out/CANDIDATE/field-finalize-stages.log"
 count=$(wc -l < "$out/CANDIDATE/stages.txt" | tr -d ' ')
 [ "$count" -ge 2 ] || die "profile10 committed fewer than two real signed W128 windows"
 [ "$(wc -l < "$out/CANDIDATE/field-finalize-stages.log" | tr -d ' ')" = "$count" ] ||
  die "profile10 finalizer samples mismatch committed window count"
 # Verify every PostgreSQL RAISE LOG belongs to exactly one durable
 # checkpoint. A rolled-back finalizer must never masquerade as committed.
 sql CANDIDATE "SELECT window_index FROM fi_recovery.typed_window WHERE window_index>=3 ORDER BY window_index" > "$out/CANDIDATE/durable-window-ids.txt"
 if ! awk '
   FNR==NR {
     if($1 !~ /^[0-9]+$/ || ($1 in expected)){bad=1;exit 1}
     expected[$1]=1;total++;next
   }
   {
     id=""
     if($1!="FI_PRIVATE_FIELD_PROFILE"){bad=1;exit 1}
     for(i=2;i<=NF;i++){
       split($i,kv,"=")
       if(kv[1]=="window")id=kv[2]
     }
     if(id !~ /^[0-9]+$/ || !(id in expected) || ++seen[id]!=1){bad=1;exit 1}
     samples++
   }
   END {
     if(bad || total!=samples)exit 1
     for(id in expected)if(seen[id]!=1)exit 1
   }' "$out/CANDIDATE/durable-window-ids.txt" "$out/CANDIDATE/field-finalize-stages.log"; then
   die "profile10 SQL finalizer samples are not a 1:1 match for durable committed windows"
 fi
 awk '
  {window="";c="";check="";fk="";attach="";total=""
   for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]=="window")window=a[2];if(a[1]=="count_ms")c=a[2];if(a[1]=="check_validate_ms")check=a[2];if(a[1]=="fk_validate_ms")fk=a[2];if(a[1]=="attach_ms")attach=a[2];if(a[1]=="total_ms")total=a[2]}
   printf "window=%s count_ms=%s check_validate_ms=%s fk_validate_ms=%s attach_ms=%s total_ms=%s\n",window,c,check,fk,attach,total
  }' "$out/CANDIDATE/field-finalize-stages.log" | tee "$out/CANDIDATE/FINALIZER_BREAKDOWN.txt"
 printf 'FI PROFILE10 PASS duration=10m real_signed_backlog=true completed_windows=%s cpu_profile=%s/CANDIDATE/cpu.pprof sql_stages=%s/CANDIDATE/FINALIZER_BREAKDOWN.txt authoritative=0 accepted=0\n' "$count" "$out" "$out" |
  tee -a "$out/SUMMARY.txt"
 exit 0
;;
bulk-full)
 # The CONTROL cluster is the unchanged three-window source-prefix control.
 # Only CANDIDATE processes the complete remainder: 114 real signed W128 windows.
 # A zero runtime is intentional: do not misreport a time-limited partial
 # ingestion as successful full-generation verification.
 [ "$(sql CANDIDATE "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 8192 ] ||
   die "CANDIDATE full-generation WAL is not 8 GiB"
 [ "$(sql CANDIDATE "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))>0")" = t ] ||
   die "CANDIDATE full-generation optimized begin function is not installed"
 [ "$(sql CANDIDATE "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.finish_security_field_window(integer,bigint)'::regprocedure))=0")" = t ] ||
   die "CANDIDATE full-generation finalization function changed unexpectedly"
 printf 'FI BULK FULL OPTIMIZATION ACTIVE arm=CANDIDATE indexes=built_on_attach event_copy=legacy source_records=15140785 windows=117 wal_mb=8192 runtime=until_complete\n' |
   tee -a "$out/SUMMARY.txt"
 run_arm CANDIDATE
 # Full source, relational, and SQL integrity gates have passed in run_arm.
 # Preserve the entire descriptor chain plus independently check that the
 # signed original three-window prefix is unmodified by the experiment.
 descriptor="SELECT window_index::text || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index"
 sql CANDIDATE "$descriptor" > "$out/CANDIDATE/checkpoints.tsv"
 sql CONTROL "$descriptor" > "$out/CONTROL/checkpoints.tsv"
 awk -F '|' '$1<3' "$out/CANDIDATE/checkpoints.tsv" > "$out/CANDIDATE/seed-prefix.tsv"
 cmp -s "$out/CANDIDATE/seed-prefix.tsv" "$out/CONTROL/checkpoints.tsv" ||
   die "full-generation original signed three-window prefix changed"
 [ "$(wc -l < "$out/CANDIDATE/checkpoints.tsv" | tr -d ' ')" = 117 ] ||
   die "full-generation descriptor chain length not 117"
 # Confirm all 114 new field partitions retain validated PK, FK, CHECK,
 # plus attached versions of every parent index. This is a metadata query:
 # it never recounts 180+ million Security field rows.
 full_constraints=$(sql CANDIDATE "
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
 readback CANDIDATE
 # Readback is AFTER the timed processing, so it does not bias throughput.
 printf 'FI BULK FULL PASS output=%s checkpoint=117|15140785|116 sql_integrity=PASS signed_batches=identical source_prefix=unchanged authoritative=0 accepted=0 full_generation_verified=true\n' "$out" |
   tee -a "$out/SUMMARY.txt"
 exit 0
;;
single30|profile30)
 [ "$(sql CANDIDATE "SELECT setting FROM pg_settings WHERE name='max_wal_size'")" = 8192 ] || die "30m WAL not 8GB"
 run_arm CANDIDATE
 readback CANDIDATE
 sql CANDIDATE "SELECT window_index::text || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index" > "$out/CANDIDATE/checkpoints.tsv"
 if [ "$experiment" = profile30 ]; then
  pglog="$jailroot$root/CANDIDATE/postgres.log"
  [ -f "$pglog" ] || die "private PostgreSQL server log missing"
  # Extract only the finalizer's own PostgreSQL RAISE LOG records. The
  # earlier preflight marker deliberately does not match this prefix.
  awk '
    /FI_PRIVATE_FIELD_PROFILE window=/ {
      line = $0
      sub(/^.*FI_PRIVATE_FIELD_PROFILE /, "FI_PRIVATE_FIELD_PROFILE ", line)
      print line
    }
  ' "$pglog" > "$out/CANDIDATE/field-finalize-stages.log" ||
    die "private finalizer telemetry extraction failed"
  committed=$(wc -l < "$out/CANDIDATE/stages.txt" | tr -d ' ')
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
  ' "$out/CANDIDATE/checkpoints.tsv" "$out/CANDIDATE/field-finalize-stages.log" > "$out/CANDIDATE/field-finalize-summary.txt"; then
    tail -n 50 "$out/CANDIDATE/field-finalize-summary.txt" >&2 || :
    die "private finalizer telemetry does not match committed checkpoints"
  fi
  cat "$out/CANDIDATE/field-finalize-summary.txt"
 fi
 printf 'FI PRIVATE 30M PASS output=%s experiment=%s sql_and_signed_readback=PASS original_count_verifier=true authoritative=0 accepted=0\n' "$out" "$experiment" | tee -a "$out/SUMMARY.txt"
 printf 'FI PRIVATE 30M FILES: %s/CANDIDATE/{result,stages,windows,pg-waits,iostat,vmstat,process}.txt_or_log\n' "$out" | tee -a "$out/SUMMARY.txt"
 exit 0
;;
esac
if [ "$order" = reverse ];then
 run_arm CANDIDATE
 run_arm CONTROL
else
 run_arm CONTROL
 run_arm CANDIDATE
fi
# Readback is deliberately AFTER BOTH timed tests. Reading every source
# batch after the control but before the candidate would artificially warm
# the candidate source cache and bias the A/B comparison.
readback CONTROL
readback CANDIDATE
case "$experiment" in bulk-index|bulk-event|fk-memory)
 # Confirm no essential DB property vanished when indexes were delayed.
 for arm in CONTROL CANDIDATE; do
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
 printf 'FI BULK INDEX CONSTRAINTS PASS arms=CONTROL,CANDIDATE windows=3,4 PK=valid FK=validated range=validated parent_indexes=attached\n' | tee -a "$out/SUMMARY.txt"
;; esac
# Compare the signed descriptor chain for every COMMON completed window,
# independent of CONTROL/CANDIDATE's differing completion counts in ten minutes.
descriptor="SELECT window_index::text || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index"
sql CONTROL "$descriptor" > "$out/CONTROL/checkpoints.tsv"
sql CANDIDATE "$descriptor" > "$out/CANDIDATE/checkpoints.tsv"
lastControl=$(tail -n 1 "$out/CONTROL/checkpoints.tsv" | cut -d '|' -f1)
lastCandidate=$(tail -n 1 "$out/CANDIDATE/checkpoints.tsv" | cut -d '|' -f1)
common=$lastControl
[ "$lastCandidate" -lt "$common" ] && common=$lastCandidate
awk -F '|' -v limit="$common" '$1<=limit' "$out/CONTROL/checkpoints.tsv" > "$out/CONTROL/common.tsv"
awk -F '|' -v limit="$common" '$1<=limit' "$out/CANDIDATE/checkpoints.tsv" > "$out/CANDIDATE/common.tsv"
diff -u "$out/CONTROL/common.tsv" "$out/CANDIDATE/common.tsv" > "$out/common.diff" || die "common signed source checkpoint chain differs"
printf 'FI BENCH AB COMMON PREFIX PASS through_window=%s descriptors_identical=true\n' "$common" | tee -a "$out/SUMMARY.txt"
# Calculate exact per-run cumulative PostgreSQL 18 counters.
awk -F '|' '
FNR==1 {
 arm=(FILENAME ~ /\/CONTROL\// ? "CONTROL" : "CANDIDATE")
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
 printf "%-29s %17s %17s %12s\n","METRIC","CONTROL CONTROL","CANDIDATE CANDIDATE","DELTA"
 for(j=1;j<=3;j++){
  count=(j==1?6:j==2?3:4)
  for(i=1;i<=count;i++){
   a=metric["CONTROL","after",j,i]-metric["CONTROL","before",j,i]
   b=metric["CANDIDATE","after",j,i]-metric["CANDIDATE","before",j,i]
   printf "%-29s %17.0f %17.0f %+12.0f\n",names[j,i],a,b,b-a
  }
 }
}' "$out/CONTROL/before.stats" "$out/CONTROL/after.stats" \
 "$out/CANDIDATE/before.stats" "$out/CANDIDATE/after.stats" | tee "$out/COUNTERS_DELTA.txt"
grep -E '^FI (TEN MINUTE STOP|PRIVATE EXACT WINDOW STOP) ' "$out/CONTROL/result.txt" "$out/CANDIDATE/result.txt" | tee "$out/THROUGHPUT_COMPARISON.txt"
if [ "$experiment" = fk-memory ]; then
 for arm in CONTROL CANDIDATE; do
  pglog="$jailroot$root/$arm/postgres.log"
  [ -f "$pglog" ] || die "$arm SQL profiler log missing"
  awk '/FI_PRIVATE_FIELD_PROFILE window=/ {line=$0;sub(/^.*FI_PRIVATE_FIELD_PROFILE /,"FI_PRIVATE_FIELD_PROFILE ",line);print line}' "$pglog" > "$out/$arm/field-profiler.log"
  sql "$arm" "SELECT window_index FROM fi_recovery.typed_window WHERE window_index>=3 ORDER BY window_index" > "$out/$arm/committed-windows.txt"
  if ! awk '
   function value(k,  i,a){for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]==k)return a[2]}return ""}
   FNR==NR{if($1!~/^[0-9]+$/||($1 in expected)){bad=1;exit 1};expected[$1]=1;committed++;next}
   {
    w=value("window");fk=value("fk_validate_ms")
    if($1!="FI_PRIVATE_FIELD_PROFILE"||w!~/^[0-9]+$/||!(w in expected)||++seen[w]!=1||fk!~/^[0-9]+([.][0-9]+)?$/){bad=1;exit 1}
    samples++
   }
   END{if(bad||committed<2||committed!=samples)exit 1;for(w in expected)if(seen[w]!=1)exit 1}
  ' "$out/$arm/committed-windows.txt" "$out/$arm/field-profiler.log"; then
   die "$arm profile is not 1:1 with committed signed windows"
  fi
  printf 'FI FK MEMORY LOG PASS arm=%s committed_windows=%s\n' "$arm" "$(wc -l < "$out/$arm/committed-windows.txt" | tr -d ' ')" | tee -a "$out/SUMMARY.txt"
 done
 if ! awk '
  function value(k,  i,a){for(i=1;i<=NF;i++){split($i,a,"=");if(a[1]==k)return a[2]}return ""}
  FNR==NR{w=value("window");ref[w]=value("fk_validate_ms")+0;next}
  {w=value("window");if(w in ref){
   a=ref[w];b=value("fk_validate_ms")+0
   printf "window=%s control_fk_ms=%.3f candidate_fk_ms=%.3f difference_ms=%+.3f\n",w,a,b,b-a
   matches++;sumA+=a;sumB+=b
  }}
  END{if(matches<2)exit 1;printf "MATCHED=%d CONTROL_FK_MS=%.3f CANDIDATE_FK_MS=%.3f DIFFERENCE_MS=%+.3f\n",matches,sumA,sumB,sumB-sumA}
 ' "$out/CONTROL/field-profiler.log" "$out/CANDIDATE/field-profiler.log" > "$out/FK_MEMORY_COMPARISON.txt"; then
  die "FK memory A/B comparison failed"
 fi
 cat "$out/FK_MEMORY_COMPARISON.txt"
 printf 'FI FK MEMORY AB PASS duration=10m_per_arm both_integrity=PASS common_signed_prefix=identical control=4MB candidate=64MB authoritative=0 accepted=0 output=%s\n' "$out" | tee -a "$out/SUMMARY.txt"
fi
if [ "$experiment" = bulk-event ]; then
 # Ten-minute wall-clock timebox for EACH independent arm. Different
 # committed window counts are expected; only identical common signed
 # prefixes can be compared directly. No partial window counts as durable.
 for name in CONTROL CANDIDATE; do
  [ "$(wc -l < "$out/$name/windows.txt" | tr -d ' ')" -ge 2 ] ||
   die "$name completed fewer than two durable W128 windows in 10 minutes"
  grep -q '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$out/$name/result.txt" ||
   die "$name did not stop at the 10m deadline with custody preserved"
 done
 for name in CONTROL CANDIDATE; do
  awk -v arm="$name" '
   /^FI PRIVATE STAGE PROFILE / {
    window=""; records=""; typed=""; envelope=""; event=""
    for (i=1;i<=NF;i++) {
     split($i,kv,"=")
     if(kv[1]=="index") window=kv[2]
     if(kv[1]=="records") records=kv[2]
     if(kv[1]=="typed_total") typed=kv[2]
     if(kv[1]=="envelope_prepare") envelope=kv[2]
     if(kv[1]=="security_event_copy") event=kv[2]
    }
    printf "arm=%s window=%s records=%s typed_total=%s envelope_prepare=%s security_event_copy=%s\n",arm,window,records,typed,envelope,event
   }' "$out/$name/stages.txt"
 done | tee "$out/EVENT_COPY_AB_STAGES.txt"
 # The Go stop marker prints durable-wall rate, checkpoint rate, and
 # committed-window rate. Retain all three: no inferred throughput.
 grep '^FI TEN MINUTE STOP ' "$out/CONTROL/result.txt" "$out/CANDIDATE/result.txt" |
  tee "$out/EVENT_COPY_AB_DURABLE_RATES.txt"
 printf 'FI EVENT COPY AB PASS duration=10m_per_arm common_prefix=identical control=legacy candidate=reusable both_chunk=32768 both=deferred_indexes durability=on accepted=0 authoritative=0 output=%s\n' "$out" |
  tee -a "$out/SUMMARY.txt"
fi
printf 'FI BENCH AB COMPLETE output=%s experiment=%s order=%s timing=%s control_wal_mb=%s candidate_wal_mb=8192 signed_data=identical independent_real_db=true\n' "$out" "$experiment" "$order" "$timing" "$expectedControlWal" | tee -a "$out/SUMMARY.txt"
printf 'FI BENCH AB COUNTER FILES: %s/CONTROL/{before,after}.stats and %s/CANDIDATE/{before,after}.stats\n' "$out" "$out"
