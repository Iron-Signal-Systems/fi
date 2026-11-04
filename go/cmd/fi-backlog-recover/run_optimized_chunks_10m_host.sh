#!/bin/sh
# FI DEV ONLY: optimized-only K32 and K64, each 10 minutes, same signed source.
# Run on fi-backend-b HOST as root. Source 55962 is read-only; no baseline rerun.
set -eu
umask 077
die(){ printf 'FI OPTFIELD 10M STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] || die 'FreeBSD host root required'
command -v jexec >/dev/null 2>&1 || die 'jexec missing'
ref=176daf7c0076ce66bff05dd3af7a126bb5da73dd
url="https://raw.githubusercontent.com/Iron-Signal-Systems/fi/$ref/go/cmd/fi-backlog-recover"
for item in optimized_chunks_provision_jail.sh:fi-optfield-10m-provision.sh optfield/relay.go:fi-optfield-10m-relay.go; do
 remote=${item%%:*};localname=${item#*:}
 jexec -U jwood fi-dev fetch -q -o "/home/jwood/$localname" "$url/$remote" || die "GitHub HTTPS fetch: $remote"
 jexec -U jwood fi-dev test -s "/home/jwood/$localname" || die "empty helper: $remote"
done
jexec -U jwood fi-dev sh -n /home/jwood/fi-optfield-10m-provision.sh || die 'provision syntax'
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root="/home/jwood/fi-window-bench-optfield-$stamp"
out="/var/tmp/fi-window-chunks-optfield-$stamp"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$cache" ] || die 'previous verified cache missing'
[ "$(find "$cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')" = 8399 ] || die '8399 signed batches not cached'
[ "$(find "$cache" -name verified.json -type f | wc -l | tr -d ' ')" = 1 ] || die 'verified marker not unique'
[ ! -e "$out" ] && [ ! -e "/usr/local/jails/containers/fi-dev$root" ] || die 'new destination exists'
printf 'FI OPTFIELD PREP optimized_only=yes chunks=32768,65536 atomic=W128 source=existing_verified_cache starting_window=3\n'
jexec -U jwood fi-dev sh /home/jwood/fi-optfield-10m-provision.sh "$root" || die 'clone/provision failed'
hostroot="/usr/local/jails/containers/fi-dev$root"
recover="$hostroot/fi-optfield-recover"
relay="$hostroot/fi-optfield-relay"
[ -x "$recover" ] && [ -x "$relay" ] || die 'new binaries not executable'
[ "$(sha256 -q "$recover")" = "$(cat "$hostroot/recover.sha256")" ] || die 'binary SHA mismatch'
[ "$(sha256 -q "$relay")" = "$(cat "$hostroot/relay.sha256")" ] || die 'relay SHA mismatch'
mkdir -m 700 "$out"
for p in K32 K64; do mkdir -m 700 "$out/$p" "$out/$p/private"; done
cat > "$out/RUN_MANIFEST.txt" <<EOF
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
signed_records=15140785
original_batches=8399
cache=$cache
postgres_root=$root
seed=accepted_optimized_windows_0_1_2
seed_durable_records=390387
window=W128
security_profile=P3
file_profile=F3
K32=32768
K64=65536
duration_each=10m
canonical_writes=disabled
recover_sha256=$(cat "$hostroot/recover.sha256")
source_worktree_status=$root/source-status.txt
EOF
: > "$out/SUMMARY.txt"
"$relay" -cluster-root="$root" -output-root="$out" -base-port=55981 -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
mvmp=;miop=;mpsp=;mpgp=
stopmon(){ for pid in $mvmp $miop $mpsp $mpgp; do kill "$pid" 2>/dev/null || :;wait "$pid" 2>/dev/null || :;done;mvmp=;miop=;mpsp=;mpgp=; }
cleanup(){ stopmon;kill "$relaypid" 2>/dev/null || :;wait "$relaypid" 2>/dev/null || :; }
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15
n=0
while :; do
 if [ "$(grep -c '^FI PG RELAY READY profile=' "$out/relay.log" 2>/dev/null || :)" = 2 ]; then break;fi
 kill -0 "$relaypid" 2>/dev/null || { cat "$out/relay.log" >&2;die 'relay died'; }
 n=$((n+1));[ "$n" -lt 30 ] || die 'relay startup timeout';sleep 1
done
cat "$out/relay.log"
sql(){ p=$1;q=$2;case "$p" in K32) port=55981;;K64) port=55982;;*)die 'bad profile';;esac
 jexec -U jwood fi-dev psql "host=$root/$p/socket port=$port user=fi_ingest dbname=fi sslmode=disable" -X -qAt -v ON_ERROR_STOP=1 -c "$q"
}
checkpoint_sql="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window"
digest_sql="SELECT md5(coalesce(string_agg(window_index::text || ':' || encode(descriptor_sha256,'hex') || ':' || committed_records::text, '|' ORDER BY window_index),'')) FROM fi_recovery.typed_window"
initial=
for p in K32 K64; do
 [ "$(sql "$p" "$checkpoint_sql")" = '3|390387|2' ] || die "$p starting checkpoint mismatch"
 d=$(sql "$p" "$digest_sql") || die "$p digest query failed"
 if [ -z "$initial" ];then initial=$d;else [ "$initial" = "$d" ] || die 'clones have different signed source checkpoint digests';fi
 [ "$(sql "$p" 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "$p authoritative rows"
 printf 'FI OPTFIELD PREFLIGHT profile=%s checkpoint=3|390387|2 digest=%s authority=0\n' "$p" "$d" | tee -a "$out/SUMMARY.txt"
done
for p in K32 K64; do
 case "$p" in K32) chunk=32768;port=55981;;K64) chunk=65536;port=55982;;esac
 dir="$out/$p"
 dsn="host=$out/pg-$p port=$port user=fi_ingest dbname=fi sslmode=disable"
 if command -v vmstat >/dev/null 2>&1; then vmstat -w 15 > "$dir/vmstat.log" 2>&1 & mvmp=$!;fi
 if command -v iostat >/dev/null 2>&1; then iostat -x -w 15 > "$dir/iostat.log" 2>&1 & miop=$!;fi
 (while :; do date -u '+UTC %Y-%m-%dT%H:%M:%SZ';ps -axo pid,ppid,%cpu,%mem,rss,comm | awk 'NR==1 || /fi-optfield-recover|postgres|postmaster/' || :;sysctl -n kern.cp_times || :;sleep 15;done) > "$dir/process.log" 2>&1 & mpsp=$!
 (while :; do date -u '+UTC %Y-%m-%dT%H:%M:%SZ';sql "$p" "SELECT pid::text || '|' || state || '|' || coalesce(wait_event_type,'CPU') || ':' || coalesce(wait_event,'-') FROM pg_stat_activity WHERE backend_type='client backend' AND usename='fi_ingest' AND pid<>pg_backend_pid() ORDER BY pid" || :;sleep 15;done) > "$dir/pg-waits.log" 2>&1 & mpgp=$!
 beforewal=$(sql "$p" "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal") || die "$p missing WAL counters"
 beforeckpt=$(sql "$p" "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer") || die "$p missing checkpoint counters"
 printf '%s FI OPTFIELD 10M START profile=%s chunk=%s outer=W128 original_archive_scans=0\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$p" "$chunk" | tee -a "$out/SUMMARY.txt"
 if ! "$recover" -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="$dsn" -custody-root=/var/db/fi/custody/generation \
  -recorded-root=/var/db/fi/custody/recorded -source-namespaces=false \
  -private-root="$dir/private" -private-writes -private-field-partitions \
  -security-profile=P3 -file-profile=F3 -window-profile=W128 \
  -processing-chunk-records="$chunk" -continuous-private \
  -start-window=3 -max-windows=0 -max-runtime=10m \
  -verified-cache-root="$cache" > "$dir/recover.log" 2>&1; then
  stopmon;tail -n 50 "$dir/recover.log" >&2 || :;die "$p optimized ingest failed"
 fi
 stopmon
 grep '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$dir/recover.log" > "$dir/result.txt" || die "$p missing 10m stop result"
 cat "$dir/result.txt" | tee -a "$out/SUMMARY.txt"
 grep '^FI PRIVATE STAGE PROFILE' "$dir/recover.log" > "$dir/stages.txt" || die "$p no committed window metrics"
 afterwal=$(sql "$p" "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal") || die "$p after WAL unavailable"
 afterckpt=$(sql "$p" "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer") || die "$p after checkpoints unavailable"
 printf 'FI OPTFIELD COUNTERS profile=%s wal_before=%s wal_after=%s ckpt_before=%s ckpt_after=%s\n' "$p" "$beforewal" "$afterwal" "$beforeckpt" "$afterckpt" | tee -a "$out/SUMMARY.txt"
 state=$(sql "$p" "$checkpoint_sql") || die "$p checkpoint SQL"
 printf 'FI OPTFIELD SQL CHECKPOINT profile=%s state=%s\n' "$p" "$state" | tee -a "$out/SUMMARY.txt"
 durable=$(printf '%s' "$state" | cut -d '|' -f 2)
 [ "$durable" -gt 390387 ] || die "$p no newly durable windows"
 valid=$(sql "$p" "SELECT CASE WHEN (SELECT count(*) FROM fi_recovery.source_window)=(SELECT count(*) FROM fi_recovery.typed_window) AND (SELECT count(*) FROM fi_recovery.pending_source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window) AND (SELECT count(*) FROM fi_recovery_projection.source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window) AND (SELECT count(*) FROM fi.recorded_generation)=0 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0 THEN 'PASS' ELSE 'FAIL' END") || die "$p integrity SQL"
 [ "$valid" = PASS ] || die "$p integrity mismatch"
 sql "$p" "SELECT window_index::text || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index" > "$dir/checkpoints.txt" || die "$p checkpoint export"
 part=$(sql "$p" "SELECT count(*) FROM pg_inherits WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass") || die "$p partitions"
 printf 'FI OPTFIELD INTEGRITY PASS profile=%s durable_records=%s partitions=%s authoritative=0 accepted=0\n' "$p" "$durable" "$part" | tee -a "$out/SUMMARY.txt"
done
last32=$(tail -n 1 "$out/K32/checkpoints.txt" | cut -d '|' -f 1)
last64=$(tail -n 1 "$out/K64/checkpoints.txt" | cut -d '|' -f 1)
common=$last32
if [ "$last64" -lt "$common" ];then common=$last64;fi
awk -F '|' -v n="$common" '$1<=n' "$out/K32/checkpoints.txt" > "$out/common-K32.txt"
awk -F '|' -v n="$common" '$1<=n' "$out/K64/checkpoints.txt" > "$out/common-K64.txt"
diff -u "$out/common-K32.txt" "$out/common-K64.txt" > "$out/common-checkpoints.diff" || die 'common signed checkpoint prefix differs'
printf 'FI OPTFIELD COMMON PREFIX PASS through_window=%s same_signed_descriptors=true\n' "$common" | tee -a "$out/SUMMARY.txt"
printf 'FI OPTFIELD 10M COMPLETE optimized_only=true results=%s\n' "$out" | tee -a "$out/SUMMARY.txt"
