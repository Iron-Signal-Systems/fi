#!/bin/sh
# FI DEV ONLY: K64 optimized 10-minute resume, no K32 rerun, no custody scan.
# On fi-backend-b HOST as root. K32's successful evidence is immutable.
set -eu
umask 077
die(){ printf 'FI OPTFIELD K64 STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] || die 'FreeBSD HOST root required'
root=/home/jwood/fi-window-bench-optfield-20261104T101811Z
hostroot="/usr/local/jails/containers/fi-dev$root"
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$hostroot/K32/data" ] && [ -d "$hostroot/K64/data" ] || die 'original isolated clusters missing'
[ -x "$hostroot/fi-optfield-relay" ] || die 'original relay missing'
[ "$(sha256 -q "$hostroot/fi-optfield-relay")" = "$(cat "$hostroot/relay.sha256")" ] || die 'relay SHA wrong'
[ -d "$cache" ] && [ "$(find "$cache" -name 'batch-*.data' -type f | wc -l | tr -d ' ')" = 8399 ] || die 'verified cache incomplete'
[ "$(find "$cache" -name verified.json -type f | wc -l | tr -d ' ')" = 1 ] || die 'verified receipt marker missing'
sql(){
 case "$1" in K32) port=55981;;K64) port=55982;;*)die 'bad profile';;esac
 jexec -U jwood fi-dev psql "host=$root/$1/socket port=$port user=fi_ingest dbname=fi sslmode=disable" -X -qAt -v ON_ERROR_STOP=1 -c "$2"
}
ckpt="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || max(window_index)::text FROM fi_recovery.typed_window"
[ "$(sql K32 "$ckpt")" = '12|1557265|11' ] || die 'K32 durable record count changed'
[ "$(sql K64 "$ckpt")" = '3|390387|2' ] || die 'K64 checkpoint is not untouched; refusing resume'
[ "$(sql K64 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 4838850 ] || die 'K64 seed field count wrong'
[ "$(sql K64 "SELECT count(*) FROM pg_inherits WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass")" = 3 ] || die 'K64 starting partitions wrong'
for profile in K32 K64;do
 [ "$(sql "$profile" 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "$profile canonical writes present"
 [ "$(sql "$profile" "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "$profile Accepted journal present"
done
for setting in fsync synchronous_commit full_page_writes;do
 [ "$(sql K64 "SHOW $setting")" = on ] || die "K64 $setting disabled"
done
# Fetch only from an immutable GitHub commit. Verify exact Git blob with installed git.
url=https://raw.githubusercontent.com/Iron-Signal-Systems/fi/14ed998659ec0a36e3262b31722bec95aef54f60/go/cmd/fi-backlog-recover/optfield/patcher/main.go
patch=/home/jwood/fi-optfield-allow-k64.go
jexec -U jwood fi-dev fetch -q -o "$patch" "$url" || die 'GitHub HTTPS patch fetch failed'
[ "$(jexec -U jwood fi-dev git hash-object "$patch")" = 72f62293b8d18a32551f7545cf462f0ab1a5b5cd ] || die 'GitHub patch blob hash mismatch'
# Surgically relax one local experimental guard. The original is saved in the clone.
jexec -U jwood fi-dev sh -c "cd /home/jwood/src/fi/go && go run '$patch' -backup-dir '$root'" || die 'local Go guard differs; no benchmark was run'
# New binary only. Do not replace previously measured K32 executable or DB.
jexec -U jwood fi-dev sh -c "cd /home/jwood/src/fi/go && go test ./cmd/fi-backlog-recover ./internal/recordingest && go build -o '$root/fi-optfield-recover-k64' ./cmd/fi-backlog-recover" || die 'Go tests/build failed; K64 database unchanged'
recover="$hostroot/fi-optfield-recover-k64"
[ -x "$recover" ] || die 'K64 binary missing'
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
out="/var/tmp/fi-window-chunks-optfield-k64-$stamp"
[ ! -e "$out" ] || die 'output exists'
mkdir -m 700 "$out" "$out/K64" "$out/K64/private"
printf 'FI OPTFIELD K64 PREFLIGHT clone=existing port=55982 checkpoint=3|390387|2 chunk=65536 outer=W128 original_custody_scans=0 binary_sha256=%s\n' "$(sha256 -q "$recover")" | tee "$out/SUMMARY.txt"
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI OPTFIELD OPTIMIZED K64 10M RESUME
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
cache=$cache
source_records=15140785
original_batches=8399
cluster_root=$root
reused_seed=3|390387|2
processing_chunk=65536
outer_window=W128
security=P3
file=F3
duration=10m
publication=disabled
recover_sha256=$(sha256 -q "$recover")
EOF
relay="$hostroot/fi-optfield-relay"
"$relay" -cluster-root="$root" -output-root="$out" -base-port=55981 -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
mv=;mi=;mp=;mw=
stopmon(){ for pid in $mv $mi $mp $mw;do kill "$pid" 2>/dev/null || :;wait "$pid" 2>/dev/null || :;done;mv=;mi=;mp=;mw=; }
cleanup(){ stopmon;kill "$relaypid" 2>/dev/null || :;wait "$relaypid" 2>/dev/null || :; }
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15
tries=0
while :;do
 [ "$(grep -c '^FI PG RELAY READY profile=' "$out/relay.log" 2>/dev/null || :)" = 2 ] && break
 kill -0 "$relaypid" 2>/dev/null || { tail -n 30 "$out/relay.log" >&2;die 'relay process stopped'; }
 tries=$((tries+1));[ "$tries" -lt 30 ] || die 'relay startup timeout';sleep 1
done
cat "$out/relay.log"
dir="$out/K64"
if command -v vmstat >/dev/null 2>&1;then vmstat -w 15 > "$dir/vmstat.log" 2>&1 &mv=$!;fi
if command -v iostat >/dev/null 2>&1;then iostat -x -w 15 > "$dir/iostat.log" 2>&1 &mi=$!;fi
(while :;do date -u '+UTC %Y-%m-%dT%H:%M:%SZ';ps -axo pid,ppid,%cpu,%mem,rss,comm | awk 'NR==1 || /fi-optfield-recover|postgres|postmaster/' || :;sysctl -n kern.cp_times || :;sleep 15;done) > "$dir/process.log" 2>&1 &mp=$!
(while :;do date -u '+UTC %Y-%m-%dT%H:%M:%SZ';sql K64 "SELECT pid::text || '|' || state || '|' || coalesce(wait_event_type,'CPU') || ':' || coalesce(wait_event,'-') FROM pg_stat_activity WHERE backend_type='client backend' AND usename='fi_ingest' AND pid<>pg_backend_pid() ORDER BY pid" || :;sleep 15;done) > "$dir/pg-waits.log" 2>&1 &mw=$!
beforewal=$(sql K64 "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal") || die 'WAL before'
beforeckpt=$(sql K64 "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer") || die 'checkpoints before'
printf '%s FI OPTFIELD 10M START profile=K64 chunk=65536 outer=W128 original_archive_scans=0\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$out/SUMMARY.txt"
if ! "$recover" -source=iss-fs-22a.iss.local \
 -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
 -postgres="host=$out/pg-K64 port=55982 user=fi_ingest dbname=fi sslmode=disable" \
 -custody-root=/var/db/fi/custody/generation -recorded-root=/var/db/fi/custody/recorded \
 -source-namespaces=false -private-root="$dir/private" -private-writes -private-field-partitions \
 -security-profile=P3 -file-profile=F3 -window-profile=W128 \
 -processing-chunk-records=65536 -continuous-private -start-window=3 -max-windows=0 -max-runtime=10m \
 -verified-cache-root="$cache" > "$dir/recover.log" 2>&1;then
 stopmon;tail -n 45 "$dir/recover.log" >&2 || :;die 'K64 recovery command failed'
fi
stopmon
grep '^FI TEN MINUTE STOP .*authoritative=0 accepted=0' "$dir/recover.log" > "$dir/result.txt" || die 'K64 timed result not found'
cat "$dir/result.txt" | tee -a "$out/SUMMARY.txt"
grep '^FI PRIVATE STAGE PROFILE' "$dir/recover.log" > "$dir/stages.txt" || die 'K64 no committed stage profiles'
afterwal=$(sql K64 "SELECT wal_bytes::text || '|' || wal_buffers_full::text FROM pg_stat_wal") || die 'WAL after'
afterckpt=$(sql K64 "SELECT num_requested::text || '|' || num_timed::text FROM pg_stat_checkpointer") || die 'checkpoints after'
printf 'FI OPTFIELD K64 COUNTERS wal_before=%s wal_after=%s ckpt_before=%s ckpt_after=%s\n' "$beforewal" "$afterwal" "$beforeckpt" "$afterckpt" | tee -a "$out/SUMMARY.txt"
state=$(sql K64 "$ckpt") || die 'checkpoint SQL'
durable=$(printf '%s' "$state" | cut -d '|' -f 2)
[ "$durable" -gt 390387 ] || die 'K64 no new durable source records'
integrity=$(sql K64 "SELECT CASE WHEN (SELECT count(*) FROM fi_recovery.source_window)=(SELECT count(*) FROM fi_recovery.typed_window) AND (SELECT count(*) FROM fi_recovery.pending_source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window) AND (SELECT count(*) FROM fi_recovery_projection.source_record)=(SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window) AND (SELECT count(*) FROM fi.recorded_generation)=0 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0 THEN 'PASS' ELSE 'FAIL' END") || die 'SQL integrity query'
[ "$integrity" = PASS ] || die 'SQL integrity failed'
part=$(sql K64 "SELECT count(*) FROM pg_inherits WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass") || die 'partition count'
windows=$(printf '%s' "$state" | cut -d '|' -f 1)
[ "$part" = "$windows" ] || die 'partition and checkpoint counts disagree'
# Compare common signed checkpoint descriptors, not identity-sequence values.
query="SELECT window_index::text || '|' || encode(descriptor_sha256,'hex') || '|' || committed_records::text FROM fi_recovery.typed_window ORDER BY window_index"
sql K32 "$query" > "$out/K32.checkpoints" || die 'K32 checkpoint export'
sql K64 "$query" > "$out/K64.checkpoints" || die 'K64 checkpoint export'
last32=$(tail -n 1 "$out/K32.checkpoints" | cut -d '|' -f 1)
last64=$(tail -n 1 "$out/K64.checkpoints" | cut -d '|' -f 1)
common=$last32
if [ "$last64" -lt "$common" ];then common=$last64;fi
awk -F '|' -v n="$common" '$1<=n' "$out/K32.checkpoints" > "$out/common-K32"
awk -F '|' -v n="$common" '$1<=n' "$out/K64.checkpoints" > "$out/common-K64"
diff -u "$out/common-K32" "$out/common-K64" > "$out/common.diff" || die 'signed checkpoint common prefix differs'
printf 'FI OPTFIELD K64 INTEGRITY PASS state=%s partitions=%s authoritative=0 accepted=0 common_through_window=%s descriptors_identical=true\n' "$state" "$part" "$common" | tee -a "$out/SUMMARY.txt"
printf 'FI OPTFIELD K64 COMPLETE output=%s K32_unchanged=true\n' "$out" | tee -a "$out/SUMMARY.txt"
