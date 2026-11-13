#!/bin/sh
# FI W512 Candidate A two-window pilot, indices 1 and 2.
# Test ONLY against an OFFLINE COPY of the validated private W512 seed.
# No W128 checkpoint, canonical SoR write or Accepted publication.
set -eu
umask 077
fail(){ printf 'FI W512 PILOT STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$#" -eq 1 ] && [ "$1" = h16 ] || fail 'run as root with h16'
seed=/home/jwood/fi-window-bench-w512-20261113T205026Z
seedout=/var/tmp/fi-window-chunks-h16-w512-seed-20261113T205026Z
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
seedhash=ff58478b40ca35f1f6cc5e52aa0300de6371ed58243c41f34e4f20ad6d61a319
name=clone-w512-2g
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root=/home/jwood/fi-window-bench-w512-p2-$stamp
out=/var/tmp/fi-window-chunks-h16-w512-p2-$stamp
port=55983
jailroot=$(jls -j fi-dev path) || fail 'fi-dev missing'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev JID missing'
sorjid=$(jls -j fi-sor-db jid) || fail 'fi-sor-db JID missing'
[ "$devjid" != "$sorjid" ] || fail 'SoR and dev jails match'
jexec fi-sor-db service postgresql status >/dev/null 2>&1 || fail 'real SoR unavailable'
existing=$(ps -axww -o pid,jid,user,rss,command | awk -v jid="$devjid" '
$2==jid && $5=="/usr/local/bin/postgres" && $6=="-D" {n++} END{print n+0}')
[ "$existing" = 0 ] || fail 'existing dev PostgreSQL postmaster; pilot not started'
[ -d "$jailroot$seed/$name/data" ] && [ ! -e "$jailroot$root" ] && [ ! -e "$out" ] ||
    fail 'W512 seed unavailable or new pilot path collides'
[ -d "$cache" ] && [ ! -L "$cache" ] || fail 'previous receiver-admitted verified cache missing'
[ "$(sha256 -q "$seedout/fi-w512-private-seed-20261113T205026Z.tar.gz")" = \
  77d378fad4fd8a4cb0cee6e4f9c46bce644590de1fda7d818a5ab8891e6489ce ] ||
    fail 'W512 accepted seed evidence SHA changed'
[ "$(cat "$seedout/$name/W512_SEED_CHECKPOINT.tsv")" = "0|493478|$seedhash" ] ||
    fail 'W512 accepted seed descriptor changed'
grep -Fq 'FI W512/2G FRESH SIGNED SEED ACCEPTED windows=1 typed_records=493478 fields=6194967 authoritative=0 accepted=0' "$seedout/SUMMARY.txt" ||
    fail 'W512 accepted seed record gate missing'
jexec -U jwood fi-dev pg_ctl -D "$seed/$name/data" status >/dev/null 2>&1 &&
    fail 'W512 seed PostgreSQL must be stopped'
socket="$root/$name/socket/.s.PGSQL.$port"
rsocket="$out/pg-$name/.s.PGSQL.$port"
[ "$(printf %s "$socket" | wc -c)" -le 103 ] &&
[ "$(printf %s "$rsocket" | wc -c)" -le 103 ] || fail 'socket length exceeds FreeBSD limit'
case "$out" in /var/tmp/fi-window-chunks-*) ;; *) fail 'relay path allowlist mismatch';; esac
relaypid=
iostatpid=
vmstatpid=
cleanup(){
    code=$?
    trap - 0 1 2 15
    for pid in "$iostatpid" "$vmstatpid" "$relaypid"; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    done
    if [ -d "$jailroot$root/$name/data" ] &&
       jexec -U jwood fi-dev pg_ctl -D "$root/$name/data" status >/dev/null 2>&1; then
        jexec -U jwood fi-dev pg_ctl -D "$root/$name/data" -m fast -w -t 60 stop ||
            { echo 'WARNING: W512 pilot PostgreSQL failed to stop' >&2; code=1; }
    fi
    printf 'FI W512 PILOT FINISHED exit=%s outputs=%s private_clone=%s original_seed_unchanged=true\n' "$code" "$out" "$root"
    exit "$code"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15
jexec -U jwood fi-dev sh -s "$seed" "$root" "$name" "$port" <<'JAIL'
set -eu
umask 077
seed=$1
root=$2
name=$3
port=$4
[ "$(id -un)" = jwood ] && [ "$(psql --version)" = 'psql (PostgreSQL) 18.6' ] || exit 1
[ ! -e "$root" ] && [ ! -e "$seed/$name/data/postmaster.pid" ] || exit 1
pg_ctl -D "$seed/$name/data" status >/dev/null 2>&1 && exit 1
mkdir -m 700 "$root" "$root/$name" "$root/$name/socket" || exit 1
cp -R "$seed/$name/data" "$root/$name/data" || exit 1
[ "$(cat "$root/$name/data/PG_VERSION")" = 18 ] || exit 1
for f in fi-optfield-recover fi-optfield-relay recover.sha256 relay.sha256; do
    cp "$seed/$f" "$root/$f" || exit 1
done
[ "$(sha256 -q "$root/fi-optfield-recover")" = "$(cat "$root/recover.sha256")" ] || exit 1
[ "$(sha256 -q "$root/fi-optfield-relay")" = "$(cat "$root/relay.sha256")" ] || exit 1
pg_ctl -D "$root/$name/data" -l "$root/$name/postgres.log" \
  -o "-p $port -k $root/$name/socket -c listen_addresses= -c unix_socket_permissions=0700" \
  -w start > "$root/$name/start.log" 2>&1 || exit 1
echo 'FI W512 PILOT OFFLINE SEED COPY PASS'
JAIL
mkdir -m 700 "$out" "$out/$name" "$out/$name/private" || fail 'private output initialization failed'
recover="$jailroot$root/fi-optfield-recover"
relay="$jailroot$root/fi-optfield-relay"
[ "$(sha256 -q "$recover")" = "$(cat "$jailroot$root/recover.sha256")" ] ||
    fail 'W512 recovery executable SHA mismatch'
[ "$(sha256 -q "$relay")" = "$(cat "$jailroot$root/relay.sha256")" ] ||
    fail 'W512 relay executable SHA mismatch'
"$relay" -cluster-root="$root" -output-root="$out" \
  -base-port="$port" -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
tries=0
while ! grep -Fq "FI PG RELAY READY profile=$name port=$port" "$out/relay.log" 2>/dev/null; do
    kill -0 "$relaypid" 2>/dev/null || fail 'W512 relay exited'
    [ "$tries" -lt 30 ] || fail 'W512 relay startup timeout'
    tries=$((tries+1))
    sleep 1
done
sql(){
    jexec -U jwood fi-dev psql \
      "host=$root/$name/socket port=$port user=fi_ingest dbname=fi sslmode=disable" \
      -X -qAt -v ON_ERROR_STOP=1 -c "$1"
}
state=$(sql "SELECT count(*)::text||'|'||sum(committed_records)::text||'|'||
  min(window_index)::text||'|'||max(window_index)::text||'|'||
  min(encode(descriptor_sha256,'hex')) FROM fi_recovery.typed_window")
[ "$state" = "1|493478|0|0|$seedhash" ] || fail "private W512 seed SQL state invalid: $state"
[ "$(sql 'SELECT count(*) FROM fi_recovery.source_window')" = 1 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 1 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery_projection.source_batch')" = 8399 ] &&
[ "$(sql 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 6194967 ] ||
    fail 'W512 copied seed schema, source metadata or field count invalid'
[ "$(sql 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] &&
[ "$(sql "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] ||
    fail 'canonical or Accepted rows present in private seed'
[ "$(sql 'SHOW max_wal_size')" = 1GB ] &&
[ "$(sql 'SHOW wal_buffers')" = 4MB ] || fail 'PostgreSQL WAL settings changed'
for f in fsync synchronous_commit full_page_writes; do
    [ "$(sql "SHOW $f")" = on ] || fail "PostgreSQL durability $f disabled"
done
cat > "$out/RUN_MANIFEST.txt" <<EOF
FI W512 CANDIDATE A TWO-WINDOW PRIVATE PILOT
source_seed=$seed
seed_descriptor=$seedhash
seed_records=493478
signed_cache=$cache
window_profile=W512
window_records_max=524288
window_source_bytes_max=2147483648
start_window=1
windows=2
K32=32768
workers=2
inflight_limit=4
sql_writers=1
private_only=true
authoritative_writes=forbidden
accepted_publication=forbidden
recover_sha256=$(sha256 -q "$recover")
EOF
stats(){
    phase=$1
    sql 'SELECT row_to_json(x)::text FROM (SELECT * FROM pg_stat_wal) x' > "$out/$name/wal_$phase.jsonl"
    sql 'SELECT row_to_json(x)::text FROM (SELECT * FROM pg_stat_checkpointer) x' > "$out/$name/checkpointer_$phase.jsonl"
    sql 'SELECT row_to_json(x)::text FROM (SELECT * FROM pg_stat_io) x' > "$out/$name/io_$phase.jsonl"
}
stats before || fail 'pre-run PostgreSQL stats unavailable'
iostat -x -w 5 > "$out/$name/iostat.txt" 2>&1 &
iostatpid=$!
vmstat -w 5 > "$out/$name/vmstat.txt" 2>&1 &
vmstatpid=$!
printf 'FI W512 CANDIDATE A PILOT START start_index=1 windows=2 workers=2 writer=1 K32=32768\n' | tee "$out/SUMMARY.txt"
if ! /usr/bin/time -l "$recover" \
  -private-w512-2g -private-hash-h16 \
  -private-mixed-family-buffers -private-dependency-buffers -private-parallel-prep-a \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="host=$out/pg-$name port=$port user=fi_ingest dbname=fi sslmode=disable" \
  -custody-root=/var/db/fi/custody/generation -recorded-root=/var/db/fi/custody/recorded \
  -source-namespaces=false -private-root="$out/$name/private" \
  -private-writes -private-field-partitions \
  -security-profile=P3 -file-profile=F3 -window-profile=W512 \
  -processing-chunk-records=32768 -continuous-private -start-window=1 \
  -max-windows=0 -max-runtime=0 -test-stop-after-windows=2 \
  -deferred-verified-clone -verified-cache-root="$cache" > "$out/$name/recover.log" 2>&1; then
    tail -n 100 "$out/$name/recover.log" >&2 || :
    fail 'W512 two-worker recovery rejected'
fi
for pid in "$iostatpid" "$vmstatpid"; do
    kill -TERM "$pid" 2>/dev/null || :
    wait "$pid" 2>/dev/null || :
done
iostatpid=
vmstatpid=
stats after || fail 'postrun PostgreSQL stats unavailable'
log="$out/$name/recover.log"
grep -Fq 'FI PRIVATE PARALLEL PREP A ENABLED workers=2 inflight=4 postgres_writers=1 source_window=W512 atomic=true' "$log" ||
    fail 'W512 Candidate A worker proof absent'
[ "$(grep -c '^FI REAL BACKLOG DURABLE ' "$log")" = 2 ] &&
[ "$(grep -c '^FI PRIVATE STAGE PROFILE ' "$log")" = 2 ] &&
[ "$(grep -c '^FI PRIVATE DEPENDENCY BUFFER PROOF ' "$log")" = 2 ] &&
[ "$(grep -c '^FI PRIVATE BATCH HASH ONCE window=' "$log")" = 2 ] ||
    fail 'W512 per-window instrumentation incomplete'
grep -q '^FI PRIVATE EXACT WINDOW STOP start=1 windows=2 last=2 records=' "$log" ||
    fail 'W512 exact two-window stop missing'
new=$(sql 'SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window WHERE window_index BETWEEN 1 AND 2')
case "$new" in ''|*[!0-9]*) fail 'invalid W512 new record count';; esac
[ "$new" -gt 0 ] && [ "$new" -le 1048576 ] || fail "invalid W512 record count $new"
total=$((493478+new))
integrity=$(sql "SELECT CASE WHEN
 (SELECT count(*) FROM fi_recovery.typed_window)=3
 AND (SELECT count(*) FROM fi_recovery.source_window)=3
 AND (SELECT count(*) FROM fi_recovery.verified_artifact_window)=3
 AND (SELECT count(*) FROM fi_recovery_projection.source_batch)=8399
 AND (SELECT count(*) FROM fi_recovery.pending_source_record)=$total
 AND (SELECT count(*) FROM fi_recovery_projection.source_record)=$total
 AND (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field)>6194967
 AND (SELECT count(*) FROM fi.recorded_generation)=0
 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0
 AND NOT EXISTS(SELECT 1 FROM fi_recovery.typed_window t
  LEFT JOIN fi_recovery.source_window s USING(receipt_sha256,window_index)
  LEFT JOIN fi_recovery.verified_artifact_window a USING(receipt_sha256,window_index)
  WHERE s.window_index IS NULL OR a.window_index IS NULL
  OR t.descriptor_sha256 IS DISTINCT FROM s.descriptor_sha256
  OR t.descriptor_sha256 IS DISTINCT FROM a.descriptor_sha256)
 AND (SELECT encode(descriptor_sha256,'hex') FROM fi_recovery.typed_window WHERE window_index=0)='$seedhash'
 THEN 'PASS' ELSE 'FAIL' END")
[ "$integrity" = PASS ] || fail 'W512 SQL source/typed/artifact integrity failed'
grep '^FI PRIVATE PARALLEL PREP BATCH ' "$log" > "$out/$name/PARALLEL_PREP.txt" ||
    fail 'parallel batch proof absent'
prep=$(awk '/^FI PRIVATE PARALLEL PREP BATCH /{
 delete f
 for(i=1;i<=NF;i++){split($i,a,"=");f[a[1]]=a[2]}
 if(f["workers"]!=2||f["inflight_limit"]!=4||f["writers"]!=1||
    f["reorder_peak"]+0>3||seen[f["batch"]]++)bad=1
 rows+=f["records"]+0;n++
 }END{if(bad||n==0)exit 1;printf "%.0f",rows}' "$out/$name/PARALLEL_PREP.txt") ||
    fail 'W512 parallel preparation invariant failed'
[ "$prep" = "$new" ] || fail "W512 prepared rows $prep do not equal $new"
grep '^FI PRIVATE BATCH HASH ONCE window=' "$log" > "$out/$name/HASH_ONCE.txt"
grep '^FI REAL BACKLOG DURABLE ' "$log" > "$out/$name/WINDOWS.txt"
grep '^FI REAL TYPED WINDOW ' "$log" > "$out/$name/COPY_CALLS.txt" ||
    fail 'W512 SQL COPY telemetry absent'
grep '^FI PRIVATE STAGE PROFILE ' "$log" > "$out/$name/STAGES.txt"
grep '^FI PRIVATE EXACT WINDOW STOP ' "$log" > "$out/$name/RESULT.txt"
elapsed=$(sed -n 's/.*committed_window_time=\([^ ]*\).*/\1/p' "$out/$name/RESULT.txt")
[ -n "$elapsed" ] || fail 'W512 elapsed time missing'
printf 'FI W512 TWO-WINDOW PILOT ACCEPTED windows=2 new_records=%s elapsed=%s workers=2 authoritative=0 accepted=0\n' \
    "$new" "$elapsed" | tee -a "$out/SUMMARY.txt"
bundle="$out/fi-w512-candidate-a-pilot2-$stamp.tar.gz"
tar -C "$out" -czf "$bundle" RUN_MANIFEST.txt SUMMARY.txt relay.log \
  "$name/recover.log" "$name/RESULT.txt" "$name/WINDOWS.txt" \
  "$name/COPY_CALLS.txt" "$name/STAGES.txt" "$name/PARALLEL_PREP.txt" \
  "$name/HASH_ONCE.txt" "$name/wal_before.jsonl" "$name/wal_after.jsonl" \
  "$name/checkpointer_before.jsonl" "$name/checkpointer_after.jsonl" \
  "$name/io_before.jsonl" "$name/io_after.jsonl" \
  "$name/iostat.txt" "$name/vmstat.txt" || fail 'W512 metrics bundle creation failed'
[ -s "$bundle" ] || fail 'W512 metrics bundle absent'
printf 'FI W512 PILOT METRICS BUNDLE PASS path=%s sha256=%s\n' "$bundle" "$(sha256 -q "$bundle")"
