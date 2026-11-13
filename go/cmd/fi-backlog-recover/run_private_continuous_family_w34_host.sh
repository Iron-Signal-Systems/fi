#!/bin/sh
# FI DEV ONLY. Real signed W3-W4 continuous family replay.
# Execute as HOST root (fi-backend-b), never from fi-dev. Only a NEW isolated
# PostgreSQL clone receives SQL writes. W0-W2 seed, cache and SoR are unchanged.
set -eu
umask 077
fail(){ printf 'FI CONTINUOUS STOP: %s\n' "$*" >&2; exit 1; }
[ "$(hostname)" = fi-backend-b ] && [ "$(id -un)" = root ] || fail 'requires fi-backend-b root'
[ "$#" -eq 1 ] && [ "$1" = w34 ] || fail 'usage: sh run_private_continuous_family_w34_host.sh w34'
for x in jls jexec sha256 ps awk tar cmp iostat vmstat; do command -v "$x" >/dev/null 2>&1 || fail "missing $x"; done
pin=8eb1c5902f688a1acaf38076caa46ffd04022de6
jailroot=$(jls -j fi-dev path) || fail 'fi-dev missing'
devjid=$(jls -j fi-dev jid) || fail 'fi-dev JID missing'
sorjid=$(jls -j fi-sor-db jid) || fail 'SoR JID missing'
[ "$devjid" != "$sorjid" ] || fail 'jail ID collision'
jexec fi-sor-db service postgresql status >/dev/null 2>&1 || fail 'SoR must remain running'
active=$(ps -axww -o pid,jid,user,command | awk -v j="$devjid" '$2==j && $4=="/usr/local/bin/postgres" && $5=="-D"{n++} END{print n+0}')
[ "$active" -eq 0 ] || fail "fi-dev has $active active PostgreSQL postmasters"
seed=/home/jwood/fi-window-bench-fieldpart-20261104T091019Z/W64
cache=/var/tmp/fi-window-chunks-20261103T172254Z/verified-cache
[ -d "$jailroot$seed/data" ] && [ -d "$jailroot$seed/socket" ] || fail 'W0-W2 seed unavailable'
[ -d "$cache" ] && [ ! -L "$cache" ] || fail 'signed verified cache unavailable'
[ "$(find "$cache" -type f -name 'batch-*.data' | wc -l | tr -d ' ')" = 8399 ] || fail 'verified-cache must have exactly 8399 batch data files'
stamp=$(date -u '+%Y%m%dT%H%M%SZ')
root=/home/jwood/fi-window-bench-continuous-$stamp
name=clone-11-08-26
out=/var/tmp/fi-window-chunks-continuous-$stamp
[ ! -e "$jailroot$root" ] && [ ! -e "$out" ] || fail 'private clone/output collision'
relaypid= iostatpid= vmstatpid=
cleanup(){
 rc=$?
 trap - 0 1 2 15
 for pid in "$relaypid" "$iostatpid" "$vmstatpid"; do
  if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
 done
 for dir in "$root/$name/data" "$seed/data"; do
  if jexec -U jwood fi-dev pg_ctl -D "$dir" status >/dev/null 2>&1; then
   jexec -U jwood fi-dev pg_ctl -D "$dir" -m fast -w -t 60 stop ||
    { echo "FI CONTINUOUS CLEANUP STOP FAILED $dir" >&2; rc=1; }
  fi
 done
 printf 'FI CONTINUOUS FINISHED exit=%s output=%s private_db=%s/%s\n' "$rc" "$out" "$root" "$name"
 exit "$rc"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15
printf 'FI CONTINUOUS PRECHECK PASS signed_batches=8399 existing_seed=390387 source_pin=%s\n' "$pin"

# The interactive jwood SSH session (with Mac-forwarded SSH agent) fetches
# the pinned Git objects BEFORE this runner starts. This host-root jexec shell
# MUST NOT contact GitHub; it has no forwarded SSH agent. The detached
# /home/jwood/fi-deferred-experiment worktree is never changed.
jexec -U jwood fi-dev sh -s "$root" "$seed" "$name" "$pin" <<'JAIL'
set -eu
umask 077
fail(){ printf 'FI CONTINUOUS JAIL STOP: %s\n' "$*" >&2; exit 1; }
root=$1 seed=$2 name=$3 pin=$4
repo=/home/jwood/src/fi
src=$root/source
db=$root/$name
[ "$(id -un)" = jwood ] || fail 'wrong jail user'
[ "$(psql --version)" = 'psql (PostgreSQL) 18.6' ] || fail 'expected PostgreSQL 18.6'
git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || fail 'expected ~/src/fi Git repo'
git -C "$repo" cat-file -e "$pin^{commit}" || fail 'missing pinned experiment commit'
[ ! -e "$root" ] || fail 'private clone destination exists'
mkdir -m 700 "$root" "$src" "$db" "$db/socket"
git -C "$repo" archive "$pin" | tar -xf - -C "$src" || fail 'pinned source archive failed'
[ -f "$src/go/internal/recordingest/private_continuous_postgres_sink.go" ] ||
 fail 'wrong SQL family source'
[ -f "$src/go/cmd/fi-backlog-recover/testdata/private_continuous_projection_receipts_clone.sql" ] ||
 fail 'private-only receipt migration missing'
relay=$src/go/cmd/fi-backlog-recover/optfield/relay.go
grep -Fq 'var profiles = []string{"K32", "K64"}' "$relay" || fail 'relay profile anchor changed'
grep -Fq '!strings.HasPrefix(jailBinary,"/home/jwood/fi-window-bench-optfield-")' "$relay" ||
 fail 'relay executable anchor changed'
sed -e 's/var profiles = \[\]string{"K32", "K64"}/var profiles = []string{"clone-11-08-26"}/' \
 -e 's|!strings.HasPrefix(jailBinary,"/home/jwood/fi-window-bench-optfield-")|jailBinary != filepath.Join(clusterRoot,"fi-optfield-relay")|' \
 "$relay" > "$relay.tmp" && mv "$relay.tmp" "$relay"
grep -Fq 'var profiles = []string{"clone-11-08-26"}' "$relay" || fail 'relay patch failed'
(cd "$src/go" && GOTOOLCHAIN=auto go test ./internal/recordingest -run '^(TestPrivateContinuous|TestIndexedPrivateWindowLimitsAllowed|TestIndexedPrivateVerifiedCacheNoCurrentCRLButExactOriginalHashes)' -count=1) \
 > "$root/unit-tests.log" 2>&1 || { cat "$root/unit-tests.log" >&2; fail 'continuous router unit tests failed'; }
(cd "$src/go" && GOTOOLCHAIN=auto go build -o "$root/fi-continuous" ./cmd/fi-backlog-recover) ||
 fail 'continuous worker build failed'
(cd "$src/go" && GOTOOLCHAIN=auto go build -o "$root/fi-optfield-relay" ./cmd/fi-backlog-recover/optfield) ||
 fail 'private PostgreSQL relay build failed'
sha256 -q "$root/fi-continuous" > "$root/worker.sha256"
sha256 -q "$root/fi-optfield-relay" > "$root/relay.sha256"
printf 'FI CONTINUOUS BUILD PASS commit=%s tests=passed\n' "$pin"

# Start verified seed only for a consistent logical read, then shut it down.
pg_ctl -D "$seed/data" status >/dev/null 2>&1 && fail 'W0-W2 seed unexpectedly running'
pg_ctl -D "$seed/data" -l "$seed/postgres.log" \
 -o "-p 55962 -k $seed/socket -c listen_addresses= -c unix_socket_permissions=0700" -w start ||
 fail 'W0-W2 seed start failed'
sconn="host=$seed/socket port=55962 user=fi_m1_admin dbname=fi sslmode=disable"
qs(){ psql "$sconn" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
[ "$(qs "SELECT count(*)::text||'|'||coalesce(sum(committed_records),0)::text||'|'||max(window_index)::text FROM fi_recovery.typed_window")" = '3|390387|2' ] ||
 fail 'seed checkpoint differs from previously accepted W0-W2'
[ "$(qs 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 4838850 ] ||
 fail 'seed Security fields do not match'
[ "$(qs 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] ||
 fail 'seed is not isolated'
[ "$(qs "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] ||
 fail 'seed contains Accepted journal'
[ "$(qs "SELECT to_regclass('fi_recovery.projected_source_record') IS NULL")" = t ] ||
 fail 'seed already has continuous receipt table; refuse duplicate'
pg_dump "$sconn" -Fc -Z 1 -f "$root/verified-seed.dump" > "$root/dump.log" 2>&1 ||
 fail 'seed dump failed'
[ -s "$root/verified-seed.dump" ] || fail 'seed dump is empty'
sha256 -q "$root/verified-seed.dump" > "$root/verified-seed.sha256"
pg_ctl -D "$seed/data" -m fast -w -t 60 stop || fail 'seed shutdown failed'

initdb -D "$db/data" -U fi_m1_admin -A trust --no-instructions > "$db/initdb.log" 2>&1 ||
 fail 'private initdb failed'
pg_ctl -D "$db/data" -l "$db/postgres.log" \
 -o "-p 55981 -k $db/socket -c listen_addresses= -c unix_socket_permissions=0700" \
 -w start || fail 'private clone start failed'
adminpg="host=$db/socket port=55981 user=fi_m1_admin dbname=postgres sslmode=disable"
psql "$adminpg" -X -q -v ON_ERROR_STOP=1 -c 'CREATE ROLE fi_owner NOLOGIN' \
 -c 'CREATE ROLE fi_ingest LOGIN' > "$db/roles.log" 2>&1 ||
 fail 'private role provisioning failed'
createdb -h "$db/socket" -p 55981 -U fi_m1_admin -O fi_owner fi || fail 'private db create failed'
admin="host=$db/socket port=55981 user=fi_m1_admin dbname=fi sslmode=disable"
pg_restore --no-owner --exit-on-error --single-transaction \
 --dbname="$admin" "$root/verified-seed.dump" > "$db/restore.log" 2>&1 ||
 fail 'seed restore to private clone failed'
psql "$admin" -X -q -v ON_ERROR_STOP=1 \
 -f "$src/go/cmd/fi-backlog-recover/testdata/private_continuous_projection_receipts_clone.sql" \
 > "$db/private-receipts.log" 2>&1 || fail 'private receipt schema install failed'
conn="host=$db/socket port=55981 user=fi_ingest dbname=fi sslmode=disable"
q(){ psql "$conn" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
[ "$(q "SELECT count(*)::text||'|'||coalesce(sum(committed_records),0)::text||'|'||max(window_index)::text FROM fi_recovery.typed_window")" = '3|390387|2' ] ||
 fail 'cloned W0-W2 checkpoint differs'
[ "$(q 'SELECT count(*) FROM fi_recovery.projected_source_record')" = 0 ] ||
 fail 'projected receipt table must start empty'
[ "$(q 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || fail 'canonical generation not empty'
for setting in fsync synchronous_commit full_page_writes; do
 [ "$(q "SHOW $setting")" = on ] || fail "PostgreSQL $setting durability off"
done
printf 'FI CONTINUOUS CLONE READY seed=3|390387|2 db=fi port=55981 authoritative=0 accepted=0\n'
JAIL

worker=$jailroot$root/fi-continuous
bridge=$jailroot$root/fi-optfield-relay
[ -x "$worker" ] && [ -x "$bridge" ] || fail 'private binaries not present on host filesystem'
[ "$(sha256 -q "$worker")" = "$(cat "$jailroot$root/worker.sha256")" ] ||
 fail 'worker hash changed after build'
[ "$(sha256 -q "$bridge")" = "$(cat "$jailroot$root/relay.sha256")" ] ||
 fail 'relay hash changed after build'
mkdir -m 700 "$out" "$out/$name" "$out/$name/private"
printf 'pinned_commit=%s\nmode=continuous_source_first\nseed=3|390387|2\nsigned_batches=8399\nsecurity=P3\nfile=F3\nwindow=W128\nexpected_W3_W4_records=259178\nexpected_W3_W4_security=232879\nexpected_W4_USN=29\n' \
 "$pin" > "$out/MANIFEST.txt"
"$bridge" -cluster-root="$root" -output-root="$out" -base-port=55981 \
 -jail-binary="$root/fi-optfield-relay" > "$out/relay.log" 2>&1 &
relaypid=$!
ready=0
tries=0
while [ "$tries" -lt 30 ]; do
 if grep -Fq "FI PG RELAY READY profile=$name port=55981" "$out/relay.log" 2>/dev/null; then ready=1; break; fi
 kill -0 "$relaypid" 2>/dev/null || fail "relay exited: $(tail -n 5 "$out/relay.log")"
 tries=$((tries+1)); sleep 1
done
[ "$ready" = 1 ] || fail 'PostgreSQL relay handshake not ready'
sql(){ jexec -U jwood fi-dev psql \
 "host=$root/$name/socket port=55981 user=fi_ingest dbname=fi sslmode=disable" \
 -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
sql 'SELECT row_to_json(w)::text FROM pg_stat_wal w' > "$out/$name/wal-before.jsonl"
sql 'SELECT row_to_json(i)::text FROM pg_stat_io i' > "$out/$name/io-before.jsonl"
iostat -x -w 5 > "$out/$name/iostat.txt" 2>&1 & iostatpid=$!
vmstat -w 5 > "$out/$name/vmstat.txt" 2>&1 & vmstatpid=$!
printf 'FI CONTINUOUS REAL SIGNED START source=iss-fs-22a.iss.local W3-W4 profile=P3/F3\n' | tee "$out/SUMMARY.txt"
# Replay the ORIGINAL receiver-authenticated receipt-bound verified cache.\n# This is a correctness probe, NOT an apples-to-apples H16 performance comparison:
# no older SHA-once overlays, K32 transaction chunks or detached field leaves.
if ! /usr/bin/time -l "$worker" \
 -source=iss-fs-22a.iss.local \
 -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
 -postgres="host=$out/pg-$name port=55981 user=fi_ingest dbname=fi sslmode=disable" \
 -custody-root=/var/db/fi/custody/generation \
 -recorded-root=/var/db/fi/custody/recorded \
 -source-namespaces=false -private-root="$out/$name/private" \
 -verified-cache-root="$cache" \
 -private-writes -indexed-private -private-continuous-family \
 -window-profile=W128 -security-profile=P3 -file-profile=F3 \
 -start-window=3 -max-windows=2 -max-runtime=0 \
 > "$out/$name/recover.log" 2>&1; then
 tail -n 100 "$out/$name/recover.log" >&2 || :
 fail 'continuous signed W3-W4 worker failed; logs retained'
fi
for pid in "$iostatpid" "$vmstatpid"; do kill -TERM "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; done
iostatpid= vmstatpid=
sql 'SELECT row_to_json(w)::text FROM pg_stat_wal w' > "$out/$name/wal-after.jsonl"
sql 'SELECT row_to_json(i)::text FROM pg_stat_io i' > "$out/$name/io-after.jsonl"
grep -Fq 'FI PRIVATE CONTINUOUS W34 SQL PASS records=259178 security=232879 usn=29 windows=2 authoritative=0 accepted=0' \
 "$out/$name/recover.log" || fail 'expected signed SQL acceptance marker missing'
state=$(sql "SELECT count(*)::text||'|'||coalesce(sum(committed_records),0)::text||'|'||max(window_index)::text FROM fi_recovery.typed_window")
[ "$state" = '5|649565|4' ] || fail "signed typed checkpoint incorrect: $state"
integrity=$(sql "
SELECT CASE WHEN
 (SELECT count(*) FROM fi_recovery.verified_artifact_window)=5
 AND (SELECT count(*) FROM fi_recovery.source_window)=5
 AND (SELECT count(*) FROM fi_recovery.typed_window)=5
 AND (SELECT count(*) FROM fi_recovery.projected_source_record WHERE window_index IN (3,4))=259178
 AND (SELECT count(*) FROM fi_recovery_projection.source_record)=649565
 AND (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field)=8111457
 AND (SELECT count(*) FROM fi.recorded_generation)=0
 AND (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')=0
 AND (SELECT count(*) FROM fi_recovery.pending_source_record WHERE window_index=3 AND record_kind='WindowsSecurityEvent')=116357
 AND (SELECT count(*) FROM fi_recovery.pending_source_record WHERE window_index=4 AND record_kind='WindowsSecurityEvent')=116522
 AND (SELECT count(*) FROM fi_recovery.pending_source_record WHERE window_index=4 AND record_kind IN ('USNReadBoundary','USNObjectObservation'))=29
 AND (SELECT count(*) FROM fi_recovery_projection.usn_read_boundary b JOIN fi_recovery.projected_source_record r ON r.shadow_source_record_id=b.source_record_id WHERE r.window_index=4)
  +(SELECT count(*) FROM fi_recovery_projection.usn_object_observation o JOIN fi_recovery.projected_source_record r ON r.shadow_source_record_id=o.source_record_id WHERE r.window_index=4)=29
 AND NOT EXISTS (SELECT 1 FROM fi_recovery.typed_window t JOIN fi_recovery.source_window s USING(receipt_sha256,window_index) WHERE t.descriptor_sha256<>s.descriptor_sha256)
 THEN 'PASS' ELSE 'FAIL' END")
[ "$integrity" = PASS ] || fail 'signed/relational integrity mismatch'
grep '^FI PRIVATE CONTINUOUS FAMILY FLUSH ' "$out/$name/recover.log" \
 > "$out/$name/FLUSHES.txt" || fail 'missing durable capacity/EOF family flushes'
if grep -Ev ' trigger=(capacity|end-of-input) ' "$out/$name/FLUSHES.txt" >/dev/null; then
 fail 'a non-capacity/non-EOF flush was recorded'
fi
grep -F ' family=Security trigger=capacity ' "$out/$name/FLUSHES.txt" >/dev/null ||
 fail 'Security never flushed at real P3 capacity'
[ "$(grep -c '^FI PRIVATE CONTINUOUS TYPED COMMIT window=' "$out/$name/recover.log")" = 2 ] ||
 fail 'expected W3 and W4 typed completion proof'

checked=0
for dir in "$out/$name/private"/receipt-*/window-*; do
 [ -d "$dir" ] || fail 'materialized signed window missing'
 receipt=$(basename "$(dirname "$dir")")
 for batch in "$dir"/batch-*.data; do
  [ -f "$batch" ] || fail 'signed batch data missing'
  f=$(basename "$batch")
  orig="$cache/$receipt/$f"
  [ -f "$orig" ] || fail "original verified batch missing: $f"
  cmp -s "$batch" "$orig" || fail "signed byte readback differs: $f"
  manifest=$(printf '%s\n' "$batch" | sed 's/\.data$/.manifest/')
  origmanifest=$(printf '%s\n' "$orig" | sed 's/\.data$/.manifest/')
  cmp -s "$manifest" "$origmanifest" || fail "signed manifest differs: $f"
  checked=$((checked+1))
 done
done
[ "$checked" = 111 ] || fail "signed cache batch count $checked not 111"
printf 'FI CONTINUOUS REAL SIGNED W34 PASS checkpoint=%s records=259178 security=232879 W4_USN=29 signed_readback=%s authoritative=0 accepted=0\n' \
 "$state" "$checked" | tee -a "$out/SUMMARY.txt"
grep '^FI PRIVATE CONTINUOUS ' "$out/$name/recover.log" > "$out/$name/TELEMETRY.txt"
bundle="$out/fi-continuous-w34-$stamp.tar.gz"
(cd "$out" && tar -czf "$bundle" MANIFEST.txt SUMMARY.txt relay.log \
 "$name/recover.log" "$name/FLUSHES.txt" "$name/TELEMETRY.txt" \
 "$name/wal-before.jsonl" "$name/wal-after.jsonl" \
 "$name/io-before.jsonl" "$name/io-after.jsonl" \
 "$name/iostat.txt" "$name/vmstat.txt") || fail 'diagnostics bundle failed'
printf 'FI CONTINUOUS METRICS BUNDLE PASS path=%s\n' "$bundle"
