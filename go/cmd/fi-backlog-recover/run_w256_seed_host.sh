#!/bin/sh
# FI DEVELOPMENT ONLY: seed an EMPTY, dedicated PostgreSQL 18 private
# recovery fixture with the first real signed W256/2GiB window. No W128
# checkpoint is reusable and no canonical SoR publication is allowed.
set -eu
umask 077
fail(){ echo "FI W256 SEED STOP: $*" >&2; exit 1; }
[ "$#" = 2 ] || fail "usage: $0 /home/jwood/fi-w256-seed 55870"
seed=$1;port=$2
case "$seed" in /home/jwood/*) ;; *) fail "seed must reside in fi-dev";; esac
case "$port" in ''|*[!0-9]*) fail "invalid port";; esac
[ "$(id -un)" = root ] || fail "FreeBSD host root required"
[ "$(sysctl -n kern.racct.enable 2>/dev/null)" = 1 ] || fail "RCTL required"
jailroot=$(jls -j fi-dev path) || fail "fi-dev jail unavailable"
repo=/home/jwood/fi-deferred-experiment
[ -d "$jailroot$seed/socket" ] || fail "fresh isolated PG socket dir required"
[ ! -f "$jailroot$seed/seed.log" ] || fail "seed log already exists"
sql(){
 jexec -U jwood fi-dev psql "host=$seed/socket port=$port user=fi_ingest dbname=fi sslmode=disable" -X -qAt -v ON_ERROR_STOP=1 -c "$1"
}
[ "$(sql "SELECT count(*) FROM fi_recovery.typed_window")" = 0 ] || fail "pre-existing typed checkpoint"
[ "$(sql "SELECT count(*) FROM fi_recovery.source_window")" = 0 ] || fail "pre-existing source checkpoint"
[ "$(sql "SELECT count(*) FROM fi_recovery.verified_artifact_window")" = 0 ] || fail "pre-existing artifact checkpoint"
[ "$(sql "SELECT count(*) FROM fi.recorded_generation")" = 0 ] || fail "canonical FI has an Accepted generation"
[ "$(sql "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || fail "existing Accepted journal"
for setting in fsync synchronous_commit full_page_writes; do
 [ "$(sql "SHOW $setting")" = on ] || fail "PostgreSQL $setting is not on"
done
jexec -U jwood fi-dev sh -c "cd '$repo/go' && GOAMD64=v1 go build -o '$seed/fi-w256-recover' ./cmd/fi-backlog-recover" ||
 fail "FreeBSD W256 build failed"
bin="$jailroot$seed/fi-w256-recover"
[ -x "$bin" ] || fail "W256 binary absent"
[ ! -e "$jailroot$seed/private" ] || fail "private seed root already present"
mkdir -m 700 "$jailroot$seed/private"
gate="$jailroot$seed/proceed"
pid=
rule=
cleanup(){
 if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || :; wait "$pid" 2>/dev/null || :; fi
 if [ -n "$rule" ]; then rctl -r "$rule" >/dev/null 2>&1 || :; fi
}
trap cleanup 0 1 2 3 15
(
 while [ ! -e "$gate" ]; do sleep 1; done
 exec "$bin" \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="host=$jailroot$seed/socket port=$port user=fi_ingest dbname=fi sslmode=disable" \
  -custody-root=/var/db/fi/custody/generation \
  -recorded-root=/var/db/fi/custody/recorded -source-namespaces=false \
  -private-root="$jailroot$seed/private" -private-writes \
  -security-profile=P3 -file-profile=F3 -window-profile=W256 \
  -stream-loader -start-window=0 -max-windows=1 -max-runtime=0s \
  -private-w256-memory4g > "$jailroot$seed/seed.log" 2>&1
) &
pid=$!
rule="process:$pid:memoryuse:deny=4G"
rctl -a "$rule" || fail "hard 4GiB process RSS limit could not be installed"
rctl -l "process:$pid" > "$jailroot$seed/rctl.txt" || fail "RCTL inspection failed"
grep -q 'memoryuse:deny=4G' "$jailroot$seed/rctl.txt" || fail "hard limit absent"
: > "$gate"
if wait "$pid"; then code=0; else code=$?; fi
pid=
rctl -r "$rule" >/dev/null 2>&1 || :
rule=
[ "$code" -eq 0 ] || { tail -n 40 "$jailroot$seed/seed.log" >&2 || :; fail "W256 signed seed failed"; }
grep -q '^FI REAL BACKLOG PAUSED completed_to_window=1 ' "$jailroot$seed/seed.log" ||
 fail "W256 window-zero durable completion missing"
[ "$(sql "SELECT count(*) FROM fi_recovery.typed_window")" = 1 ] || fail "W256 seed typed checkpoint missing"
[ "$(sql "SELECT max(window_index) FROM fi_recovery.typed_window")" = 0 ] || fail "W256 seed wrong checkpoint index"
[ "$(sql "SELECT count(*) FROM fi_recovery.source_window")" = 1 ] || fail "W256 seed source checkpoint missing"
[ "$(sql "SELECT count(*) FROM fi_recovery.verified_artifact_window")" = 1 ] || fail "W256 seed artifact checkpoint missing"
[ "$(sql "SELECT count(*) FROM fi.recorded_generation")" = 0 ] || fail "SoR modified"
chmod 644 "$jailroot$seed/seed.log"
printf 'FI W256 REAL SIGNED SEED PASS seed=%s record_limit=262144 byte_limit=2147483648 RCTL=4GiB\n' "$seed"
