#!/bin/sh
# FI DEV ONLY: two identical 32768-row chunk experiment arms,
# PostgreSQL fixtures for the existing two-endpoint host relay.
# Real signed source cache; original three-window seed is READ-ONLY.
# Experimental source worktree: /home/jwood/fi-deferred-experiment.
set -eu
umask 077
die(){ echo "FI OPTFIELD PROVISION STOP: $*" >&2; exit 1; }
[ "$#" = 1 ] && [ "$(id -un)" = jwood ] && [ "$(sysctl -n security.jail.jailed)" = 1 ] || die 'fi-dev jwood required'
root=$1
case "$root" in /home/jwood/fi-window-bench-optfield-[0-9]*) ;; *) die 'bad root';; esac
case "$root" in *..*|*' '*|*'*'*|*'?'*|*'['*|*']'*) die 'unsafe root';; esac
[ ! -e "$root" ] || die 'destination exists'
[ -d /home/jwood/fi-deferred-experiment/.git ] && die 'unexpected nested Git metadata (worktree expected)' || :
[ -f /home/jwood/fi-deferred-experiment/.git ] || die 'detached experiment worktree required'
[ -z "$(cd /home/jwood/fi-deferred-experiment && git status --porcelain --untracked-files=no)" ] || die 'experiment tracked source is modified'
[ -z "$(cd /home/jwood/fi-deferred-experiment && git branch --show-current)" ] || die 'experiment source must be detached'

[ "$(psql --version)" = 'psql (PostgreSQL) 18.6' ] || die 'PostgreSQL version'
base=/home/jwood/fi-window-bench-fieldpart-20261104T091019Z/W64
[ -d "$base/data" ] && [ -d "$base/socket" ] || die 'validated source cluster missing'
src="host=$base/socket port=55962 user=fi_m1_admin dbname=fi sslmode=disable"
q(){ psql "$src" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
[ "$(q 'SELECT count(*) FROM fi_recovery.typed_window')" = 3 ] || die 'checkpoint count'
[ "$(q 'SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window')" = 390387 ] || die 'source record count'
[ "$(q 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 4838850 ] || die 'source field count'
[ "$(q "SELECT count(*) FROM pg_partitioned_table WHERE partrelid='fi_recovery_projection.windows_security_event_field'::regclass")" = 1 ] || die 'source not partitioned'
[ "$(q 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die 'canonical rows'
[ "$(q "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die 'Accepted journal'
repo=/home/jwood/fi-deferred-experiment
[ -s "$repo/go/internal/recordingest/backlog_private_field_partition.go" ] || die 'optimized Go code missing'
grep -q 'deferred-verified-clone' "$repo/go/cmd/fi-backlog-recover/main_freebsd.go" || die 'experiment flag missing'
[ -s "$repo/go/cmd/fi-backlog-recover/optfield/relay.go" ] || die 'relay source missing'
mkdir -m 700 "$root"
cp "$repo/go/cmd/fi-backlog-recover/optfield/relay.go" "$root/relay.go"
pg_dump "$src" -Fc -Z 1 -f "$root/accepted-prefix.dump" > "$root/dump.log" 2>&1 || die 'source dump'
[ -s "$root/accepted-prefix.dump" ] || die 'empty dump'
sha256 -q "$root/accepted-prefix.dump" > "$root/accepted-prefix.sha256"
for entry in CONTROL:55981 CANDIDATE:55982; do
 name=${entry%:*};port=${entry#*:};dir="$root/$name";sock="$dir/socket"
 mkdir -m 700 "$dir" "$sock"
 initdb -D "$dir/data" -U fi_m1_admin -A trust --no-instructions > "$dir/initdb.log" 2>&1 || die "$name initdb"
 pg_ctl -D "$dir/data" -l "$dir/postgres.log" -o "-p $port -k $sock -c listen_addresses= -c unix_socket_permissions=0700" -w start > "$dir/start.log" 2>&1 || die "$name start"
 pgadmin="host=$sock port=$port user=fi_m1_admin dbname=postgres sslmode=disable"
 psql "$pgadmin" -X -q -v ON_ERROR_STOP=1 -c 'CREATE ROLE fi_owner NOLOGIN' -c 'CREATE ROLE fi_ingest LOGIN' > "$dir/roles.log" 2>&1 || die "$name roles"
 createdb -h "$sock" -p "$port" -U fi_m1_admin -O fi_owner fi || die "$name db"
 admin="host=$sock port=$port user=fi_m1_admin dbname=fi sslmode=disable"
 pg_restore --no-owner --exit-on-error --single-transaction --dbname="$admin" "$root/accepted-prefix.dump" > "$dir/restore.log" 2>&1 || { tail -n 25 "$dir/restore.log" >&2; die "$name restore"; }
 ingest="host=$sock port=$port user=fi_ingest dbname=fi sslmode=disable"
 check(){ psql "$ingest" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
 [ "$(check 'SELECT count(*) FROM fi_recovery.typed_window')" = 3 ] || die "$name typed restore"
 [ "$(check 'SELECT count(*) FROM fi_recovery_projection.source_record')" = 390387 ] || die "$name source restore"
 [ "$(check 'SELECT count(*) FROM fi_recovery_projection.windows_security_event_field')" = 4838850 ] || die "$name field restore"
 [ "$(check 'SELECT count(*) FROM fi.recorded_generation')" = 0 ] || die "$name authoritative"
 [ "$(check "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "$name accepted"
 for setting in fsync synchronous_commit full_page_writes; do [ "$(check "SHOW $setting")" = on ] || die "$name $setting disabled"; done
 echo "FI OPTFIELD CLONE PASS profile=$name port=$port checkpoint=3 records=390387 fields=4838850"
done
(cd "$repo/go" && go build -o "$root/fi-optfield-recover" ./cmd/fi-backlog-recover) || die 'recovery build'
(cd "$root" && go build -o "$root/fi-optfield-relay" ./relay.go) || die 'relay build'
sha256 -q "$root/fi-optfield-recover" > "$root/recover.sha256"
sha256 -q "$root/fi-optfield-relay" > "$root/relay.sha256"
(cd "$repo";git rev-parse HEAD;git status --short) > "$root/source-status.txt"
echo "FI DEFERRED CLONE PROVISION COMPLETE root=$root binaries=experiment fixture=real_signed_seed source_worktree=$repo"
