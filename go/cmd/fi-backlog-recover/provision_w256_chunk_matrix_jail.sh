#!/bin/sh
# FI DEVELOPMENT ONLY: provision four independent PostgreSQL 18.6 arms
# from ONE fully signed, completely committed W256 window-zero seed.
# Must run as jwood INSIDE fi-dev; no canonical FI database is modified.
set -eu
umask 077
die(){ echo "FI W256 PROVISION STOP: $*" >&2; exit 1; }
[ "$#" = 3 ] || die "usage: $0 /home/jwood/fi-w256-matrix-TIMESTAMP /home/jwood/W256-SEED 55870"
[ "$(id -un)" = jwood ] && [ "$(sysctl -n security.jail.jailed)" = 1 ] ||
 die "fi-dev jailed jwood required"
root=$1
seed=$2
seed_port=$3
case "$root" in /home/jwood/fi-w256-matrix-[0-9]*) ;; *) die "unexpected output path";; esac
case "$seed" in /home/jwood/*) ;; *) die "seed must be an absolute fi-dev path";; esac
case "$root:$seed:$seed_port" in *..*|*' '*|*'*'*|*'?'*) die "unsafe path or port";; esac
case "$seed_port" in ''|*[!0-9]*) die "invalid seed port";; esac
[ ! -e "$root" ] || die "output path already exists"
[ -d "$seed/socket" ] && [ -f "$seed/seed.log" ] || die "independent W256 signed seed and log required"
grep -q '^FI REAL BACKLOG CONFIG security_profile=P3 window_profile=W256 max_window_records=262144 max_window_data_bytes=2147483648$' "$seed/seed.log" ||
 die "seed log is not explicit W256/P3"
grep -q '^FI REAL BACKLOG PAUSED completed_to_window=1 ' "$seed/seed.log" ||
 die "W256 window-zero signed seed not completed"
[ "$(psql --version)" = 'psql (PostgreSQL) 18.6' ] || die "PostgreSQL 18.6 required"
repo=/home/jwood/fi-deferred-experiment
[ -f "$repo/.git" ] || die "detached experimental worktree required"
[ -z "$(cd "$repo" && git branch --show-current)" ] || die "experiment worktree must be detached"
[ -z "$(cd "$repo" && git status --porcelain --untracked-files=no)" ] || die "tracked source modified"
grep -q 'private-w256-memory4g' "$repo/go/cmd/fi-backlog-recover/main_freebsd.go" ||
 die "W256 code not installed in worktree"
src="host=$seed/socket port=$seed_port user=fi_m1_admin dbname=fi sslmode=disable"
q(){ psql "$src" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
checkpoint="SELECT count(*)::text || '|' || coalesce(sum(committed_records),0)::text || '|' || coalesce(max(window_index),-1)::text FROM fi_recovery.typed_window"
seed_state=$(q "$checkpoint")
case "$seed_state" in 1\|*\|0) ;; *) die "seed contains wrong checkpoint chain: $seed_state";; esac
[ "$(q "SELECT coalesce(sum(committed_records),0) BETWEEN 200000 AND 262144 FROM fi_recovery.typed_window")" = t ] ||
 die "seed records are not W256-sized"
[ "$(q 'SELECT count(*) FROM fi_recovery.verified_artifact_window')" = 1 ] || die "seed artifact ledger missing"
[ "$(q 'SELECT count(*) FROM fi_recovery.source_window')" = 1 ] || die "seed source marker missing"
[ "$(q "SELECT count(*) FROM fi.recorded_generation")" = 0 ] || die "seed has authoritative generation"
[ "$(q "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "seed has Accepted outcome"
[ "$(q "SELECT count(*) FROM pg_partitioned_table WHERE partrelid='fi_recovery_projection.windows_security_event_field'::regclass")" = 1 ] ||
 die "seed Security field table is not partitioned"
sql="$repo/go/cmd/fi-backlog-recover/testdata/private_w256_deferred_index_isolated.sql"
[ -f "$sql" ] || die "W256 deferred index SQL missing"
# Installation changes only the disposable W256 seed's private SQL
# function; the SQL file validates the existing signed checkpoint FIRST.
psql "$src" -X -v ON_ERROR_STOP=1 -f "$sql" > "$seed/w256-index-install.log" 2>&1 ||
 { tail -n 25 "$seed/w256-index-install.log" >&2; die "W256 index installation failed"; }
[ "$(q "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))>0")" = t ] ||
 die "deferred index function not installed"
mkdir -m 700 "$root"
pg_dump "$src" -Fc -Z 1 -f "$root/w256-signed-seed.dump" > "$root/dump.log" 2>&1 ||
 die "W256 signed-seed dump failed"
[ -s "$root/w256-signed-seed.dump" ] || die "empty W256 seed"
sha256 -q "$root/w256-signed-seed.dump" > "$root/w256-signed-seed.sha256"
for entry in K32:55991 K64:55992 K96:55993 K128:55994; do
 name=${entry%:*}
 port=${entry#*:}
 dir="$root/$name"
 sock="$dir/socket"
 mkdir -m 700 "$dir" "$sock"
 initdb -D "$dir/data" -U fi_m1_admin -A trust --no-instructions > "$dir/initdb.log" 2>&1 ||
  die "$name initdb"
 pg_ctl -D "$dir/data" -l "$dir/postgres.log" -o "-p $port -k $sock -c listen_addresses= -c unix_socket_permissions=0700 -c max_wal_size=8GB -c track_io_timing=off -c track_wal_io_timing=off" -w start > "$dir/start.log" 2>&1 ||
  die "$name start"
 pgadmin="host=$sock port=$port user=fi_m1_admin dbname=postgres sslmode=disable"
 psql "$pgadmin" -X -q -v ON_ERROR_STOP=1 -c 'CREATE ROLE fi_owner NOLOGIN' -c 'CREATE ROLE fi_ingest LOGIN' > "$dir/roles.log" 2>&1 ||
  die "$name role setup"
 createdb -h "$sock" -p "$port" -U fi_m1_admin -O fi_owner fi ||
  die "$name database"
 admin="host=$sock port=$port user=fi_m1_admin dbname=fi sslmode=disable"
 pg_restore --no-owner --exit-on-error --single-transaction --dbname="$admin" "$root/w256-signed-seed.dump" > "$dir/restore.log" 2>&1 ||
  { tail -n 30 "$dir/restore.log" >&2; die "$name restore"; }
 ingest="host=$sock port=$port user=fi_ingest dbname=fi sslmode=disable"
 check(){ psql "$ingest" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
 [ "$(check "$checkpoint")" = "$seed_state" ] || die "$name W256 checkpoint differs"
 [ "$(check 'SHOW fsync')" = on ] && [ "$(check 'SHOW synchronous_commit')" = on ] &&
 [ "$(check 'SHOW full_page_writes')" = on ] || die "$name durability disabled"
 [ "$(check "SELECT count(*) FROM fi.recorded_generation")" = 0 ] || die "$name canonical records"
 [ "$(check "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] || die "$name Accepted journal"
 [ "$(check "SELECT position('EXCLUDING INDEXES' IN pg_get_functiondef('fi_recovery_projection.begin_security_field_window(integer)'::regprocedure))>0")" = t ] ||
  die "$name deferred index function lost on restore"
 echo "FI W256 SEED CLONE PASS arm=$name port=$port signed_seed=$seed_state"
done
(cd "$repo/go" && GOAMD64=v1 go build -o "$root/fi-w256-recover" ./cmd/fi-backlog-recover) ||
 die "W256 Go binary build failed"
sha256 -q "$root/fi-w256-recover" > "$root/recover.sha256"
(cd "$repo" && git rev-parse HEAD && git status --short) > "$root/source-status.txt"
printf 'FI W256 MATRIX PROVISION COMPLETE root=%s seed=%s profile=W256 source=real_signed arms=K32,K64,K96,K128\n' "$root" "$seed"
