#!/bin/sh
# C220 one-jail C1 isolated PostgreSQL 18 benchmark clone creation.
# Does not stop live Postgres, write its data, alter receiver custody/READY,
# reset an existing DB, delete seeds, or launch FI ingestion.
# The shell script runs on C220 host root; Go SQL clone bootstrap runs as
# postgres INSIDE fi-sor on a fresh Unix socket, never the live PGDATA.
set -eu
umask 077
die(){ echo "FI C1 SOR CLONE STOP: $*" >&2; exit 1; }
[ "$#" -eq 2 ] || die 'usage: --audit|--prepare PINNED_COMMIT_SHA'
case "$1" in --audit|--prepare) mode=$1;; *) die 'invalid action';; esac
pin=$2
case "$pin" in
    *[!0123456789abcdef]*|'') die 'invalid commit pin' ;;
esac
[ "${#pin}" -eq 40 ] || die 'full 40-char commit pin required'
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
    [ "$(id -u)" -eq 0 ] || die 'physical C220 host root required'

repo=/home/jwood/fi-c1-two-process-2a449f1a
branch=dev/c1-sor-single-jail-20261124
devhost=/fast/jails/roots/fi-dev
sorhost=/fast/jails/roots/fi-sor
for j in fi-dev fi-sor fi-receiver;do jls -j "$j" >/dev/null 2>&1 || die "required jail missing: $j";done
if jls -j fi-ingest >/dev/null 2>&1;then die 'obsolete fi-ingest jail is running';fi
for svc in fi_c1_sor fi_c1_sor_local;do
    if jexec fi-sor service "$svc" onestatus >/dev/null 2>&1;then
        die "C1 processing service already running: $svc"
    fi
done
[ -d /work/fi-c220-20261114/custody/generation ] &&
[ -d /work/fi-c220-20261114/custody/recorded ] &&
[ -d /work/fi-c220-20261114/custody/ready ] ||
    die 'original signed custody or receiver READY missing'
[ -d "$sorhost/var/tmp" ] || die 'fi-sor scratch parent missing'
[ "$(cat "$sorhost/etc/rc.conf.d/fi_c1_sor_local" | grep -Fxc 'fi_c1_sor_local_enable="NO"' || :)" = 1 ] ||
    die 'single-jail service must remain disabled'
# Exact READ-ONLY physical live identity and canonical/accepted baseline.
sql(){
    jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
        -h /var/db/fi/sor/run -p 5432 -d fi -c "$1"
}
live=$(sql "SELECT current_setting('data_directory') || '|' ||
    current_setting('port') || '|' ||
    (SELECT count(*) FROM fi.recorded_generation)::text || '|' ||
    (SELECT count(*) FROM fi_c1_pending.generation_control)::text")
case "$live" in
    '/var/db/fi/sor/postgres|5432|6773|0') : ;;
    *) die "live SoR physical identity/count changed: $live" ;;
esac
[ "$(cat "$sorhost/usr/local/sbin/fi-c1-sor-local" | wc -c | tr -d ' ')" -gt 0 ] ||
    die 'native C1 single-jail executable missing'
# Prior full backlog benchmark used 8GB WAL and 16MB buffers. Disk and
# workload profile remain clone-only and are NOT applied to live Postgres.
free_kib=$(df -Pk "$sorhost/var/tmp" | awk 'END {print $4}')
case "$free_kib" in ''|*[!0-9]*) die 'invalid fast-pool available capacity';; esac
[ "$free_kib" -ge 629145600 ] ||
    die "at least 600 GiB isolated benchmark headroom required; available KiB=$free_kib"
echo "FI C1 SOR CLONE STORAGE/SQL PREFLIGHT PASS live_canonical=6773 live_pending=0 fast_available_kib=$free_kib original_signed_custody_preserved=true"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pin^{commit}" ||
    die 'requested development source pin not present in fi-dev'
if [ "$mode" = --audit ];then
    echo 'FI C1 SOR CLONE AUDIT PASS read_only=true original_seed_preserved=true no_new_postgres_started=true'
    exit 0
fi

# Make unique new root; no overwrite/reuse is possible. PostgreSQL listens
# ONLY on an internal Unix socket with no TCP listeners.
uid=$(jexec fi-sor id -u postgres)
pgid=$(jexec fi-sor id -g postgres)
sorgid=$(jexec fi-sor id -g fi-sor)
for v in "$uid" "$pgid" "$sorgid";do
    case "$v" in ''|*[!0-9]*) die 'unexpected fi-sor Unix ID';; esac
done
base=$sorhost/var/tmp
full=$(mktemp -d "$base/fi-c1-sor-bench.XXXXXXXX") ||
    die 'cannot allocate fresh isolated fast-pool clone'
clone=${full#"$sorhost"}
[ "$clone" != "$full" ] || die 'clone is outside fi-sor jail'
chown "$uid:$sorgid" "$full"
chmod 0770 "$full"
install -d -o "$uid" -g "$sorgid" -m 0770 "$full/socket"
echo "FI C1 SOR CLONE_ROOT=$clone"

# Build the exact pinned Go bootstrap source in fi-dev. No branch checkout
# mutation and no live database access in the build phase.
build=$(jexec -U jwood fi-dev mktemp -d /home/jwood/fi-c1-sor-clone-build.XXXXXXXX) ||
    die 'cannot allocate fi-dev source archive'
jexec -U jwood fi-dev /bin/sh -c '
set -eu
repo=$1; pin=$2; build=$3
git -C "$repo" archive "$pin" | tar -xf - -C "$build"
cd "$build/go"
go test -tags fi_c1_sor_dev -run "^TestC1SoRLocal" ./internal/recordingest
go build -trimpath -tags fi_c1_sor_dev -o "$build/fi-c1-sor-clone-bootstrap" ./cmd/fi-c1-sor-clone-bootstrap
test -s "$build/fi-c1-sor-clone-bootstrap"
' sh "$repo" "$pin" "$build" ||
    die 'pinned C1 clone schema/bootstrap build failed'
candidate=$devhost$build/fi-c1-sor-clone-bootstrap
[ -s "$candidate" ] && [ ! -L "$candidate" ] || die 'unsafe private build artifact'
install -o "$uid" -g "$pgid" -m 0500 "$candidate" "$full/fi-c1-sor-clone-bootstrap"

echo '===== INITIALIZE SEPARATE POSTGRESQL 18 ====='
jexec -U postgres fi-sor initdb -D "$clone/pgdata" -A trust --locale=C --encoding=UTF8 --no-instructions ||
    die 'disposable clone PostgreSQL initdb failed'
# Explicitly refuse if any other PG18 cluster is serving this socket.
[ ! -e "$full/socket/.s.PGSQL.5432" ] ||
    die 'private socket collision; no PostgreSQL start'
jexec -U postgres fi-sor pg_ctl -D "$clone/pgdata" \
    -l "$clone/postgres.log" \
    -o "-p 5432 -k $clone/socket -c listen_addresses= -c unix_socket_permissions=0777 -c max_connections=128 -c max_wal_size=8GB -c wal_buffers=16MB -c fsync=on -c synchronous_commit=on -c full_page_writes=on" \
    -w start ||
    die 'isolated PostgreSQL failed to start; leave clone untouched for diagnostics'
jexec -U postgres fi-sor psql -X -w -v ON_ERROR_STOP=1 \
    -h "$clone/socket" -p 5432 -d postgres -c "CREATE DATABASE fi OWNER postgres" ||
    die 'isolated fi database creation failed'
echo '===== INSTALL FROZEN 49-TABLE CANONICAL AND GOVERNED PENDING INTO CLONE ====='
jexec -U postgres fi-sor "$clone/fi-c1-sor-clone-bootstrap" -clone-root "$clone" ||
    die 'isolated clone SQL schema failed; leave for read-only diagnostics'
echo '===== PROVE LIVE SOR STILL UNCHANGED ====='
[ "$(sql "SELECT current_setting('data_directory') || '|' ||
    current_setting('port') || '|' ||
    (SELECT count(*) FROM fi.recorded_generation)::text || '|' ||
    (SELECT count(*) FROM fi_c1_pending.generation_control)::text")" = "$live" ] ||
    die 'live SoR count or physical identity changed unexpectedly'
echo "FI C1 SOR ISOLATED BENCHMARK CLONE READY pgdata=$clone/pgdata socket=$clone/socket live_canonical_unchanged=true original_signed_custody_untouched=true worker_disabled=true receiver_ready_unchanged=true private_fi=empty"
echo "FI_C1_PRIVATE_WORKER_DSN=host=$clone/socket port=5432 dbname=fi user=fi_ingest sslmode=disable"
echo "FI_C1_PRIVATE_PUBLISHER_DSN=host=$clone/socket port=5432 dbname=fi user=fi_c1_publisher sslmode=disable"
