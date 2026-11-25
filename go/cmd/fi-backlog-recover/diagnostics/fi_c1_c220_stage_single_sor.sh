#!/bin/sh
# C220 SINGLE-JAIL C1: build the pinned tested source inside fi-dev,
# install ONLY the new fi-sor local worker and run its READ-ONLY preflight.
# Never start ingestion, change jail.conf, READY, signed custody or SQL.
set -eu
umask 077
fail(){ echo "FI C1 SINGLE-JAIL STAGE STOP: $*" >&2; exit 1; }
[ "$#" -eq 1 ] && [ "$1" = --stage-readonly ] ||
    fail 'usage: --stage-readonly'
[ "$(uname -s)" = FreeBSD ] && [ "$(id -u)" = 0 ] ||
    fail 'physical FreeBSD root required'
[ "$(hostname -s)" = c220 ] ||
    fail 'pinned physical C220 host required'
repo=/home/jwood/fi-c1-two-process-2a449f1a
branch=dev/c1-sor-single-jail-20261124
pin=6473fafbbf0e952842b7009ae726b79ec4f370d3
fi_dev=/fast/jails/roots/fi-dev
fi_sor=/fast/jails/roots/fi-sor
target=$fi_sor/usr/local/sbin/fi-c1-sor-local
for name in fi-dev fi-sor fi-receiver;do
    jls -j "$name" >/dev/null 2>&1 ||
        fail "required surviving jail missing: $name"
done
if jls -j fi-ingest >/dev/null 2>&1;then
    fail 'obsolete fi-ingest still running; stop it before staging replacement'
fi
jexec fi-sor /usr/sbin/service fi_c1_sor onestatus >/dev/null 2>&1 &&
    fail 'old inter-jail fi-sor service still running'
pgrep=
for name in /bin/pgrep /usr/bin/pgrep;do
    if jexec fi-sor /bin/test -x "$name";then pgrep=$name;break;fi
done
[ -n "$pgrep" ] ||
    fail 'cannot verify absence of workers without FreeBSD pgrep'
if jexec fi-sor "$pgrep" -fl 'fi-c1-sor-local|fi-c1-ingest-worker';then
    fail 'FI native C1 worker already running'
fi
for dir in /work/fi-c220-20261114/custody/generation \
           /work/fi-c220-20261114/custody/recorded;do
    [ -d "$dir" ] || fail "original receiver custody absent: $dir"
done
echo "===== ORIGINAL LIVE CANONICAL READ-ONLY BEFORE ====="
sql(){
    jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
        -h /var/db/fi/sor/run -p 5432 -d fi -c "$1"
}
before=$(sql "BEGIN READ ONLY; SELECT count(*) FROM fi.recorded_generation; COMMIT;" |
    grep -E '^[0-9]+$' | tail -1)
[ -n "$before" ] || fail 'authoritative canonical count unavailable'
echo "CANONICAL_BEFORE=$before"
echo "===== FETCH PINNED DEVELOPMENT COMMIT ====="
jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch" ||
    fail 'cannot fetch signed development source'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pin^{commit}" ||
    fail 'pinned single-jail development source unavailable'
build=$(jexec -U jwood fi-dev mktemp -d \
    /home/jwood/fi-c1-sor-local-stage.XXXXXXXX) ||
    fail 'cannot allocate isolated fi-dev build'
echo "BUILD_PATH=$build"
jexec -U jwood fi-dev /bin/sh -c '
set -eu
repo=$1
commit=$2
dir=$3
git -C "$repo" archive "$commit" | tar -xf - -C "$dir"
cd "$dir/go"
go test -tags fi_c1_sor_dev -count=1 -run "^TestC1SoRLocal" ./internal/recordingest
go build -trimpath -tags fi_c1_sor_dev -o "$dir/fi-c1-sor-local" ./cmd/fi-c1-sor-local
test -s "$dir/fi-c1-sor-local"
' sh "$repo" "$pin" "$build" ||
    fail 'single-jail native Go build or original C1 parity tests failed'
candidate=$fi_dev$build/fi-c1-sor-local
[ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -s "$candidate" ] ||
    fail 'native fi-dev binary path unsafe or missing'
want=$(sha256 -q "$candidate")
echo "FI_SOR_LOCAL_SHA256=$want"
if [ -e "$target" ] || [ -L "$target" ];then
    [ -f "$target" ] && [ ! -L "$target" ] &&
      [ "$(sha256 -q "$target")" = "$want" ] ||
        fail 'different local worker already installed; never overwrite'
else
    install -o root -g wheel -m 0555 "$candidate" "$target" ||
        fail 'unable to stage new fi-sor binary'
fi
echo "===== INSTALL DISABLED BY DEFAULT SINGLE-JAIL SERVICE ASSETS ====="
stage_asset(){
    original=$1
    destination=$2
    mode=$3
    tmp=$(mktemp /root/fi-c1-local-asset.XXXXXXXX) ||
        fail 'cannot allocate atomic service artifact'
    jexec -U jwood fi-dev git -C "$repo" show "$pin:$original" > "$tmp" ||
        fail "cannot fetch pinned service asset $original"
    [ -s "$tmp" ] || fail "empty service asset $original"
    case "$original" in
        *.sh) sh -n "$tmp" || fail "invalid service runner $original" ;;
    esac
    if [ -e "$destination" ] || [ -L "$destination" ];then
        [ -f "$destination" ] && [ ! -L "$destination" ] &&
            cmp -s "$tmp" "$destination" ||
            fail "different service asset already installed: $destination"
    else
        install -o root -g wheel -m "$mode" "$tmp" "$destination" ||
            fail "cannot stage service asset $destination"
    fi
    rm -f "$tmp"
}
stage_asset tools/deployment/freebsd/fi-c1-sor-local-run.sh \
    "$fi_sor/usr/local/libexec/fi-c1-sor-local-run" 0555
stage_asset tools/deployment/freebsd/fi-c1-sor-local-rc.sh \
    "$fi_sor/usr/local/etc/rc.d/fi_c1_sor_local" 0555
stage_asset tools/deployment/freebsd/fi-c1-sor-local.conf \
    "$fi_sor/etc/rc.conf.d/fi_c1_sor_local" 0644
echo "===== CREATE EMPTY DISPOSABLE FI-SOR CACHE DIRECTORY ====="
stage=$fi_sor/var/tmp/fi-c1-sor-local-scratch
if [ -e "$stage" ] || [ -L "$stage" ];then
    [ -d "$stage" ] && [ ! -L "$stage" ] ||
        fail 'staging path exists but is not a real directory'
    [ -z "$(ls -A "$stage")" ] ||
        fail 'existing fi-sor scratch is not empty; never delete it'
else
    install -d -o 4100 -g 4100 -m 0700 "$stage" ||
        fail 'unable to create fi-sor-owned local scratch'
fi
echo "===== NATIVE SINGLE-JAIL WORKER READ-ONLY PREFLIGHT ====="
jexec -U fi-sor fi-sor /bin/sh -c '
    set -eu
    . /etc/rc.conf.d/fi_c1_sor
    : "${fi_c1_sor_postgres_local:?}"
    : "${fi_c1_sor_postgres_publisher_local:?}"
    if [ -n "${fi_c1_sor_pgpass:-}" ];then
        [ -f "$fi_c1_sor_pgpass" ] && [ ! -L "$fi_c1_sor_pgpass" ] &&
            [ -r "$fi_c1_sor_pgpass" ] ||
            exit 1
        PGPASSFILE=$fi_c1_sor_pgpass
        export PGPASSFILE
    fi
    # Match the ORIGINAL receiver receipt layout used by the working
    # C220 C1 SoR. Never invent a "sources/<id>" namespace.
    set -- \
        -preflight \
        -source-id iss-fs-22a.iss.local \
        -generation-id 20261030T000032.061323100Z-3e38b2210771462c \
        -custody-root /var/db/fi/custody/generation \
        -recorded-root /var/db/fi/custody/recorded \
        -postgres-local "$fi_c1_sor_postgres_local" \
        -postgres-publisher-local "$fi_c1_sor_postgres_publisher_local" \
        -sql-workers-max 32 \
        -staging-root /var/tmp/fi-c1-sor-local-scratch
    case "${fi_c1_sor_source_namespaces:-NO}" in
        YES) set -- "$@" -source-namespaces ;;
        NO) ;;
        *) echo "FI C1 local: invalid original receipt namespace setting" >&2; exit 1 ;;
    esac
    exec /usr/local/sbin/fi-c1-sor-local "$@"
' || fail 'new native C1 direct fi-sor read-only preflight failed'
jexec -U fi-sor fi-sor /usr/local/libexec/fi-c1-sor-local-run --verify ||
    fail 'disabled single-jail dual-source service runner preflight failed'
echo "===== FI-SOR READY SCHEDULING MOUNT AUDIT (READ ONLY) ====="
host_ready=/work/fi-c220-20261114/custody/ready
sor_ready=$fi_sor/var/db/fi/custody/ready
[ -d "$host_ready" ] ||
    fail 'receiver READY scheduling root missing; original custody untouched'
if mount -p | awk -v src="$host_ready" -v dst="$sor_ready" '
    $2==dst {count++; if ($1==src && $3=="nullfs" && index(","$4",",",rw,")>0)good++}
    END {exit !(count==1 && good==1)}
';then
    echo 'C1_SOR_ORIGINAL_READY_MOUNT=RW_VERIFIED'
else
    echo 'C1_SOR_ORIGINAL_READY_MOUNT=NOT_VERIFIED'
    echo 'FI C1: READY intake cannot be enabled until original receiver READY root is mounted RW inside fi-sor'
fi
after=$(sql "BEGIN READ ONLY; SELECT count(*) FROM fi.recorded_generation; COMMIT;" |
    grep -E '^[0-9]+$' | tail -1)
[ "$after" = "$before" ] ||
    fail 'unexpected canonical count change; stop and inspect'
echo "CANONICAL_AFTER=$after"
echo "FI C1 SINGLE-JAIL STAGING PASS source_commit=$pin binary_sha256=$want custody_preserved=true canonical_unchanged=true sql_writes=false receiver_ready_unchanged=true no_worker_started=true continuous=false"
