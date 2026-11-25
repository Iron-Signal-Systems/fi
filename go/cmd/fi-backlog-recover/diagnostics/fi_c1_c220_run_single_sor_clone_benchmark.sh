#!/bin/sh
# Exact original 15,140,785-record C1 full signed generation replay against
# the NEW isolated PostgreSQL18 cluster in fi-sor. Never use READY queue and
# NEVER write or clean up original receiver custody or live SoR.
#
# --audit: fully read-only host+clone+receipt checks, no process start
# --run:   compile pinned benchmark worker, verify PGDATA again, then
#          explicitly ingest ONLY into clone PostgreSQL, verify Accepted.
set -eu
umask 077
fail(){ echo "FI C1 SINGLE-JAIL CLONE BENCHMARK STOP: $*" >&2; exit 1; }
# These two mutually distinct cluster identities were independently observed
# on the physical C220, not inferred from the benchmark clone configuration.
# Only the disposable clone is required to have NO TCP listener.
live_identity_expected='/var/db/fi/sor/postgres|/var/db/fi/sor/run|172.20.20.22|5432|6773|0|6773'
live_identity_matches(){ [ "$1" = "$live_identity_expected" ]; }
clone_identity_matches(){ [ "$1" = "$2|$3||5432|0|0|0" ]; }
if [ "$#" -eq 1 ] && [ "$1" = --selftest ];then
    live_identity_matches "$live_identity_expected" ||
        fail 'valid original live SoR fixture refused'
    for bad in \
        '/var/db/fi/sor/postgres|/var/db/fi/sor/run||5432|6773|0|6773' \
        '/var/db/fi/sor/postgres|/var/db/fi/sor/run|172.20.20.23|5432|6773|0|6773' \
        '/var/db/fi/sor/postgres|/var/db/fi/sor/run|172.20.20.22|5432|6773|1|6773' \
        '/var/db/fi/sor/postgres|/var/db/fi/sor/run|172.20.20.22|5432|6773|0|6772';do
        if live_identity_matches "$bad";then fail "unsafe live identity accepted: $bad";fi
    done
    clone_identity_matches '/var/tmp/fi-c1-sor-bench.test1234/pgdata|/var/tmp/fi-c1-sor-bench.test1234/socket||5432|0|0|0' \
        '/var/tmp/fi-c1-sor-bench.test1234/pgdata' '/var/tmp/fi-c1-sor-bench.test1234/socket' ||
        fail 'valid isolated empty clone fixture refused'
    for bad in \
        '/var/tmp/fi-c1-sor-bench.test1234/pgdata|/var/tmp/fi-c1-sor-bench.test1234/socket|172.20.20.22|5432|0|0|0' \
        '/var/db/fi/sor/postgres|/var/db/fi/sor/run||5432|0|0|0' \
        '/var/tmp/fi-c1-sor-bench.test1234/pgdata|/var/tmp/fi-c1-sor-bench.test1234/socket||5432|1|0|0';do
        if clone_identity_matches "$bad" '/var/tmp/fi-c1-sor-bench.test1234/pgdata' \
            '/var/tmp/fi-c1-sor-bench.test1234/socket';then
            fail "unsafe clone identity accepted: $bad"
        fi
    done
    echo 'FI C1 SINGLE-JAIL CLONE LIVE/PRIVATE SQL IDENTITY SELFTEST PASS accepts_original_live_listener=true clone_tcp_disabled_required=true rejects_wrong_live_address=true rejects_pending_or_accepted_drift=true rejects_nonempty_or_live_clone=true'
    exit 0
fi
[ "$#" -eq 2 ] || fail 'usage: --selftest | --audit|--run PINNED_COMMIT_SHA'
case "$1" in --audit|--run) mode=$1;; *) fail 'only --audit or --run';; esac
pin=$2
case "$pin" in *[!0123456789abcdef]*|'') fail 'invalid full source pin';; esac
[ "${#pin}" -eq 40 ] || fail 'exact 40-character commit pin required'
[ "$(uname -s)" = FreeBSD ] && [ "$(hostname -s)" = c220 ] &&
    [ "$(id -u)" -eq 0 ] || fail 'physical root@c220 only'

repo=/home/jwood/fi-c1-two-process-2a449f1a
sorhost=/fast/jails/roots/fi-sor
devhost=/fast/jails/roots/fi-dev
clone=/var/tmp/fi-c1-sor-bench.yBi1CkVm
hostclone=$sorhost$clone
pgdata=$clone/pgdata
socket=$clone/socket
scratch=/var/tmp/fi-c1-sor-local-scratch
source=iss-fs-22a.iss.local
generation=20261030T000032.061323100Z-3e38b2210771462c
receipt=generation-67ef0182b7803049344fafb4a693c0fa559abc603a15a4157fc982548b249c38.record.json
receipt_sha=29891703eea7bef6e21b84374c49193a9b1d58666665d418267e418e3414c7ed

for jail in fi-sor fi-receiver fi-dev;do
    jls -j "$jail" >/dev/null 2>&1 || fail "missing required jail $jail"
done
if jls -j fi-ingest >/dev/null 2>&1;then fail 'obsolete fi-ingest unexpectedly running';fi
for svc in fi_c1_sor fi_c1_sor_local;do
    if jexec fi-sor service "$svc" onestatus >/dev/null 2>&1;then
        fail "old or new FI C1 service active: $svc"
    fi
done
[ -d "$hostclone" ] && [ ! -L "$hostclone" ] &&
[ -d "$hostclone/pgdata" ] && [ ! -L "$hostclone/pgdata" ] &&
[ -d "$hostclone/socket" ] && [ ! -L "$hostclone/socket" ] &&
[ -d "$sorhost$scratch" ] && [ ! -L "$sorhost$scratch" ] ||
    fail 'specific previously created isolated PG18 clone or staging path changed'
[ -f "$hostclone/pgdata/PG_VERSION" ] &&
[ "$(cat "$hostclone/pgdata/PG_VERSION")" = 18 ] ||
    fail 'isolated clone is not PostgreSQL18'
[ -d /work/fi-c220-20261114/custody/generation ] &&
[ -d /work/fi-c220-20261114/custody/recorded ] &&
[ -d /work/fi-c220-20261114/custody/ready ] ||
    fail 'original receiver custody/READY root unavailable'
[ -f "/work/fi-c220-20261114/custody/recorded/$receipt" ] &&
[ ! -L "/work/fi-c220-20261114/custody/recorded/$receipt" ] ||
    fail 'original recorded signed generation missing'
[ "$(sha256 -q "/work/fi-c220-20261114/custody/recorded/$receipt")" = "$receipt_sha" ] ||
    fail 'signed original receipt digest changed; preserve original custody'
[ -f "$sorhost/etc/rc.conf.d/fi_c1_sor_local" ] &&
grep -Fx 'fi_c1_sor_local_enable="NO"' "$sorhost/etc/rc.conf.d/fi_c1_sor_local" >/dev/null ||
    fail 'single-jail C1 continuous service was enabled'
jexec -U fi-sor fi-sor /bin/test -w "$scratch" &&
jexec -U fi-sor fi-sor /bin/test -r /var/db/fi/custody/recorded ||
    fail 'unprivileged fi-sor cannot use scratch/read signed custody'
[ -z "$(ls -A "$sorhost$scratch")" ] ||
    fail 'fi-sor scratch is not empty, preserve existing extracted staging and investigate'

# An independent physical DATA-DIR check is repeated in the newly compiled
# C1 worker, before any signed extraction or governed Pending transaction.
sql(){
    jexec -U postgres fi-sor /usr/local/bin/psql -X -w -At \
        -v ON_ERROR_STOP=1 -h "$socket" -p 5432 -d fi -c "$1"
}
livesql(){
    jexec -U postgres fi-sor /usr/local/bin/psql -X -w -At \
        -v ON_ERROR_STOP=1 -h /var/db/fi/sor/run -p 5432 -d fi -c "$1"
}
identity="SELECT current_setting('data_directory') || '|' ||
  current_setting('unix_socket_directories') || '|' ||
  current_setting('listen_addresses') || '|' ||
  current_setting('port') || '|' ||
  (SELECT count(*) FROM fi.recorded_generation)::text || '|' ||
  (SELECT count(*) FROM fi_c1_pending.generation_control)::text || '|' ||
  (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')::text"
live_before=$(livesql "$identity")
# The LIVE SoR is published at 172.20.20.22 by its established networking
# contract. TCP isolation applies ONLY to the new disposable clone.
# Compare the exact observed live identity (including Accepted journal),
# rather than incorrectly demanding no TCP listener on live fi-sor.
live_identity_matches "$live_before" ||
    fail "actual live PostgreSQL identity changed; abort benchmark: $live_before"
clone_before=$(sql "$identity")
clone_identity_matches "$clone_before" "$pgdata" "$socket" ||
    fail "clone PGDATA, socket, TCP/listen or fresh stage differs: $clone_before"
# Both SQL roles (which must NOT gain pg_read_all_settings) will validate
# this SAME immutable control-file identifier at runtime via pg_control_system.
system_id=$(sql "SELECT system_identifier::text FROM pg_control_system()")
live_system_id=$(livesql "SELECT system_identifier::text FROM pg_control_system()")
case "$system_id" in ''|*[!0123456789]*) fail 'isolated clone control system identifier is missing or malformed';; esac
[ "${#system_id}" -ge 12 ] && [ "$system_id" != "$live_system_id" ] ||
    fail 'clone and live SoR have matching or invalid PostgreSQL system identifiers'
# A read-only probe AS EACH restricted worker role proves the cluster
# identifier function is available without ANY new PostgreSQL privilege.
# Do this in --audit BEFORE compiling or extracting original 65GiB data.
for role in fi_ingest fi_c1_publisher;do
    probe=$(jexec -U fi-sor fi-sor /usr/local/bin/psql \
        -X -w -At -v ON_ERROR_STOP=1 -h "$socket" -p 5432 -U "$role" -d fi \
        -c "SELECT current_user || '|' ||
            (SELECT system_identifier::text FROM pg_control_system()) || '|' ||
            (inet_server_addr() IS NULL)::text") ||
        fail "restricted clone role $role cannot query local physical cluster identity"
    [ "$probe" = "$role|$system_id|true" ] ||
        fail "restricted clone role $role is not using the original isolated cluster"
done
echo "FI C1 BENCHMARK CLONE ROLE IDENTITY PASS worker=fi_ingest publisher=fi_c1_publisher system_identifier=$system_id isolated=true no_additional_role_privileges=true"
[ "$(sql "SELECT count(*) FROM pg_tables WHERE schemaname='fi'")" = 49 ] &&
[ "$(sql "SELECT count(*) FROM pg_tables WHERE schemaname='fi_c1_pending'")" = 50 ] ||
    fail 'original FI and governed Pending clone schema differs'
jexec -U postgres fi-sor /usr/local/bin/pg_ctl -D "$pgdata" status >/dev/null 2>&1 ||
    fail 'isolated PostgreSQL18 clone is not running'
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pin^{commit}" ||
    fail 'approved pinned single-jail benchmark source not available'
[ -s "$sorhost/usr/local/sbin/fi-c1-sor-local" ] &&
[ ! -L "$sorhost/usr/local/sbin/fi-c1-sor-local" ] ||
    fail 'existing staged single-jail service binary changed'
free_kib=$(df -Pk "$sorhost/var/tmp" | awk 'END{print $4}')
case "$free_kib" in ''|*[!0123456789]*) fail 'invalid fast-pool available space';; esac
[ "$free_kib" -ge 524288000 ] ||
    fail "need at least 500 GiB free for original signed expansion, full relational clone and WAL; current_kib=$free_kib"
echo "FI C1 SINGLE-JAIL CLONE BENCHMARK AUDIT PASS mode=$mode source=$source generation=$generation signed_receipt_sha256=$receipt_sha canonical_before=6773 clone_canonical=0 clone_pending=0 clone_accepted=0 clone_pgdata=$pgdata clone_system_identifier=$system_id distinct_from_live=true original_custody_readonly=true service_disabled=true ready_untouched=true"
[ "$mode" = --audit ] && exit 0

# No source checkout mutation: archive EXACT pinned revision inside fi-dev.
log="$hostclone/c1-original-signed-15m-benchmark.log"
binary="$hostclone/fi-c1-sor-benchmark"
[ ! -e "$log" ] && [ ! -L "$log" ] &&
[ ! -e "$binary" ] && [ ! -L "$binary" ] ||
    fail 'benchmark evidence/binary already exists, no overwrite of a prior attempt'
build=$(jexec -U jwood fi-dev mktemp -d /home/jwood/fi-c1-single-sor-benchmark-build.XXXXXXXX) ||
    fail 'could not allocate fresh fi-dev source build'
jexec -U jwood fi-dev /bin/sh -c '
set -eu
repo=$1; pin=$2; build=$3
git -C "$repo" archive "$pin" | tar -xf - -C "$build"
cd "$build/go"
go test -tags fi_c1_sor_dev -count=1 -run "^TestC1SoR(CloneGate|Local)" ./internal/recordingest
go build -trimpath -tags fi_c1_sor_dev -o "$build/fi-c1-sor-benchmark" ./cmd/fi-c1-sor-local
test -s "$build/fi-c1-sor-benchmark"
' sh "$repo" "$pin" "$build" ||
    fail 'single-jail isolated clone regression test or benchmark worker build failed'
candidate=$devhost$build/fi-c1-sor-benchmark
[ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -s "$candidate" ] ||
    fail 'missing fi-dev exact pin compiled worker'
owner_uid=$(jexec fi-sor id -u fi-sor)
owner_gid=$(jexec fi-sor id -g fi-sor)
install -o "$owner_uid" -g "$owner_gid" -m 0555 "$candidate" "$binary" ||
    fail 'unable to install disposable clone-only benchmark binary'
echo "FI C1 BENCHMARK EXECUTABLE_SHA256=$(sha256 -q "$binary")"
echo "FI C1 BENCHMARK LOG=$log"
echo '===== ONE EXACT SIGNED GENERATION: FI-SOR + CLONE POSTGRESQL ONLY ====='
worker="host=$socket port=5432 user=fi_ingest dbname=fi sslmode=disable"
publisher="host=$socket port=5432 user=fi_c1_publisher dbname=fi sslmode=disable"
# No READY argument: benchmark cannot retire a scheduling marker.
# Benchmark clone gate enforces both DB roles' actual PGDATA and socket.
if ! jexec -U fi-sor fi-sor "$clone/fi-c1-sor-benchmark" \
    -benchmark-clone-root "$clone" -benchmark-system-id "$system_id" \
    -source-id "$source" -generation-id "$generation" \
    -custody-root /var/db/fi/custody/generation \
    -recorded-root /var/db/fi/custody/recorded \
    -postgres-local "$worker" -postgres-publisher-local "$publisher" \
    -sql-workers-max 32 -staging-root "$scratch" > "$log" 2>&1;then
    echo '===== ORIGINAL SIGNED 15M BENCHMARK FAILURE EVIDENCE =====' >&2
    tail -100 "$log" >&2 || :
    echo "FI C1 BENCHMARK FAILED: preserve clone, original signed custody, Pending SQL and logs; no automatic replay" >&2
    exit 1
fi
echo '===== ORIGINALLY SIGNED C1 INGEST AND ACCEPTED REPORT ====='
grep -E '^FI C1 SOR (CLONE WORKER/PUBLISHER PIN PASS|LOCAL INGEST THROUGHPUT|LOCAL VERIFICATION/PUBLICATION TIMING|LOCAL CANONICAL ACCEPTED|LOCAL COMPLETE)' "$log" ||
    fail 'missing new C1 ingestion/Accepted timing and signed proof'
clone_after=$(sql "$identity")
[ "$clone_after" = "$pgdata|$socket||5432|1|0|1" ] ||
    fail "clone accepted/Pending postcondition differs: $clone_after"
accepted=$(sql "SELECT count(*) FROM fi.recorded_generation WHERE
    source_id='$source' AND generation_id='$generation' AND record_count=15140785")
[ "$accepted" = 1 ] ||
    fail 'clone canonical signed generation count did not match exact 15,140,785'
[ "$(sql "SELECT count(*) FROM fi.ingest_journal WHERE source_id='$source'
     AND generation_id='$generation' AND outcome='Accepted'")" = 1 ] ||
    fail 'clone canonical Accepted journal missing or duplicated'
[ "$(livesql "$identity")" = "$live_before" ] ||
    fail 'LIVE SOR physical identity, canonical or Pending count changed unexpectedly'
[ "$(sha256 -q "/work/fi-c220-20261114/custody/recorded/$receipt")" = "$receipt_sha" ] ||
    fail 'original receiver signed receipt changed unexpectedly'
echo 'FI C1 SINGLE-JAIL CLONE FULL SIGNED ACCEPTANCE PASS records=15140785 signed_receiver_custody_preserved=true clone_pgdata_verified=true clone_canonical=1 clone_pending=0 clone_accepted=1 live_canonical_unchanged=6773 original_ready_untouched=true service_disabled=true'
echo "FI C1 BENCHMARK_LOG=$log"
