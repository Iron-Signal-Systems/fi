#!/bin/sh
# Run on root@c220. FI-dev builds the pinned tool first.
# This script never launches live FI-ingest or connects to authoritative SoR.
set -eu
umask 077
fail(){ echo "FI C220 CACHE STOP: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "root required on c220"
[ "$(hostname -s)" = c220 ] || fail "wrong host (expected c220)"
[ "$#" -eq 1 ] || fail "usage: sh $0 preflight|prepare"
case "$1" in preflight|prepare) mode=$1;; *) fail "mode must be preflight or prepare";; esac

jr=$(jls -j fi-dev path) || fail "fi-dev jail unavailable"
[ "$jr" = /fast/jails/roots/fi-dev ] || fail "unrecognized fi-dev root: $jr"
jls -j fi-sor jid >/dev/null || fail "fi-sor jail absent"
src=/work/fi-c220-20261114/custody
conf=/work/fi-c220-20261114/ingest-config
trust=/work/fi-c220-20261114/config/receiver/pki/trust
project=/home/jwood/fi-w512-c220-stage
cache=/home/jwood/fi-w512-c220-verified-cache
targetgen="$jr/var/db/fi/custody/generation"
targetrec="$jr/var/db/fi/custody/recorded"
targetcfg="$jr/usr/local/etc/fi"
targettrust="$targetcfg/pki/trust"

# Check service and processes, not just the rc setting.
if jexec fi-ingest service fi_ingest_worker onestatus >/dev/null 2>&1; then
    fail "LIVE ingest worker service is running"
fi
if jexec fi-ingest ps -axww -o command | grep -q '[f]i-ingest-worker'; then
    fail "LIVE ingest worker process is running"
fi
[ -d "$src/generation" ] && [ -d "$src/recorded" ] ||
    fail "migrated custody directories missing"
for file in \
    "$conf/sources/iss-fs-22a.iss.local.conf" \
    "$conf/pki/trust/fi-root-ca.crt.pem" \
    "$conf/pki/trust/fi-batch-signing-ca.crt.pem" \
    "$trust/fi-batch-signing-ca.crl.pem"; do
    [ -f "$file" ] && [ ! -L "$file" ] || fail "trust/authorization input missing: $file"
done
[ -x "$jr$project/fi-private-cache" ] ||
    fail "pinned tool not built; complete fi-dev build first"
# Never obscure existing jail files or pre-existing mounts.
for p in "$targetgen" "$targetrec" "$targetcfg"; do
    [ ! -e "$p" ] && [ ! -L "$p" ] ||
        fail "target already exists; do not cover it: $p"
done
[ ! -e "$jr$cache" ] && [ ! -L "$jr$cache" ] ||
    fail "existing cache path; do not overwrite: $jr$cache"

echo "===== FI-DEV PRIVATE BENCHMARK PREFLIGHT ====="
echo "host=$(hostname -s) jailroot=$jr"
echo "source=$src"
echo "ingest_config=$conf"
echo "current_receiver_trust=$trust"
echo "===== HISTORICAL SIGNED CUSTODY ====="
printf "figt_files="
find "$src/generation" -maxdepth 1 -type f -name '*.figt' | wc -l
printf "receipt_files="
find "$src/recorded" -maxdepth 1 -type f -name '*.record.json' | wc -l
echo "===== CRL EXPIRATION (MUST BE CURRENT WHEN AUTHENTICATING) ====="
openssl crl -in "$trust/fi-batch-signing-ca.crl.pem" -noout -lastupdate -nextupdate ||
    fail "CRL parse failed"
echo "===== SPACE ====="
df -h "$jr" "$src"
echo "===== GO BIN ====="
jexec fi-dev "$project/fi-private-cache" -help >/dev/null 2>&1 &&
    fail "unexpected cache binary accepted arguments"
echo "FI C220 CACHE PREFLIGHT PASS mode=$mode live_ingest=stopped postgres_started=no"

if [ "$mode" = preflight ]; then
    exit 0
fi

# Every target was checked absent. Mount signed inputs read-only. If one
# operation fails, unwind only the mounts created by this invocation.
mounted=""
success=no
cleanup(){
    code=$?
    trap - 0 1 2 15
    if [ "$success" != yes ]; then
        for p in $mounted; do umount "$p" 2>/dev/null || :; done
    fi
    exit "$code"
}
trap cleanup 0
trap 'exit 130' 2
trap 'exit 143' 15

install -d -m 0755 "$targetgen" "$targetrec" "$targetcfg"
mount -t nullfs -o ro "$src/generation" "$targetgen" ||
    fail "cannot mount custody read-only"
mounted="$targetgen $mounted"
mount -t nullfs -o ro "$src/recorded" "$targetrec" ||
    fail "cannot mount receipts read-only"
mounted="$targetrec $mounted"
mount -t nullfs -o ro "$conf" "$targetcfg" ||
    fail "cannot mount FI config read-only"
mounted="$targetcfg $mounted"
[ -d "$targettrust" ] || fail "expected trust directory not present inside mounted config"
# The current validated CRL from FI-receiver must not be replaced by the old
# migrated ingest configuration. This overlay is read-only.
mount -t nullfs -o ro "$trust" "$targettrust" ||
    fail "cannot mount receiver trust read-only"
mounted="$targettrust $mounted"

install -d -m 0700 -o 0 -g 0 "$jr$cache"
echo "===== AUTHENTICATE FULL ORIGINAL FIGT AND BUILD PRIVATE CACHE ====="
jexec fi-dev "$project/fi-private-cache" ||
    fail "authenticated cache builder failed"
success=yes
echo "FI C220 CACHE STAGE COMPLETE: signed cache only; no SQL, no live ingest"
