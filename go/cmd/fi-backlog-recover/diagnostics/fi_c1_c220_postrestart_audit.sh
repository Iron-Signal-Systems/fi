#!/bin/sh
# FI C1 C220 independent post-restart acceptance (read-only).
# This script never triggers a restart, mount, database mutation,
# C1 ingestion, or a volatile test file. It is for a future controlled
# restart ONLY, after separate restart authorization.
set -eu
fail(){ echo "FI C1 C220 POSTRESTART STOP: $*" >&2; exit 1; }
[ "$#" -eq 1 ] && [ "$1" = --verify ] ||
    fail 'usage: sh script --verify'
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'physical C220 root required'

# These two installed scripts do not modify host state. The first
# audits all 18 exact nullfs mappings (6 per jail) and all three devfs
# mounts, checks 4 GiB RAM backing and confirms stage SQL absent.
persist=/var/tmp/fi_c1_c220_persist_boot.sh
boot=/var/tmp/fi_c1_c220_boot_verify.sh
for script in "$persist" "$boot"; do
    [ -f "$script" ] && [ ! -L "$script" ] ||
        fail "missing pinned boot verifier $script"
    sh -n "$script" || fail "invalid pinned boot verifier $script"
done
echo '===== POSTRESTART EXACT ORIGINAL MOUNT INVENTORY ====='
sh "$persist" --audit ||
    fail 'one or more original receiver, ingest or SoR mounts did not recover'
echo '===== POSTRESTART FREEBSD EFFECTIVE JAIL CONFIG AND RCORDER ====='
sh "$boot" --verify ||
    fail 'persisted FreeBSD startup/mount dependencies did not recover'
echo '===== POSTRESTART C1 VOLATILE RAM MOUNT AND ORIGINAL SOURCE READ ACCESS ====='
# Native binary is built on FreeBSD and installed separately into /var/tmp;
# do not claim full postrestart acceptance if a temporary artifact was
# cleared during the reboot. Restore the PINNED native build first.
native=/var/tmp/fi_c1_c220_native_acceptance.sh
bin=/var/tmp/fi-c1-host-preflight
[ -f "$native" ] && [ ! -L "$native" ] &&
[ -x "$bin" ] && [ ! -L "$bin" ] ||
    fail 'native host preflight and signed-input runner unavailable after restart'
sh "$native" --verify ||
    fail 'native read-only SoR signed input or tmpfs verification failed'
echo '===== POSTRESTART CANONICAL SOURCE-OF-TRUTH SAFETY ====='
# At least 6249 canonical generations were observed before the boot
# configuration changed. A later source may validly add more; a smaller
# count is a hard stop. Both discarded development schemas must be absent.
check=$(jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
    -h /var/db/fi/sor/run -p 5432 -d fi \
    -c "SELECT (SELECT count(*) >= 6249 FROM fi.recorded_generation)
         AND to_regnamespace('fi_recovery') IS NULL
         AND to_regnamespace('fi_recovery_projection') IS NULL") ||
    fail 'cannot read and validate original accepted SoR'
[ "$check" = t ] ||
    fail 'authoritative generation baseline regressed or private SQL staging reappeared'
# A successful mount proof is not sufficient if either development C1
# worker was inadvertently activated by a jail rc script after reboot.
for jail in fi-ingest fi-sor; do
    if jexec "$jail" pgrep -f 'fi-c1-(ingest|sor)-worker' >/dev/null 2>&1; then
        fail "C1 development worker unexpectedly active in $jail"
    fi
done
echo 'FI C1 C220 POSTRESTART READ-ONLY ACCEPTANCE PASS original_nullfs=18 devfs=3 sor_inputs=ro C1_workers_started=false'
echo 'C1 CANONICAL APPLICATION INGESTION NOT ACCEPTED by this filesystem/boot proof'
