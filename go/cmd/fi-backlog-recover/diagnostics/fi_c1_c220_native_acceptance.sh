#!/bin/sh
# FI C1 actual C220 native FreeBSD statfs and original signed custody
# reachability acceptance. READ ONLY: no mount, database write, jail
# restart, rc service start, or receiver custody modification.
set -eu
fail(){ printf 'FI C1 NATIVE C220 ACCEPTANCE STOP: %s\n' "$*" >&2; exit 1; }
[ "$(id -un)" = root ] && [ "$(hostname -s)" = c220 ] ||
    fail 'physical C220 root required'
[ "$#" -eq 1 ] && [ "$1" = --verify ] ||
    fail 'usage: sh script --verify'
bin=/var/tmp/fi-c1-host-preflight
[ -f "$bin" ] && [ ! -L "$bin" ] && [ -x "$bin" ] ||
    fail 'native FreeBSD preflight binary missing or unsafe'
[ "$(jls -h jid name path | awk '$2=="fi-ingest"{print $3}')" = /fast/jails/roots/fi-ingest ] ||
    fail 'fi-ingest jail root mismatch'
[ "$(jls -h jid name path | awk '$2=="fi-sor"{print $3}')" = /fast/jails/roots/fi-sor ] ||
    fail 'fi-sor jail root mismatch'
[ "$(jexec fi-sor id -u fi-sor)" = 4100 ] ||
    fail 'fi-sor runtime identity changed'

echo '===== NATIVE FREEBSD STATFS AND RAM SECURITY ACCEPTANCE ====='
"$bin" \
    -host-tmpfs /var/run/fi-c1-handoff \
    -ingest-root /fast/jails/roots/fi-ingest \
    -sor-root /fast/jails/roots/fi-sor \
    -jail-ram-path /var/run/fi-c1-handoff \
    -runtime-uid 4100 \
    -runtime-gid 4100 \
    -host-custody-root /work/fi-c220-20261114/custody/generation \
    -host-recorded-root /work/fi-c220-20261114/custody/recorded \
    -sor-custody-path /var/db/fi/custody/generation \
    -sor-recorded-path /var/db/fi/custody/recorded \
    -host-trust-root /work/fi-c220-20261114/config/receiver/pki/trust \
    -host-sources-root /work/fi-c220-20261114/config/receiver/sources \
    -sor-trust-path /usr/local/etc/fi/pki/trust \
    -sor-sources-path /usr/local/etc/fi/sources ||
    fail 'native statfs mount validation failed'
echo '===== UNPRIVILEGED SOR ORIGINAL SIGNED INPUT VISIBILITY ====='
# Read-only checks done AS the actual future C1 worker (UID 4100), not root.
jexec -U fi-sor fi-sor /bin/sh -c '
set -eu
for file in \
    /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem \
    /usr/local/etc/fi/sources/iss-fs-22a.iss.local.conf
do
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        echo "C1 B verifier cannot read original receiver trust/source input: $file" >&2
        exit 1
    fi
done
for dir in /var/db/fi/custody/generation /var/db/fi/custody/recorded; do
    [ -d "$dir" ] && [ -r "$dir" ] && [ -x "$dir" ] ||
        { echo "C1 B signed custody directory unreadable: $dir" >&2; exit 1; }
    file=$(find "$dir" -type f -print -quit 2>/dev/null) ||
        { echo "C1 B cannot search signed custody: $dir" >&2; exit 1; }
    [ -n "$file" ] && [ -r "$file" ] ||
        { echo "C1 B found no readable signed file: $dir" >&2; exit 1; }
done
echo "C1_SOR_ORIGINAL_SIGNED_INPUTS_ACCESSIBLE=true identity=fi-sor"
' || fail 'unprivileged original signed custody/trust accessibility failed'

# No active work was started. Post-check PostgreSQL still exists, private
# development staging remains absent and the existing canonical generation
# ledger is untouched.
echo '===== EXISTING CANONICAL FI AND PRIVATE STAGE READ ONLY ====='
jexec -U postgres fi-sor psql -X -w -At -v ON_ERROR_STOP=1 \
    -h /var/db/fi/sor/run -p 5432 -d fi <<'SQL'
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SELECT 'C1_EXISTING_CANONICAL_GENERATIONS='||count(*) FROM fi.recorded_generation;
SELECT 'C1_PRIVATE_STAGE_ABSENT='||
    (to_regnamespace('fi_recovery_projection') IS NULL
     AND to_regnamespace('fi_recovery') IS NULL)::text;
COMMIT;
SQL
echo 'FI C1 C220 NATIVE MOUNT ACCEPTANCE COMPLETE readonly=true services_started=false reboot_persistent=false'
