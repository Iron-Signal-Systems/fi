#!/bin/sh

# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: ingest-worker-runner

set -eu

CONFIG="/etc/rc.conf.d/fi_ingest_worker"
BINARY="/usr/local/sbin/fi-ingest-worker"

fail()
{
    printf 'fi-ingest-worker-run: %s\n' "$*" >&2
    exit 1
}

[ -f "$CONFIG" ] &&
[ ! -L "$CONFIG" ] ||
    fail "runtime configuration is absent or invalid: $CONFIG"

. "$CONFIG"

[ -n "${fi_ingest_worker_postgres:-}" ] ||
    fail "fi_ingest_worker_postgres is required"

[ -n "${fi_ingest_worker_pgpass:-}" ] ||
    fail "fi_ingest_worker_pgpass is required"

case "${fi_ingest_worker_namespaces:-NO}" in
    YES|NO) ;;
    *) fail "fi_ingest_worker_namespaces must be YES or NO" ;;
esac

[ -x "$BINARY" ] ||
    fail "ingest worker binary is absent or not executable: $BINARY"

[ -r "$fi_ingest_worker_pgpass" ] ||
    fail "PostgreSQL credential file is not readable"

for trust_file in \
    /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem
do
    [ -r "$trust_file" ] ||
        fail "required ingest trust file is not readable: $trust_file"
done

fi_ingest_worker_workers="${fi_ingest_worker_workers:-1}"

case "$fi_ingest_worker_workers" in
    ""|*[!0-9]*)
        fail "fi_ingest_worker_workers must be an integer"
        ;;
esac

[ "$fi_ingest_worker_workers" -ge 1 ] &&
[ "$fi_ingest_worker_workers" -le 32 ] ||
    fail "fi_ingest_worker_workers must be between 1 and 32"

export PGPASSFILE="$fi_ingest_worker_pgpass"

set -- \
    -postgres "$fi_ingest_worker_postgres" \
    -workers "$fi_ingest_worker_workers" \
    -generation-custody-root /var/db/fi/custody/generation \
    -generation-recorded-root /var/db/fi/custody/recorded \
    -generation-ready-root /var/db/fi/custody/ready \
    -generation-max-canonical-bytes 68719476736 \
    -generation-max-encoded-bytes 68719476736 \
    -generation-max-manifest-bytes 1048576

if [ "${fi_ingest_worker_namespaces:-NO}" = "YES" ]; then
    state_root="/var/db/fi/ingest"

    # Verify the persistent host-controlled nullfs mount.
    # A jail-local directory must never substitute for durable state.
    mount -p | awk '
        $2 == "/var/db/fi/ingest" {
            count++
            if ($1 != "/var/db/fi/ingest" ||
                $3 != "nullfs" ||
                $4 !~ /(^|,)rw(,|$)/) {
                bad = 1
            }
        }
        END {
            if (count != 1 || bad == 1) {
                exit 1
            }
        }
    ' || fail "persistent ingest-state nullfs mount is absent or invalid"

    runtime_uid=$(id -u) ||
        fail "unable to determine worker UID"

    runtime_gid=$(id -g) ||
        fail "unable to determine worker GID"

    expected="${runtime_uid}:${runtime_gid}:0700"

    for state_dir in \
        "$state_root" \
        "$state_root/quarantine" \
        "$state_root/history"
    do
        [ -d "$state_dir" ] &&
        [ ! -L "$state_dir" ] ||
            fail "persistent ingest-state directory missing: $state_dir"

        actual=$(stat -f '%u:%g:%#Lp' "$state_dir") ||
            fail "unable to inspect ingest-state directory: $state_dir"

        [ "$actual" = "$expected" ] ||
            fail "ingest-state directory ownership or mode mismatch: $state_dir"
    done

    set -- "$@" \
        -generation-source-namespaces \
        -quarantine-state-root "$state_root/quarantine"
fi

exec "$BINARY" "$@"
