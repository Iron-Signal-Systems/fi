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

[ -n "${fi_ingest_worker_source:-}" ] ||
    fail "fi_ingest_worker_source is required"

[ -n "${fi_ingest_worker_postgres:-}" ] ||
    fail "fi_ingest_worker_postgres is required"

[ -n "${fi_ingest_worker_pgpass:-}" ] ||
    fail "fi_ingest_worker_pgpass is required"

[ -x "$BINARY" ] ||
    fail "ingest worker binary is absent or not executable: $BINARY"

[ -r "$fi_ingest_worker_pgpass" ] ||
    fail "PostgreSQL credential file is not readable"

case "$fi_ingest_worker_source" in
    *[!A-Za-z0-9._-]*)
        fail "fi_ingest_worker_source contains unsupported characters"
        ;;
esac

for trust_file in \
    /usr/local/etc/fi/pki/trust/fi-root-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crt.pem \
    /usr/local/etc/fi/pki/trust/fi-batch-signing-ca.crl.pem \
    "/usr/local/etc/fi/sources/${fi_ingest_worker_source}.conf"
do
    [ -r "$trust_file" ] ||
        fail "required ingest trust file is not readable: $trust_file"
done

export PGPASSFILE="$fi_ingest_worker_pgpass"

exec "$BINARY" \
    -source "$fi_ingest_worker_source" \
    -postgres "$fi_ingest_worker_postgres" \
    -generation-custody-root /var/db/fi/custody/generation \
    -generation-recorded-root /var/db/fi/custody/recorded \
    -generation-ready-root /var/db/fi/custody/ready \
    -generation-max-canonical-bytes 68719476736 \
    -generation-max-encoded-bytes 68719476736 \
    -generation-max-manifest-bytes 1048576
