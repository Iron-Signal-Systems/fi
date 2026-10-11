#!/bin/sh

# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: receiver-supervisor
#
# The receiver owns one persistent bounded listener. This wrapper validates
# runtime configuration and then replaces itself with the receiver process.
# Listener-level failure remains service-fatal; individual connection failures
# are isolated inside fi-receiver.

set -eu

CONFIG="/etc/rc.conf.d/fi_receiver"
BINARY="/usr/local/sbin/fi-receiver"

fail()
{
    printf 'fi-receiver-supervisor: %s\n' "$*" >&2
    exit 1
}

[ -f "$CONFIG" ] &&
[ ! -L "$CONFIG" ] ||
    fail "runtime configuration is absent or invalid: $CONFIG"

. "$CONFIG"

[ -n "${fi_receiver_bind:-}" ] ||
    fail "fi_receiver_bind is required"

[ -n "${fi_receiver_custody_root:-}" ] ||
    fail "fi_receiver_custody_root is required"

[ -n "${fi_receiver_max_concurrent_connections:-}" ] ||
    fail "fi_receiver_max_concurrent_connections is required"

[ -n "${fi_receiver_max_data_bytes:-}" ] ||
    fail "fi_receiver_max_data_bytes is required"

[ -n "${fi_receiver_generation_custody_root:-}" ] ||
    fail "fi_receiver_generation_custody_root is required"

[ -n "${fi_receiver_generation_recorded_root:-}" ] ||
    fail "fi_receiver_generation_recorded_root is required"

[ -n "${fi_receiver_generation_ready_root:-}" ] ||
    fail "fi_receiver_generation_ready_root is required"

[ -n "${fi_receiver_generation_max_canonical_bytes:-}" ] ||
    fail "fi_receiver_generation_max_canonical_bytes is required"

[ -n "${fi_receiver_generation_max_encoded_bytes:-}" ] ||
    fail "fi_receiver_generation_max_encoded_bytes is required"

[ -n "${fi_receiver_generation_max_manifest_bytes:-}" ] ||
    fail "fi_receiver_generation_max_manifest_bytes is required"

[ -x "$BINARY" ] ||
    fail "receiver binary is absent or not executable: $BINARY"

exec "$BINARY" \
    -transport-listen \
    -bind "$fi_receiver_bind" \
    -custody-root "$fi_receiver_custody_root" \
    -max-concurrent-connections "$fi_receiver_max_concurrent_connections" \
    -max-data-bytes "$fi_receiver_max_data_bytes" \
    -generation-enable \
    -generation-custody-root "$fi_receiver_generation_custody_root" \
    -generation-recorded-root "$fi_receiver_generation_recorded_root" \
    -generation-ready-root "$fi_receiver_generation_ready_root" \
    -generation-max-canonical-bytes "$fi_receiver_generation_max_canonical_bytes" \
    -generation-max-encoded-bytes "$fi_receiver_generation_max_encoded_bytes" \
    -generation-max-manifest-bytes "$fi_receiver_generation_max_manifest_bytes"
