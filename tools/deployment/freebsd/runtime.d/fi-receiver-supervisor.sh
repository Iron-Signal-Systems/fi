#!/bin/sh

# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: receiver-supervisor
#
# fi-receiver intentionally accepts one authenticated transport connection
# per process. Restart only after a successful transaction. Any receiver
# failure terminates the supervisor and leaves the service failed closed.

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

[ -n "${fi_receiver_source:-}" ] ||
    fail "fi_receiver_source is required"

[ -n "${fi_receiver_bind:-}" ] ||
    fail "fi_receiver_bind is required"

[ -n "${fi_receiver_custody_root:-}" ] ||
    fail "fi_receiver_custody_root is required"

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

case "$fi_receiver_source" in
    *[!A-Za-z0-9._-]*)
        fail "fi_receiver_source contains unsupported characters"
        ;;
esac

child_pid=""

stop_child()
{
    if [ -n "$child_pid" ]; then
        kill -TERM "$child_pid" 2>/dev/null || :
        wait "$child_pid" 2>/dev/null || :
    fi

    exit 0
}

trap stop_child HUP INT TERM

while :
do
    "$BINARY" \
        -transport-listen \
        -bind "$fi_receiver_bind" \
        -custody-root "$fi_receiver_custody_root" \
        -max-data-bytes "$fi_receiver_max_data_bytes" \
        -generation-enable \
        -generation-custody-root "$fi_receiver_generation_custody_root" \
        -generation-recorded-root "$fi_receiver_generation_recorded_root" \
        -generation-ready-root "$fi_receiver_generation_ready_root" \
        -generation-max-canonical-bytes "$fi_receiver_generation_max_canonical_bytes" \
        -generation-max-encoded-bytes "$fi_receiver_generation_max_encoded_bytes" \
        -generation-max-manifest-bytes "$fi_receiver_generation_max_manifest_bytes" \
        -source "$fi_receiver_source" &

    child_pid=$!

    set +e
    wait "$child_pid"
    status=$?
    set -e

    child_pid=""

    if [ "$status" -ne 0 ]; then
        exit "$status"
    fi
done
