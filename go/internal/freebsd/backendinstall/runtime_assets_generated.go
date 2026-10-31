// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Code generated from accepted FreeBSD runtime assets. DO NOT EDIT.

package backendinstall

// Source: tools/deployment/freebsd/runtime.d/fi-receiver-supervisor.sh
// SHA256: 19d72ff0d2cf551920b75cb90d2f560416d5e2500a83403586bd27f1b925a6f2
const runtimeAssetReceiverSupervisor = `#!/bin/sh

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
`

// Source: tools/deployment/freebsd/runtime.d/fi-receiver.rc.d
// SHA256: 3ffa60abb88742399daae1ff0722ff9a93f8b8983e58750f2142e24ee385d219
const runtimeAssetReceiverRCService = `#!/bin/sh
#
# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: receiver-rc-service
#
# PROVIDE: fi_receiver
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="fi_receiver"
rcvar="fi_receiver_enable"

load_rc_config "$name"

: ${fi_receiver_enable:="NO"}

command="/usr/sbin/daemon"
pidfile="/var/run/fi/fi-receiver-supervisor.pid"
procname="/usr/sbin/daemon"

required_dirs="/usr/local/etc/fi"
required_files="/usr/local/sbin/fi-receiver /usr/local/libexec/fi-receiver-supervisor /etc/rc.conf.d/fi_receiver"

start_precmd="fi_receiver_prestart"

fi_receiver_prestart()
{
    runtime_dir="/var/run/fi"
    runtime_user="fi-receiver"

    runtime_uid=$(
        id -u "$runtime_user" 2>/dev/null
    ) || {
        printf '%s\n' \
            "fi_receiver: unable to resolve runtime UID for $runtime_user" \
            >&2
        return 1
    }

    runtime_gid=$(
        id -g "$runtime_user" 2>/dev/null
    ) || {
        printf '%s\n' \
            "fi_receiver: unable to resolve runtime GID for $runtime_user" \
            >&2
        return 1
    }

    if [ ! -e "$runtime_dir" ] &&
        [ ! -L "$runtime_dir" ]
    then
        mkdir -m 0700 "$runtime_dir" || {
            printf '%s\n' \
                "fi_receiver: unable to create $runtime_dir" \
                >&2
            return 1
        }

        if ! chown "${runtime_uid}:${runtime_gid}" "$runtime_dir"; then
            rmdir "$runtime_dir" 2>/dev/null || :
            printf '%s\n' \
                "fi_receiver: unable to assign runtime directory ownership" \
                >&2
            return 1
        fi
    fi

    if [ -L "$runtime_dir" ] ||
        [ ! -d "$runtime_dir" ]
    then
        printf '%s\n' \
            "fi_receiver: runtime path is not an exact directory: $runtime_dir" \
            >&2
        return 1
    fi

    runtime_actual=$(
        stat -f '%u:%g:%#Lp' "$runtime_dir" 2>/dev/null
    ) || {
        printf '%s\n' \
            "fi_receiver: unable to inspect runtime directory" \
            >&2
        return 1
    }

    runtime_expected="${runtime_uid}:${runtime_gid}:0700"

    if [ "$runtime_actual" != "$runtime_expected" ]; then
        printf '%s\n' \
            "fi_receiver: runtime directory metadata mismatch: expected $runtime_expected observed $runtime_actual" \
            >&2
        return 1
    fi

    return 0
}

fi_receiver_flags="-P ${pidfile} -u fi-receiver -S -T fi-receiver"
command_args="/usr/local/libexec/fi-receiver-supervisor"

run_rc_command "$1"
`

// Source: tools/deployment/freebsd/runtime.d/fi-receiver.rc.conf.template
// SHA256: 20617887620e31eb1cf01b97c78a005c2da9eb672e04669d54bc9ec55cc9a422
const runtimeAssetReceiverRCConfig = `# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: receiver-runtime-config

fi_receiver_enable="YES"

fi_receiver_bind="@FI_RECEIVER_EXTERNAL_IP@:8443"

fi_receiver_custody_root="/var/db/fi/custody/transport"
fi_receiver_max_concurrent_connections="8"
fi_receiver_max_data_bytes="67108864"

fi_receiver_generation_custody_root="/var/db/fi/custody/generation"
fi_receiver_generation_recorded_root="/var/db/fi/custody/recorded"
fi_receiver_generation_ready_root="/var/db/fi/custody/ready"

fi_receiver_generation_max_canonical_bytes="68719476736"
fi_receiver_generation_max_encoded_bytes="68719476736"
fi_receiver_generation_max_manifest_bytes="1048576"
`

// Source: tools/deployment/freebsd/runtime.d/fi-ingest-worker-run.sh
// SHA256: 6194b01b0e283b4c5f27b87c6d47b0dd6c9141644607fd07b4f7365bb53a1157
const runtimeAssetIngestRunner = `#!/bin/sh

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


# Optional operator bounds. Zero preserves the installed default.
fi_ingest_worker_max_generation_records="${fi_ingest_worker_max_generation_records-0}"
fi_ingest_worker_max_generation_data_bytes="${fi_ingest_worker_max_generation_data_bytes-0}"
fi_ingest_worker_max_attempts="${fi_ingest_worker_max_attempts-0}"

for bound in \
    "$fi_ingest_worker_max_generation_records" \
    "$fi_ingest_worker_max_generation_data_bytes" \
    "$fi_ingest_worker_max_attempts"
do
    case "$bound" in
        0) ;;
        [1-9]*)
            case "$bound" in
                *[!0-9]*) fail "ingest bound must contain decimal digits only" ;;
            esac
            ;;
        *) fail "ingest bound must be zero or a positive decimal integer" ;;
    esac
done

export PGPASSFILE="$fi_ingest_worker_pgpass"

set -- \
    -postgres "$fi_ingest_worker_postgres" \
    -workers "$fi_ingest_worker_workers" \
    -generation-custody-root /var/db/fi/custody/generation \
    -generation-recorded-root /var/db/fi/custody/recorded \
    -generation-ready-root /var/db/fi/custody/ready \
    -generation-max-canonical-bytes 68719476736 \
    -generation-max-encoded-bytes 68719476736 \
    -generation-max-manifest-bytes 1048576 \
    -max-generation-records "$fi_ingest_worker_max_generation_records" \
    -max-generation-data-bytes "$fi_ingest_worker_max_generation_data_bytes" \
    -max-attempts "$fi_ingest_worker_max_attempts"

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
`

// Source: tools/deployment/freebsd/runtime.d/fi-ingest-worker.rc.d
// SHA256: 3552eed12600b1acc85f94cf8a6c6fb6ae194599a707f69f2acca84421292766
const runtimeAssetIngestRCService = `#!/bin/sh
#
# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: ingest-worker-rc-service
#
# PROVIDE: fi_ingest_worker
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="fi_ingest_worker"
rcvar="fi_ingest_worker_enable"

load_rc_config "$name"

: ${fi_ingest_worker_enable:="NO"}

command="/usr/sbin/daemon"
pidfile="/var/run/fi/fi-ingest-worker-supervisor.pid"
procname="/usr/sbin/daemon"

required_dirs="/usr/local/etc/fi"
required_files="/usr/local/sbin/fi-ingest-worker /usr/local/libexec/fi-ingest-worker-run /etc/rc.conf.d/fi_ingest_worker"

start_precmd="fi_ingest_worker_prestart"

fi_ingest_worker_prestart()
{
    runtime_dir="/var/run/fi"
    runtime_user="fi-ingest"

    runtime_uid=$(
        id -u "$runtime_user" 2>/dev/null
    ) || {
        printf '%s\n' \
            "fi_ingest_worker: unable to resolve runtime UID for $runtime_user" \
            >&2
        return 1
    }

    runtime_gid=$(
        id -g "$runtime_user" 2>/dev/null
    ) || {
        printf '%s\n' \
            "fi_ingest_worker: unable to resolve runtime GID for $runtime_user" \
            >&2
        return 1
    }

    if [ ! -e "$runtime_dir" ] &&
        [ ! -L "$runtime_dir" ]
    then
        mkdir -m 0700 "$runtime_dir" || {
            printf '%s\n' \
                "fi_ingest_worker: unable to create $runtime_dir" \
                >&2
            return 1
        }

        if ! chown "${runtime_uid}:${runtime_gid}" "$runtime_dir"; then
            rmdir "$runtime_dir" 2>/dev/null || :
            printf '%s\n' \
                "fi_ingest_worker: unable to assign runtime directory ownership" \
                >&2
            return 1
        fi
    fi

    if [ -L "$runtime_dir" ] ||
        [ ! -d "$runtime_dir" ]
    then
        printf '%s\n' \
            "fi_ingest_worker: runtime path is not an exact directory: $runtime_dir" \
            >&2
        return 1
    fi

    runtime_actual=$(
        stat -f '%u:%g:%#Lp' "$runtime_dir" 2>/dev/null
    ) || {
        printf '%s\n' \
            "fi_ingest_worker: unable to inspect runtime directory" \
            >&2
        return 1
    }

    runtime_expected="${runtime_uid}:${runtime_gid}:0700"

    if [ "$runtime_actual" != "$runtime_expected" ]; then
        printf '%s\n' \
            "fi_ingest_worker: runtime directory metadata mismatch: expected $runtime_expected observed $runtime_actual" \
            >&2
        return 1
    fi

    return 0
}

fi_ingest_worker_flags="-P ${pidfile} -u fi-ingest -S -T fi-ingest-worker"
command_args="/usr/local/libexec/fi-ingest-worker-run"

run_rc_command "$1"
`

// Source: tools/deployment/freebsd/runtime.d/fi-ingest-worker.rc.conf.template
// SHA256: 6d57cd9bc19a0faaafae86d53098a49a84fc1d09630403b46a50d3b75b80bd99
const runtimeAssetIngestRCConfig = `# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: ingest-worker-runtime-config

fi_ingest_worker_enable="YES"

# Namespaced ingest requires completed migration and operator approval.
# The installer must not silently activate this mode.
fi_ingest_worker_namespaces="NO"

fi_ingest_worker_postgres="host=@FI_SOR_DB_WORK_IP@ port=5432 dbname=fi user=fi_ingest sslmode=disable"
fi_ingest_worker_pgpass="/usr/local/etc/fi/postgres.pgpass"
fi_ingest_worker_workers="2"

# Zero disables operator acceptance bounds.
# Configure explicit values before bounded ingestion testing.
fi_ingest_worker_max_generation_records="0"
fi_ingest_worker_max_generation_data_bytes="0"
fi_ingest_worker_max_attempts="0"
`
