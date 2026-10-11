// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Code generated from accepted FreeBSD runtime assets. DO NOT EDIT.

package backendinstall

// Source: tools/deployment/freebsd/runtime.d/fi-receiver-supervisor.sh
// SHA256: 9af734d2cac8bf8ba6f96dc152e47ed30eb0ed8e6a2f6863fb4c60e2317c672a
const runtimeAssetReceiverSupervisor = `#!/bin/sh

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
        -generation-max-manifest-bytes "$fi_receiver_generation_max_manifest_bytes" &

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
// SHA256: 9f3772891690391ea74b8b3d3a3232bdb60b7ec6bdcbab9f3a3fa60c3ee7d4cc
const runtimeAssetReceiverRCConfig = `# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: receiver-runtime-config

fi_receiver_enable="YES"

fi_receiver_bind="@FI_RECEIVER_EXTERNAL_IP@:8443"

fi_receiver_custody_root="/var/db/fi/custody/transport"
fi_receiver_max_data_bytes="67108864"

fi_receiver_generation_custody_root="/var/db/fi/custody/generation"
fi_receiver_generation_recorded_root="/var/db/fi/custody/recorded"
fi_receiver_generation_ready_root="/var/db/fi/custody/ready"

fi_receiver_generation_max_canonical_bytes="68719476736"
fi_receiver_generation_max_encoded_bytes="68719476736"
fi_receiver_generation_max_manifest_bytes="1048576"
`

// Source: tools/deployment/freebsd/runtime.d/fi-ingest-worker-run.sh
// SHA256: fb03353fd2a4ca09bbacb8b298896796896e461f5981dfd9ff8e44f0571528f6
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
// SHA256: aa8d2fff34ec22d95be8e65673b3c2ad95e8425bd4542919faab351fb012694f
const runtimeAssetIngestRCConfig = `# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: ingest-worker-runtime-config

fi_ingest_worker_enable="YES"

fi_ingest_worker_source="@FI_RUNTIME_SOURCE_ID@"
fi_ingest_worker_postgres="host=@FI_SOR_DB_WORK_IP@ port=5432 dbname=fi user=fi_ingest sslmode=disable"
fi_ingest_worker_pgpass="/usr/local/etc/fi/postgres.pgpass"
`
