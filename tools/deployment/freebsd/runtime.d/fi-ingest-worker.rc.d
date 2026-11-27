#!/bin/sh
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
