#!/bin/sh
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
