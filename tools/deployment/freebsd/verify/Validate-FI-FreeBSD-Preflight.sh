#!/bin/sh

# Read-only acceptance verification for FI FreeBSD host preflight.

umask 077

PROGRAM=${0##*/}
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)
BOOTSTRAP="$FREEBSD_DIR/fi-bootstrap.sh"

WORK_DIR=""

fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

pass()
{
    printf '[PASS] %s\n' "$*"
}

cleanup()
{
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
}

require_command()
{
    command -v "$1" >/dev/null 2>&1 ||
        fail "required command not found: $1"
}

usage()
{
    cat <<EOF_USAGE
Usage:
    $PROGRAM <config-file>

The verifier is read-only.

As a non-root user it verifies the preflight root guard.
As root on the intended FreeBSD host it executes preflight and verifies that
selected host control-plane state is identical before and after the run.
EOF_USAGE
}

capture_host_state()
{
    capture_destination=$1

    {
        echo "===== FREEBSD RELEASE ====="
        freebsd-version

        echo "===== ZFS ====="
        zfs list \
            -H \
            -t filesystem,volume \
            -o name,mountpoint,canmount,readonly,origin |
            sort

        echo "===== MOUNTS ====="
        mount -p | sort

        echo "===== INTERFACES ====="
        ifconfig -l

        echo "===== JAILS ====="
        jls -n | sort

        echo "===== DEVFS RULESETS ====="
        devfs rule showsets | sort -n

        echo "===== USERS ====="
        getent passwd | sort

        echo "===== GROUPS ====="
        getent group | sort

        echo "===== RC STATE ====="
        for capture_key in \
            jail_enable \
            pf_enable \
            pf_rules \
            gateway_enable \
            cloned_interfaces \
            ifconfig_bridge10 \
            ifconfig_bridge20
        do
            printf '%s=' "$capture_key"

            if capture_value=$(sysrc -n "$capture_key" 2>/dev/null)
            then
                printf '%s\n' "$capture_value"
            else
                printf '<unset>\n'
            fi
        done

        echo "===== FORWARDING ====="
        sysctl -n net.inet.ip.forwarding

        echo "===== PF FILTER RULES ====="
        pfctl -sr

        echo "===== PF NAT RULES ====="
        pfctl -sn

        echo "===== DEPLOYMENT PARENT PATHS ====="
        for capture_path in \
            /etc/jail.conf \
            /etc/jail.conf.d \
            /usr/local/jails/containers \
            /var/db/fi
        do
            if [ -e "$capture_path" ] || [ -L "$capture_path" ]; then
                ls -ld "$capture_path"
            else
                printf 'ABSENT %s\n' "$capture_path"
            fi
        done

        echo "===== PRODUCTION CONFIG PATHS ====="
        for capture_path in \
            /etc/jail.conf.d/fi-receiver.conf \
            /etc/jail.conf.d/fi-ingest.conf \
            /etc/jail.conf.d/fi-sor-db.conf \
            /etc/fstab.fi-receiver \
            /etc/fstab.fi-ingest \
            /etc/fstab.fi-sor-db \
            /etc/devfs.rules.fi \
            /usr/local/libexec/fi-vnet-pair
        do
            if [ -e "$capture_path" ] || [ -L "$capture_path" ]; then
                ls -ld "$capture_path"
            else
                printf 'ABSENT %s\n' "$capture_path"
            fi
        done
    } > "$capture_destination"
}

if [ "$#" -ne 1 ]; then
    usage
    exit 2
fi

CONFIG_FILE=$1

[ -r "$CONFIG_FILE" ] ||
    fail "configuration file is not readable: $CONFIG_FILE"

[ -f "$BOOTSTRAP" ] ||
    fail "bootstrap not found: $BOOTSTRAP"

for required_command in \
    cat \
    grep \
    id \
    mktemp \
    rm \
    sh
do
    require_command "$required_command"
done

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fi-preflight-verify.XXXXXX") ||
    fail "unable to create verification workspace"

trap cleanup 0 HUP INT TERM

PREFLIGHT_OUTPUT="$WORK_DIR/preflight.out"

if [ "$(id -u)" -ne 0 ]; then
    sh "$BOOTSTRAP" preflight "$CONFIG_FILE" \
        > "$PREFLIGHT_OUTPUT" 2>&1

    preflight_rc=$?

    cat "$PREFLIGHT_OUTPUT"

    [ "$preflight_rc" -ne 0 ] ||
        fail "non-root preflight unexpectedly succeeded"

    grep -Fq \
        '[FAIL] preflight must run as root on the intended FreeBSD host' \
        "$PREFLIGHT_OUTPUT" ||
        fail "non-root preflight did not fail at the root guard"

    pass "non-root preflight guard"
    pass "FI FreeBSD preflight acceptance complete"
    exit 0
fi

for required_command in \
    cat \
    cmp \
    diff \
    devfs \
    freebsd-version \
    getent \
    ifconfig \
    jls \
    ls \
    mount \
    pfctl \
    sort \
    sysctl \
    sysrc \
    zfs
do
    require_command "$required_command"
done

BEFORE_STATE="$WORK_DIR/before.state"
AFTER_STATE="$WORK_DIR/after.state"

capture_host_state "$BEFORE_STATE" ||
    fail "unable to capture host state before preflight"

sh "$BOOTSTRAP" preflight "$CONFIG_FILE" \
    > "$PREFLIGHT_OUTPUT" 2>&1

preflight_rc=$?

capture_host_state "$AFTER_STATE" ||
    fail "unable to capture host state after preflight"

cat "$PREFLIGHT_OUTPUT"

if cmp -s "$BEFORE_STATE" "$AFTER_STATE"
then
    pass "selected host control-plane state unchanged by preflight"
else
    echo "===== HOST STATE DIFFERENCE =====" >&2
    diff -u "$BEFORE_STATE" "$AFTER_STATE" >&2 || true
    fail "selected host control-plane state changed during preflight"
fi

[ "$preflight_rc" -eq 0 ] ||
    fail "bootstrap preflight failed with exit code $preflight_rc"

pass "bootstrap host preflight"
pass "FI FreeBSD preflight acceptance complete"
