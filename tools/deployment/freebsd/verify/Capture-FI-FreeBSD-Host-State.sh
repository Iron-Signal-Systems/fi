#!/bin/sh

PROGRAM=${0##*/}

usage()
{
    cat <<EOF_USAGE
Usage:
    $PROGRAM <admin-if> <receiver-external-if> <management-bridge> <workload-bridge> [label]

Example:
    $PROGRAM vtnet0 vtnet1 bridge10 bridge20 baseline
EOF_USAGE
}

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    usage
    exit 2
fi

ADMIN_IF=$1
RECEIVER_IF=$2
MGMT_BRIDGE=$3
WORK_BRIDGE=$4
LABEL=${5:-snapshot}

snapshot_heading()
{
    printf '\n===== %s =====\n' "$1"
}

snapshot_command()
{
    snapshot_description=$1
    shift

    snapshot_heading "$snapshot_description"

    "$@" 2>&1 || {
        snapshot_rc=$?
        printf '[WARN] command returned %d: %s\n' \
            "$snapshot_rc" \
            "$*"
    }
}

snapshot_interface()
{
    snapshot_if=$1
    snapshot_heading "INTERFACE: $snapshot_if"

    if ifconfig "$snapshot_if" 2>/dev/null; then
        :
    else
        printf 'ABSENT OR INACCESSIBLE: %s\n' "$snapshot_if"
    fi
}

snapshot_file()
{
    snapshot_path=$1

    printf '\n--- %s ---\n' "$snapshot_path"

    if [ -L "$snapshot_path" ]; then
        printf 'TYPE=symlink\n'
        ls -ld "$snapshot_path" 2>&1
        return 0
    fi

    if [ ! -e "$snapshot_path" ]; then
        printf 'STATE=ABSENT\n'
        return 0
    fi

    stat -f \
        'MODE=%Sp UID=%u GID=%g LINKS=%l SIZE=%z PATH=%N' \
        "$snapshot_path" \
        2>&1 || true

    if [ -f "$snapshot_path" ]; then
        sha256 "$snapshot_path" 2>&1 || true

        grep -E \
            '^# FI-(MANAGED|ROLE):' \
            "$snapshot_path" \
            2>/dev/null \
            || true
    fi
}

printf 'FI_FREEBSD_HOST_STATE_V1\n'
printf 'LABEL=%s\n' "$LABEL"

snapshot_command "HOSTNAME" hostname
snapshot_command "UNAME" uname -a
snapshot_command "IDENTITY" id

snapshot_interface "$ADMIN_IF"
snapshot_interface "$RECEIVER_IF"
snapshot_interface "$MGMT_BRIDGE"
snapshot_interface "$WORK_BRIDGE"

snapshot_command \
    "IPV4 ROUTING TABLE" \
    netstat -rn -f inet

snapshot_command \
    "RUNNING JAILS" \
    jls -n

snapshot_heading "GLOBAL JAIL POLICY"

for snapshot_key in \
    jail_enable \
    jail_parallel_start \
    jail_list \
    jail_reverse_stop
do
    printf '%s=' "$snapshot_key"

    sysrc -n "$snapshot_key" 2>/dev/null ||
        printf '<unavailable>\n'
done

snapshot_heading "DEVFS RC POLICY"

for snapshot_key in \
    devfs_load_rulesets \
    devfs_rulesets \
    devfs_system_ruleset
do
    printf '%s=' "$snapshot_key"

    sysrc -n "$snapshot_key" 2>/dev/null ||
        printf '<unavailable>\n'
done

snapshot_command \
    "DEVFS RULESETS" \
    devfs rule showsets

snapshot_heading "FI PRODUCTION FILES"

for snapshot_path in \
    /etc/jail.conf.d/fi-receiver.conf \
    /etc/jail.conf.d/fi-ingest.conf \
    /etc/jail.conf.d/fi-sor-db.conf \
    /etc/fstab.fi-receiver \
    /etc/fstab.fi-ingest \
    /etc/fstab.fi-sor-db \
    /etc/devfs.rules.fi \
    /usr/local/libexec/fi-vnet-pair \
    /usr/local/etc/rc.d/fi_jails \
    /etc/rc.conf.d/fi_jails \
    /etc/rc.conf.d/devfs/90-fi
do
    snapshot_file "$snapshot_path"
done

snapshot_heading "DEDICATED INTERFACE ROUTE REFERENCES"

netstat -rn -f inet 2>/dev/null |
    awk -v interface="$RECEIVER_IF" '
        NR <= 3 || $NF == interface {
            print
        }
    '

snapshot_heading "DEDICATED INTERFACE BRIDGE REFERENCES"

for snapshot_bridge in "$MGMT_BRIDGE" "$WORK_BRIDGE"
do
    printf '%s:\n' "$snapshot_bridge"

    ifconfig "$snapshot_bridge" 2>/dev/null |
        awk -v interface="$RECEIVER_IF" '
            $1 == "member:" && $2 == interface {
                print
                found=1
            }

            END {
                if (!found) {
                    print "  no dedicated-interface membership observed"
                }
            }
        '
done

snapshot_heading "FI LIFECYCLE SERVICE"

if [ -x /usr/local/etc/rc.d/fi_jails ]; then
    /usr/local/etc/rc.d/fi_jails status 2>&1 || true
else
    printf 'ABSENT: /usr/local/etc/rc.d/fi_jails\n'
fi

snapshot_heading "END"

printf 'LABEL=%s\n' "$LABEL"
printf 'FI_FREEBSD_HOST_STATE_V1_COMPLETE\n'
