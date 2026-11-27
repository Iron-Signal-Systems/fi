#!/bin/sh

PROGRAM=${0##*/}

usage()
{
    cat <<EOF_USAGE
Usage:
    $PROGRAM <admin-if> <expected-admin-ip> <receiver-physical-if> <external-bridge> <external-host-if> <external-jail-if> <management-bridge> <workload-bridge>

Example:
    $PROGRAM vtnet0 192.168.1.218 vtnet1 bridge30 epre0a epre0b bridge10 bridge20
EOF_USAGE
}

fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    FAILED=1
}

pass()
{
    printf '[PASS] %s\n' "$*"
}

if [ "$#" -ne 8 ]; then
    usage
    exit 2
fi

ADMIN_IF=$1
EXPECTED_ADMIN_IP=$2
RECEIVER_IF=$3
EXTERNAL_BRIDGE=$4
EXTERNAL_HOST_IF=$5
EXTERNAL_JAIL_IF=$6
MGMT_BRIDGE=$7
WORK_BRIDGE=$8

FAILED=0

admin_state=$(
    ifconfig "$ADMIN_IF" 2>/dev/null
) || {
    fail "administrative interface is absent or inaccessible: $ADMIN_IF"
    admin_state=""
}

if [ -n "$admin_state" ]; then
    if printf '%s\n' "$admin_state" |
        grep -Eq "^[[:space:]]*inet[[:space:]]+${EXPECTED_ADMIN_IP}([[:space:]]|/)"
    then
        pass "administrative IPv4 remains present on $ADMIN_IF"
    else
        fail "expected administrative IPv4 is absent from $ADMIN_IF"
    fi
fi

receiver_state=$(
    ifconfig "$RECEIVER_IF" 2>/dev/null
) || {
    fail "dedicated receiver physical interface is absent: $RECEIVER_IF"
    receiver_state=""
}

if [ -n "$receiver_state" ]; then
    pass "dedicated receiver physical interface remains present on host"

    if printf '%s\n' "$receiver_state" |
        grep -Eq '^[[:space:]]*inet6?[[:space:]]'
    then
        fail "dedicated receiver physical interface retains a layer-3 address"
    else
        pass "dedicated receiver physical interface has no IPv4 or IPv6 address"
    fi
fi

ipv4_routes=$(
    netstat -rn -f inet 2>/dev/null
) || {
    fail "unable to inspect IPv4 routing table"
    ipv4_routes=""
}

if [ -n "$ipv4_routes" ]; then
    if printf '%s\n' "$ipv4_routes" |
        awk -v interface="$RECEIVER_IF" '
            $NF == interface {
                found=1
            }

            END {
                exit(found ? 0 : 1)
            }
        '
    then
        fail "IPv4 routing table references dedicated receiver physical interface"
    else
        pass "IPv4 routing table has no dedicated-interface route"
    fi
fi

ipv6_routes=$(
    netstat -rn -f inet6 2>/dev/null
) || {
    fail "unable to inspect IPv6 routing table"
    ipv6_routes=""
}

if [ -n "$ipv6_routes" ]; then
    if printf '%s\n' "$ipv6_routes" |
        awk -v interface="$RECEIVER_IF" '
            $NF == interface {
                found=1
            }

            END {
                exit(found ? 0 : 1)
            }
        '
    then
        fail "IPv6 routing table references dedicated receiver physical interface"
    else
        pass "IPv6 routing table has no dedicated-interface route"
    fi
fi

for bridge in "$MGMT_BRIDGE" "$WORK_BRIDGE"
do
    bridge_state=$(
        ifconfig "$bridge" 2>/dev/null
    ) || {
        fail "required internal FI bridge is absent: $bridge"
        bridge_state=""
    }

    if [ -n "$bridge_state" ]; then
        if printf '%s\n' "$bridge_state" |
            awk -v interface="$RECEIVER_IF" '
                $1 == "member:" && $2 == interface {
                    found=1
                }

                END {
                    exit(found ? 0 : 1)
                }
            '
        then
            fail "$RECEIVER_IF remains attached to $bridge"
        else
            pass "$RECEIVER_IF is not attached to $bridge"
        fi
    fi
done

for interface in \
    "$EXTERNAL_BRIDGE" \
    "$EXTERNAL_HOST_IF" \
    "$EXTERNAL_JAIL_IF"
do
    if ifconfig "$interface" >/dev/null 2>&1; then
        fail "receiver external runtime interface remains after stop: $interface"
    else
        pass "receiver external runtime interface is absent: $interface"
    fi
done

if jls -j fi-receiver >/dev/null 2>&1; then
    fail "fi-receiver is still running during receiver teardown proof"
else
    pass "fi-receiver is stopped"
fi

if [ "$FAILED" -eq 0 ]; then
    printf '%s\n' \
        "[PASS] FI dedicated receiver interface return acceptance complete"
else
    printf '%s\n' \
        "[FAIL] FI dedicated receiver interface return acceptance failed" >&2
fi

exit "$FAILED"
