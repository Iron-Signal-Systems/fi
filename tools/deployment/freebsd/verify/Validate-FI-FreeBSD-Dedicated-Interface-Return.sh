#!/bin/sh

PROGRAM=${0##*/}

usage()
{
    cat <<EOF_USAGE
Usage:
    $PROGRAM <admin-if> <expected-admin-ip> <receiver-external-if> <management-bridge> <workload-bridge>

Example:
    $PROGRAM vtnet0 192.168.1.218 vtnet1 bridge10 bridge20
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

if [ "$#" -ne 5 ]; then
    usage
    exit 2
fi

ADMIN_IF=$1
EXPECTED_ADMIN_IP=$2
RECEIVER_IF=$3
MGMT_BRIDGE=$4
WORK_BRIDGE=$5

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
    fail "dedicated receiver interface has not returned to host: $RECEIVER_IF"
    receiver_state=""
}

if [ -n "$receiver_state" ]; then
    pass "dedicated receiver interface is present on host"

    if printf '%s\n' "$receiver_state" |
        grep -Eq '^[[:space:]]*inet[[:space:]]'
    then
        fail "dedicated receiver interface retains an IPv4 address"
    else
        pass "dedicated receiver interface has no IPv4 address"
    fi
fi

if netstat -rn -f inet 2>/dev/null |
    awk -v interface="$RECEIVER_IF" '
        $NF == interface {
            found=1
        }

        END {
            exit(found ? 0 : 1)
        }
    '
then
    fail "IPv4 routing table still references dedicated receiver interface"
else
    pass "IPv4 routing table has no dedicated-interface route"
fi

for bridge in "$MGMT_BRIDGE" "$WORK_BRIDGE"
do
    if ifconfig "$bridge" 2>/dev/null |
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
done

if jls -j fi-receiver >/dev/null 2>&1; then
    fail "fi-receiver is still running during dedicated-interface return proof"
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
