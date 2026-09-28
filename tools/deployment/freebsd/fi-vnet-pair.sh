#!/bin/sh

fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

vnet_interface_state()
{
    vnet_state_name=$1

    vnet_state_names=$(/sbin/ifconfig -l 2>/dev/null) ||
        return 2

    case " $vnet_state_names " in
        *" $vnet_state_name "*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

vnet_require_absent()
{
    vnet_absent_name=$1

    vnet_interface_state "$vnet_absent_name"
    vnet_absent_state=$?

    case "$vnet_absent_state" in
        0)
            printf '[FAIL] configured VNET interface already exists: %s\n' \
                "$vnet_absent_name" >&2
            return 1
            ;;
        1)
            return 0
            ;;
        *)
            printf '[FAIL] unable to inspect VNET interface namespace\n' >&2
            return 1
            ;;
    esac
}

vnet_require_bridge()
{
    vnet_bridge=$1

    /sbin/ifconfig "$vnet_bridge" >/dev/null 2>&1 || {
        printf '[FAIL] configured bridge does not exist: %s\n' \
            "$vnet_bridge" >&2
        return 1
    }

    return 0
}

vnet_require_dedicated_interface()
{
    vnet_dedicated_if=$1
    vnet_mgmt_bridge=$2
    vnet_work_bridge=$3

    /sbin/ifconfig "$vnet_dedicated_if" >/dev/null 2>&1 || {
        printf '[FAIL] dedicated VNET interface does not exist: %s\n' \
            "$vnet_dedicated_if" >&2
        return 1
    }

    if /sbin/ifconfig "$vnet_dedicated_if" |
        /usr/bin/awk '
            $1 == "inet" || $1 == "inet6" {
                found = 1
            }

            END {
                exit found ? 0 : 1
            }
        '
    then
        printf '[FAIL] dedicated VNET interface has a host address: %s\n' \
            "$vnet_dedicated_if" >&2
        return 1
    fi

    for vnet_dedicated_bridge in \
        "$vnet_mgmt_bridge" \
        "$vnet_work_bridge"
    do
        vnet_require_bridge "$vnet_dedicated_bridge" || return 1

        if /sbin/ifconfig "$vnet_dedicated_bridge" |
            /usr/bin/awk -v interface="$vnet_dedicated_if" '
                $1 == "member:" && $2 == interface {
                    found = 1
                }

                END {
                    exit found ? 0 : 1
                }
            '
        then
            printf '[FAIL] dedicated VNET interface is a member of %s: %s\n' \
                "$vnet_dedicated_bridge" \
                "$vnet_dedicated_if" >&2
            return 1
        fi
    done

    printf '[PASS] dedicated VNET interface ready: %s\n' \
        "$vnet_dedicated_if"

    return 0
}

vnet_create_pair()
{
    vnet_host_if=$1
    vnet_jail_if=$2
    vnet_bridge=$3
    vnet_description=$4

    vnet_require_absent "$vnet_host_if" || return 1
    vnet_require_absent "$vnet_jail_if" || return 1
    vnet_require_bridge "$vnet_bridge" || return 1

    vnet_created=$(/sbin/ifconfig epair create) || {
        printf '[FAIL] unable to create epair\n' >&2
        return 1
    }

    case "$vnet_created" in
        epair*a)
            ;;
        *)
            /sbin/ifconfig "$vnet_created" destroy >/dev/null 2>&1 || true
            printf '[FAIL] unexpected epair clone name: %s\n' \
                "$vnet_created" >&2
            return 1
            ;;
    esac

    vnet_peer=${vnet_created%a}b

    /sbin/ifconfig "$vnet_peer" name "$vnet_jail_if" || {
        /sbin/ifconfig "$vnet_created" destroy >/dev/null 2>&1 || true
        printf '[FAIL] unable to rename jail-side epair to %s\n' \
            "$vnet_jail_if" >&2
        return 1
    }

    /sbin/ifconfig "$vnet_created" name "$vnet_host_if" || {
        /sbin/ifconfig "$vnet_jail_if" destroy >/dev/null 2>&1 || true
        printf '[FAIL] unable to rename host-side epair to %s\n' \
            "$vnet_host_if" >&2
        return 1
    }

    /sbin/ifconfig "$vnet_host_if" up descr "$vnet_description" || {
        /sbin/ifconfig "$vnet_host_if" destroy >/dev/null 2>&1 || true
        printf '[FAIL] unable to configure host-side epair: %s\n' \
            "$vnet_host_if" >&2
        return 1
    }

    /sbin/ifconfig "$vnet_bridge" addm "$vnet_host_if" up || {
        /sbin/ifconfig "$vnet_host_if" destroy >/dev/null 2>&1 || true
        printf '[FAIL] unable to attach %s to %s\n' \
            "$vnet_host_if" "$vnet_bridge" >&2
        return 1
    }

    printf '[PASS] VNET pair created: %s / %s -> %s\n' \
        "$vnet_host_if" \
        "$vnet_jail_if" \
        "$vnet_bridge"

    return 0
}

vnet_destroy_pair()
{
    vnet_host_if=$1
    vnet_jail_if=$2
    vnet_bridge=$3

    vnet_interface_state "$vnet_host_if"
    vnet_host_state=$?

    case "$vnet_host_state" in
        0)
            ;;
        1)
            vnet_interface_state "$vnet_jail_if"
            vnet_jail_state=$?

            case "$vnet_jail_state" in
                0)
                    printf '[FAIL] host VNET endpoint absent while jail endpoint remains: %s\n' \
                        "$vnet_jail_if" >&2
                    return 1
                    ;;
                1)
                    printf '[PASS] VNET pair already absent: %s / %s\n' \
                        "$vnet_host_if" "$vnet_jail_if"
                    return 0
                    ;;
                *)
                    printf '[FAIL] unable to inspect VNET interface namespace\n' >&2
                    return 1
                    ;;
            esac
            ;;
        *)
            printf '[FAIL] unable to inspect VNET interface namespace\n' >&2
            return 1
            ;;
    esac

    /sbin/ifconfig "$vnet_bridge" deletem "$vnet_host_if" \
        >/dev/null 2>&1 || true

    /sbin/ifconfig "$vnet_host_if" destroy || {
        printf '[FAIL] unable to destroy VNET pair through %s\n' \
            "$vnet_host_if" >&2
        return 1
    }

    vnet_interface_state "$vnet_jail_if"
    vnet_jail_state=$?

    case "$vnet_jail_state" in
        1)
            ;;
        0)
            printf '[FAIL] jail VNET endpoint remained after pair destruction: %s\n' \
                "$vnet_jail_if" >&2
            return 1
            ;;
        *)
            printf '[FAIL] unable to verify VNET pair destruction\n' >&2
            return 1
            ;;
    esac

    printf '[PASS] VNET pair removed: %s / %s\n' \
        "$vnet_host_if" "$vnet_jail_if"

    return 0
}

vnet_create_dual()
{
    vnet_mgmt_host=$1
    vnet_mgmt_jail=$2
    vnet_mgmt_bridge=$3
    vnet_mgmt_description=$4
    vnet_work_host=$5
    vnet_work_jail=$6
    vnet_work_bridge=$7
    vnet_work_description=$8

    # Layer-wide preclassification before the first mutation.
    vnet_require_absent "$vnet_mgmt_host" || return 1
    vnet_require_absent "$vnet_mgmt_jail" || return 1
    vnet_require_absent "$vnet_work_host" || return 1
    vnet_require_absent "$vnet_work_jail" || return 1
    vnet_require_bridge "$vnet_mgmt_bridge" || return 1
    vnet_require_bridge "$vnet_work_bridge" || return 1

    vnet_create_pair \
        "$vnet_mgmt_host" \
        "$vnet_mgmt_jail" \
        "$vnet_mgmt_bridge" \
        "$vnet_mgmt_description" ||
        return 1

    if ! vnet_create_pair \
        "$vnet_work_host" \
        "$vnet_work_jail" \
        "$vnet_work_bridge" \
        "$vnet_work_description"
    then
        printf '[INFO] rolling back management VNET pair after workload failure\n' >&2

        vnet_destroy_pair \
            "$vnet_mgmt_host" \
            "$vnet_mgmt_jail" \
            "$vnet_mgmt_bridge" \
            >/dev/null 2>&1 || true

        return 1
    fi

    printf '[PASS] dual VNET provisioning complete\n'
}

vnet_create_receiver()
{
    vnet_receiver_external=$1
    vnet_receiver_mgmt_host=$2
    vnet_receiver_mgmt_jail=$3
    vnet_receiver_mgmt_bridge=$4
    vnet_receiver_mgmt_description=$5
    vnet_receiver_work_host=$6
    vnet_receiver_work_jail=$7
    vnet_receiver_work_bridge=$8
    vnet_receiver_work_description=$9

    vnet_require_dedicated_interface \
        "$vnet_receiver_external" \
        "$vnet_receiver_mgmt_bridge" \
        "$vnet_receiver_work_bridge" ||
        return 1

    vnet_create_dual \
        "$vnet_receiver_mgmt_host" \
        "$vnet_receiver_mgmt_jail" \
        "$vnet_receiver_mgmt_bridge" \
        "$vnet_receiver_mgmt_description" \
        "$vnet_receiver_work_host" \
        "$vnet_receiver_work_jail" \
        "$vnet_receiver_work_bridge" \
        "$vnet_receiver_work_description"
}

vnet_destroy_dual()
{
    vnet_mgmt_host=$1
    vnet_mgmt_jail=$2
    vnet_mgmt_bridge=$3
    vnet_work_host=$4
    vnet_work_jail=$5
    vnet_work_bridge=$6

    vnet_destroy_status=0

    vnet_destroy_pair \
        "$vnet_work_host" \
        "$vnet_work_jail" \
        "$vnet_work_bridge" ||
        vnet_destroy_status=1

    vnet_destroy_pair \
        "$vnet_mgmt_host" \
        "$vnet_mgmt_jail" \
        "$vnet_mgmt_bridge" ||
        vnet_destroy_status=1

    [ "$vnet_destroy_status" -eq 0 ]
}

[ "$(id -u)" -eq 0 ] ||
    fail "VNET provisioning must run as root"

[ "$(uname -s)" = "FreeBSD" ] ||
    fail "VNET provisioning requires FreeBSD"

[ "$#" -ge 1 ] ||
    fail "usage: fi-vnet-pair.sh create-dual|create-receiver|destroy-dual ..."

case "$1" in
    create-dual)
        [ "$#" -eq 9 ] ||
            fail "create-dual requires management and workload endpoint definitions"

        vnet_create_dual \
            "$2" "$3" "$4" "$5" \
            "$6" "$7" "$8" "$9" ||
            fail "dual VNET provisioning failed"
        ;;

    create-receiver)
        [ "$#" -eq 10 ] ||
            fail "create-receiver requires one dedicated interface plus management and workload endpoint definitions"

        vnet_create_receiver \
            "$2" \
            "$3" "$4" "$5" "$6" \
            "$7" "$8" "$9" "${10}" ||
            fail "receiver VNET provisioning failed"
        ;;

    destroy-dual)
        [ "$#" -eq 7 ] ||
            fail "destroy-dual requires management and workload endpoint definitions"

        vnet_destroy_dual \
            "$2" "$3" "$4" \
            "$5" "$6" "$7" ||
            fail "dual VNET cleanup failed"
        ;;

    *)
        fail "unsupported VNET operation: $1"
        ;;
esac
