#!/bin/sh

# Offline acceptance tests for the FI FreeBSD ZFS apply state machine.

umask 077

PROGRAM=${0##*/}
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)
HELPER="$FREEBSD_DIR/fi-host-zfs-apply.sh"

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

require_command()
{
    command -v "$1" >/dev/null 2>&1 ||
        fail "required command not found: $1"
}

cleanup()
{
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
}

get_value()
{
    case "$1" in
        FI_HOSTNAME)
            printf '%s\n' "$MOCK_CONFIG_HOSTNAME"
            ;;
        FI_ZPOOL)
            printf '%s\n' "mockpool"
            ;;
        *)
            return 1
            ;;
    esac
}

mock_reset()
{
    : > "$MOCK_DATASETS"
    : > "$MOCK_PROPERTIES"
    : > "$MOCK_CREATE_LOG"
    MOCK_LIST_FAIL=0
}

mock_add_property()
{
    printf '%s|%s|%s|%s\n' \
        "$1" \
        "$2" \
        "$3" \
        "$4" \
        >> "$MOCK_PROPERTIES"
}

mock_add_managed_dataset()
{
    mock_dataset=$1
    mock_role=$2
    mock_mountpoint=$3
    mock_canmount=$4
    mock_mounted=$5

    printf '%s\n' "$mock_dataset" >> "$MOCK_DATASETS"

    mock_add_property \
        "$mock_dataset" \
        "org.ironsignal.fi:managed" \
        "1" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "org.ironsignal.fi:schema" \
        "1" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "org.ironsignal.fi:role" \
        "$mock_role" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "mountpoint" \
        "$mock_mountpoint" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "canmount" \
        "$mock_canmount" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "atime" \
        "off" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "exec" \
        "off" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "setuid" \
        "off" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "devices" \
        "off" \
        "local"

    mock_add_property \
        "$mock_dataset" \
        "mounted" \
        "$mock_mounted" \
        "local"
}

mock_property_record()
{
    awk -F '|' \
        -v dataset="$1" \
        -v property="$2" \
        '
            $1 == dataset && $2 == property {
                record = $0
            }

            END {
                if (record != "") {
                    print record
                }
            }
        ' \
        "$MOCK_PROPERTIES"
}

zfs()
{
    mock_command=$1
    shift

    case "$mock_command" in
        list)
            if [ "$MOCK_LIST_FAIL" -ne 0 ]; then
                return 1
            fi

            cat "$MOCK_DATASETS"
            ;;
        get)
            mock_format=""

            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -H)
                        shift
                        ;;
                    -o)
                        mock_format=$2
                        shift 2
                        ;;
                    *)
                        break
                        ;;
                esac
            done

            [ "$#" -eq 2 ] ||
                return 1

            mock_property=$1
            mock_dataset=$2

            mock_record=$(
                mock_property_record \
                    "$mock_dataset" \
                    "$mock_property"
            )

            if [ -z "$mock_record" ]; then
                case "$mock_format" in
                    value,source)
                        printf '%s\t%s\n' "-" "-"
                        ;;
                    value)
                        printf '%s\n' "-"
                        ;;
                    *)
                        return 1
                        ;;
                esac

                return 0
            fi

            mock_value=$(
                printf '%s\n' "$mock_record" |
                    awk -F '|' '{print $3}'
            )

            mock_source=$(
                printf '%s\n' "$mock_record" |
                    awk -F '|' '{print $4}'
            )

            case "$mock_format" in
                value,source)
                    printf '%s\t%s\n' \
                        "$mock_value" \
                        "$mock_source"
                    ;;
                value)
                    printf '%s\n' "$mock_value"
                    ;;
                *)
                    return 1
                    ;;
            esac
            ;;
        create)
            mock_mountpoint=""
            mock_canmount=""

            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -o)
                        mock_spec=$2
                        mock_property=${mock_spec%%=*}
                        mock_value=${mock_spec#*=}

                        case "$mock_property" in
                            mountpoint)
                                mock_mountpoint=$mock_value
                                ;;
                            canmount)
                                mock_canmount=$mock_value
                                ;;
                        esac

                        mock_create_properties="${mock_create_properties}
${mock_property}|${mock_value}"

                        shift 2
                        ;;
                    *)
                        break
                        ;;
                esac
            done

            [ "$#" -eq 1 ] ||
                return 1

            mock_dataset=$1

            printf '%s\n' "$mock_dataset" >> "$MOCK_DATASETS"
            printf '%s\n' "$mock_dataset" >> "$MOCK_CREATE_LOG"

            printf '%s\n' "$mock_create_properties" |
                while IFS='|' read -r mock_property mock_value
                do
                    [ -n "$mock_property" ] || continue

                    mock_add_property \
                        "$mock_dataset" \
                        "$mock_property" \
                        "$mock_value" \
                        "local"
                done

            if \
                [ "$mock_mountpoint" = "none" ] ||
                [ "$mock_canmount" = "off" ]
            then
                mock_mounted="no"
            else
                mock_mounted="yes"

                mkdir -p "$mock_mountpoint" ||
                    return 1
            fi

            mock_add_property \
                "$mock_dataset" \
                "mounted" \
                "$mock_mounted" \
                "local"

            mock_create_properties=""
            ;;
        *)
            return 1
            ;;
    esac
}

assert_classification()
{
    expected=$1
    dataset=$2
    role=$3
    mountpoint=$4
    canmount=$5
    mounted=$6

    actual=$(
        zfs_apply_classify_dataset \
            "$dataset" \
            "$role" \
            "$mountpoint" \
            "$canmount" \
            "$mounted"
    )

    [ "$actual" = "$expected" ] ||
        fail \
            "classification mismatch for $dataset: expected $expected, observed $actual"

    pass "$expected classification"
}

for required_command in \
    awk \
    cat \
    grep \
    mkdir \
    mktemp \
    rm \
    sh \
    wc
do
    require_command "$required_command"
done

[ -f "$HELPER" ] ||
    fail "ZFS apply helper not found: $HELPER"

sh -n "$HELPER" ||
    fail "ZFS apply helper shell syntax"

. "$HELPER"

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fi-zfs-apply-test.XXXXXX") ||
    fail "unable to create ZFS apply verification workspace"

trap cleanup 0 HUP INT TERM

MOCK_DATASETS="$WORK_DIR/datasets"
MOCK_PROPERTIES="$WORK_DIR/properties"
MOCK_CREATE_LOG="$WORK_DIR/create.log"
MOCK_CONFIG_HOSTNAME="mock-host"
MOCK_ACTUAL_HOSTNAME="mock-host"

mock_reset

assert_classification \
    "ABSENT" \
    "mockpool/fi/absent" \
    "ready" \
    "$WORK_DIR/absent" \
    "on" \
    "yes"

mock_reset
MOCK_LIST_FAIL=1

assert_classification \
    "UNKNOWN" \
    "mockpool/fi/inspection-error" \
    "ready" \
    "$WORK_DIR/inspection-error" \
    "on" \
    "yes"

pass "inspection failure is never classified as ABSENT"

mock_reset

printf '%s\n' \
    "mockpool/fi/foreign" \
    >> "$MOCK_DATASETS"

assert_classification \
    "FOREIGN_COLLISION" \
    "mockpool/fi/foreign" \
    "ready" \
    "$WORK_DIR/foreign" \
    "on" \
    "yes"

mock_reset

mock_add_managed_dataset \
    "mockpool/fi/drift" \
    "wrong-role" \
    "$WORK_DIR/drift" \
    "on" \
    "yes"

assert_classification \
    "OWNED_DRIFT" \
    "mockpool/fi/drift" \
    "ready" \
    "$WORK_DIR/drift" \
    "on" \
    "yes"

mock_reset

mock_add_managed_dataset \
    "mockpool/fi/match" \
    "ready" \
    "$WORK_DIR/match" \
    "on" \
    "yes"

assert_classification \
    "OWNED_MATCH" \
    "mockpool/fi/match" \
    "ready" \
    "$WORK_DIR/match" \
    "on" \
    "yes"

mock_reset

CREATE_MOUNTPOINT="$WORK_DIR/create-mount"

zfs_apply_dataset \
    "mockpool/fi/create-once" \
    "ready" \
    "$CREATE_MOUNTPOINT" \
    "on" \
    "yes"

create_count=$(
    wc -l < "$MOCK_CREATE_LOG" |
        awk '{print $1}'
)

[ "$create_count" -eq 1 ] ||
    fail "first apply did not create exactly one dataset"

zfs_apply_dataset \
    "mockpool/fi/create-once" \
    "ready" \
    "$CREATE_MOUNTPOINT" \
    "on" \
    "yes"

create_count=$(
    wc -l < "$MOCK_CREATE_LOG" |
        awk '{print $1}'
)

[ "$create_count" -eq 1 ] ||
    fail "second exact apply unexpectedly created another dataset"

pass "exact second ZFS apply is a no-op"

mock_reset

printf '%s\n' \
    "mockpool/fi/foreign-apply" \
    >> "$MOCK_DATASETS"

if (
    zfs_apply_dataset \
        "mockpool/fi/foreign-apply" \
        "ready" \
        "$WORK_DIR/foreign-apply" \
        "on" \
        "yes"
) >/dev/null 2>&1
then
    fail "FOREIGN_COLLISION unexpectedly applied"
fi

pass "FOREIGN_COLLISION fails closed"

mock_reset
MOCK_LIST_FAIL=1

if (
    zfs_apply_dataset \
        "mockpool/fi/unknown-apply" \
        "ready" \
        "$WORK_DIR/unknown-apply" \
        "on" \
        "yes"
) >/dev/null 2>&1
then
    fail "UNKNOWN state unexpectedly applied"
fi

pass "UNKNOWN state fails closed"

mock_reset

printf '%s\n' \
    "mockpool/fi/inherited-owner" \
    >> "$MOCK_DATASETS"

mock_add_property \
    "mockpool/fi/inherited-owner" \
    "org.ironsignal.fi:managed" \
    "1" \
    "inherited"

assert_classification \
    "FOREIGN_COLLISION" \
    "mockpool/fi/inherited-owner" \
    "ready" \
    "$WORK_DIR/inherited-owner" \
    "on" \
    "yes"

pass "inherited FI managed property does not establish ownership"

mock_reset

mock_add_managed_dataset \
    "mockpool/fi/inherited-required" \
    "ready" \
    "$WORK_DIR/inherited-required" \
    "on" \
    "yes"

mock_add_property \
    "mockpool/fi/inherited-required" \
    "atime" \
    "off" \
    "inherited"

assert_classification \
    "OWNED_DRIFT" \
    "mockpool/fi/inherited-required" \
    "ready" \
    "$WORK_DIR/inherited-required" \
    "on" \
    "yes"

pass "inherited controlled property is not accepted as local desired state"

mock_reset

COLLISION_PATH="$WORK_DIR/mountpoint-collision"
mkdir -p "$COLLISION_PATH"

if (
    zfs_apply_precheck_dataset \
        "mockpool/fi/path-collision" \
        "ready" \
        "$COLLISION_PATH" \
        "on" \
        "yes"
) >/dev/null 2>&1
then
    fail "existing mountpoint path unexpectedly passed ZFS precheck"
fi

pass "existing mountpoint path fails before ZFS creation"

mock_reset

mock_reset
MOCK_CONFIG_HOSTNAME="wrong-host"
MOCK_ACTUAL_HOSTNAME="mock-host"

if (
    apply_zfs_hierarchy
) >/dev/null 2>&1
then
    fail "wrong-host ZFS apply unexpectedly succeeded"
fi

create_count=$(
    wc -l < "$MOCK_CREATE_LOG" |
        awk '{print $1}'
)

[ "$create_count" -eq 0 ] ||
    fail "wrong-host ZFS apply reached dataset creation"

pass "wrong-host ZFS apply fails before mutation"

MOCK_CONFIG_HOSTNAME="mock-host"
MOCK_ACTUAL_HOSTNAME="mock-host"

mock_reset

printf '%s\n' "mockpool/fi" >> "$MOCK_DATASETS"

mock_add_property \
    "mockpool/fi" \
    "mountpoint" \
    "/var/db/fi" \
    "local"

printf '%s\n' \
    "mockpool/fi/backups" \
    >> "$MOCK_DATASETS"

id()
{
    case "$1" in
        -u)
            printf '%s\n' "0"
            ;;
        *)
            return 1
            ;;
    esac
}

hostname()
{
    printf '%s\n' "$MOCK_ACTUAL_HOSTNAME"
}

uname()
{
    case "$1" in
        -s)
            printf '%s\n' "FreeBSD"
            ;;
        *)
            return 1
            ;;
    esac
}

zpool()
{
    [ "$1" = "list" ] ||
        return 1

    printf '%s\n' "mockpool"
}

if (
    apply_zfs_hierarchy
) >/dev/null 2>&1
then
    fail "late FOREIGN_COLLISION unexpectedly passed hierarchy preclassification"
fi

create_count=$(
    wc -l < "$MOCK_CREATE_LOG" |
        awk '{print $1}'
)

[ "$create_count" -eq 0 ] ||
    fail "hierarchy mutated before discovering a pre-existing late collision"

pass "layer-wide ZFS preclassification prevents avoidable partial mutation"

pass "FI FreeBSD ZFS apply acceptance complete"
