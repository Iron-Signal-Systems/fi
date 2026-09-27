#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
HELPER="$SCRIPT_DIR/../fi-host-jail-root-apply.sh"

[ -f "$HELPER" ] || {
    printf '[FAIL] helper not found: %s\n' "$HELPER" >&2
    exit 1
}

. "$HELPER"

test_fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

test_pass()
{
    printf '[PASS] %s\n' "$*"
}

fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

pass()
{
    :
}

get_value()
{
    case "$1" in
        FI_HOSTNAME)
            printf '%s\n' "fi-test.invalid"
            ;;
        FI_JAIL_DATASET_ROOT)
            printf '%s\n' "mockpool/jails/containers"
            ;;
        FI_JAIL_ROOT_BASE)
            printf '%s\n' "/mock/jails/containers"
            ;;
        FI_JAIL_TEMPLATE_SNAPSHOT)
            printf '%s\n' "mockpool/jails/templates/15.1-RELEASE@base-test"
            ;;
        *)
            test_fail "unexpected configuration lookup: $1"
            ;;
    esac
}

MOCK_CONTROLLED_STATUS=0
MOCK_DATASET_PRESENCE=1
MOCK_MANAGED_STATUS=0
MOCK_ORIGIN_STATUS=0
MOCK_PATH_PRESENCE=1
MOCK_ROLE_STATUS=0
MOCK_RUNTIME_STATUS=0
MOCK_SCHEMA_STATUS=0

jail_root_dataset_presence()
{
    return "$MOCK_DATASET_PRESENCE"
}

jail_root_local_property_status()
{
    case "$2" in
        "$FI_JAIL_ZFS_MANAGED_PROPERTY")
            return "$MOCK_MANAGED_STATUS"
            ;;
        "$FI_JAIL_ZFS_SCHEMA_PROPERTY")
            return "$MOCK_SCHEMA_STATUS"
            ;;
        "$FI_JAIL_ZFS_ROLE_PROPERTY")
            return "$MOCK_ROLE_STATUS"
            ;;
        *)
            return "$MOCK_CONTROLLED_STATUS"
            ;;
    esac
}

jail_root_origin_status()
{
    return "$MOCK_ORIGIN_STATUS"
}

jail_root_path_presence()
{
    return "$MOCK_PATH_PRESENCE"
}

jail_root_runtime_property_status()
{
    return "$MOCK_RUNTIME_STATUS"
}

expect_state()
{
    expected=$1
    description=$2

    actual=$(
        jail_root_classify_dataset \
            "mockpool/jails/containers/fi-receiver" \
            "/mock/jails/containers/fi-receiver" \
            "jail-root-receiver" \
            "mockpool/jails/templates/15.1-RELEASE@base-test" \
            "mockpool/jails/containers"
    ) || test_fail "$description: classifier returned failure"

    [ "$actual" = "$expected" ] ||
        test_fail "$description: expected $expected, observed $actual"

    test_pass "$description"
}

MOCK_DATASET_PRESENCE=1
MOCK_PATH_PRESENCE=1
expect_state "ABSENT" "ABSENT classification"

MOCK_DATASET_PRESENCE=2
expect_state "UNKNOWN" "UNKNOWN classification"

MOCK_DATASET_PRESENCE=1
MOCK_PATH_PRESENCE=0
expect_state "FOREIGN_COLLISION" "existing destination path is a foreign collision"

MOCK_DATASET_PRESENCE=0
MOCK_MANAGED_STATUS=1
MOCK_PATH_PRESENCE=1
expect_state "FOREIGN_COLLISION" "missing or inherited FI managed property does not establish ownership"

MOCK_MANAGED_STATUS=0
MOCK_SCHEMA_STATUS=1
expect_state "OWNED_DRIFT" "FI-owned schema drift classification"

MOCK_SCHEMA_STATUS=0
MOCK_ROLE_STATUS=1
expect_state "OWNED_DRIFT" "FI-owned role drift classification"

MOCK_ROLE_STATUS=0
MOCK_CONTROLLED_STATUS=1
expect_state "OWNED_DRIFT" "FI-owned controlled-property drift classification"

MOCK_CONTROLLED_STATUS=0
MOCK_ORIGIN_STATUS=1
expect_state "OWNED_DRIFT" "wrong clone origin classification"

MOCK_ORIGIN_STATUS=0
MOCK_RUNTIME_STATUS=1
expect_state "OWNED_DRIFT" "runtime mount drift classification"

MOCK_RUNTIME_STATUS=0
expect_state "OWNED_MATCH" "OWNED_MATCH classification"

MOCK_CLONE_LOG=$(mktemp "${TMPDIR:-/tmp}/fi-jail-root-clones.XXXXXX")
trap 'rm -f "$MOCK_CLONE_LOG"' EXIT HUP INT TERM

MOCK_HOSTNAME="fi-test.invalid"
MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="ABSENT"
MOCK_SOR_DB_STATE="ABSENT"

id()
{
    if [ "$1" = "-u" ]; then
        printf '%s\n' "0"
        return 0
    fi

    return 1
}

uname()
{
    if [ "$1" = "-s" ]; then
        printf '%s\n' "FreeBSD"
        return 0
    fi

    return 1
}

hostname()
{
    printf '%s\n' "$MOCK_HOSTNAME"
}

jail_root_require_commands()
{
    :
}

jail_root_require_prerequisites()
{
    :
}

jail_root_classify_dataset()
{
    case "$1" in
        */fi-receiver)
            printf '%s\n' "$MOCK_RECEIVER_STATE"
            ;;
        */fi-ingest)
            printf '%s\n' "$MOCK_INGEST_STATE"
            ;;
        */fi-sor-db)
            printf '%s\n' "$MOCK_SOR_DB_STATE"
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            ;;
    esac
}

jail_root_clone_dataset()
{
    mock_clone_snapshot=$1
    mock_clone_dataset=$2

    printf '%s|%s\n' \
        "$mock_clone_snapshot" \
        "$mock_clone_dataset" \
        >> "$MOCK_CLONE_LOG"

    case "$mock_clone_dataset" in
        */fi-receiver)
            MOCK_RECEIVER_STATE="OWNED_MATCH"
            ;;
        */fi-ingest)
            MOCK_INGEST_STATE="OWNED_MATCH"
            ;;
        */fi-sor-db)
            MOCK_SOR_DB_STATE="OWNED_MATCH"
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}

: > "$MOCK_CLONE_LOG"

apply_jail_roots

clone_count=$(wc -l < "$MOCK_CLONE_LOG" | tr -d ' ')

[ "$clone_count" -eq 3 ] ||
    test_fail "first jail-root apply expected 3 clones, observed $clone_count"

test_pass "first jail-root apply creates exactly three clones"

apply_jail_roots

clone_count=$(wc -l < "$MOCK_CLONE_LOG" | tr -d ' ')

[ "$clone_count" -eq 3 ] ||
    test_fail "second jail-root apply created additional clones"

test_pass "exact second jail-root apply is a no-op"

: > "$MOCK_CLONE_LOG"
MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="ABSENT"
MOCK_SOR_DB_STATE="FOREIGN_COLLISION"

if (
    apply_jail_roots >/dev/null 2>&1
); then
    test_fail "layer-wide collision unexpectedly allowed jail-root apply"
fi

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "layer-wide preclassification allowed partial clone mutation"

test_pass "layer-wide jail-root preclassification prevents avoidable partial mutation"

: > "$MOCK_CLONE_LOG"
MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="ABSENT"
MOCK_SOR_DB_STATE="ABSENT"
MOCK_HOSTNAME="wrong-host.invalid"

if (
    apply_jail_roots >/dev/null 2>&1
); then
    test_fail "wrong-host jail-root apply unexpectedly succeeded"
fi

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "wrong-host jail-root apply reached clone mutation"

test_pass "wrong-host jail-root apply fails before mutation"

test_pass "FI FreeBSD jail-root apply acceptance complete"

echo "===== EXACT CLONE PRIMITIVE ====="

CLONE_ARGS=$(mktemp "${TMPDIR:-/tmp}/fi-jail-root-clone-args.XXXXXX")

if (
    . "$HELPER"

    zfs()
    {
        printf '%s\n' "$*" > "$CLONE_ARGS"
        return 0
    }

    jail_root_clone_dataset \
        "mockpool/jails/templates/15.1-RELEASE@base-test" \
        "mockpool/jails/containers/fi-receiver" \
        "/mock/jails/containers/fi-receiver" \
        "jail-root-receiver"
)
then
    :
else
    rm -f "$CLONE_ARGS"
    test_fail "real jail-root clone primitive returned failure"
fi

EXPECTED_CLONE='clone -o org.ironsignal.fi:managed=1 -o org.ironsignal.fi:schema=1 -o org.ironsignal.fi:role=jail-root-receiver -o mountpoint=/mock/jails/containers/fi-receiver -o canmount=on -o readonly=off -o atime=off -o exec=on -o setuid=on -o devices=on mockpool/jails/templates/15.1-RELEASE@base-test mockpool/jails/containers/fi-receiver'

ACTUAL_CLONE=$(cat "$CLONE_ARGS")

if [ "$ACTUAL_CLONE" = "$EXPECTED_CLONE" ]; then
    test_pass "real jail-root clone primitive emits exact controlled properties"
else
    printf '[FAIL] expected clone arguments:\n%s\n' "$EXPECTED_CLONE" >&2
    printf '[FAIL] actual clone arguments:\n%s\n' "$ACTUAL_CLONE" >&2
    rm -f "$CLONE_ARGS"
    exit 1
fi

rm -f "$CLONE_ARGS"

test_pass "exact jail-root clone primitive acceptance complete"

echo "===== READ-ONLY JAIL-ROOT VERIFICATION ====="

MOCK_HOSTNAME="fi-test.invalid"
MOCK_RECEIVER_STATE="OWNED_MATCH"
MOCK_INGEST_STATE="OWNED_MATCH"
MOCK_SOR_DB_STATE="OWNED_MATCH"

: > "$MOCK_CLONE_LOG"

verify_jail_roots

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "verify-jail-roots unexpectedly reached clone mutation"

test_pass "verify-jail-roots accepts exact OWNED_MATCH state without mutation"

MOCK_RECEIVER_STATE="OWNED_MATCH"
MOCK_INGEST_STATE="ABSENT"
MOCK_SOR_DB_STATE="OWNED_MATCH"

if (
    verify_jail_roots >/dev/null 2>&1
); then
    test_fail "verify-jail-roots unexpectedly accepted an absent jail root"
fi

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "failed verify-jail-roots reached clone mutation"

test_pass "verify-jail-roots fails closed on ABSENT state"

MOCK_RECEIVER_STATE="OWNED_MATCH"
MOCK_INGEST_STATE="OWNED_MATCH"
MOCK_SOR_DB_STATE="OWNED_MATCH"
MOCK_HOSTNAME="wrong-host.invalid"

if (
    verify_jail_roots >/dev/null 2>&1
); then
    test_fail "wrong-host verify-jail-roots unexpectedly succeeded"
fi

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "wrong-host verify-jail-roots reached clone mutation"

test_pass "wrong-host verify-jail-roots fails before inspection acceptance"

test_pass "FI FreeBSD read-only jail-root verification acceptance complete"

echo "===== READ-ONLY JAIL-ROOT PREFLIGHT ====="

MOCK_HOSTNAME="fi-test.invalid"
MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="ABSENT"
MOCK_SOR_DB_STATE="ABSENT"

: > "$MOCK_CLONE_LOG"

preflight_jail_roots

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "preflight-jail-roots unexpectedly reached clone mutation"

test_pass "preflight-jail-roots accepts all-ABSENT state without mutation"

MOCK_RECEIVER_STATE="OWNED_MATCH"
MOCK_INGEST_STATE="ABSENT"
MOCK_SOR_DB_STATE="OWNED_MATCH"

preflight_jail_roots

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "mixed ready-state jail-root preflight reached clone mutation"

test_pass "preflight-jail-roots accepts ABSENT and OWNED_MATCH mixture"

MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="OWNED_DRIFT"
MOCK_SOR_DB_STATE="ABSENT"

if (
    preflight_jail_roots >/dev/null 2>&1
); then
    test_fail "preflight-jail-roots unexpectedly accepted OWNED_DRIFT"
fi

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "OWNED_DRIFT preflight reached clone mutation"

test_pass "preflight-jail-roots fails closed on OWNED_DRIFT"

MOCK_INGEST_STATE="FOREIGN_COLLISION"

if (
    preflight_jail_roots >/dev/null 2>&1
); then
    test_fail "preflight-jail-roots unexpectedly accepted FOREIGN_COLLISION"
fi

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "FOREIGN_COLLISION preflight reached clone mutation"

test_pass "preflight-jail-roots fails closed on FOREIGN_COLLISION"

MOCK_INGEST_STATE="UNKNOWN"

if (
    preflight_jail_roots >/dev/null 2>&1
); then
    test_fail "preflight-jail-roots unexpectedly accepted UNKNOWN"
fi

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "UNKNOWN preflight reached clone mutation"

test_pass "preflight-jail-roots fails closed on UNKNOWN"

MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="ABSENT"
MOCK_SOR_DB_STATE="ABSENT"
MOCK_HOSTNAME="wrong-host.invalid"

if (
    preflight_jail_roots >/dev/null 2>&1
); then
    test_fail "wrong-host preflight-jail-roots unexpectedly succeeded"
fi

[ ! -s "$MOCK_CLONE_LOG" ] ||
    test_fail "wrong-host preflight-jail-roots reached clone mutation"

test_pass "wrong-host preflight-jail-roots fails before acceptance"

test_pass "FI FreeBSD read-only jail-root preflight acceptance complete"
