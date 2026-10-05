#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
HELPER="$SCRIPT_DIR/../fi-host-directory-apply.sh"

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

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-directory-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

TEST_UID=$(id -u)
TEST_GID=$(id -g)
TEST_HOST="$TEST_ROOT/host"
TEST_LINK="$TEST_ROOT/link"
TEST_JAIL="$TEST_ROOT/jail"

mkdir "$TEST_HOST" "$TEST_JAIL"
chgrp "$TEST_GID" "$TEST_HOST"
chmod 0750 "$TEST_HOST"

MOCK_MARKER_STATUS=1

directory_local_marker_status()
{
    return "$MOCK_MARKER_STATUS"
}

expect_host_state()
{
    expected=$1
    path=$2
    uid=$3
    gid=$4
    mode=$5
    description=$6

    actual=$(
        directory_classify_host_source \
            "mockpool/fi/test" \
            "$path" \
            "$uid" \
            "$gid" \
            "$mode"
    ) || test_fail "$description: classifier returned failure"

    [ "$actual" = "$expected" ] ||
        test_fail "$description: expected $expected, observed $actual"

    test_pass "$description"
}

MOCK_MARKER_STATUS=1
expect_host_state \
    "ABSENT" \
    "$TEST_HOST" \
    "$TEST_UID" \
    "$TEST_GID" \
    "0750" \
    "uninitialized FI-owned host directory classification"

MOCK_MARKER_STATUS=0
expect_host_state \
    "OWNED_MATCH" \
    "$TEST_HOST" \
    "$TEST_UID" \
    "$TEST_GID" \
    "0750" \
    "OWNED_MATCH host directory classification"

chmod 0700 "$TEST_HOST"

expect_host_state \
    "OWNED_DRIFT" \
    "$TEST_HOST" \
    "$TEST_UID" \
    "$TEST_GID" \
    "0750" \
    "mode drift classification"

chmod 0750 "$TEST_HOST"

ln -s "$TEST_HOST" "$TEST_LINK"
MOCK_MARKER_STATUS=1

expect_host_state \
    "FOREIGN_COLLISION" \
    "$TEST_LINK" \
    "$TEST_UID" \
    "$TEST_GID" \
    "0750" \
    "symbolic-link collision classification"

MOCK_MARKER_STATUS=2

expect_host_state \
    "OWNED_DRIFT" \
    "$TEST_HOST" \
    "$TEST_UID" \
    "$TEST_GID" \
    "0750" \
    "wrong local directory-schema version classification"

MOCK_MARKER_STATUS=3

expect_host_state \
    "UNKNOWN" \
    "$TEST_HOST" \
    "$TEST_UID" \
    "$TEST_GID" \
    "0750" \
    "directory marker inspection failure classification"

MOCK_MARKER_STATUS=1

actual=$(
    directory_classify_jail_root \
        "mockpool/jails/containers/fi-receiver" \
        "$TEST_JAIL" \
        "receiver" \
        "$TEST_UID" \
        "$TEST_GID"
) || test_fail "empty jail directory classifier returned failure"

[ "$actual" = "ABSENT" ] ||
    test_fail "empty jail directory classification expected ABSENT, observed $actual"

test_pass "empty uninitialized jail directory set classifies ABSENT"

mkdir -p "$TEST_JAIL/var/db/fi"

actual=$(
    directory_classify_jail_root \
        "mockpool/jails/containers/fi-receiver" \
        "$TEST_JAIL" \
        "receiver" \
        "$TEST_UID" \
        "$TEST_GID"
) || test_fail "pre-existing jail path classifier returned failure"

[ "$actual" = "FOREIGN_COLLISION" ] ||
    test_fail "pre-existing jail path expected FOREIGN_COLLISION, observed $actual"

test_pass "pre-existing managed jail path fails closed as FOREIGN_COLLISION"

ZFS_LOG=$(mktemp "${TMPDIR:-/tmp}/fi-directory-zfs.XXXXXX")
trap 'rm -rf "$TEST_ROOT"; rm -f "$ZFS_LOG"' EXIT HUP INT TERM

zfs()
{
    printf '%s\n' "$*" >> "$ZFS_LOG"
    return 0
}

: > "$ZFS_LOG"

directory_set_marker "mockpool/fi/test" ||
    test_fail "directory marker mutation primitive returned failure"

EXPECTED_ZFS='set org.ironsignal.fi:directory-schema=1 mockpool/fi/test'
ACTUAL_ZFS=$(cat "$ZFS_LOG")

[ "$ACTUAL_ZFS" = "$EXPECTED_ZFS" ] ||
    test_fail "directory marker mutation differs from contract"

test_pass "directory marker primitive emits exact zfs set arguments"

get_value()
{
    case "$1" in
        FI_HOSTNAME)
            printf '%s\n' "fi-test.invalid"
            ;;
        FI_RUNTIME_UID|FI_RUNTIME_GID)
            printf '%s\n' "4100"
            ;;
        FI_ZPOOL)
            printf '%s\n' "mockpool"
            ;;
        FI_JAIL_DATASET_ROOT)
            printf '%s\n' "mockpool/jails/containers"
            ;;
        FI_JAIL_TEMPLATE_SNAPSHOT)
            printf '%s\n' "mockpool/jails/templates/15.1-RELEASE@base-test"
            ;;
        FI_RECEIVER_ROOT)
            printf '%s\n' "/mock/jails/containers/fi-receiver"
            ;;
        FI_INGEST_ROOT)
            printf '%s\n' "/mock/jails/containers/fi-ingest"
            ;;
        FI_SOR_DB_ROOT)
            printf '%s\n' "/mock/jails/containers/fi-sor-db"
            ;;
        FI_CUSTODY_GENERATION_HOST)
            printf '%s\n' "/mock/fi/custody/generation"
            ;;
        FI_CUSTODY_TRANSPORT_HOST)
            printf '%s\n' "/mock/fi/custody/transport"
            ;;
        FI_RECORDED_HOST)
            printf '%s\n' "/mock/fi/custody/recorded"
            ;;
        FI_READY_HOST)
            printf '%s\n' "/mock/fi/custody/ready"
            ;;
        FI_RECEIVER_CONFIG_HOST)
            printf '%s\n' "/mock/fi/config/receiver"
            ;;
        FI_INGEST_CONFIG_HOST)
            printf '%s\n' "/mock/fi/config/ingest"
            ;;
        *)
            test_fail "unexpected configuration lookup: $1"
            ;;
    esac
}

MOCK_HOSTNAME="fi-test.invalid"

id()
{
    [ "$1" = "-u" ] || return 1
    printf '%s\n' "0"
}

uname()
{
    [ "$1" = "-s" ] || return 1
    printf '%s\n' "FreeBSD"
}

hostname()
{
    printf '%s\n' "$MOCK_HOSTNAME"
}

directory_require_prerequisites()
{
    :
}

STATE_CUSTODY="ABSENT"
STATE_TRANSPORT_CUSTODY="ABSENT"
STATE_RECORDED="ABSENT"
STATE_READY="ABSENT"
STATE_RECEIVER_CONFIG="ABSENT"
STATE_INGEST_CONFIG="ABSENT"
STATE_RECEIVER="ABSENT"
STATE_INGEST="ABSENT"
STATE_SOR="ABSENT"

directory_classify_host_source()
{
    case "$1" in
        mockpool/fi/custody/generation)
            printf '%s\n' "$STATE_CUSTODY"
            ;;
        mockpool/fi/custody/transport)
            printf '%s\n' "$STATE_TRANSPORT_CUSTODY"
            ;;
        mockpool/fi/recorded)
            printf '%s\n' "$STATE_RECORDED"
            ;;
        mockpool/fi/ready)
            printf '%s\n' "$STATE_READY"
            ;;
        mockpool/fi/config/receiver)
            printf '%s\n' "$STATE_RECEIVER_CONFIG"
            ;;
        mockpool/fi/config/ingest)
            printf '%s\n' "$STATE_INGEST_CONFIG"
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            ;;
    esac
}

directory_classify_jail_root()
{
    case "$3" in
        receiver)
            printf '%s\n' "$STATE_RECEIVER"
            ;;
        ingest)
            printf '%s\n' "$STATE_INGEST"
            ;;
        sor)
            printf '%s\n' "$STATE_SOR"
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            ;;
    esac
}

MUTATION_LOG=$(mktemp "${TMPDIR:-/tmp}/fi-directory-mutation.XXXXXX")
trap 'rm -rf "$TEST_ROOT"; rm -f "$ZFS_LOG" "$MUTATION_LOG"' EXIT HUP INT TERM

directory_initialize_host_source()
{
    printf 'host:%s\n' "$1" >> "$MUTATION_LOG"

    case "$1" in
        mockpool/fi/custody/generation)
            STATE_CUSTODY="OWNED_MATCH"
            ;;
        mockpool/fi/custody/transport)
            STATE_TRANSPORT_CUSTODY="OWNED_MATCH"
            ;;
        mockpool/fi/recorded)
            STATE_RECORDED="OWNED_MATCH"
            ;;
        mockpool/fi/ready)
            STATE_READY="OWNED_MATCH"
            ;;
        mockpool/fi/config/receiver)
            STATE_RECEIVER_CONFIG="OWNED_MATCH"
            ;;
        mockpool/fi/config/ingest)
            STATE_INGEST_CONFIG="OWNED_MATCH"
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}

directory_create_jail_paths()
{
    printf 'jail:%s\n' "$2" >> "$MUTATION_LOG"
    return 0
}

directory_set_marker()
{
    case "$1" in
        mockpool/jails/containers/fi-receiver)
            STATE_RECEIVER="OWNED_MATCH"
            ;;
        mockpool/jails/containers/fi-ingest)
            STATE_INGEST="OWNED_MATCH"
            ;;
        mockpool/jails/containers/fi-sor-db)
            STATE_SOR="OWNED_MATCH"
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}

: > "$MUTATION_LOG"

apply_directories

MUTATION_COUNT=$(wc -l < "$MUTATION_LOG" | tr -d ' ')

[ "$MUTATION_COUNT" -eq 9 ] ||
    test_fail "first directory apply expected nine resource mutations, observed $MUTATION_COUNT"

test_pass "first directory apply initializes exactly six host and three jail resources"

apply_directories

MUTATION_COUNT=$(wc -l < "$MUTATION_LOG" | tr -d ' ')

[ "$MUTATION_COUNT" -eq 9 ] ||
    test_fail "second directory apply performed additional mutation"

test_pass "exact second directory apply is a no-op"

STATE_CUSTODY="ABSENT"
STATE_TRANSPORT_CUSTODY="ABSENT"
STATE_RECORDED="ABSENT"
STATE_READY="ABSENT"
STATE_RECEIVER_CONFIG="ABSENT"
STATE_INGEST_CONFIG="FOREIGN_COLLISION"
STATE_RECEIVER="ABSENT"
STATE_INGEST="ABSENT"
STATE_SOR="ABSENT"
: > "$MUTATION_LOG"

if (
    apply_directories >/dev/null 2>&1
); then
    test_fail "layer-wide directory collision unexpectedly allowed apply"
fi

[ ! -s "$MUTATION_LOG" ] ||
    test_fail "directory preclassification allowed avoidable partial mutation"

test_pass "layer-wide directory preclassification prevents avoidable partial mutation"

STATE_INGEST_CONFIG="ABSENT"
MOCK_HOSTNAME="wrong-host.invalid"
: > "$MUTATION_LOG"

if (
    apply_directories >/dev/null 2>&1
); then
    test_fail "wrong-host directory apply unexpectedly succeeded"
fi

[ ! -s "$MUTATION_LOG" ] ||
    test_fail "wrong-host directory apply reached mutation"

test_pass "wrong-host directory apply fails before mutation"

test_pass "FI FreeBSD filesystem directory acceptance complete"
