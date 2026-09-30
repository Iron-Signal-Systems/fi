#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
HELPER="$SCRIPT_DIR/../fi-host-file-apply.sh"

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
    test_fail "$*"
}

pass()
{
    :
}

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-host-file-test.XXXXXX") ||
    test_fail "unable to create test workspace"

trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

TEST_UID=$(id -u)
TEST_GID=$(stat -f '%g' "$TEST_ROOT")

make_expected()
{
    make_expected_path=$1
    make_expected_role=$2
    make_expected_payload=$3

    cat > "$make_expected_path" <<EOF_EXPECTED
# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: $make_expected_role
$make_expected_payload
EOF_EXPECTED
}

expect_state()
{
    expected_state=$1
    expected_source=$2
    expected_target=$3
    expected_mode=$4
    expected_description=$5

    actual_state=$(
        host_file_classify \
            "$expected_source" \
            "$expected_target" \
            "$TEST_UID" \
            "$TEST_GID" \
            "$expected_mode"
    ) || test_fail "$expected_description: classifier returned failure"

    [ "$actual_state" = "$expected_state" ] ||
        test_fail \
            "$expected_description: expected $expected_state, observed $actual_state"

    test_pass "$expected_description"
}

SOURCE="$TEST_ROOT/source"
TARGET="$TEST_ROOT/target"

make_expected "$SOURCE" "test-file" "payload=exact"
chmod 0644 "$SOURCE"

expect_state \
    "ABSENT" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "absent host-file classification"

cp "$SOURCE" "$TARGET"
chmod 0644 "$TARGET"

expect_state \
    "OWNED_MATCH" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "exact FI-owned host-file classification"

printf '%s\n' "drift=true" >> "$TARGET"

expect_state \
    "OWNED_DRIFT" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "FI-owned content drift classification"

cp "$SOURCE" "$TARGET"
chmod 0600 "$TARGET"

expect_state \
    "OWNED_DRIFT" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "FI-owned mode drift classification"

printf '%s\n' "foreign=true" > "$TARGET"
chmod 0644 "$TARGET"

expect_state \
    "FOREIGN_COLLISION" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "unmarked existing file is a foreign collision"

rm -f "$TARGET"
ln -s "$SOURCE" "$TARGET"

expect_state \
    "FOREIGN_COLLISION" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "symbolic-link destination is a foreign collision"

rm -f "$TARGET"
mkdir "$TARGET"

expect_state \
    "FOREIGN_COLLISION" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "directory destination is a foreign collision"

rmdir "$TARGET"
cp "$SOURCE" "$TARGET"
chmod 0644 "$TARGET"
ln "$TARGET" "$TEST_ROOT/target-extra-link"

expect_state \
    "OWNED_DRIFT" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "unexpected additional hard link is owned drift"

rm -f "$TEST_ROOT/target-extra-link"

stat()
{
    return 1
}

expect_state \
    "UNKNOWN" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "metadata inspection failure is UNKNOWN"

unset -f stat

rm -f "$TARGET"

chown()
{
    :
}

ln()
{
    printf '%s\n' "foreign-race" > "$2"
    /bin/ln "$1" "$2"
}

if (
    host_file_install_absent \
        "$SOURCE" \
        "$TARGET" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0644" \
        "race-test" \
        >/dev/null 2>&1
); then
    test_fail "no-clobber publication unexpectedly overwrote a racing destination"
fi

grep -Fqx "foreign-race" "$TARGET" ||
    test_fail "racing destination content was altered"

test_pass "atomic no-clobber publication preserves a racing destination"

unset -f ln
unset -f chown

rm -f "$TARGET"

host_file_install_absent \
    "$SOURCE" \
    "$TARGET" \
    "$TEST_UID" \
    "$TEST_GID" \
    "0644" \
    "create-test" \
    >/dev/null

expect_state \
    "OWNED_MATCH" \
    "$SOURCE" \
    "$TARGET" \
    "0644" \
    "no-clobber creation produces exact host file"

rm -f "$TARGET"

MOCK_HOSTNAME="fi-test"

get_value()
{
    case "$1" in
        FI_HOSTNAME)
            printf '%s\n' "fi-test"
            ;;
        *)
            return 1
            ;;
    esac
}

hostname()
{
    printf '%s\n' "$MOCK_HOSTNAME"
}

id()
{
    case "$1" in
        -u)
            printf '%s\n' "0"
            ;;
        -g)
            printf '%s\n' "$TEST_GID"
            ;;
        *)
            return 1
            ;;
    esac
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

host_file_prepare_expected()
{
    HOST_FILE_PLAN_ROOT="$TEST_ROOT/layer"
    HOST_FILE_PLAN="$HOST_FILE_PLAN_ROOT/plan"

    mkdir -p "$HOST_FILE_PLAN"

    make_expected \
        "$HOST_FILE_PLAN/a" \
        "test-a" \
        "payload=a"

    make_expected \
        "$HOST_FILE_PLAN/b" \
        "test-b" \
        "payload=b"
}

host_file_cleanup_expected()
{
    :
}

host_file_resource_map()
{
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "test-a" \
        "$HOST_FILE_PLAN/a" \
        "$TEST_ROOT/live-a" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "test-b" \
        "$HOST_FILE_PLAN/b" \
        "$TEST_ROOT/live-b" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0600"
}

rm -f "$TEST_ROOT/live-a" "$TEST_ROOT/live-b"

apply_host_files >/dev/null

expect_state \
    "OWNED_MATCH" \
    "$TEST_ROOT/layer/plan/a" \
    "$TEST_ROOT/live-a" \
    "0644" \
    "first layer apply creates exact first host file"

expect_state \
    "OWNED_MATCH" \
    "$TEST_ROOT/layer/plan/b" \
    "$TEST_ROOT/live-b" \
    "0600" \
    "first layer apply creates exact second host file"

inode_a_before=$(stat -f '%i' "$TEST_ROOT/live-a")
inode_b_before=$(stat -f '%i' "$TEST_ROOT/live-b")

apply_host_files >/dev/null

inode_a_after=$(stat -f '%i' "$TEST_ROOT/live-a")
inode_b_after=$(stat -f '%i' "$TEST_ROOT/live-b")

[ "$inode_a_before" = "$inode_a_after" ] ||
    test_fail "exact second apply replaced first host file"

[ "$inode_b_before" = "$inode_b_after" ] ||
    test_fail "exact second apply replaced second host file"

test_pass "exact second host-file apply is a no-op"

verify_host_files >/dev/null

test_pass "read-only host-file verification accepts exact state"

rm -f "$TEST_ROOT/live-a" "$TEST_ROOT/live-b"

printf '%s\n' "foreign=true" > "$TEST_ROOT/live-b"

if (
    apply_host_files >/dev/null 2>&1
); then
    test_fail "layer-wide preclassification accepted a foreign collision"
fi

[ ! -e "$TEST_ROOT/live-a" ] ||
    test_fail "layer-wide preclassification created an earlier absent resource"

test_pass "layer-wide host-file preclassification prevents avoidable partial mutation"

rm -f "$TEST_ROOT/live-a" "$TEST_ROOT/live-b"

cp "$TEST_ROOT/layer/plan/b" "$TEST_ROOT/live-b"
chmod 0600 "$TEST_ROOT/live-b"

stat()
{
    return 1
}

if (
    apply_host_files >/dev/null 2>&1
); then
    test_fail "UNKNOWN host-file state unexpectedly allowed apply"
fi

unset -f stat

[ ! -e "$TEST_ROOT/live-a" ] ||
    test_fail "UNKNOWN later resource allowed earlier host-file mutation"

test_pass "UNKNOWN host-file state fails before layer mutation"

rm -f "$TEST_ROOT/live-a" "$TEST_ROOT/live-b"

MOCK_HOSTNAME="wrong-host.invalid"

if (
    apply_host_files >/dev/null 2>&1
); then
    test_fail "wrong-host host-file apply unexpectedly succeeded"
fi

[ ! -e "$TEST_ROOT/live-a" ] &&
[ ! -e "$TEST_ROOT/live-b" ] ||
    test_fail "wrong-host host-file apply reached mutation"

test_pass "wrong-host host-file apply fails before mutation"

MOCK_HOSTNAME="fi-test"

if (
    verify_host_files >/dev/null 2>&1
); then
    test_fail "verify-host-files unexpectedly accepted absent resources"
fi

[ ! -e "$TEST_ROOT/live-a" ] &&
[ ! -e "$TEST_ROOT/live-b" ] ||
    test_fail "failed verify-host-files performed mutation"

test_pass "verify-host-files fails closed on absent state"

test_pass "FI FreeBSD host-file acceptance complete"
