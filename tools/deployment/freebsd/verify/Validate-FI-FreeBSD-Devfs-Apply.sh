#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
HELPER="$SCRIPT_DIR/../fi-host-devfs-apply.sh"

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

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-devfs-test.XXXXXX") ||
    test_fail "unable to create test workspace"

MOCK_STATE="$TEST_ROOT/rules"
MOCK_LOG="$TEST_ROOT/mutations"
MOCK_HOSTNAME="fi-test"
MOCK_FAIL_SHOWSETS=0

trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

get_value()
{
    case "$1" in
        FI_DEVFS_RULESET)
            printf '%s\n' "100"
            ;;
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

devfs()
{
    [ "$1" = "rule" ] || return 64

    case "$2" in
        showsets)
            [ "$MOCK_FAIL_SHOWSETS" -eq 0 ] || return 1

            if [ -f "$MOCK_STATE" ]; then
                printf '%s\n' "100"
            fi
            ;;

        -s)
            [ "$3" = "100" ] || return 64

            case "$4" in
                show)
                    [ -f "$MOCK_STATE" ] || return 1
                    cat "$MOCK_STATE"
                    ;;

                add)
                    shift 4

                    printf 'rule -s 100 add %s\n' "$*" >> "$MOCK_LOG"
                    [ -f "$MOCK_STATE" ] || : > "$MOCK_STATE"
                    printf '%s\n' "$*" >> "$MOCK_STATE"
                    ;;

                *)
                    return 64
                    ;;
            esac
            ;;

        *)
            return 64
            ;;
    esac
}

mock_absent()
{
    rm -f "$MOCK_STATE"
    : > "$MOCK_LOG"
    MOCK_FAIL_SHOWSETS=0
}

mock_exact()
{
    cat > "$MOCK_STATE" <<'EOF_RULES'
100 hide
200 path null unhide
300 path zero unhide
400 path random unhide
500 path urandom unhide
EOF_RULES

    : > "$MOCK_LOG"
    MOCK_FAIL_SHOWSETS=0
}

expect_state()
{
    expected_state=$1
    description=$2

    actual_state=$(devfs_classify_ruleset 100) ||
        test_fail "$description: classifier returned failure"

    [ "$actual_state" = "$expected_state" ] ||
        test_fail \
            "$description: expected $expected_state, observed $actual_state"

    test_pass "$description"
}

mock_absent
expect_state \
    "ABSENT" \
    "absent FI devfs ruleset classification"

MOCK_FAIL_SHOWSETS=1
expect_state \
    "UNKNOWN" \
    "devfs ruleset inspection failure classification"
MOCK_FAIL_SHOWSETS=0

mock_exact
expect_state \
    "OWNED_MATCH" \
    "exact FI devfs ruleset classification"

cat > "$MOCK_STATE" <<'EOF_RULES'
100 hide
200 path null unhide
300 path zero unhide
400 path random unhide
EOF_RULES

expect_state \
    "FOREIGN_COLLISION" \
    "missing FI devfs rule fails closed"

cat > "$MOCK_STATE" <<'EOF_RULES'
100 hide
200 path null unhide
300 path zero unhide
400 path random unhide
500 path urandom unhide
600 path zfs unhide
EOF_RULES

expect_state \
    "FOREIGN_COLLISION" \
    "additional devfs rule fails closed"

cat > "$MOCK_STATE" <<'EOF_RULES'
100 hide
200 path zero unhide
300 path null unhide
400 path random unhide
500 path urandom unhide
EOF_RULES

expect_state \
    "FOREIGN_COLLISION" \
    "devfs rule order drift fails closed"

mock_absent

apply_devfs >/dev/null

expect_state \
    "OWNED_MATCH" \
    "first devfs apply creates exact ruleset"

expected_log=$(
    printf '%s\n' \
        "rule -s 100 add 100 hide" \
        "rule -s 100 add 200 path null unhide" \
        "rule -s 100 add 300 path zero unhide" \
        "rule -s 100 add 400 path random unhide" \
        "rule -s 100 add 500 path urandom unhide"
)

actual_log=$(cat "$MOCK_LOG")

[ "$actual_log" = "$expected_log" ] ||
    test_fail "devfs mutation primitive arguments are not exact"

test_pass "devfs creation emits exact ordered mutation arguments"

mutation_count_before=$(wc -l < "$MOCK_LOG" | tr -d ' ')

apply_devfs >/dev/null

mutation_count_after=$(wc -l < "$MOCK_LOG" | tr -d ' ')

[ "$mutation_count_before" = "$mutation_count_after" ] ||
    test_fail "exact second devfs apply performed additional mutation"

test_pass "exact second devfs apply is a no-op"

: > "$MOCK_LOG"

verify_devfs >/dev/null

[ ! -s "$MOCK_LOG" ] ||
    test_fail "read-only devfs verification performed mutation"

test_pass "verify-devfs accepts exact state without mutation"

mock_absent

if (
    verify_devfs >/dev/null 2>&1
); then
    test_fail "verify-devfs unexpectedly accepted absent ruleset"
fi

[ ! -s "$MOCK_LOG" ] ||
    test_fail "failed verify-devfs performed mutation"

test_pass "verify-devfs fails closed on absent state"

mock_absent
MOCK_HOSTNAME="wrong-host.invalid"

if (
    apply_devfs >/dev/null 2>&1
); then
    test_fail "wrong-host devfs apply unexpectedly succeeded"
fi

[ ! -s "$MOCK_LOG" ] ||
    test_fail "wrong-host devfs apply reached mutation"

test_pass "wrong-host devfs apply fails before mutation"

MOCK_HOSTNAME="fi-test"
mock_absent
MOCK_FAIL_SHOWSETS=1

if (
    apply_devfs >/dev/null 2>&1
); then
    test_fail "unknown devfs state unexpectedly allowed apply"
fi

[ ! -s "$MOCK_LOG" ] ||
    test_fail "unknown devfs state reached mutation"

test_pass "unknown devfs state fails before mutation"

test_pass "FI FreeBSD devfs acceptance complete"
