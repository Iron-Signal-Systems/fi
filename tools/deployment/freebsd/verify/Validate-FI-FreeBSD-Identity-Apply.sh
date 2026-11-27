#!/bin/sh

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
HELPER="$SCRIPT_DIR/../fi-host-identity-apply.sh"

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

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-identity-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

TEST_JAIL="$TEST_ROOT/jail"
mkdir -p "$TEST_JAIL/etc"

reset_identity_files()
{
    cat > "$TEST_JAIL/etc/master.passwd" <<'EOM'
root:*:0:0::0:0:Charlie &:/root:/bin/csh
EOM

    cat > "$TEST_JAIL/etc/group" <<'EOG'
wheel:*:0:root
EOG
}

expect_state()
{
    expected=$1
    description=$2

    actual=$(
        identity_classify_account \
            "$TEST_JAIL" \
            "fi-receiver" \
            "fi-receiver" \
            "4100" \
            "4100"
    ) || test_fail "$description: classifier returned failure"

    [ "$actual" = "$expected" ] ||
        test_fail "$description: expected $expected, observed $actual"

    test_pass "$description"
}

reset_identity_files
expect_state "ABSENT" "ABSENT identity classification"

cat >> "$TEST_JAIL/etc/master.passwd" <<'EOF_USER'
foreign:*:4100:100::0:0:Foreign:/nonexistent:/usr/sbin/nologin
EOF_USER
expect_state "FOREIGN_COLLISION" "foreign UID collision classification"

reset_identity_files
cat >> "$TEST_JAIL/etc/group" <<'EOF_GROUP'
foreign:*:4100:
EOF_GROUP
expect_state "FOREIGN_COLLISION" "foreign GID collision classification"

reset_identity_files
cat >> "$TEST_JAIL/etc/group" <<'EOF_GROUP'
fi-receiver:*:4100:
EOF_GROUP
expect_state "OWNED_DRIFT" "partial FI identity classification"

cat >> "$TEST_JAIL/etc/master.passwd" <<'EOF_USER'
fi-receiver:*:4100:4100::0:0::/nonexistent:/usr/sbin/nologin
EOF_USER
expect_state "OWNED_MATCH" "OWNED_MATCH identity classification"

sed -i '' \
    's#fi-receiver:\*:4100:4100::0:0::/nonexistent:/usr/sbin/nologin#fi-receiver:$6$hash:4100:4100::0:0::/nonexistent:/usr/sbin/nologin#' \
    "$TEST_JAIL/etc/master.passwd"
expect_state "OWNED_DRIFT" "password-enabled FI identity is rejected"

reset_identity_files
cat >> "$TEST_JAIL/etc/group" <<'EOF_GROUP'
fi-receiver:*:4100:
EOF_GROUP
cat >> "$TEST_JAIL/etc/master.passwd" <<'EOF_USER'
fi-receiver:*LOCKED*:4100:4100::0:0::/nonexistent:/usr/sbin/nologin
EOF_USER
expect_state "OWNED_MATCH" "locked FI password state is accepted"

PW_LOG=$(mktemp "${TMPDIR:-/tmp}/fi-identity-pw.XXXXXX")
trap 'rm -rf "$TEST_ROOT"; rm -f "$PW_LOG"' EXIT HUP INT TERM

pw()
{
    printf '%s\n' "$*" >> "$PW_LOG"
    return 0
}

: > "$PW_LOG"

identity_create_account \
    "/mock/jail" \
    "fi-receiver" \
    "fi-receiver" \
    "4100" \
    "4100" ||
    test_fail "identity create primitive returned failure"

EXPECTED_GROUP='-R /mock/jail groupadd -n fi-receiver -g 4100'
EXPECTED_USER='-R /mock/jail useradd -n fi-receiver -u 4100 -g fi-receiver -d /nonexistent -s /usr/sbin/nologin -w no'

ACTUAL_GROUP=$(sed -n '1p' "$PW_LOG")
ACTUAL_USER=$(sed -n '2p' "$PW_LOG")
PW_COUNT=$(wc -l < "$PW_LOG" | tr -d ' ')

[ "$PW_COUNT" -eq 2 ] ||
    test_fail "identity create primitive expected two pw mutations, observed $PW_COUNT"

[ "$ACTUAL_GROUP" = "$EXPECTED_GROUP" ] ||
    test_fail "groupadd argument vector differs from contract"

[ "$ACTUAL_USER" = "$EXPECTED_USER" ] ||
    test_fail "useradd argument vector differs from contract"

test_pass "identity create primitive emits exact groupadd and useradd arguments"

get_value()
{
    case "$1" in
        FI_HOSTNAME)
            printf '%s\n' "fi-test.invalid"
            ;;
        FI_JAIL_ROOT_BASE)
            printf '%s\n' "/mock/jails/containers"
            ;;
        FI_RUNTIME_UID|FI_RUNTIME_GID)
            printf '%s\n' "4100"
            ;;
        *)
            test_fail "unexpected configuration lookup: $1"
            ;;
    esac
}

MOCK_HOSTNAME="fi-test.invalid"
MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="ABSENT"
CREATE_LOG=$(mktemp "${TMPDIR:-/tmp}/fi-identity-create.XXXXXX")
trap 'rm -rf "$TEST_ROOT"; rm -f "$PW_LOG" "$CREATE_LOG"' EXIT HUP INT TERM

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

identity_require_host_clear()
{
    :
}

identity_require_prerequisites()
{
    :
}

identity_classify_account()
{
    case "$2" in
        fi-receiver)
            printf '%s\n' "$MOCK_RECEIVER_STATE"
            ;;
        fi-ingest)
            printf '%s\n' "$MOCK_INGEST_STATE"
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            ;;
    esac
}

identity_create_account()
{
    printf '%s\n' "$2" >> "$CREATE_LOG"

    case "$2" in
        fi-receiver)
            MOCK_RECEIVER_STATE="OWNED_MATCH"
            ;;
        fi-ingest)
            MOCK_INGEST_STATE="OWNED_MATCH"
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}

: > "$CREATE_LOG"
apply_identities

CREATE_COUNT=$(wc -l < "$CREATE_LOG" | tr -d ' ')

[ "$CREATE_COUNT" -eq 2 ] ||
    test_fail "first identity apply expected two account creations, observed $CREATE_COUNT"

test_pass "first identity apply creates exactly receiver and ingest identities"

apply_identities

CREATE_COUNT=$(wc -l < "$CREATE_LOG" | tr -d ' ')

[ "$CREATE_COUNT" -eq 2 ] ||
    test_fail "second identity apply created additional identities"

test_pass "exact second identity apply is a no-op"

: > "$CREATE_LOG"
MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="FOREIGN_COLLISION"

if (
    apply_identities >/dev/null 2>&1
); then
    test_fail "layer-wide identity collision unexpectedly allowed apply"
fi

[ ! -s "$CREATE_LOG" ] ||
    test_fail "identity preclassification allowed partial account mutation"

test_pass "layer-wide identity preclassification prevents avoidable partial mutation"

: > "$CREATE_LOG"
MOCK_RECEIVER_STATE="ABSENT"
MOCK_INGEST_STATE="ABSENT"
MOCK_HOSTNAME="wrong-host.invalid"

if (
    apply_identities >/dev/null 2>&1
); then
    test_fail "wrong-host identity apply unexpectedly succeeded"
fi

[ ! -s "$CREATE_LOG" ] ||
    test_fail "wrong-host identity apply reached mutation"

test_pass "wrong-host identity apply fails before mutation"

test_pass "FI FreeBSD jail-local identity acceptance complete"
