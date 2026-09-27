#!/bin/sh

PROGRAM=${0##*/}
VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

BOOTSTRAP="$FREEBSD_DIR/fi-bootstrap.sh"
FIXTURE="$VERIFY_DIR/fixtures/fi-bootstrap.test.conf"

WORK_ROOT=""

fail()
{
    printf '[FAIL] %s\n' "$*" >&2

    if [ -n "$WORK_ROOT" ] && [ -d "$WORK_ROOT" ]; then
        rm -rf "$WORK_ROOT"
    fi

    exit 1
}

pass()
{
    printf '[PASS] %s\n' "$*"
}

cleanup()
{
    if [ -n "$WORK_ROOT" ] && [ -d "$WORK_ROOT" ]; then
        rm -rf "$WORK_ROOT"
    fi
}

trap cleanup EXIT HUP INT TERM

[ -x "$BOOTSTRAP" ] ||
    fail "bootstrap is not executable: $BOOTSTRAP"

[ -f "$FIXTURE" ] ||
    fail "acceptance fixture not found: $FIXTURE"

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-render-test.XXXXXX") ||
    fail "unable to create test directory"

PLAN_A="$WORK_ROOT/plan-a"
PLAN_B="$WORK_ROOT/plan-b"

"$BOOTSTRAP" plan "$FIXTURE" "$PLAN_A" ||
    fail "first deterministic render failed"

"$BOOTSTRAP" plan "$FIXTURE" "$PLAN_B" ||
    fail "second deterministic render failed"

for expected_file in \
    fi-receiver.conf \
    fi-ingest.conf \
    fi-sor-db.conf \
    fstab.fi-receiver \
    fstab.fi-ingest \
    fstab.fi-sor-db \
    MANIFEST.sha256
do
    [ -f "$PLAN_A/$expected_file" ] ||
        fail "first plan missing $expected_file"

    [ -f "$PLAN_B/$expected_file" ] ||
        fail "second plan missing $expected_file"
done

if grep -R -E '@FI_[A-Z0-9_]+@' "$PLAN_A" >/dev/null 2>&1; then
    fail "first plan contains unresolved FI template tokens"
fi

if grep -R -E '@FI_[A-Z0-9_]+@' "$PLAN_B" >/dev/null 2>&1; then
    fail "second plan contains unresolved FI template tokens"
fi

diff -ru "$PLAN_A" "$PLAN_B" >/dev/null 2>&1 ||
    fail "identical input did not produce byte-identical plans"

pass "identical configuration produces byte-identical plans"

BAD_UNKNOWN="$WORK_ROOT/bad-unknown.conf"
cp "$FIXTURE" "$BAD_UNKNOWN" ||
    fail "unable to create unknown-key test fixture"

printf '\nFI_UNEXPECTED_VALUE="bad"\n' >> "$BAD_UNKNOWN"

if "$BOOTSTRAP" plan "$BAD_UNKNOWN" "$WORK_ROOT/bad-unknown-plan" \
    >/dev/null 2>&1
then
    fail "unknown configuration key was accepted"
fi

pass "unknown configuration keys fail closed"

BAD_DUPLICATE="$WORK_ROOT/bad-duplicate.conf"
cp "$FIXTURE" "$BAD_DUPLICATE" ||
    fail "unable to create duplicate-key test fixture"

printf '\nFI_ZPOOL="otherpool"\n' >> "$BAD_DUPLICATE"

if "$BOOTSTRAP" plan "$BAD_DUPLICATE" "$WORK_ROOT/bad-duplicate-plan" \
    >/dev/null 2>&1
then
    fail "duplicate configuration key was accepted"
fi

pass "duplicate configuration keys fail closed"

BAD_SHELL="$WORK_ROOT/bad-shell.conf"

sed \
    's#FI_ZPOOL="zroot"#FI_ZPOOL="$(id)"#' \
    "$FIXTURE" > "$BAD_SHELL" ||
    fail "unable to create shell-expression test fixture"

if "$BOOTSTRAP" plan "$BAD_SHELL" "$WORK_ROOT/bad-shell-plan" \
    >/dev/null 2>&1
then
    fail "shell expression was accepted as configuration data"
fi

pass "shell expressions are rejected"

BAD_NETWORK="$WORK_ROOT/bad-network.conf"

sed \
    's#FI_RECEIVER_MGMT_ADDRESS="10.77.10.20/24"#FI_RECEIVER_MGMT_ADDRESS="10.77.99.20/24"#' \
    "$FIXTURE" > "$BAD_NETWORK" ||
    fail "unable to create network-boundary test fixture"

if "$BOOTSTRAP" plan "$BAD_NETWORK" "$WORK_ROOT/bad-network-plan" \
    >/dev/null 2>&1
then
    fail "out-of-network jail address was accepted"
fi

pass "address/network mismatch fails closed"

printf '[PASS] FI FreeBSD render acceptance complete\n'
