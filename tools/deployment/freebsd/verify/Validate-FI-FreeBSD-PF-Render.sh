#!/bin/sh

VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

BOOTSTRAP="$FREEBSD_DIR/fi-bootstrap.sh"
FIXTURE="$VERIFY_DIR/fixtures/fi-bootstrap.test.conf"

WORK_ROOT=""

fail()
{
    printf '[FAIL] %s\n' "$*" >&2
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

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-pf-render.XXXXXX") ||
    fail "unable to create PF render workspace"

PLAN="$WORK_ROOT/plan"

"$BOOTSTRAP" plan "$FIXTURE" "$PLAN" >/dev/null ||
    fail "unable to render PF plan"

PF_POLICY="$PLAN/pf.conf"

[ -f "$PF_POLICY" ] ||
    fail "rendered PF policy is absent"

grep -Fqx \
    '# FI-MANAGED: ironsignal-fi-freebsd-pf-v1' \
    "$PF_POLICY" ||
    fail "PF policy lacks exact FI ownership marker"

grep -Fqx \
    '# FI-ROLE: host-packet-filter-policy' \
    "$PF_POLICY" ||
    fail "PF policy lacks exact role marker"

grep -Fqx \
    'ext_if   = "vtnet0"' \
    "$PF_POLICY" ||
    fail "PF policy does not use configured host administrative interface"

grep -Fqx \
    'mgmt_net = "10.77.10.0/24"' \
    "$PF_POLICY" ||
    fail "PF policy management network is not exact"

grep -Fqx \
    'work_net = "10.77.20.0/24"' \
    "$PF_POLICY" ||
    fail "PF policy workload network is not exact"

grep -Fqx \
    'nat on $ext_if inet from $mgmt_net to any -> ($ext_if)' \
    "$PF_POLICY" ||
    fail "PF management NAT rule is not exact"

grep -Fqx \
    'pass in quick inet proto tcp from 10.77.20.21 to 10.77.20.22 port 5432 keep state' \
    "$PF_POLICY" ||
    fail "authorized ingest PostgreSQL rule is not exact"

grep -Fqx \
    'block drop in quick inet proto tcp from any to 10.77.20.22 port 5432' \
    "$PF_POLICY" ||
    fail "default PostgreSQL deny rule is not exact"

grep -Fqx \
    'block drop in quick inet from $work_net to ! $work_net' \
    "$PF_POLICY" ||
    fail "workload off-subnet deny rule is not exact"

[ "$(tail -n 1 "$PF_POLICY")" = "pass all" ] ||
    fail "PF policy does not end with current permissive fallback"

if grep -Eq \
    'from 10\.77\.20\.21/24|to 10\.77\.20\.22/24' \
    "$PF_POLICY"
then
    fail "PF authorization incorrectly uses subnet-width jail addresses"
fi

pass "PF PostgreSQL authorization uses exact host addresses"

if grep -Eq \
    'eprw0a|epiw0a|epair120a|epre0a|epre0b' \
    "$PF_POLICY"
then
    fail "persistent PF policy depends on runtime epair existence"
fi

pass "persistent PF policy is independent of runtime epair existence"

allow_line=$(
    grep -nF \
        'pass in quick inet proto tcp from 10.77.20.21 to 10.77.20.22 port 5432 keep state' \
        "$PF_POLICY" |
        cut -d: -f1
)

deny_line=$(
    grep -nF \
        'block drop in quick inet proto tcp from any to 10.77.20.22 port 5432' \
        "$PF_POLICY" |
        cut -d: -f1
)

fallback_line=$(
    grep -nF 'pass all' "$PF_POLICY" |
        cut -d: -f1
)

[ "$allow_line" -lt "$deny_line" ] &&
[ "$deny_line" -lt "$fallback_line" ] ||
    fail "PF PostgreSQL authorization ordering is incorrect"

pass "PF authorization precedes default deny and permissive fallback"

grep -Eq \
    '^[0-9a-fA-F]{64}  pf\.conf$' \
    "$PLAN/MANIFEST.sha256" ||
    fail "PF policy is absent from deterministic manifest"

pass "PF policy participates in deterministic manifest"

BAD_ADMIN="$WORK_ROOT/bad-admin.conf"

sed \
    's#FI_HOST_ADMIN_IF="vtnet0"#FI_HOST_ADMIN_IF="vtnet1"#' \
    "$FIXTURE" > "$BAD_ADMIN" ||
    fail "unable to build host-interface collision fixture"

if "$BOOTSTRAP" plan "$BAD_ADMIN" "$WORK_ROOT/bad-admin-plan" \
    >/dev/null 2>&1
then
    fail "host administrative interface collision was accepted"
fi

pass "host administrative interface collision fails closed"

printf '[PASS] FI FreeBSD PF render acceptance complete\n'
