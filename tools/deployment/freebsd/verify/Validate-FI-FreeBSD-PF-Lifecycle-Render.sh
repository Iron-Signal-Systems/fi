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

require_line()
{
    required_file=$1
    required_line=$2
    description=$3

    grep -Fqx "$required_line" "$required_file" ||
        fail "$description"

    pass "$description"
}

trap cleanup EXIT HUP INT TERM

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-pf-lifecycle-render.XXXXXX") ||
    fail "unable to create PF lifecycle render workspace"

PLAN="$WORK_ROOT/plan"

"$BOOTSTRAP" plan "$FIXTURE" "$PLAN" >/dev/null ||
    fail "unable to render PF lifecycle plan"

PF_POLICY="$PLAN/pf.conf"
PF_RC="$PLAN/rc.conf.d.fi_pf"
PF_SERVICE="$PLAN/rc.d.fi_pf"
FI_JAILS_SERVICE="$PLAN/rc.d.fi_jails"

for required_file in \
    "$PF_POLICY" \
    "$PF_RC" \
    "$PF_SERVICE" \
    "$FI_JAILS_SERVICE"
do
    [ -f "$required_file" ] ||
        fail "required PF lifecycle artifact absent: $required_file"
done

expected_pf_sha256=$(sha256 -q "$PF_POLICY") ||
    fail "unable to hash rendered PF policy"

require_line \
    "$PF_RC" \
    '# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1' \
    "PF runtime configuration has lifecycle marker"

require_line \
    "$PF_RC" \
    '# FI-ROLE: fi-pf-enable-policy' \
    "PF runtime configuration has exact role"

require_line \
    "$PF_RC" \
    'fi_pf_enable="YES"' \
    "FI PF runtime controller is enabled"

require_line \
    "$PF_RC" \
    'fi_pf_rules="/etc/pf.conf"' \
    "FI PF runtime controller uses exact persistent rules path"

require_line \
    "$PF_RC" \
    "fi_pf_expected_sha256=\"$expected_pf_sha256\"" \
    "FI PF runtime configuration binds exact rendered policy hash"

require_line \
    "$PF_RC" \
    'fi_pf_sor_db_work_ip="10.77.20.22"' \
    "FI PF runtime configuration carries exact System of Record host address"

require_line \
    "$PF_RC" \
    'fi_pf_pfil_member="1"' \
    "FI PF enables bridge member filtering"

require_line \
    "$PF_RC" \
    'fi_pf_pfil_bridge="0"' \
    "FI PF disables duplicate bridge-interface filtering"

require_line \
    "$PF_RC" \
    'fi_pf_pfil_onlyip="1"' \
    "FI PF retains IP-only bridge filtering policy"

require_line \
    "$PF_SERVICE" \
    '# PROVIDE: fi_pf' \
    "FI PF controller provides fi_pf"

require_line \
    "$PF_SERVICE" \
    '# REQUIRE: pf' \
    "FI PF controller is ordered after base PF"

require_line \
    "$PF_SERVICE" \
    '# BEFORE: fi_jails' \
    "FI PF controller is ordered before production jails"

require_line \
    "$FI_JAILS_SERVICE" \
    '# REQUIRE: jail fi_pf' \
    "FI jail controller requires FI PF runtime policy"

require_line \
    "$FI_JAILS_SERVICE" \
    '    /usr/local/etc/rc.d/fi_pf onestatus >/dev/null 2>&1' \
    "FI jail startup verifies PF runtime readiness"

load_line=$(
    grep -nF \
        '    pfctl -f "$fi_pf_rules" || {' \
        "$PF_SERVICE" |
        cut -d: -f1
)

member_line=$(
    grep -nF \
        '        "net.link.bridge.pfil_member=$fi_pf_pfil_member" \' \
        "$PF_SERVICE" |
        cut -d: -f1
)

[ -n "$load_line" ] &&
[ -n "$member_line" ] &&
[ "$load_line" -lt "$member_line" ] ||
    fail "FI PF does not load validated rules before enabling member filtering"

pass "validated PF rules load before bridge member filtering"

grep -Fq \
    'pfctl \' \
    "$PF_SERVICE" ||
    fail "FI PF controller lacks PF state invalidation"

grep -Fq -- \
    '-k "$fi_pf_sor_db_work_ip"' \
    "$PF_SERVICE" ||
    fail "FI PF controller does not invalidate System of Record states"

pass "FI PF activation invalidates pre-policy System of Record states"

sh -n "$PF_SERVICE" ||
    fail "rendered FI PF controller has invalid shell syntax"

sh -n "$FI_JAILS_SERVICE" ||
    fail "rendered FI jail controller has invalid shell syntax"

pass "PF and jail lifecycle controllers have valid shell syntax"

BASE_ORDER="$WORK_ROOT/rcorder-base.out"
BASE_ERR="$WORK_ROOT/rcorder-base.err"
FI_ORDER="$WORK_ROOT/rcorder-fi.out"
FI_ERR="$WORK_ROOT/rcorder-fi.err"

rcorder /etc/rc.d/* >"$BASE_ORDER" 2>"$BASE_ERR"
base_rc=$?

rcorder \
    /etc/rc.d/* \
    "$PF_SERVICE" \
    "$FI_JAILS_SERVICE" \
    >"$FI_ORDER" 2>"$FI_ERR"
fi_rc=$?

[ "$fi_rc" -eq "$base_rc" ] ||
    fail "FI PF lifecycle changes rcorder exit status relative to base graph"

cmp -s "$BASE_ERR" "$FI_ERR" ||
    fail "FI PF lifecycle introduces additional rcorder diagnostics"

base_pf_position=$(
    awk '$0 == "/etc/rc.d/pf" { print NR; exit }' "$FI_ORDER"
)

fi_pf_position=$(
    awk -v service="$PF_SERVICE" \
        '$0 == service { print NR; exit }' \
        "$FI_ORDER"
)

fi_jails_position=$(
    awk -v service="$FI_JAILS_SERVICE" \
        '$0 == service { print NR; exit }' \
        "$FI_ORDER"
)

[ -n "$base_pf_position" ] ||
    fail "base PF service is absent from rcorder output"

[ -n "$fi_pf_position" ] ||
    fail "FI PF controller is absent from rcorder output"

[ -n "$fi_jails_position" ] ||
    fail "FI jail controller is absent from rcorder output"

[ "$fi_pf_position" -gt "$base_pf_position" ] ||
    fail "FI PF controller is not ordered after base PF"

[ "$fi_jails_position" -gt "$fi_pf_position" ] ||
    fail "FI production jails are not ordered after FI PF"

pass "rcorder places base PF -> FI PF -> FI production jails"

grep -Eq '@FI_[A-Z0-9_]+@' \
    "$PF_RC" \
    "$PF_SERVICE" &&
    fail "PF lifecycle artifacts contain unresolved FI tokens"

pass "PF lifecycle artifacts contain no unresolved FI tokens"

printf '[PASS] FI FreeBSD PF lifecycle render acceptance complete\n'
