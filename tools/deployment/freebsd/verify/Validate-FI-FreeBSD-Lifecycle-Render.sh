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

[ -x "$BOOTSTRAP" ] ||
    fail "bootstrap is not executable: $BOOTSTRAP"

[ -f "$FIXTURE" ] ||
    fail "fixture not found: $FIXTURE"

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-lifecycle-render.XXXXXX") ||
    fail "unable to create lifecycle render workspace"

PLAN="$WORK_ROOT/plan"

"$BOOTSTRAP" plan "$FIXTURE" "$PLAN" >/dev/null ||
    fail "unable to render lifecycle plan"

FI_RC="$PLAN/rc.conf.d.fi_jails"
DEVFS_RC="$PLAN/rc.conf.d.devfs.90-fi"
FI_SERVICE="$PLAN/rc.d.fi_jails"

RECEIVER="$PLAN/fi-receiver.conf"
INGEST="$PLAN/fi-ingest.conf"
SOR="$PLAN/fi-sor-db.conf"

for required_file in \
    "$FI_RC" \
    "$DEVFS_RC" \
    "$FI_SERVICE" \
    "$RECEIVER" \
    "$INGEST" \
    "$SOR"
do
    [ -f "$required_file" ] ||
        fail "required lifecycle artifact absent: $required_file"
done

pass "all lifecycle artifacts render"

require_line \
    "$FI_RC" \
    '# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1' \
    "FI jail enable fragment has FI marker"

require_line \
    "$FI_RC" \
    '# FI-ROLE: fi-jails-enable-policy' \
    "FI jail enable fragment has exact role"

require_line \
    "$FI_RC" \
    'fi_jails_enable="YES"' \
    "dedicated FI jail controller is enabled"

for forbidden_global in \
    jail_enable \
    jail_parallel_start \
    jail_list \
    jail_reverse_stop
do
    if grep -Eq "^${forbidden_global}=" "$FI_RC"; then
        fail "FI lifecycle config controls global jail variable: $forbidden_global"
    fi
done

pass "FI lifecycle config does not control global jail policy"

require_line \
    "$FI_SERVICE" \
    '# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1' \
    "FI jail controller has FI marker"

require_line \
    "$FI_SERVICE" \
    '# FI-ROLE: fi-jails-controller' \
    "FI jail controller has exact role"

require_line \
    "$FI_SERVICE" \
    '# PROVIDE: fi_jails' \
    "FI jail controller provides fi_jails"

require_line \
    "$FI_SERVICE" \
    '# REQUIRE: jail' \
    "FI jail controller is ordered after base jail service"

require_line \
    "$FI_SERVICE" \
    '# KEYWORD: shutdown' \
    "FI jail controller participates in shutdown"

require_line \
    "$FI_SERVICE" \
    'rcvar="fi_jails_enable"' \
    "FI jail controller uses dedicated enable variable"

require_line \
    "$FI_SERVICE" \
    '        fi-sor-db \' \
    "FI startup begins with System of Record"

require_line \
    "$FI_SERVICE" \
    '        fi-ingest \' \
    "FI startup contains ingest"

require_line \
    "$FI_SERVICE" \
    '        fi-receiver' \
    "FI startup contains receiver"

require_line \
    "$FI_SERVICE" \
    '        fi-receiver \' \
    "FI shutdown begins with receiver"

require_line \
    "$FI_SERVICE" \
    '        fi-sor-db' \
    "FI shutdown ends with System of Record"

require_line \
    "$FI_SERVICE" \
    '    /etc/rc.d/jail onestart "$fi_jail_name"' \
    "FI starts exactly one named jail per base-jail invocation"

require_line \
    "$FI_SERVICE" \
    '    /etc/rc.d/jail onestop "$fi_jail_name"' \
    "FI stops exactly one named jail per base-jail invocation"

require_line \
    "$FI_SERVICE" \
    '    /usr/sbin/jls -j "$1" >/dev/null 2>&1' \
    "FI independently verifies jail runtime state"

require_line \
    "$DEVFS_RC" \
    '# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1' \
    "devfs lifecycle fragment has FI marker"

require_line \
    "$DEVFS_RC" \
    '# FI-ROLE: devfs-boot-policy' \
    "devfs lifecycle fragment has exact role"

require_line \
    "$DEVFS_RC" \
    'devfs_load_rulesets="YES"' \
    "FI persistent devfs ruleset loading is enabled"

if grep -Fq 'devfs_system_ruleset=' "$DEVFS_RC"; then
    fail "FI lifecycle fragment must not control devfs_system_ruleset"
fi

pass "host devfs system ruleset remains outside FI authority"

devfs_eval=$(
    devfs_rulesets="/site/a /site/b"
    devfs_load_rulesets="NO"

    . "$DEVFS_RC"
    . "$DEVFS_RC"

    printf '%s|%s\n' \
        "$devfs_rulesets" \
        "$devfs_load_rulesets"
)

[ "$devfs_eval" = \
    "/site/a /site/b /etc/devfs.rules.fi|YES" ] ||
    fail "devfs lifecycle fragment does not preserve site rulesets idempotently"

pass "devfs lifecycle fragment preserves site rulesets without duplication"

require_line \
    "$INGEST" \
    '    depend = "fi-sor-db";' \
    "ingest depends on System of Record"

require_line \
    "$RECEIVER" \
    '    depend = "fi-ingest";' \
    "receiver depends on ingest"

if grep -Fq 'depend =' "$SOR"; then
    fail "System of Record must not have an FI jail dependency"
fi

pass "System of Record is the FI dependency root"

if grep -Eq '@FI_[A-Z0-9_]+@' \
    "$FI_RC" \
    "$DEVFS_RC" \
    "$FI_SERVICE"
then
    fail "lifecycle artifacts contain unresolved FI tokens"
fi

pass "lifecycle artifacts contain no unresolved FI tokens"

sh -n "$FI_SERVICE" ||
    fail "rendered FI jail controller has invalid shell syntax"

pass "rendered FI jail controller shell syntax is valid"

BASE_ORDER="$WORK_ROOT/rcorder-base.out"
BASE_ERR="$WORK_ROOT/rcorder-base.err"
FI_ORDER="$WORK_ROOT/rcorder-fi.out"
FI_ERR="$WORK_ROOT/rcorder-fi.err"

rcorder /etc/rc.d/* >"$BASE_ORDER" 2>"$BASE_ERR"
base_rc=$?

rcorder /etc/rc.d/* "$FI_SERVICE" >"$FI_ORDER" 2>"$FI_ERR"
fi_rc=$?

[ "$fi_rc" -eq "$base_rc" ] ||
    fail "FI controller changes rcorder exit status relative to base graph"

pass "FI controller does not worsen base rcorder exit status"

cmp -s "$BASE_ERR" "$FI_ERR" ||
    fail "FI controller introduces additional rcorder diagnostics"

pass "FI controller introduces no new rcorder diagnostics"

jail_position=$(
    awk '$0 == "/etc/rc.d/jail" { print NR; exit }' "$FI_ORDER"
)

fi_position=$(
    awk -v fi_service="$FI_SERVICE" \
        '$0 == fi_service { print NR; exit }' \
        "$FI_ORDER"
)

securelevel_position=$(
    awk '$0 == "/etc/rc.d/securelevel" { print NR; exit }' "$FI_ORDER"
)

[ -n "$jail_position" ] ||
    fail "base jail service is absent from rcorder output"

[ -n "$fi_position" ] ||
    fail "FI jail controller is absent from rcorder output"

[ -n "$securelevel_position" ] ||
    fail "securelevel is absent from rcorder output"

[ "$fi_position" -gt "$jail_position" ] ||
    fail "FI jail controller is not ordered after base jail service"

pass "FI jail controller is ordered after base jail service"

[ "$fi_position" -lt "$securelevel_position" ] ||
    fail "FI jail controller is not ordered before securelevel"

pass "FI jail controller is ordered before securelevel"

pass "FI FreeBSD lifecycle render acceptance complete"
