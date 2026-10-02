#!/bin/sh

VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

CONTROLLER="$FREEBSD_DIR/lifecycle.d/fi-pf.rc.d.template"
FI_JAILS="$FREEBSD_DIR/lifecycle.d/fi-jails.rc.d.template"

fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

pass()
{
    printf '[PASS] %s\n' "$*"
}

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-pf-runtime.XXXXXX") ||
    fail "unable to create PF runtime test workspace"

trap 'rm -rf "$WORK_ROOT"' EXIT HUP INT TERM

POLICY="$WORK_ROOT/pf.conf"
SNAPSHOT="$WORK_ROOT/fi_pf.runtime"
TEST_CONTROLLER="$WORK_ROOT/fi_pf-controller.sh"
CALL_LOG="$WORK_ROOT/calls.log"

sed \
    -e 's|^\. /etc/rc.subr$|:|' \
    -e "s|/etc/pf.conf|$POLICY|g" \
    -e "s|/var/run/fi_pf.runtime|$SNAPSHOT|g" \
    -e '/^load_rc_config /d' \
    -e '/^run_rc_command /d' \
    "$CONTROLLER" > "$TEST_CONTROLLER" ||
    fail "unable to prepare PF controller test copy"

. "$TEST_CONTROLLER"

warn()
{
    :
}

write_policy()
{
    cat > "$POLICY" <<'EOF_POLICY'
# FI-MANAGED: ironsignal-fi-freebsd-pf-v1
# FI-ROLE: host-packet-filter-policy

pass all
EOF_POLICY

    chmod 0644 "$POLICY"
    fi_pf_expected_sha256=$(sha256 -q "$POLICY") ||
        fail "unable to hash test PF policy"
}

MOCK_POLICY_MODE=0644
MOCK_SNAPSHOT_MODE=0600
MOCK_PF_ENABLED=1
MOCK_LOAD_FAIL=0
MOCK_KILL_TARGET_FAIL=0
MOCK_KILL_SOURCE_FAIL=0
MOCK_SYSCTL_FAIL=""
MOCK_FILTER_RULES="old-filter"
MOCK_NAT_RULES="old-nat"
MOCK_LOADED_FILTER="new-filter"
MOCK_LOADED_NAT="new-nat"
MOCK_MEMBER=0
MOCK_BRIDGE=0
MOCK_ONLYIP=1

stat()
{
    last=""
    for last
    do
        :
    done

    case "$last" in
        "$POLICY")
            printf '0:0:0:%s:1\n' "$MOCK_POLICY_MODE"
            ;;
        "$SNAPSHOT")
            printf '0:0:0:%s:1\n' "$MOCK_SNAPSHOT_MODE"
            ;;
        *)
            command stat "$@"
            ;;
    esac
}

chown()
{
    printf 'chown %s\n' "$*" >> "$CALL_LOG"
    return 0
}

chmod()
{
    printf 'chmod %s\n' "$*" >> "$CALL_LOG"
    command chmod "$@"
}

pfctl()
{
    case "$1" in
        -nf)
            return 0
            ;;

        -s)
            [ "$2" = "Running" ] || return 1
            [ "$MOCK_PF_ENABLED" -eq 1 ]
            ;;

        -f)
            printf 'pfctl-load\n' >> "$CALL_LOG"

            [ "$MOCK_LOAD_FAIL" -eq 0 ] ||
                return 1

            MOCK_FILTER_RULES=$MOCK_LOADED_FILTER
            MOCK_NAT_RULES=$MOCK_LOADED_NAT
            return 0
            ;;

        -k)
            if [ "$#" -eq 4 ]; then
                printf 'pfctl-k-target %s %s %s %s\n' \
                    "$1" "$2" "$3" "$4" >> "$CALL_LOG"

                [ "$MOCK_KILL_TARGET_FAIL" -eq 0 ]
                return
            fi

            printf 'pfctl-k-source %s %s\n' \
                "$1" "$2" >> "$CALL_LOG"

            [ "$MOCK_KILL_SOURCE_FAIL" -eq 0 ]
            return
            ;;

        -sr)
            printf '%s\n' "$MOCK_FILTER_RULES"
            ;;

        -sn)
            printf '%s\n' "$MOCK_NAT_RULES"
            ;;

        *)
            return 1
            ;;
    esac
}

sysctl()
{
    if [ "$1" = "-n" ]; then
        case "$2" in
            net.link.bridge.pfil_member)
                printf '%s\n' "$MOCK_MEMBER"
                ;;
            net.link.bridge.pfil_bridge)
                printf '%s\n' "$MOCK_BRIDGE"
                ;;
            net.link.bridge.pfil_onlyip)
                printf '%s\n' "$MOCK_ONLYIP"
                ;;
            *)
                return 1
                ;;
        esac

        return 0
    fi

    key=${1%%=*}
    value=${1#*=}

    printf 'sysctl-set %s=%s\n' \
        "$key" "$value" >> "$CALL_LOG"

    [ "$MOCK_SYSCTL_FAIL" != "$key" ] ||
        return 1

    case "$key" in
        net.link.bridge.pfil_member)
            MOCK_MEMBER=$value
            ;;
        net.link.bridge.pfil_bridge)
            MOCK_BRIDGE=$value
            ;;
        net.link.bridge.pfil_onlyip)
            MOCK_ONLYIP=$value
            ;;
        *)
            return 1
            ;;
    esac

    return 0
}

reset_runtime()
{
    rm -f "$SNAPSHOT"

    write_policy

    # Fixture preparation is not runtime-controller mutation.
    : > "$CALL_LOG"

    fi_pf_enable=YES
    fi_pf_rules="$POLICY"
    fi_pf_sor_db_work_ip=10.77.20.22
    fi_pf_pfil_member=1
    fi_pf_pfil_bridge=0
    fi_pf_pfil_onlyip=1
    fi_pf_runtime_snapshot="$SNAPSHOT"

    MOCK_POLICY_MODE=0644
    MOCK_SNAPSHOT_MODE=0600
    MOCK_PF_ENABLED=1
    MOCK_LOAD_FAIL=0
    MOCK_KILL_TARGET_FAIL=0
    MOCK_KILL_SOURCE_FAIL=0
    MOCK_SYSCTL=""
    MOCK_SYSCTL_FAIL=""
    MOCK_FILTER_RULES="old-filter"
    MOCK_NAT_RULES="old-nat"
    MOCK_LOADED_FILTER="new-filter"
    MOCK_LOADED_NAT="new-nat"
    MOCK_MEMBER=0
    MOCK_BRIDGE=0
    MOCK_ONLYIP=1
}

assert_no_runtime_mutation()
{
    [ ! -s "$CALL_LOG" ] ||
        fail "$1"
}

# Persistent hash drift must fail before mutation.
reset_runtime
printf '\n# drift\n' >> "$POLICY"

if fi_pf_start >/dev/null 2>&1; then
    fail "persistent PF hash drift was accepted"
fi

assert_no_runtime_mutation \
    "persistent PF drift caused runtime mutation"

pass "persistent PF drift fails before runtime mutation"

# Persistent metadata drift must fail before mutation.
reset_runtime
MOCK_POLICY_MODE=0600

if fi_pf_start >/dev/null 2>&1; then
    fail "persistent PF metadata drift was accepted"
fi

assert_no_runtime_mutation \
    "persistent PF metadata drift caused runtime mutation"

pass "persistent PF metadata drift fails before runtime mutation"

# Existing snapshot symlink must fail before mutation.
reset_runtime
ln -s "$WORK_ROOT/symlink-target" "$SNAPSHOT" ||
    fail "unable to create snapshot symlink fixture"

if fi_pf_start >/dev/null 2>&1; then
    fail "snapshot symlink was accepted"
fi

assert_no_runtime_mutation \
    "snapshot symlink caused runtime mutation"

rm -f "$SNAPSHOT"

pass "snapshot symbolic link fails before runtime mutation"

# Existing snapshot metadata drift must fail before mutation.
reset_runtime
printf '%s\n' \
    'filter_sha256=stale' \
    'nat_sha256=stale' \
    > "$SNAPSHOT"

MOCK_SNAPSHOT_MODE=0644

if fi_pf_start >/dev/null 2>&1; then
    fail "snapshot metadata drift was accepted"
fi

assert_no_runtime_mutation \
    "snapshot metadata drift caused runtime mutation"

pass "snapshot metadata drift fails before runtime mutation"

# Disabled base PF must fail before mutation.
reset_runtime
MOCK_PF_ENABLED=0

if fi_pf_start >/dev/null 2>&1; then
    fail "disabled base PF was accepted"
fi

assert_no_runtime_mutation \
    "disabled base PF caused runtime mutation"

pass "disabled base PF fails before runtime mutation"

# Rule load failure must stop before state invalidation/sysctls.
reset_runtime
MOCK_LOAD_FAIL=1

if fi_pf_start >/dev/null 2>&1; then
    fail "PF rule-load failure was accepted"
fi

[ "$(cat "$CALL_LOG")" = "pfctl-load" ] ||
    fail "PF load failure advanced beyond the load operation"

pass "PF load failure stops before state invalidation"

# State invalidation failure must stop before sysctls.
reset_runtime
MOCK_KILL_TARGET_FAIL=1

if fi_pf_start >/dev/null 2>&1; then
    fail "PF state-invalidation failure was accepted"
fi

grep -Fqx 'pfctl-load' "$CALL_LOG" ||
    fail "state failure test did not load PF"

grep -Fq 'pfctl-k-target' "$CALL_LOG" ||
    fail "state failure test did not attempt target invalidation"

if grep -Fq 'sysctl-set ' "$CALL_LOG"; then
    fail "state invalidation failure advanced into sysctl mutation"
fi

pass "PF state invalidation failure stops before bridge filtering"

# Non-member sysctl failure must occur before pfil_member.
reset_runtime
MOCK_SYSCTL_FAIL=net.link.bridge.pfil_onlyip

if fi_pf_start >/dev/null 2>&1; then
    fail "pfil_onlyip mutation failure was accepted"
fi

if grep -Fq \
    'sysctl-set net.link.bridge.pfil_member=1' \
    "$CALL_LOG"
then
    fail "pfil_member was enabled after earlier sysctl failure"
fi

pass "bridge-member filtering is not enabled after earlier sysctl failure"

# Successful activation.
reset_runtime

fi_pf_start >/dev/null ||
    fail "valid PF runtime activation failed"

load_line=$(grep -nF 'pfctl-load' "$CALL_LOG" | cut -d: -f1)
target_line=$(grep -nF 'pfctl-k-target' "$CALL_LOG" | cut -d: -f1)
source_line=$(grep -nF 'pfctl-k-source' "$CALL_LOG" | cut -d: -f1)
bridge_line=$(
    grep -nF \
        'sysctl-set net.link.bridge.pfil_bridge=0' \
        "$CALL_LOG" |
        cut -d: -f1
)
onlyip_line=$(
    grep -nF \
        'sysctl-set net.link.bridge.pfil_onlyip=1' \
        "$CALL_LOG" |
        cut -d: -f1
)
member_line=$(
    grep -nF \
        'sysctl-set net.link.bridge.pfil_member=1' \
        "$CALL_LOG" |
        cut -d: -f1
)

[ "$load_line" -lt "$target_line" ] &&
[ "$target_line" -lt "$source_line" ] &&
[ "$source_line" -lt "$bridge_line" ] &&
[ "$bridge_line" -lt "$onlyip_line" ] &&
[ "$onlyip_line" -lt "$member_line" ] ||
    fail "PF runtime mutation ordering is incorrect"

pass "PF load/state/sysctl ordering is exact and member filtering is last"

[ -f "$SNAPSHOT" ] &&
[ ! -L "$SNAPSHOT" ] ||
    fail "runtime snapshot was not created as a regular file"

filter_hash=$(
    printf '%s\n' "$MOCK_FILTER_RULES" |
        sha256 -q
) || fail "unable to calculate expected filter snapshot hash"

nat_hash=$(
    printf '%s\n' "$MOCK_NAT_RULES" |
        sha256 -q
) || fail "unable to calculate expected NAT snapshot hash"

grep -Fqx \
    "filter_sha256=$filter_hash" \
    "$SNAPSHOT" ||
    fail "runtime snapshot filter hash is incorrect"

grep -Fqx \
    "nat_sha256=$nat_hash" \
    "$SNAPSHOT" ||
    fail "runtime snapshot NAT hash is incorrect"

pass "runtime snapshot records exact active filter and NAT hashes"

fi_pf_status_internal ||
    fail "valid PF runtime status did not succeed"

pass "runtime status accepts exact active state"

# Rule drift must be detected.
MOCK_FILTER_RULES="unexpected-filter"

if fi_pf_status_internal; then
    fail "active filter-rule drift was not detected"
fi

MOCK_FILTER_RULES=$MOCK_LOADED_FILTER

pass "runtime status detects active filter-rule drift"

# NAT drift must be detected.
MOCK_NAT_RULES="unexpected-nat"

if fi_pf_status_internal; then
    fail "active NAT drift was not detected"
fi

MOCK_NAT_RULES=$MOCK_LOADED_NAT

pass "runtime status detects active NAT drift"

# Exact second start must not reload/kill/change sysctls.
: > "$CALL_LOG"

fi_pf_start >/dev/null ||
    fail "exact second PF start failed"

assert_no_runtime_mutation \
    "exact second PF start performed runtime mutation"

pass "exact second PF start is idempotent"

# stop is intentionally a no-op.
: > "$CALL_LOG"

fi_pf_stop >/dev/null ||
    fail "FI PF stop returned failure"

assert_no_runtime_mutation \
    "FI PF stop mutated runtime state"

pass "FI PF stop leaves runtime enforcement active"

# Shutdown model: jails participate, PF intentionally does not.
grep -Fqx '# KEYWORD: shutdown' "$FI_JAILS" ||
    fail "FI jail controller lacks shutdown participation"

if grep -Fqx '# KEYWORD: shutdown' "$CONTROLLER"; then
    fail "FI PF controller unexpectedly participates in shutdown"
fi

pass "shutdown model stops FI jails while leaving PF enforcement active"

pass "FI FreeBSD PF runtime behavior acceptance complete"
