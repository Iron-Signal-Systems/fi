#!/bin/sh

VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

HOST_FILE_HELPER="$FREEBSD_DIR/fi-host-file-apply.sh"
LIFECYCLE_HELPER="$FREEBSD_DIR/fi-host-lifecycle-apply.sh"

[ -f "$HOST_FILE_HELPER" ] || {
    printf '[FAIL] host-file helper not found: %s\n' "$HOST_FILE_HELPER" >&2
    exit 1
}

[ -f "$LIFECYCLE_HELPER" ] || {
    printf '[FAIL] lifecycle helper not found: %s\n' "$LIFECYCLE_HELPER" >&2
    exit 1
}

. "$HOST_FILE_HELPER"
. "$LIFECYCLE_HELPER"

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

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-lifecycle-apply-test.XXXXXX") ||
    test_fail "unable to create test workspace"

trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

TEST_UID=$(id -u)
TEST_GID=$(stat -f '%g' "$TEST_ROOT")

SOURCE="$TEST_ROOT/source"
TARGET="$TEST_ROOT/target-parent"

mkdir "$TARGET"
chmod 0755 "$TARGET"

state=$(
    lifecycle_parent_classify \
        "$TARGET" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0755"
)

[ "$state" = "DIRECTORY_MATCH" ] ||
    test_fail "exact lifecycle parent classification: observed $state"

test_pass "exact lifecycle parent classification"

chmod 0777 "$TARGET"

state=$(
    lifecycle_parent_classify \
        "$TARGET" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0755"
)

[ "$state" = "FOREIGN_COLLISION" ] ||
    test_fail "lifecycle parent mode collision: observed $state"

test_pass "lifecycle parent metadata drift fails closed"

rm -rf "$TARGET"
ln -s "$TEST_ROOT" "$TARGET"

state=$(
    lifecycle_parent_classify \
        "$TARGET" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0755"
)

[ "$state" = "FOREIGN_COLLISION" ] ||
    test_fail "lifecycle parent symlink collision: observed $state"

test_pass "lifecycle parent symbolic link fails closed"

rm -f "$TARGET"

MOCK_JAIL_ENABLE="NO"
MOCK_JAIL_LIST=""

sysrc()
{
    [ "$1" = "-n" ] || return 1

    case "$2" in
        jail_enable)
            printf '%s\n' "$MOCK_JAIL_ENABLE"
            ;;
        jail_list)
            printf '%s\n' "$MOCK_JAIL_LIST"
            ;;
        *)
            return 1
            ;;
    esac
}

lifecycle_global_jail_policy_precheck

test_pass "disabled global jail service is compatible"

MOCK_JAIL_ENABLE="YES"
MOCK_JAIL_LIST="site-jail another-jail"

lifecycle_global_jail_policy_precheck

test_pass "enabled unrelated global jail list is compatible"

MOCK_JAIL_ENABLE="YES"
MOCK_JAIL_LIST=""

if (
    lifecycle_global_jail_policy_precheck >/dev/null 2>&1
); then
    test_fail "enabled empty jail_list unexpectedly accepted"
fi

test_pass "enabled global _ALL policy fails closed"

MOCK_JAIL_LIST="site-jail fi-ingest"

if (
    lifecycle_global_jail_policy_precheck >/dev/null 2>&1
); then
    test_fail "enabled global FI jail ownership unexpectedly accepted"
fi

test_pass "global FI jail ownership collision fails closed"

MOCK_JAIL_ENABLE="MAYBE"
MOCK_JAIL_LIST="site-jail"

if (
    lifecycle_global_jail_policy_precheck >/dev/null 2>&1
); then
    test_fail "unrecognized jail_enable unexpectedly accepted"
fi

test_pass "unrecognized global jail enable state fails closed"

MOCK_JAIL_ENABLE="NO"
MOCK_JAIL_LIST=""

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

make_expected()
{
    expected_path=$1
    expected_role=$2
    expected_payload=$3

    cat > "$expected_path" <<EOF_EXPECTED
# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1
# FI-ROLE: $expected_role
$expected_payload
EOF_EXPECTED
}

lifecycle_prepare_expected()
{
    HOST_FILE_MARKER=$LIFECYCLE_FILE_MARKER

    HOST_FILE_PLAN_ROOT="$TEST_ROOT/layer"
    HOST_FILE_PLAN="$HOST_FILE_PLAN_ROOT/plan"

    LIFECYCLE_PLAN_ROOT=$HOST_FILE_PLAN_ROOT
    LIFECYCLE_PLAN=$HOST_FILE_PLAN

    mkdir -p "$LIFECYCLE_PLAN"

    make_expected \
        "$LIFECYCLE_PLAN/rc.d.fi_jails" \
        "fi-jails-controller" \
        "controller=true"

    make_expected \
        "$LIFECYCLE_PLAN/rc.conf.d.fi_jails" \
        "fi-jails-enable-policy" \
        'fi_jails_enable="YES"'

    make_expected \
        "$LIFECYCLE_PLAN/rc.conf.d.devfs.90-fi" \
        "devfs-boot-policy" \
        'devfs_load_rulesets="YES"'
}

lifecycle_cleanup_expected()
{
    :
}

lifecycle_parent_map()
{
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "local-rc-directory" \
        "$TEST_ROOT/live/rc-local" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "rc-conf-directory" \
        "$TEST_ROOT/live/rc-conf" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "devfs-rc-conf-directory" \
        "$TEST_ROOT/live/rc-conf/devfs" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0755"
}

lifecycle_resource_map()
{
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fi-jails-controller" \
        "$LIFECYCLE_PLAN/rc.d.fi_jails" \
        "$TEST_ROOT/live/rc-local/fi_jails" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fi-jails-enable-policy" \
        "$LIFECYCLE_PLAN/rc.conf.d.fi_jails" \
        "$TEST_ROOT/live/rc-conf/fi_jails" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "devfs-boot-policy" \
        "$LIFECYCLE_PLAN/rc.conf.d.devfs.90-fi" \
        "$TEST_ROOT/live/rc-conf/devfs/90-fi" \
        "$TEST_UID" \
        "$TEST_GID" \
        "0644"
}

mkdir "$TEST_ROOT/live"
chmod 0755 "$TEST_ROOT/live"

apply_lifecycle >/dev/null

HOST_FILE_MARKER=$LIFECYCLE_FILE_MARKER

for lifecycle_test_spec in \
    "rc.d.fi_jails|$TEST_ROOT/live/rc-local/fi_jails|0555" \
    "rc.conf.d.fi_jails|$TEST_ROOT/live/rc-conf/fi_jails|0644" \
    "rc.conf.d.devfs.90-fi|$TEST_ROOT/live/rc-conf/devfs/90-fi|0644"
do
    lifecycle_test_expected_name=${lifecycle_test_spec%%|*}
    lifecycle_test_rest=${lifecycle_test_spec#*|}
    lifecycle_test_target=${lifecycle_test_rest%%|*}
    lifecycle_test_mode=${lifecycle_test_rest##*|}

    lifecycle_test_state=$(
        host_file_classify \
            "$TEST_ROOT/layer/plan/$lifecycle_test_expected_name" \
            "$lifecycle_test_target" \
            "$TEST_UID" \
            "$TEST_GID" \
            "$lifecycle_test_mode"
    )

    [ "$lifecycle_test_state" = "OWNED_MATCH" ] ||
        test_fail "first lifecycle apply did not create exact file: $lifecycle_test_target"
done

test_pass "first lifecycle apply creates exact managed files"

inode_controller_before=$(
    stat -f '%i' "$TEST_ROOT/live/rc-local/fi_jails"
)

inode_enable_before=$(
    stat -f '%i' "$TEST_ROOT/live/rc-conf/fi_jails"
)

inode_devfs_before=$(
    stat -f '%i' "$TEST_ROOT/live/rc-conf/devfs/90-fi"
)

apply_lifecycle >/dev/null

inode_controller_after=$(
    stat -f '%i' "$TEST_ROOT/live/rc-local/fi_jails"
)

inode_enable_after=$(
    stat -f '%i' "$TEST_ROOT/live/rc-conf/fi_jails"
)

inode_devfs_after=$(
    stat -f '%i' "$TEST_ROOT/live/rc-conf/devfs/90-fi"
)

[ "$inode_controller_before" = "$inode_controller_after" ] &&
[ "$inode_enable_before" = "$inode_enable_after" ] &&
[ "$inode_devfs_before" = "$inode_devfs_after" ] ||
    test_fail "exact second lifecycle apply replaced managed files"

test_pass "exact second lifecycle apply is a no-op"

verify_lifecycle >/dev/null

test_pass "read-only lifecycle verification accepts exact state"

rm -rf "$TEST_ROOT/live"
mkdir "$TEST_ROOT/live"
chmod 0755 "$TEST_ROOT/live"

mkdir "$TEST_ROOT/live/rc-local"
mkdir "$TEST_ROOT/live/rc-conf"
mkdir "$TEST_ROOT/live/rc-conf/devfs"

chmod 0755 \
    "$TEST_ROOT/live/rc-local" \
    "$TEST_ROOT/live/rc-conf" \
    "$TEST_ROOT/live/rc-conf/devfs"

printf '%s\n' "foreign=true" \
    > "$TEST_ROOT/live/rc-conf/devfs/90-fi"

if (
    apply_lifecycle >/dev/null 2>&1
); then
    test_fail "layer preclassification accepted late foreign collision"
fi

[ ! -e "$TEST_ROOT/live/rc-local/fi_jails" ] &&
[ ! -e "$TEST_ROOT/live/rc-conf/fi_jails" ] ||
    test_fail "late lifecycle collision allowed earlier file mutation"

test_pass "lifecycle layer preclassification prevents avoidable partial file mutation"

rm -rf "$TEST_ROOT/live"
mkdir "$TEST_ROOT/live"
chmod 0755 "$TEST_ROOT/live"

MOCK_JAIL_ENABLE="YES"
MOCK_JAIL_LIST=""

if (
    apply_lifecycle >/dev/null 2>&1
); then
    test_fail "global jail authority conflict unexpectedly allowed lifecycle apply"
fi

[ ! -e "$TEST_ROOT/live/rc-local" ] &&
[ ! -e "$TEST_ROOT/live/rc-conf" ] ||
    test_fail "global jail authority conflict reached lifecycle mutation"

test_pass "global jail authority conflict fails before lifecycle mutation"

MOCK_JAIL_ENABLE="NO"
MOCK_JAIL_LIST=""
MOCK_HOSTNAME="wrong-host.invalid"

if (
    apply_lifecycle >/dev/null 2>&1
); then
    test_fail "wrong-host lifecycle apply unexpectedly succeeded"
fi

[ ! -e "$TEST_ROOT/live/rc-local" ] &&
[ ! -e "$TEST_ROOT/live/rc-conf" ] ||
    test_fail "wrong-host lifecycle apply reached mutation"

test_pass "wrong-host lifecycle apply fails before mutation"

MOCK_HOSTNAME="fi-test"

if grep -Eq \
    '/etc/rc\.d/jail|/usr/sbin/jls|devfs rule|service[[:space:]]' \
    "$LIFECYCLE_HELPER"
then
    test_fail "lifecycle installer contains live service/runtime mutation command"
fi

test_pass "lifecycle installer contains no live jail or devfs activation"

test_pass "FI FreeBSD lifecycle apply acceptance complete"
