#!/bin/sh

VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

HOST_FILE_HELPER="$FREEBSD_DIR/fi-host-file-apply.sh"
LIFECYCLE_HELPER="$FREEBSD_DIR/fi-host-lifecycle-apply.sh"
RUNTIME_HELPER="$FREEBSD_DIR/fi-host-runtime-apply.sh"

for helper in \
    "$HOST_FILE_HELPER" \
    "$LIFECYCLE_HELPER" \
    "$RUNTIME_HELPER"
do
    [ -f "$helper" ] || {
        printf '[FAIL] helper not found: %s\n' "$helper" >&2
        exit 1
    }
done

. "$HOST_FILE_HELPER"
. "$LIFECYCLE_HELPER"
. "$RUNTIME_HELPER"

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

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-runtime-adoption-test.XXXXXX") ||
    test_fail "unable to create test workspace"

trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

TEST_UID=$(id -u)
TEST_GID=$(stat -f '%g' "$TEST_ROOT")

MOCK_HOSTNAME="fi-test"

get_value()
{
    case "$1" in
        FI_HOSTNAME)
            printf '%s\n' "fi-test"
            ;;
        FI_RECEIVER_ROOT)
            printf '%s\n' "$TEST_ROOT/live/receiver"
            ;;
        FI_INGEST_ROOT)
            printf '%s\n' "$TEST_ROOT/live/ingest"
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

make_runtime_expected()
{
    path=$1
    role=$2
    payload=$3

    cat > "$path" <<EOF_EXPECTED
# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: $role
$payload
EOF_EXPECTED
}

runtime_prepare_expected()
{
    RUNTIME_SAVED_HOST_FILE_MARKER=$HOST_FILE_MARKER
    HOST_FILE_MARKER=$RUNTIME_FILE_MARKER

    HOST_FILE_PLAN_ROOT="$TEST_ROOT/layer"
    HOST_FILE_PLAN="$HOST_FILE_PLAN_ROOT/plan"

    RUNTIME_PLAN_ROOT=$HOST_FILE_PLAN_ROOT
    RUNTIME_PLAN=$HOST_FILE_PLAN

    rm -rf "$HOST_FILE_PLAN_ROOT"
    mkdir -p "$RUNTIME_PLAN"

    make_runtime_expected \
        "$RUNTIME_PLAN/fi-receiver-supervisor" \
        "receiver-supervisor" \
        "receiver_supervisor=new"

    make_runtime_expected \
        "$RUNTIME_PLAN/rc.d.fi_receiver" \
        "receiver-rc-service" \
        "receiver_rc=new"

    make_runtime_expected \
        "$RUNTIME_PLAN/rc.conf.d.fi_receiver" \
        "receiver-runtime-config" \
        'fi_receiver_enable="YES"'

    make_runtime_expected \
        "$RUNTIME_PLAN/fi-ingest-worker-run" \
        "ingest-worker-runner" \
        "ingest_runner=new"

    make_runtime_expected \
        "$RUNTIME_PLAN/rc.d.fi_ingest_worker" \
        "ingest-worker-rc-service" \
        "ingest_rc=new"

    make_runtime_expected \
        "$RUNTIME_PLAN/rc.conf.d.fi_ingest_worker" \
        "ingest-worker-runtime-config" \
        'fi_ingest_worker_enable="YES"'
}

runtime_cleanup_expected()
{
    if [ -n "$RUNTIME_SAVED_HOST_FILE_MARKER" ]; then
        HOST_FILE_MARKER=$RUNTIME_SAVED_HOST_FILE_MARKER
    fi

    RUNTIME_PLAN=""
    RUNTIME_PLAN_ROOT=""
    RUNTIME_SAVED_HOST_FILE_MARKER=""
}

runtime_parent_map()
{
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "receiver-local-libexec" \
        "$TEST_ROOT/live/receiver/usr/local/libexec" \
        "$TEST_UID" "$TEST_GID" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "receiver-local-rc-directory" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
        "$TEST_UID" "$TEST_GID" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "receiver-rc-conf-directory" \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
        "$TEST_UID" "$TEST_GID" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "ingest-local-libexec" \
        "$TEST_ROOT/live/ingest/usr/local/libexec" \
        "$TEST_UID" "$TEST_GID" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "ingest-local-rc-directory" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
        "$TEST_UID" "$TEST_GID" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "ingest-rc-conf-directory" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d" \
        "$TEST_UID" "$TEST_GID" "0755"
}

runtime_resource_map()
{
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "receiver-supervisor" \
        "$RUNTIME_PLAN/fi-receiver-supervisor" \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor" \
        "$TEST_UID" "$TEST_GID" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "receiver-rc-service" \
        "$RUNTIME_PLAN/rc.d.fi_receiver" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver" \
        "$TEST_UID" "$TEST_GID" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "receiver-runtime-config" \
        "$RUNTIME_PLAN/rc.conf.d.fi_receiver" \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver" \
        "$TEST_UID" "$TEST_GID" "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "ingest-runner" \
        "$RUNTIME_PLAN/fi-ingest-worker-run" \
        "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run" \
        "$TEST_UID" "$TEST_GID" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "ingest-rc-service" \
        "$RUNTIME_PLAN/rc.d.fi_ingest_worker" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker" \
        "$TEST_UID" "$TEST_GID" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "ingest-runtime-config" \
        "$RUNTIME_PLAN/rc.conf.d.fi_ingest_worker" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker" \
        "$TEST_UID" "$TEST_GID" "0644"
}

prepare_foreign_state()
{
    rm -rf "$TEST_ROOT/live" "$TEST_ROOT/prior"

    mkdir -p \
        "$TEST_ROOT/live/receiver/usr/local/libexec" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
        "$TEST_ROOT/live/ingest/usr/local/libexec" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d" \
        "$TEST_ROOT/prior"

    chmod 0755 \
        "$TEST_ROOT/live/receiver/usr/local/libexec" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
        "$TEST_ROOT/live/ingest/usr/local/libexec" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d"

    printf '%s\n' "legacy receiver supervisor" \
        > "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"

    printf '%s\n' "legacy receiver rc" \
        > "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver"

    printf '%s\n' 'fi_receiver_enable="YES"' \
        > "$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver"

    printf '%s\n' "legacy ingest runner" \
        > "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run"

    printf '%s\n' "legacy ingest rc" \
        > "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker"

    printf '%s\n' 'fi_ingest_worker_enable="YES"' \
        > "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

    chmod 0555 \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver" \
        "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker"

    chmod 0644 \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

    cp \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor" \
        "$TEST_ROOT/prior/fi-receiver-supervisor"

    cp \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver" \
        "$TEST_ROOT/prior/rc.d.fi_receiver"

    cp \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver" \
        "$TEST_ROOT/prior/rc.conf.d.fi_receiver"

    cp \
        "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run" \
        "$TEST_ROOT/prior/fi-ingest-worker-run"

    cp \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker" \
        "$TEST_ROOT/prior/rc.d.fi_ingest_worker"

    cp \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker" \
        "$TEST_ROOT/prior/rc.conf.d.fi_ingest_worker"
}

assert_no_managed_live_files()
{
    if grep -R -F \
        "# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1" \
        "$TEST_ROOT/live/receiver" \
        "$TEST_ROOT/live/ingest" \
        >/dev/null 2>&1
    then
        test_fail "failed adoption mutated a live runtime file"
    fi
}

# ------------------------------------------------------------
# Exact foreign state may be explicitly adopted.
# ------------------------------------------------------------

prepare_foreign_state

adopt_runtime "$TEST_ROOT/prior" >/dev/null

HOST_FILE_MARKER=$RUNTIME_FILE_MARKER

for spec in \
    "fi-receiver-supervisor|$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor|0555" \
    "rc.d.fi_receiver|$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver|0555" \
    "rc.conf.d.fi_receiver|$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver|0644" \
    "fi-ingest-worker-run|$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run|0555" \
    "rc.d.fi_ingest_worker|$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker|0555" \
    "rc.conf.d.fi_ingest_worker|$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker|0644"
do
    expected_name=${spec%%|*}
    rest=${spec#*|}
    target=${rest%%|*}
    mode=${rest##*|}

    state=$(
        host_file_classify \
            "$TEST_ROOT/layer/plan/$expected_name" \
            "$target" \
            "$TEST_UID" \
            "$TEST_GID" \
            "$mode"
    )

    [ "$state" = "OWNED_MATCH" ] ||
        test_fail "adoption did not create exact managed state: $target"
done

test_pass "exact foreign runtime state can be explicitly adopted"

# ------------------------------------------------------------
# Second adoption must not replace exact managed files.
# ------------------------------------------------------------

inode_before=$(
    stat -f '%i' \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"
)

adopt_runtime "$TEST_ROOT/prior" >/dev/null

inode_after=$(
    stat -f '%i' \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"
)

[ "$inode_before" = "$inode_after" ] ||
    test_fail "second runtime adoption replaced an exact managed file"

test_pass "exact second runtime adoption is a no-op"

# ------------------------------------------------------------
# One bad approved-prior file must block every replacement.
# ------------------------------------------------------------

prepare_foreign_state

printf '%s\n' "not the approved live file" \
    > "$TEST_ROOT/prior/rc.conf.d.fi_ingest_worker"

if (
    adopt_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "runtime adoption accepted mismatched approved prior"
fi

assert_no_managed_live_files

test_pass "mismatched approved prior blocks complete runtime adoption"

# ------------------------------------------------------------
# Bad parent metadata must block adoption before publication.
# ------------------------------------------------------------

prepare_foreign_state

chmod 0700 \
    "$TEST_ROOT/live/receiver/usr/local/libexec"

if (
    adopt_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "runtime adoption accepted incorrect parent metadata"
fi

assert_no_managed_live_files

test_pass "runtime adoption rejects parent metadata drift"

# ------------------------------------------------------------
# Missing live targets are not adoption candidates.
# ------------------------------------------------------------

prepare_foreign_state

rm -f \
    "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker"

if (
    adopt_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "runtime adoption accepted missing live target"
fi

assert_no_managed_live_files

test_pass "runtime adoption rejects missing live resources"

# ------------------------------------------------------------
# Wrong host must fail before publication.
# ------------------------------------------------------------

prepare_foreign_state
MOCK_HOSTNAME="wrong-host.invalid"

if (
    adopt_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "wrong-host runtime adoption unexpectedly succeeded"
fi

assert_no_managed_live_files

MOCK_HOSTNAME="fi-test"

test_pass "wrong-host runtime adoption fails before mutation"

test_pass "FI FreeBSD runtime adoption acceptance complete"
