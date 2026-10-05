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

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-runtime-apply-test.XXXXXX") ||
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

prepare_live_containers()
{
    rm -rf "$TEST_ROOT/live"

    mkdir -p \
        "$TEST_ROOT/live/receiver/usr/local/etc" \
        "$TEST_ROOT/live/receiver/etc" \
        "$TEST_ROOT/live/ingest/usr/local/etc" \
        "$TEST_ROOT/live/ingest/etc"

    chmod 0755 \
        "$TEST_ROOT/live" \
        "$TEST_ROOT/live/receiver" \
        "$TEST_ROOT/live/receiver/usr" \
        "$TEST_ROOT/live/receiver/usr/local" \
        "$TEST_ROOT/live/receiver/usr/local/etc" \
        "$TEST_ROOT/live/receiver/etc" \
        "$TEST_ROOT/live/ingest" \
        "$TEST_ROOT/live/ingest/usr" \
        "$TEST_ROOT/live/ingest/usr/local" \
        "$TEST_ROOT/live/ingest/usr/local/etc" \
        "$TEST_ROOT/live/ingest/etc"
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
        "receiver_supervisor=true"

    make_runtime_expected \
        "$RUNTIME_PLAN/rc.d.fi_receiver" \
        "receiver-rc-service" \
        "receiver_rc=true"

    make_runtime_expected \
        "$RUNTIME_PLAN/rc.conf.d.fi_receiver" \
        "receiver-runtime-config" \
        'fi_receiver_enable="YES"'

    make_runtime_expected \
        "$RUNTIME_PLAN/fi-ingest-worker-run" \
        "ingest-worker-runner" \
        "ingest_runner=true"

    make_runtime_expected \
        "$RUNTIME_PLAN/rc.d.fi_ingest_worker" \
        "ingest-worker-rc-service" \
        "ingest_rc=true"

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

# ------------------------------------------------------------
# Fresh apply.
# ------------------------------------------------------------

prepare_live_containers

apply_runtime >/dev/null

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
        test_fail "fresh runtime apply did not create exact file: $target"
done

test_pass "fresh runtime apply creates exact managed files"

for directory in \
    "$TEST_ROOT/live/receiver/usr/local/libexec" \
    "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
    "$TEST_ROOT/live/ingest/usr/local/libexec" \
    "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d"
do
    mode=$(stat -f '%Lp' "$directory")

    [ "$mode" = "755" ] ||
        test_fail "runtime directory mode is not 0755: $directory ($mode)"
done

test_pass "runtime parent directories are exact 0755"

# ------------------------------------------------------------
# Idempotence.
# ------------------------------------------------------------

inode_receiver_before=$(
    stat -f '%i' \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"
)

inode_ingest_before=$(
    stat -f '%i' \
        "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run"
)

apply_runtime >/dev/null

inode_receiver_after=$(
    stat -f '%i' \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"
)

inode_ingest_after=$(
    stat -f '%i' \
        "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run"
)

[ "$inode_receiver_before" = "$inode_receiver_after" ] &&
[ "$inode_ingest_before" = "$inode_ingest_after" ] ||
    test_fail "exact second runtime apply replaced managed files"

test_pass "exact second runtime apply is a no-op"

verify_runtime >/dev/null

test_pass "runtime verification accepts exact state"

# ------------------------------------------------------------
# Foreign file collision must stop before any file mutation.
# ------------------------------------------------------------

prepare_live_containers

mkdir \
    "$TEST_ROOT/live/receiver/usr/local/libexec" \
    "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
    "$TEST_ROOT/live/ingest/usr/local/libexec" \
    "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d"

chmod 0755 \
    "$TEST_ROOT/live/receiver/usr/local/libexec" \
    "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
    "$TEST_ROOT/live/ingest/usr/local/libexec" \
    "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d"

printf '%s\n' "foreign=true" \
    > "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

if (
    apply_runtime >/dev/null 2>&1
); then
    test_fail "runtime apply accepted foreign service-file collision"
fi

[ ! -e "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor" ] &&
[ ! -e "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver" ] &&
[ ! -e "$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver" ] ||
    test_fail "late foreign collision allowed earlier runtime-file mutation"

test_pass "runtime preclassification prevents partial file mutation"

# ------------------------------------------------------------
# Parent metadata drift fails closed.
# ------------------------------------------------------------

prepare_live_containers

mkdir "$TEST_ROOT/live/receiver/usr/local/libexec"
chmod 0700 "$TEST_ROOT/live/receiver/usr/local/libexec"

if (
    apply_runtime >/dev/null 2>&1
); then
    test_fail "runtime apply accepted incorrect libexec mode"
fi

[ ! -e "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" ] &&
[ ! -e "$TEST_ROOT/live/receiver/etc/rc.conf.d" ] ||
    test_fail "parent metadata collision allowed later directory mutation"

test_pass "runtime parent metadata drift fails closed"

# ------------------------------------------------------------
# FI-owned content drift fails closed.
# ------------------------------------------------------------

prepare_live_containers

mkdir \
    "$TEST_ROOT/live/receiver/usr/local/libexec" \
    "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
    "$TEST_ROOT/live/ingest/usr/local/libexec" \
    "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d"

chmod 0755 \
    "$TEST_ROOT/live/receiver/usr/local/libexec" \
    "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
    "$TEST_ROOT/live/ingest/usr/local/libexec" \
    "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d"

runtime_prepare_expected

cp \
    "$RUNTIME_PLAN/fi-receiver-supervisor" \
    "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"

chmod 0644 \
    "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"

printf '%s\n' "# drift" \
    >> "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"

chmod 0555 \
    "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"

runtime_cleanup_expected

if (
    apply_runtime >/dev/null 2>&1
); then
    test_fail "runtime apply accepted FI-owned content drift"
fi

[ ! -e "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver" ] ||
    test_fail "FI-owned drift allowed later runtime mutation"

test_pass "FI-owned runtime drift fails closed"

# ------------------------------------------------------------
# Wrong host fails before mutation.
# ------------------------------------------------------------

prepare_live_containers
MOCK_HOSTNAME="wrong-host.invalid"

if (
    apply_runtime >/dev/null 2>&1
); then
    test_fail "wrong-host runtime apply unexpectedly succeeded"
fi

[ ! -e "$TEST_ROOT/live/receiver/usr/local/libexec" ] &&
[ ! -e "$TEST_ROOT/live/ingest/usr/local/libexec" ] ||
    test_fail "wrong-host runtime apply reached mutation"

MOCK_HOSTNAME="fi-test"

test_pass "wrong-host runtime apply fails before mutation"

test_pass "FI FreeBSD runtime apply acceptance complete"
