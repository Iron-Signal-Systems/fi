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

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-runtime-update-test.XXXXXX") ||
    test_fail "unable to create update test workspace"

trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

TEST_UID=$(command stat -f '%u' "$TEST_ROOT")
TEST_GID=$(command stat -f '%g' "$TEST_ROOT")

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
            command id "$@"
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
            command uname "$@"
            ;;
    esac
}

make_managed_file()
{
    path=$1
    role=$2
    payload=$3

    cat > "$path" <<EOF_FILE
# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: $role
$payload
EOF_FILE
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

    make_managed_file \
        "$RUNTIME_PLAN/fi-receiver-supervisor" \
        "receiver-supervisor" \
        "receiver_supervisor=v2"

    make_managed_file \
        "$RUNTIME_PLAN/rc.d.fi_receiver" \
        "receiver-rc-service" \
        "receiver_rc=v2"

    make_managed_file \
        "$RUNTIME_PLAN/rc.conf.d.fi_receiver" \
        "receiver-runtime-config" \
        'fi_receiver_version="v2"'

    make_managed_file \
        "$RUNTIME_PLAN/fi-ingest-worker-run" \
        "ingest-worker-runner" \
        "ingest_runner=v2"

    make_managed_file \
        "$RUNTIME_PLAN/rc.d.fi_ingest_worker" \
        "ingest-worker-rc-service" \
        "ingest_rc=v2"

    make_managed_file \
        "$RUNTIME_PLAN/rc.conf.d.fi_ingest_worker" \
        "ingest-worker-runtime-config" \
        'fi_ingest_worker_version="v2"'
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

prepare_prior_managed_state()
{
    rm -rf \
        "$TEST_ROOT/live" \
        "$TEST_ROOT/prior" \
        "$TEST_ROOT/state"

    mkdir -p \
        "$TEST_ROOT/live/receiver/usr/local/libexec" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
        "$TEST_ROOT/live/ingest/usr/local/libexec" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d" \
        "$TEST_ROOT/prior" \
        "$TEST_ROOT/state"

    chmod 0755 \
        "$TEST_ROOT/live/receiver/usr/local/libexec" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d" \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d" \
        "$TEST_ROOT/live/ingest/usr/local/libexec" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d"

    make_managed_file \
        "$TEST_ROOT/prior/fi-receiver-supervisor" \
        "receiver-supervisor" \
        "receiver_supervisor=v1"

    make_managed_file \
        "$TEST_ROOT/prior/rc.d.fi_receiver" \
        "receiver-rc-service" \
        "receiver_rc=v1"

    make_managed_file \
        "$TEST_ROOT/prior/rc.conf.d.fi_receiver" \
        "receiver-runtime-config" \
        'fi_receiver_version="v1"'

    make_managed_file \
        "$TEST_ROOT/prior/fi-ingest-worker-run" \
        "ingest-worker-runner" \
        "ingest_runner=v1"

    make_managed_file \
        "$TEST_ROOT/prior/rc.d.fi_ingest_worker" \
        "ingest-worker-rc-service" \
        "ingest_rc=v1"

    make_managed_file \
        "$TEST_ROOT/prior/rc.conf.d.fi_ingest_worker" \
        "ingest-worker-runtime-config" \
        'fi_ingest_worker_version="v1"'

    cp \
        "$TEST_ROOT/prior/fi-receiver-supervisor" \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"

    cp \
        "$TEST_ROOT/prior/rc.d.fi_receiver" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver"

    cp \
        "$TEST_ROOT/prior/rc.conf.d.fi_receiver" \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver"

    cp \
        "$TEST_ROOT/prior/fi-ingest-worker-run" \
        "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run"

    cp \
        "$TEST_ROOT/prior/rc.d.fi_ingest_worker" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker"

    cp \
        "$TEST_ROOT/prior/rc.conf.d.fi_ingest_worker" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

    chmod 0555 \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver" \
        "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker"

    chmod 0644 \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"
}

live_state_manifest()
{
    for target in \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor" \
        "$TEST_ROOT/live/receiver/usr/local/etc/rc.d/fi_receiver" \
        "$TEST_ROOT/live/receiver/etc/rc.conf.d/fi_receiver" \
        "$TEST_ROOT/live/ingest/usr/local/libexec/fi-ingest-worker-run" \
        "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker" \
        "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"
    do
        if [ -L "$target" ]; then
            printf 'LINK\t%s\t%s\n' \
                "$target" \
                "$(readlink "$target")"
        elif [ -f "$target" ]; then
            printf 'FILE\t%s\t%s\t%s\n' \
                "$target" \
                "$(sha256 -q "$target")" \
                "$(stat -f '%u:%g:%#Lp' "$target")"
        elif [ -e "$target" ]; then
            printf 'OTHER\t%s\n' "$target"
        else
            printf 'ABSENT\t%s\n' "$target"
        fi
    done
}

capture_live_state()
{
    live_state_manifest > "$TEST_ROOT/state/before"
}

assert_live_state_unchanged()
{
    live_state_manifest > "$TEST_ROOT/state/after"

    cmp -s \
        "$TEST_ROOT/state/before" \
        "$TEST_ROOT/state/after" ||
        test_fail "failed runtime update changed live state"
}

assert_new_runtime_exact()
{
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
        ) || test_fail \
            "unable to classify updated runtime file: $target"

        [ "$state" = "OWNED_MATCH" ] ||
            test_fail \
                "runtime update did not publish exact managed state: $target ($state)"
    done
}

# ------------------------------------------------------------
# Exact approved managed prior -> new managed version.
# ------------------------------------------------------------

prepare_prior_managed_state

update_runtime "$TEST_ROOT/prior" >/dev/null

assert_new_runtime_exact

test_pass "approved managed runtime updates to exact new version"

# ------------------------------------------------------------
# Exact new version -> second update is a no-op.
# ------------------------------------------------------------

inode_before=$(
    stat -f '%i' \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"
)

update_runtime "$TEST_ROOT/prior" >/dev/null

inode_after=$(
    stat -f '%i' \
        "$TEST_ROOT/live/receiver/usr/local/libexec/fi-receiver-supervisor"
)

[ "$inode_before" = "$inode_after" ] ||
    test_fail "second runtime update replaced exact new-version file"

assert_new_runtime_exact

test_pass "exact second runtime update is a no-op"

# ------------------------------------------------------------
# One mismatched approved prior must block all publication.
# ------------------------------------------------------------

prepare_prior_managed_state

printf '%s\n' "# unexpected prior mutation" \
    >> "$TEST_ROOT/prior/rc.conf.d.fi_ingest_worker"

capture_live_state

if (
    update_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "runtime update accepted mismatched approved prior"
fi

assert_live_state_unchanged

test_pass "mismatched approved prior blocks complete runtime update"

# ------------------------------------------------------------
# Foreign live state must never be replaced by update-runtime.
# ------------------------------------------------------------

prepare_prior_managed_state

chmod 0644 \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

cat > "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker" <<'EOF_FOREIGN'
foreign runtime configuration
EOF_FOREIGN

chmod 0644 \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

capture_live_state

if (
    update_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "runtime update accepted foreign live state"
fi

assert_live_state_unchanged

test_pass "runtime update rejects foreign live state"

# ------------------------------------------------------------
# Missing live resource must not be recreated by update-runtime.
# ------------------------------------------------------------

prepare_prior_managed_state

rm -f \
    "$TEST_ROOT/live/ingest/usr/local/etc/rc.d/fi_ingest_worker"

capture_live_state

if (
    update_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "runtime update accepted absent live resource"
fi

assert_live_state_unchanged

test_pass "runtime update rejects absent live resources"

# ------------------------------------------------------------
# Parent metadata drift must fail before publication.
# ------------------------------------------------------------

prepare_prior_managed_state

chmod 0700 \
    "$TEST_ROOT/live/receiver/usr/local/libexec"

capture_live_state

if (
    update_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "runtime update accepted parent metadata drift"
fi

assert_live_state_unchanged

test_pass "runtime update rejects parent metadata drift"

# ------------------------------------------------------------
# FI-owned live content not matching prior must fail closed.
# ------------------------------------------------------------

prepare_prior_managed_state

chmod 0644 \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

printf '%s\n' "# unauthorized FI-owned drift" \
    >> "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

chmod 0644 \
    "$TEST_ROOT/live/ingest/etc/rc.conf.d/fi_ingest_worker"

capture_live_state

if (
    update_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "runtime update accepted unapproved FI-owned live drift"
fi

assert_live_state_unchanged

test_pass "unapproved FI-owned runtime drift fails closed"

# ------------------------------------------------------------
# Wrong host must fail before publication.
# ------------------------------------------------------------

prepare_prior_managed_state
capture_live_state

MOCK_HOSTNAME="wrong-host.invalid"

if (
    update_runtime "$TEST_ROOT/prior" >/dev/null 2>&1
); then
    test_fail "wrong-host runtime update unexpectedly succeeded"
fi

MOCK_HOSTNAME="fi-test"

assert_live_state_unchanged

test_pass "wrong-host runtime update fails before mutation"

test_pass "FI FreeBSD runtime update acceptance complete"
