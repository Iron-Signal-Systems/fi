#!/bin/sh

VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

RECEIVER_RC="$FREEBSD_DIR/runtime.d/fi-receiver.rc.d"
INGEST_RC="$FREEBSD_DIR/runtime.d/fi-ingest-worker.rc.d"

test_fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

test_pass()
{
    printf '[PASS] %s\n' "$*"
}

for file in "$RECEIVER_RC" "$INGEST_RC"
do
    [ -f "$file" ] ||
        test_fail "runtime rc.d source is unavailable: $file"

    sh -n "$file" ||
        test_fail "runtime rc.d source has invalid syntax: $file"
done

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-runtime-boot-test.XXXXXX") ||
    test_fail "unable to create runtime boot test workspace"

trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

# Use the actual ownership inherited by files created in the test
# workspace. The chown() mock deliberately performs no real ownership
# mutation, so the simulated runtime identity must match this filesystem
# state.
TEST_UID=$(command stat -f '%u' "$TEST_ROOT")
TEST_GID=$(command stat -f '%g' "$TEST_ROOT")

TEST_RUNTIME_DIR=""
TEST_ID_FAIL=""
TEST_STAT_OVERRIDE=""
TEST_STAT_FAIL=0
TEST_CHOWN_FAIL=0

id()
{
    case "$1" in
        -u)
            [ "$TEST_ID_FAIL" != "uid" ] ||
                return 1

            printf '%s\n' "$TEST_UID"
            ;;
        -g)
            [ "$TEST_ID_FAIL" != "gid" ] ||
                return 1

            printf '%s\n' "$TEST_GID"
            ;;
        *)
            command id "$@"
            ;;
    esac
}

stat()
{
    if [ "$1" = "-f" ] &&
        [ "$2" = "%u:%g:%#Lp" ] &&
        [ "$3" = "$TEST_RUNTIME_DIR" ]
    then
        [ "$TEST_STAT_FAIL" -eq 0 ] ||
            return 1

        if [ -n "$TEST_STAT_OVERRIDE" ]; then
            printf '%s\n' "$TEST_STAT_OVERRIDE"
            return 0
        fi
    fi

    command stat "$@"
}

chown()
{
    [ "$TEST_CHOWN_FAIL" -eq 0 ] ||
        return 1

    # Test directories are already owned by the invoking test identity.
    # The production function still executes the chown call; this harness
    # avoids requiring root merely to prove its control flow.
    return 0
}

reset_case()
{
    rm -rf "$TEST_ROOT/case"

    mkdir -p "$TEST_ROOT/case" ||
        test_fail "unable to reset runtime boot test case"

    TEST_RUNTIME_DIR="$TEST_ROOT/case/fi"
    TEST_ID_FAIL=""
    TEST_STAT_OVERRIDE=""
    TEST_STAT_FAIL=0
    TEST_CHOWN_FAIL=0
}

extract_prestart()
{
    source_file=$1
    function_name=$2
    destination=$3

    sed -n \
        "/^${function_name}()/,/^}/p" \
        "$source_file" |
        sed \
            's|    runtime_dir="/var/run/fi"|    runtime_dir="$TEST_RUNTIME_DIR"|' \
            > "$destination" ||
        test_fail "unable to extract prestart function: $function_name"

    grep -Fq \
        'runtime_dir="$TEST_RUNTIME_DIR"' \
        "$destination" ||
        test_fail "prestart runtime path was not isolated for test: $function_name"

    sh -n "$destination" ||
        test_fail "extracted prestart function has invalid syntax: $function_name"
}

run_contract()
{
    source_file=$1
    function_name=$2
    label=$3

    function_file="$TEST_ROOT/${function_name}.sh"

    extract_prestart \
        "$source_file" \
        "$function_name" \
        "$function_file"

    . "$function_file"

    # --------------------------------------------------------
    # Absent -> create exact 0700 runtime directory.
    # --------------------------------------------------------

    reset_case

    if ! "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart rejected absent runtime directory"
    fi

    [ -d "$TEST_RUNTIME_DIR" ] &&
    [ ! -L "$TEST_RUNTIME_DIR" ] ||
        test_fail "$label prestart did not create an exact directory"

    actual=$(
        command stat -f '%u:%g:%#Lp' "$TEST_RUNTIME_DIR"
    ) || test_fail "$label unable to inspect created runtime directory"

    expected="${TEST_UID}:${TEST_GID}:0700"

    [ "$actual" = "$expected" ] ||
        test_fail \
            "$label created incorrect runtime metadata: expected $expected observed $actual"

    test_pass "$label absent runtime directory is created exactly"

    # --------------------------------------------------------
    # Exact existing directory -> accept without replacement.
    # --------------------------------------------------------

    inode_before=$(
        command stat -f '%i' "$TEST_RUNTIME_DIR"
    )

    if ! "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart rejected exact runtime directory"
    fi

    inode_after=$(
        command stat -f '%i' "$TEST_RUNTIME_DIR"
    )

    [ "$inode_before" = "$inode_after" ] ||
        test_fail "$label prestart replaced exact runtime directory"

    test_pass "$label exact runtime directory is a no-op"

    # --------------------------------------------------------
    # Symbolic link -> fail closed.
    # --------------------------------------------------------

    reset_case

    mkdir "$TEST_ROOT/case/target" ||
        test_fail "$label unable to create symlink target"

    ln -s \
        "$TEST_ROOT/case/target" \
        "$TEST_RUNTIME_DIR" ||
        test_fail "$label unable to create runtime symlink fixture"

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted runtime symlink"
    fi

    [ -L "$TEST_RUNTIME_DIR" ] ||
        test_fail "$label prestart mutated runtime symlink"

    test_pass "$label runtime symlink fails closed"

    # --------------------------------------------------------
    # Regular file -> fail closed.
    # --------------------------------------------------------

    reset_case

    printf '%s\n' "not-a-directory" > "$TEST_RUNTIME_DIR"

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted runtime regular file"
    fi

    [ -f "$TEST_RUNTIME_DIR" ] &&
    [ ! -L "$TEST_RUNTIME_DIR" ] ||
        test_fail "$label prestart mutated runtime regular file"

    test_pass "$label wrong runtime path type fails closed"

    # --------------------------------------------------------
    # Mode drift -> fail closed without repair.
    # --------------------------------------------------------

    reset_case

    mkdir -m 0755 "$TEST_RUNTIME_DIR" ||
        test_fail "$label unable to create mode-drift fixture"

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted runtime mode drift"
    fi

    actual_mode=$(
        command stat -f '%#Lp' "$TEST_RUNTIME_DIR"
    )

    [ "$actual_mode" = "0755" ] ||
        test_fail "$label prestart repaired mode drift instead of failing"

    test_pass "$label runtime mode drift fails closed"

    # --------------------------------------------------------
    # UID drift -> fail closed.
    # --------------------------------------------------------

    reset_case
    mkdir -m 0700 "$TEST_RUNTIME_DIR"

    TEST_STAT_OVERRIDE="99998:${TEST_GID}:0700"

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted runtime UID drift"
    fi

    test_pass "$label runtime UID drift fails closed"

    # --------------------------------------------------------
    # GID drift -> fail closed.
    # --------------------------------------------------------

    reset_case
    mkdir -m 0700 "$TEST_RUNTIME_DIR"

    TEST_STAT_OVERRIDE="${TEST_UID}:99998:0700"

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted runtime GID drift"
    fi

    test_pass "$label runtime GID drift fails closed"

    # --------------------------------------------------------
    # UID lookup failure -> fail before creation.
    # --------------------------------------------------------

    reset_case
    TEST_ID_FAIL="uid"

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted unresolved runtime UID"
    fi

    [ ! -e "$TEST_RUNTIME_DIR" ] &&
    [ ! -L "$TEST_RUNTIME_DIR" ] ||
        test_fail "$label created runtime directory after UID lookup failure"

    test_pass "$label unresolved runtime UID fails before mutation"

    # --------------------------------------------------------
    # GID lookup failure -> fail before creation.
    # --------------------------------------------------------

    reset_case
    TEST_ID_FAIL="gid"

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted unresolved runtime GID"
    fi

    [ ! -e "$TEST_RUNTIME_DIR" ] &&
    [ ! -L "$TEST_RUNTIME_DIR" ] ||
        test_fail "$label created runtime directory after GID lookup failure"

    test_pass "$label unresolved runtime GID fails before mutation"

    # --------------------------------------------------------
    # Chown failure -> remove newly created candidate.
    # --------------------------------------------------------

    reset_case
    TEST_CHOWN_FAIL=1

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted runtime ownership failure"
    fi

    [ ! -e "$TEST_RUNTIME_DIR" ] &&
    [ ! -L "$TEST_RUNTIME_DIR" ] ||
        test_fail "$label left partial runtime directory after chown failure"

    test_pass "$label ownership failure cleans partial directory"

    # --------------------------------------------------------
    # Stat failure -> fail closed.
    # --------------------------------------------------------

    reset_case
    mkdir -m 0700 "$TEST_RUNTIME_DIR"
    TEST_STAT_FAIL=1

    if "$function_name" >/dev/null 2>&1; then
        test_fail "$label prestart accepted uninspectable runtime directory"
    fi

    test_pass "$label runtime metadata inspection failure fails closed"
}

run_contract \
    "$RECEIVER_RC" \
    "fi_receiver_prestart" \
    "receiver"

run_contract \
    "$INGEST_RC" \
    "fi_ingest_worker_prestart" \
    "ingest"

test_pass "FI FreeBSD runtime boot-directory acceptance complete"
