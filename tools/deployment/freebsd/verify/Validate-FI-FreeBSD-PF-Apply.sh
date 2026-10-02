#!/bin/sh

VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

HOST_FILE_HELPER="$FREEBSD_DIR/fi-host-file-apply.sh"
PF_HELPER="$FREEBSD_DIR/fi-host-pf-apply.sh"

[ -f "$HOST_FILE_HELPER" ] || {
    printf '[FAIL] host-file helper not found: %s\n' "$HOST_FILE_HELPER" >&2
    exit 1
}

[ -f "$PF_HELPER" ] || {
    printf '[FAIL] PF helper not found: %s\n' "$PF_HELPER" >&2
    exit 1
}

. "$HOST_FILE_HELPER"
. "$PF_HELPER"

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

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-pf-apply-test.XXXXXX") ||
    test_fail "unable to create PF acceptance workspace"

trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

TEST_UID=$(id -u)
TEST_GID=$(stat -f '%g' "$TEST_ROOT")

EXPECTED="$TEST_ROOT/expected-pf.conf"
TARGET="$TEST_ROOT/live/pf.conf"
PRIOR="$TEST_ROOT/approved-prior-pf.conf"

mkdir "$TEST_ROOT/live" ||
    test_fail "unable to create live PF fixture directory"

cat > "$EXPECTED" <<'EOF_EXPECTED'
# FI-MANAGED: ironsignal-fi-freebsd-pf-v1
# FI-ROLE: host-packet-filter-policy

pass all
EOF_EXPECTED

chmod 0644 "$EXPECTED"

PF_TARGET="$TARGET"
PF_UID="$TEST_UID"
PF_GID="$TEST_GID"
PF_MODE="0644"

pf_require_host()
{
    :
}

pf_prepare_expected()
{
    pf_use_marker
    PF_EXPECTED="$EXPECTED"
}

pf_cleanup_expected()
{
    :
}

pfctl()
{
    [ "$1" = "-nf" ] || return 1

    grep -Fq 'SYNTAX_INVALID' "$2" && return 1

    return 0
}

# ------------------------------------------------------------
# Fresh apply.
# ------------------------------------------------------------

apply_pf >/dev/null

cmp -s "$EXPECTED" "$TARGET" ||
    test_fail "fresh PF apply did not create exact expected policy"

[ "$(stat -f '%u:%g:%Lp:%l' "$TARGET")" = \
    "${TEST_UID}:${TEST_GID}:644:1" ] ||
    test_fail "fresh PF apply created incorrect metadata"

test_pass "fresh PF apply creates exact managed policy"

# ------------------------------------------------------------
# Idempotence.
# ------------------------------------------------------------

inode_before=$(stat -f '%i' "$TARGET")

apply_pf >/dev/null

inode_after=$(stat -f '%i' "$TARGET")

[ "$inode_before" = "$inode_after" ] ||
    test_fail "exact second PF apply replaced managed policy"

test_pass "exact second PF apply is a no-op"

# ------------------------------------------------------------
# Read-only verification.
# ------------------------------------------------------------

verify_pf >/dev/null

test_pass "read-only PF verification accepts exact state"

# ------------------------------------------------------------
# Foreign policy cannot be silently claimed by apply-pf.
# ------------------------------------------------------------

printf '%s\n' 'foreign-policy=true' > "$TARGET"
chmod 0644 "$TARGET"

if (
    apply_pf >/dev/null 2>&1
); then
    test_fail "apply-pf silently claimed foreign PF policy"
fi

grep -Fqx 'foreign-policy=true' "$TARGET" ||
    test_fail "failed foreign-policy apply altered live target"

test_pass "foreign PF policy requires explicit adoption"

# ------------------------------------------------------------
# FI-owned drift cannot be silently repaired.
# ------------------------------------------------------------

cp "$EXPECTED" "$TARGET"
printf '%s\n' 'drift=true' >> "$TARGET"
chmod 0644 "$TARGET"

if (
    apply_pf >/dev/null 2>&1
); then
    test_fail "apply-pf silently repaired FI-owned PF drift"
fi

grep -Fqx 'drift=true' "$TARGET" ||
    test_fail "failed drift apply altered PF target"

test_pass "FI-owned PF drift fails closed"

# ------------------------------------------------------------
# Exact approved prior policy may be adopted.
# ------------------------------------------------------------

printf '%s\n' 'legacy-policy=true' > "$PRIOR"
cp "$PRIOR" "$TARGET"
chmod 0644 "$TARGET"

adopt_pf "$PRIOR" >/dev/null

cmp -s "$EXPECTED" "$TARGET" ||
    test_fail "approved prior PF policy did not advance to exact FI policy"

test_pass "exact approved prior PF policy is adoptable"

# ------------------------------------------------------------
# Adoption is idempotent after ownership transition.
# ------------------------------------------------------------

inode_before=$(stat -f '%i' "$TARGET")

adopt_pf "$PRIOR" >/dev/null

inode_after=$(stat -f '%i' "$TARGET")

[ "$inode_before" = "$inode_after" ] ||
    test_fail "second PF adoption replaced already exact FI policy"

test_pass "exact second PF adoption is a no-op"

# ------------------------------------------------------------
# Wrong approved prior cannot authorize replacement.
# ------------------------------------------------------------

printf '%s\n' 'legacy-live=true' > "$TARGET"
printf '%s\n' 'legacy-approved-different=true' > "$PRIOR"
chmod 0644 "$TARGET"

if (
    adopt_pf "$PRIOR" >/dev/null 2>&1
); then
    test_fail "mismatched approved prior PF policy was accepted"
fi

grep -Fqx 'legacy-live=true' "$TARGET" ||
    test_fail "failed prior-policy adoption altered live target"

test_pass "unapproved prior PF contents fail closed"

# ------------------------------------------------------------
# Metadata drift cannot be repaired during adoption.
# ------------------------------------------------------------

printf '%s\n' 'legacy-policy=true' > "$PRIOR"
cp "$PRIOR" "$TARGET"
chmod 0600 "$TARGET"

if (
    adopt_pf "$PRIOR" >/dev/null 2>&1
); then
    test_fail "PF adoption silently repaired metadata drift"
fi

[ "$(stat -f '%Lp' "$TARGET")" = "600" ] ||
    test_fail "failed PF adoption altered drifted target mode"

test_pass "PF adoption rejects metadata drift"

# ------------------------------------------------------------
# Exact approved FI-owned prior may advance to the new policy.
# ------------------------------------------------------------

cat > "$PRIOR" <<'EOF_UPDATE_PRIOR'
# FI-MANAGED: ironsignal-fi-freebsd-pf-v1
# FI-ROLE: host-packet-filter-policy

block drop quick inet proto tcp from any to 10.77.20.22 port 5432
pass all
EOF_UPDATE_PRIOR

cp "$PRIOR" "$TARGET"
chmod 0644 "$TARGET"

update_pf "$PRIOR" >/dev/null

cmp -s "$EXPECTED" "$TARGET" ||
    test_fail "approved FI-owned prior did not advance to exact new PF policy"

test_pass "approved FI-owned PF policy updates to exact new version"

# ------------------------------------------------------------
# Exact second update is a no-op.
# ------------------------------------------------------------

inode_before=$(stat -f '%i' "$TARGET")

update_pf "$PRIOR" >/dev/null

inode_after=$(stat -f '%i' "$TARGET")

[ "$inode_before" = "$inode_after" ] ||
    test_fail "second PF update replaced already exact policy"

test_pass "exact second PF update is a no-op"

# ------------------------------------------------------------
# A different FI-owned prior cannot authorize replacement.
# ------------------------------------------------------------

cat > "$TARGET" <<'EOF_UPDATE_LIVE'
# FI-MANAGED: ironsignal-fi-freebsd-pf-v1
# FI-ROLE: host-packet-filter-policy

block drop quick inet proto tcp from any to 10.77.20.22 port 5432
pass all
EOF_UPDATE_LIVE

cat > "$PRIOR" <<'EOF_UPDATE_WRONG_PRIOR'
# FI-MANAGED: ironsignal-fi-freebsd-pf-v1
# FI-ROLE: host-packet-filter-policy

block drop in quick inet proto tcp from any to 10.77.20.99 port 5432
pass all
EOF_UPDATE_WRONG_PRIOR

chmod 0644 "$TARGET"

if (
    update_pf "$PRIOR" >/dev/null 2>&1
); then
    test_fail "PF update accepted an unapproved FI-owned prior"
fi

grep -Fqx \
    'block drop quick inet proto tcp from any to 10.77.20.22 port 5432' \
    "$TARGET" ||
    test_fail "failed PF update altered unapproved live FI policy"

test_pass "unapproved FI-owned PF prior fails closed"

# ------------------------------------------------------------
# Metadata drift cannot be repaired by update-pf.
# ------------------------------------------------------------

cat > "$PRIOR" <<'EOF_UPDATE_PRIOR_METADATA'
# FI-MANAGED: ironsignal-fi-freebsd-pf-v1
# FI-ROLE: host-packet-filter-policy

block drop quick inet proto tcp from any to 10.77.20.22 port 5432
pass all
EOF_UPDATE_PRIOR_METADATA

cp "$PRIOR" "$TARGET"
chmod 0600 "$TARGET"

if (
    update_pf "$PRIOR" >/dev/null 2>&1
); then
    test_fail "PF update silently repaired metadata drift"
fi

[ "$(stat -f '%Lp' "$TARGET")" = "600" ] ||
    test_fail "failed PF update altered drifted target metadata"

test_pass "PF update rejects metadata drift"

# ------------------------------------------------------------
# update-pf cannot claim a foreign policy.
# ------------------------------------------------------------

printf '%s\n' 'foreign-policy=true' > "$TARGET"
chmod 0644 "$TARGET"

if (
    update_pf "$PRIOR" >/dev/null 2>&1
); then
    test_fail "PF update claimed foreign policy"
fi

grep -Fqx 'foreign-policy=true' "$TARGET" ||
    test_fail "failed PF update altered foreign target"

test_pass "PF update rejects foreign policy"

# ------------------------------------------------------------
# update-pf cannot recreate an absent PF target.
# ------------------------------------------------------------

rm -f "$TARGET"

if (
    update_pf "$PRIOR" >/dev/null 2>&1
); then
    test_fail "PF update recreated absent target"
fi

[ ! -e "$TARGET" ] ||
    test_fail "failed absent-target PF update created target"

test_pass "PF update rejects absent target"

# ------------------------------------------------------------
# Invalid rendered policy fails before target creation.
# ------------------------------------------------------------

rm -f "$TARGET"

cat > "$EXPECTED" <<'EOF_BAD'
# FI-MANAGED: ironsignal-fi-freebsd-pf-v1
# FI-ROLE: host-packet-filter-policy

SYNTAX_INVALID
EOF_BAD

chmod 0644 "$EXPECTED"

if (
    apply_pf >/dev/null 2>&1
); then
    test_fail "syntactically invalid PF policy was installed"
fi

[ ! -e "$TARGET" ] ||
    test_fail "invalid PF policy created a live target"

test_pass "PF syntax failure occurs before mutation"

# ------------------------------------------------------------
# Helper must never activate runtime packet filtering.
# ------------------------------------------------------------

if grep -Eq \
    'pfctl[[:space:]]+-f|sysctl[[:space:]].*=|service[[:space:]]|kldload[[:space:]]' \
    "$PF_HELPER"
then
    test_fail "PF persistence helper contains runtime activation command"
fi

test_pass "PF persistence helper performs no runtime PF activation"

test_pass "FI FreeBSD PF apply acceptance complete"
