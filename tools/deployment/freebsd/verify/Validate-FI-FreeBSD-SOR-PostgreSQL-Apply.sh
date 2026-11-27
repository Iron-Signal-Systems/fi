#!/bin/sh

VERIFY_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
FREEBSD_DIR=$(CDPATH= cd "$VERIFY_DIR/.." 2>/dev/null && pwd)

SCRIPT_DIR="$FREEBSD_DIR"
HELPER="$FREEBSD_DIR/fi-sor-postgresql-apply.sh"

[ -f "$HELPER" ] || {
    printf '[FAIL] helper not found: %s\n' "$HELPER" >&2
    exit 1
}

. "$HELPER"

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
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

pass()
{
    :
}

[ "$(id -u)" -eq 0 ] ||
    test_fail "test must run as root"

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-sor-pg-test.XXXXXX") ||
    test_fail "unable to create workspace"

trap 'rm -rf "$TEST_ROOT"' EXIT HUP INT TERM

MOCK_SOR_ROOT="$TEST_ROOT/fi-sor-db"
MOCK_PGDATA="$TEST_ROOT/pgdata"

mkdir -p \
    "$MOCK_SOR_ROOT/etc/rc.conf.d" \
    "$MOCK_SOR_ROOT/usr/local/etc/rc.d" \
    "$MOCK_SOR_ROOT/usr/local/bin" \
    "$MOCK_PGDATA"

cat > "$MOCK_SOR_ROOT/etc/master.passwd" <<'EOF_PASSWD'
postgres:*:770:770::0:0:PostgreSQL Daemon:/var/db/postgres:/usr/sbin/nologin
EOF_PASSWD

cat > "$MOCK_SOR_ROOT/etc/group" <<'EOF_GROUP'
postgres:*:770:
EOF_GROUP

: > "$MOCK_SOR_ROOT/usr/local/etc/rc.d/postgresql"
: > "$MOCK_SOR_ROOT/usr/local/bin/pg_ctl"

chmod 0555 \
    "$MOCK_SOR_ROOT/usr/local/bin/pg_ctl"

chown 770:770 \
    "$MOCK_PGDATA"

chmod 0700 \
    "$MOCK_PGDATA"

get_value()
{
    case "$1" in
        FI_SOR_DB_ROOT)
            printf '%s\n' "$MOCK_SOR_ROOT"
            ;;
        FI_SOR_POSTGRES_HOST)
            printf '%s\n' "$MOCK_PGDATA"
            ;;
        FI_HOSTNAME)
            printf '%s\n' "fi-test"
            ;;
        *)
            return 1
            ;;
    esac
}

echo "===== PGDATA PREREQUISITE ====="

sor_postgresql_require_prerequisites >/dev/null

test_pass \
    "PostgreSQL prerequisite accepts exact PGDATA owner/group/mode"

chmod 0750 \
    "$MOCK_PGDATA"

if (
    sor_postgresql_require_prerequisites >/dev/null 2>&1
); then
    test_fail \
        "PostgreSQL prerequisite accepted wrong PGDATA mode"
fi

test_pass \
    "PostgreSQL prerequisite rejects wrong PGDATA mode"

chmod 0700 \
    "$MOCK_PGDATA"

chown 771:770 \
    "$MOCK_PGDATA"

if (
    sor_postgresql_require_prerequisites >/dev/null 2>&1
); then
    test_fail \
        "PostgreSQL prerequisite accepted wrong PGDATA owner"
fi

test_pass \
    "PostgreSQL prerequisite rejects wrong PGDATA owner"

chown 770:770 \
    "$MOCK_PGDATA"

echo
sor_postgresql_require_host()
{
    :
}

sor_postgresql_require_stopped()
{
    :
}

sor_postgresql_require_prerequisites()
{
    :
}

expect_state()
{
    expected=$1
    description=$2

    actual=$(sor_postgresql_classify) ||
        test_fail "$description: classifier failed"

    [ "$actual" = "$expected" ] ||
        test_fail \
            "$description: expected $expected, observed $actual"

    test_pass "$description"
}

echo "===== ABSENT CLASSIFICATION ====="

expect_state \
    "ABSENT" \
    "absent PostgreSQL policy classification"

echo
echo "===== FIRST APPLY ====="

apply_sor_postgresql >/dev/null

expect_state \
    "OWNED_MATCH" \
    "first apply creates exact PostgreSQL policy"

cmp -s \
    "$SOR_POSTGRESQL_SOURCE" \
    "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql" ||
    test_fail "installed PostgreSQL policy differs from reviewed source"

metadata=$(
    stat -f '%u:%g:%Lp:%l' \
        "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql"
)

[ "$metadata" = "0:0:644:1" ] ||
    test_fail \
        "installed PostgreSQL policy metadata is not exact: $metadata"

test_pass "PostgreSQL policy content and metadata are exact"

echo
echo "===== IDEMPOTENT SECOND APPLY ====="

inode_before=$(
    stat -f '%i' \
        "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql"
)

apply_sor_postgresql >/dev/null

inode_after=$(
    stat -f '%i' \
        "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql"
)

[ "$inode_before" = "$inode_after" ] ||
    test_fail "exact second apply replaced PostgreSQL policy"

test_pass "exact second PostgreSQL policy apply is a no-op"

echo
echo "===== OWNED DRIFT ====="

printf '\n# drift\n' \
    >> "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql"

expect_state \
    "OWNED_DRIFT" \
    "managed PostgreSQL policy drift classification"

if (
    verify_sor_postgresql >/dev/null 2>&1
); then
    test_fail "verification accepted PostgreSQL policy drift"
fi

test_pass "verification rejects PostgreSQL policy drift"

echo
echo "===== FOREIGN COLLISION ====="

rm -f "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql"

cat > "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql" <<'EOF_FOREIGN'
postgresql_enable="YES"
postgresql_user="postgres"
postgresql_data="/var/db/fi/sor/postgres"
postgresql_initdb_flags="--encoding=UTF8 --locale=C --data-checksums"
EOF_FOREIGN

chmod 0644 \
    "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql"

chown 0:0 \
    "$MOCK_SOR_ROOT/etc/rc.conf.d/postgresql"

expect_state \
    "FOREIGN_COLLISION" \
    "unmarked PostgreSQL policy is not silently adopted"

echo
echo "=============================================="
echo " FI SOR POSTGRESQL POLICY ACCEPTANCE COMPLETE"
echo "=============================================="
