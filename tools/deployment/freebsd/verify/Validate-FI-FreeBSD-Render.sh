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

trap cleanup EXIT HUP INT TERM

[ -x "$BOOTSTRAP" ] ||
    fail "bootstrap is not executable: $BOOTSTRAP"

[ -f "$FIXTURE" ] ||
    fail "acceptance fixture not found: $FIXTURE"

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fi-render-test.XXXXXX") ||
    fail "unable to create test directory"

PLAN_A="$WORK_ROOT/plan-a"
PLAN_B="$WORK_ROOT/plan-b"

"$BOOTSTRAP" plan "$FIXTURE" "$PLAN_A" ||
    fail "first deterministic render failed"

"$BOOTSTRAP" plan "$FIXTURE" "$PLAN_B" ||
    fail "second deterministic render failed"

for expected_file in \
    fi-receiver.conf \
    fi-ingest.conf \
    fi-sor-db.conf \
    fstab.fi-receiver \
    fstab.fi-ingest \
    fstab.fi-sor-db \
    devfs.rules.fi \
    pf.conf \
    rc.conf.d.fi_pf \
    rc.d.fi_pf \
    fi-vnet-pair \
    rc.conf.d.postgresql \
    MANIFEST.sha256
do
    [ -f "$PLAN_A/$expected_file" ] ||
        fail "first plan missing $expected_file"

    [ -f "$PLAN_B/$expected_file" ] ||
        fail "second plan missing $expected_file"
done

if grep -R -E '@FI_[A-Z0-9_]+@' "$PLAN_A" >/dev/null 2>&1; then
    fail "first plan contains unresolved FI template tokens"
fi

if grep -R -E '@FI_[A-Z0-9_]+@' "$PLAN_B" >/dev/null 2>&1; then
    fail "second plan contains unresolved FI template tokens"
fi

diff -ru "$PLAN_A" "$PLAN_B" >/dev/null 2>&1 ||
    fail "identical input did not produce byte-identical plans"

pass "identical configuration produces byte-identical plans"

BAD_UNKNOWN="$WORK_ROOT/bad-unknown.conf"
cp "$FIXTURE" "$BAD_UNKNOWN" ||
    fail "unable to create unknown-key test fixture"

printf '\nFI_UNEXPECTED_VALUE="bad"\n' >> "$BAD_UNKNOWN"

if "$BOOTSTRAP" plan "$BAD_UNKNOWN" "$WORK_ROOT/bad-unknown-plan" \
    >/dev/null 2>&1
then
    fail "unknown configuration key was accepted"
fi

pass "unknown configuration keys fail closed"

BAD_DUPLICATE="$WORK_ROOT/bad-duplicate.conf"
cp "$FIXTURE" "$BAD_DUPLICATE" ||
    fail "unable to create duplicate-key test fixture"

printf '\nFI_ZPOOL="otherpool"\n' >> "$BAD_DUPLICATE"

if "$BOOTSTRAP" plan "$BAD_DUPLICATE" "$WORK_ROOT/bad-duplicate-plan" \
    >/dev/null 2>&1
then
    fail "duplicate configuration key was accepted"
fi

pass "duplicate configuration keys fail closed"

BAD_SHELL="$WORK_ROOT/bad-shell.conf"

sed \
    's#FI_ZPOOL="zroot"#FI_ZPOOL="$(id)"#' \
    "$FIXTURE" > "$BAD_SHELL" ||
    fail "unable to create shell-expression test fixture"

if "$BOOTSTRAP" plan "$BAD_SHELL" "$WORK_ROOT/bad-shell-plan" \
    >/dev/null 2>&1
then
    fail "shell expression was accepted as configuration data"
fi

pass "shell expressions are rejected"

BAD_NETWORK="$WORK_ROOT/bad-network.conf"

sed \
    's#FI_RECEIVER_MGMT_ADDRESS="10.77.10.20/24"#FI_RECEIVER_MGMT_ADDRESS="10.77.99.20/24"#' \
    "$FIXTURE" > "$BAD_NETWORK" ||
    fail "unable to create network-boundary test fixture"

if "$BOOTSTRAP" plan "$BAD_NETWORK" "$WORK_ROOT/bad-network-plan" \
    >/dev/null 2>&1
then
    fail "out-of-network jail address was accepted"
fi

pass "address/network mismatch fails closed"

BAD_PATH_PARENT="$WORK_ROOT/bad-path-parent.conf"

sed \
    's#FI_RECEIVER_ROOT="/usr/local/jails/containers/fi-receiver"#FI_RECEIVER_ROOT="/usr/local/jails/containers/../fi-receiver"#' \
    "$FIXTURE" > "$BAD_PATH_PARENT" ||
    fail "unable to create parent-path test fixture"

if "$BOOTSTRAP" plan "$BAD_PATH_PARENT" "$WORK_ROOT/bad-path-parent-plan" \
    >/dev/null 2>&1
then
    fail "parent path component was accepted"
fi

pass "parent path components are rejected"

BAD_PATH_CURRENT="$WORK_ROOT/bad-path-current.conf"

sed \
    's#FI_RECEIVER_ROOT="/usr/local/jails/containers/fi-receiver"#FI_RECEIVER_ROOT="/usr/local/jails/containers/./fi-receiver"#' \
    "$FIXTURE" > "$BAD_PATH_CURRENT" ||
    fail "unable to create current-path test fixture"

if "$BOOTSTRAP" plan "$BAD_PATH_CURRENT" "$WORK_ROOT/bad-path-current-plan" \
    >/dev/null 2>&1
then
    fail "current path component was accepted"
fi

pass "current path components are rejected"

BAD_PATH_DOUBLE="$WORK_ROOT/bad-path-double.conf"

sed \
    's#FI_RECEIVER_ROOT="/usr/local/jails/containers/fi-receiver"#FI_RECEIVER_ROOT="/usr/local/jails//containers/fi-receiver"#' \
    "$FIXTURE" > "$BAD_PATH_DOUBLE" ||
    fail "unable to create duplicate-separator test fixture"

if "$BOOTSTRAP" plan "$BAD_PATH_DOUBLE" "$WORK_ROOT/bad-path-double-plan" \
    >/dev/null 2>&1
then
    fail "duplicate path separator was accepted"
fi

pass "duplicate path separators are rejected"

ACCEPTED_NAME_IDENTITY_CONTRACTS=""

while IFS='|' read -r contract_name old_value new_value
do
    [ -n "$contract_name" ] || continue

    bad_config="$WORK_ROOT/bad-contract-$contract_name.conf"

    sed "s#$old_value#$new_value#" "$FIXTURE" > "$bad_config" ||
        fail "unable to create $contract_name test fixture"

    if "$BOOTSTRAP" plan         "$bad_config"         "$WORK_ROOT/bad-contract-$contract_name-plan"         >/dev/null 2>&1
    then
        if [ -n "$ACCEPTED_NAME_IDENTITY_CONTRACTS" ]; then
            ACCEPTED_NAME_IDENTITY_CONTRACTS="$ACCEPTED_NAME_IDENTITY_CONTRACTS, "
        fi

        ACCEPTED_NAME_IDENTITY_CONTRACTS="${ACCEPTED_NAME_IDENTITY_CONTRACTS}${contract_name}"
    fi
done <<'EOF_NAME_IDENTITY'
hostname-label|FI_HOSTNAME="fi-test.invalid"|FI_HOSTNAME="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.invalid"
dns-label|FI_HOST_DNS_SEARCH="iss.local"|FI_HOST_DNS_SEARCH="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.local"
uid-low|FI_RUNTIME_UID="4100"|FI_RUNTIME_UID="999"
uid-high|FI_RUNTIME_UID="4100"|FI_RUNTIME_UID="32001"
gid-low|FI_RUNTIME_GID="4100"|FI_RUNTIME_GID="999"
gid-high|FI_RUNTIME_GID="4100"|FI_RUNTIME_GID="32001"
EOF_NAME_IDENTITY

[ -z "$ACCEPTED_NAME_IDENTITY_CONTRACTS" ] ||
    fail "invalid name/identity contracts were accepted: $ACCEPTED_NAME_IDENTITY_CONTRACTS"

pass "hostname, DNS label, UID, and GID limits fail closed"

BAD_DEVFS="$WORK_ROOT/bad-devfs.conf"

sed \
    's#FI_DEVFS_RULESET="100"#FI_DEVFS_RULESET="5"#' \
    "$FIXTURE" > "$BAD_DEVFS" ||
    fail "unable to create devfs-ruleset test fixture"

if "$BOOTSTRAP" plan "$BAD_DEVFS" "$WORK_ROOT/bad-devfs-plan" \
    >/dev/null 2>&1
then
    fail "low-numbered FI devfs ruleset was accepted"
fi

pass "FI devfs ruleset numbers below 100 fail closed"

for managed_file in \
    fi-receiver.conf \
    fi-ingest.conf \
    fi-sor-db.conf \
    fstab.fi-receiver \
    fstab.fi-ingest \
    fstab.fi-sor-db \
    devfs.rules.fi \
    fi-vnet-pair
do
    grep -Fqx \
        '# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1' \
        "$PLAN_A/$managed_file" ||
        fail "rendered host artifact lacks FI ownership marker: $managed_file"
done

pass "all rendered host artifacts contain the FI ownership marker"

grep -Fqx \
    '# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-v1' \
    "$PLAN_A/rc.conf.d.postgresql" ||
    fail "rendered PostgreSQL policy lacks FI ownership marker"

grep -Fqx \
    '# FI-ROLE: postgresql-rc-policy' \
    "$PLAN_A/rc.conf.d.postgresql" ||
    fail "rendered PostgreSQL policy lacks exact role marker"

for expected_postgresql_line in \
    'postgresql_enable="YES"' \
    'postgresql_user="postgres"' \
    'postgresql_data="/var/db/fi/sor/postgres"' \
    'postgresql_initdb_flags="--encoding=UTF8 --locale=C --data-checksums"'
do
    grep -Fqx \
        "$expected_postgresql_line" \
        "$PLAN_A/rc.conf.d.postgresql" ||
        fail \
            "rendered PostgreSQL policy is incomplete: $expected_postgresql_line"
done

cmp -s \
    "$FREEBSD_DIR/sor.d/postgresql.rc.conf" \
    "$PLAN_A/rc.conf.d.postgresql" ||
    fail "rendered PostgreSQL policy differs from reviewed source"

grep -Eq \
    '^[0-9a-fA-F]{64}  rc\.conf\.d\.postgresql$' \
    "$PLAN_A/MANIFEST.sha256" ||
    fail "PostgreSQL policy is absent from deterministic manifest"

pass "rendered PostgreSQL policy is exact"

grep -Fqx \
    '[fi_production=100]' \
    "$PLAN_A/devfs.rules.fi" ||
    fail "rendered devfs ruleset declaration is not exact"

for expected_devfs_rule in \
    'add hide' \
    'add path null unhide' \
    'add path zero unhide' \
    'add path random unhide' \
    'add path urandom unhide'
do
    grep -Fqx "$expected_devfs_rule" "$PLAN_A/devfs.rules.fi" ||
        fail "rendered devfs rule is absent: $expected_devfs_rule"
done

pass "rendered persistent devfs rules are exact"

cmp -s \
    "$FREEBSD_DIR/fi-vnet-pair.sh" \
    "$PLAN_A/fi-vnet-pair" ||
    fail "rendered VNET helper differs from reviewed source"

pass "rendered VNET helper is byte-identical to reviewed source"

grep -Fq \
    "/var/db/fi/custody/transport" \
    "$PLAN_A/fstab.fi-receiver" ||
    fail "receiver fstab is missing transport custody"

if grep -Fq \
    "/var/db/fi/custody/transport" \
    "$PLAN_A/fstab.fi-ingest"
then
    fail "ingest fstab unexpectedly receives transport custody"
fi

pass "transport custody is mounted only into the receiver plan"

BAD_FSTAB="$WORK_ROOT/bad-fstab.conf"

sed \
    's#FI_RECEIVER_FSTAB="/etc/fstab.fi-receiver"#FI_RECEIVER_FSTAB="/tmp/fstab.fi-receiver"#' \
    "$FIXTURE" > "$BAD_FSTAB" ||
    fail "unable to create host-file destination test fixture"

if "$BOOTSTRAP" plan "$BAD_FSTAB" "$WORK_ROOT/bad-fstab-plan" \
    >/dev/null 2>&1
then
    fail "unsupported receiver fstab destination was accepted"
fi

pass "unsupported host-file destinations fail closed"

printf '[PASS] FI FreeBSD render acceptance complete\n'
