#!/bin/sh

# FI FreeBSD System-of-Record PostgreSQL rc-policy helper.
#
# Sourcing this file performs no mutation.

SOR_POSTGRESQL_MARKER="# FI-MANAGED: ironsignal-fi-freebsd-sor-postgresql-v1"
SOR_POSTGRESQL_ROLE="# FI-ROLE: postgresql-rc-policy"
SOR_POSTGRESQL_SOURCE="$SCRIPT_DIR/sor.d/postgresql.rc.conf"

sor_postgresql_target()
{
    printf '%s/etc/rc.conf.d/postgresql\n' \
        "$(get_value FI_SOR_DB_ROOT)"
}

sor_postgresql_require_commands()
{
    for command_name in \
        awk \
        cat \
        chmod \
        chown \
        cmp \
        grep \
        hostname \
        id \
        jls \
        ln \
        mktemp \
        rm \
        stat \
        uname
    do
        command -v "$command_name" >/dev/null 2>&1 ||
            fail "required PostgreSQL policy command not found: $command_name"
    done
}

sor_postgresql_require_host()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "PostgreSQL policy operation must run as root"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "PostgreSQL policy operation requires FreeBSD"

    expected_hostname=$(get_value FI_HOSTNAME)
    actual_hostname=$(hostname)

    [ "$actual_hostname" = "$expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $expected_hostname, observed $actual_hostname"

    pass "deployment hostname matches: $actual_hostname"
}

sor_postgresql_require_stopped()
{
    if jls -j fi-sor-db >/dev/null 2>&1; then
        fail "fi-sor-db must be stopped before PostgreSQL policy mutation"
    fi
}

sor_postgresql_require_prerequisites()
{
    sor_root=$(get_value FI_SOR_DB_ROOT)
    pgdata=$(get_value FI_SOR_POSTGRES_HOST)
    target=$(sor_postgresql_target)
    parent=${target%/*}

    [ -d "$sor_root" ] &&
        [ ! -L "$sor_root" ] ||
        fail "System-of-Record jail root unavailable: $sor_root"

    [ -d "$parent" ] &&
        [ ! -L "$parent" ] ||
        fail "PostgreSQL rc.conf.d parent unavailable: $parent"

    [ -f "$sor_root/usr/local/etc/rc.d/postgresql" ] ||
        fail "PostgreSQL rc.d service is not installed"

    [ -x "$sor_root/usr/local/bin/pg_ctl" ] ||
        fail "PostgreSQL pg_ctl is not installed"

    [ -r "$sor_root/etc/master.passwd" ] &&
        [ -r "$sor_root/etc/group" ] ||
        fail "unable to inspect PostgreSQL service identity"

    user_line=$(
        awk -F: '
            $1 == "postgres" {
                count++
                line=$0
            }

            END {
                if (count == 1) {
                    print line
                    exit 0
                }

                exit 1
            }
        ' "$sor_root/etc/master.passwd"
    ) || fail "exact PostgreSQL service user unavailable"

    group_line=$(
        awk -F: '
            $1 == "postgres" {
                count++
                line=$0
            }

            END {
                if (count == 1) {
                    print line
                    exit 0
                }

                exit 1
            }
        ' "$sor_root/etc/group"
    ) || fail "exact PostgreSQL service group unavailable"

    uid=$(printf '%s\n' "$user_line" | awk -F: '{print $3}')
    primary_gid=$(printf '%s\n' "$user_line" | awk -F: '{print $4}')
    group_gid=$(printf '%s\n' "$group_line" | awk -F: '{print $3}')

    [ "$primary_gid" = "$group_gid" ] ||
        fail "PostgreSQL primary GID does not match postgres group"

    case "$uid:$primary_gid" in
        *[!0-9:]*|:*|*:)
            fail "invalid PostgreSQL numeric service identity"
            ;;
    esac

    [ -d "$pgdata" ] &&
        [ ! -L "$pgdata" ] ||
        fail "authoritative PostgreSQL data path unavailable: $pgdata"

    pgdata_metadata=$(
        stat -f '%u:%g:%Lp' "$pgdata" 2>/dev/null
    ) || fail \
        "unable to inspect authoritative PostgreSQL data path metadata: $pgdata"

    expected_pgdata_metadata="$uid:$primary_gid:700"

    [ "$pgdata_metadata" = "$expected_pgdata_metadata" ] ||
        fail \
            "authoritative PostgreSQL data path metadata mismatch: expected $expected_pgdata_metadata, observed $pgdata_metadata"

    pass \
        "PostgreSQL prerequisites present: uid=$uid gid=$primary_gid"
}

sor_postgresql_classify()
{
    target=$(sor_postgresql_target)

    [ -f "$SOR_POSTGRESQL_SOURCE" ] || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    grep -Fqx "$SOR_POSTGRESQL_MARKER" \
        "$SOR_POSTGRESQL_SOURCE" 2>/dev/null || {
            printf '%s\n' "UNKNOWN"
            return 0
        }

    grep -Fqx "$SOR_POSTGRESQL_ROLE" \
        "$SOR_POSTGRESQL_SOURCE" 2>/dev/null || {
            printf '%s\n' "UNKNOWN"
            return 0
        }

    if [ ! -e "$target" ] && [ ! -L "$target" ]; then
        printf '%s\n' "ABSENT"
        return 0
    fi

    if [ -L "$target" ] || [ ! -f "$target" ]; then
        printf '%s\n' "FOREIGN_COLLISION"
        return 0
    fi

    if ! grep -Fqx "$SOR_POSTGRESQL_MARKER" "$target" 2>/dev/null; then
        printf '%s\n' "FOREIGN_COLLISION"
        return 0
    fi

    if ! grep -Fqx "$SOR_POSTGRESQL_ROLE" "$target" 2>/dev/null; then
        printf '%s\n' "OWNED_DRIFT"
        return 0
    fi

    if ! cmp -s "$SOR_POSTGRESQL_SOURCE" "$target"; then
        printf '%s\n' "OWNED_DRIFT"
        return 0
    fi

    metadata=$(stat -f '%u:%g:%Lp:%l' "$target" 2>/dev/null) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    [ "$metadata" = "0:0:644:1" ] || {
        printf '%s\n' "OWNED_DRIFT"
        return 0
    }

    printf '%s\n' "OWNED_MATCH"
}

sor_postgresql_install_absent()
{
    target=$(sor_postgresql_target)
    parent=${target%/*}
    name=${target##*/}

    state=$(sor_postgresql_classify)

    [ "$state" = "ABSENT" ] ||
        fail "PostgreSQL policy changed before creation: $state"

    temp=$(
        mktemp "$parent/.${name}.fi.XXXXXX"
    ) || fail "unable to create PostgreSQL policy temporary file"

    if ! cat "$SOR_POSTGRESQL_SOURCE" > "$temp"; then
        rm -f "$temp"
        fail "unable to populate PostgreSQL policy temporary file"
    fi

    if ! chown 0:0 "$temp"; then
        rm -f "$temp"
        fail "unable to set PostgreSQL policy ownership"
    fi

    if ! chmod 0644 "$temp"; then
        rm -f "$temp"
        fail "unable to set PostgreSQL policy mode"
    fi

    if ! ln "$temp" "$target"; then
        rm -f "$temp"
        fail "unable to publish PostgreSQL policy without overwrite"
    fi

    rm -f "$temp" ||
        fail "unable to remove PostgreSQL policy temporary link"

    state=$(sor_postgresql_classify)

    [ "$state" = "OWNED_MATCH" ] ||
        fail "created PostgreSQL policy failed verification: $state"

    pass "created and verified PostgreSQL rc policy: $target"
}

apply_sor_postgresql()
{
    sor_postgresql_require_host
    sor_postgresql_require_stopped
    sor_postgresql_require_prerequisites

    state=$(sor_postgresql_classify)

    case "$state" in
        OWNED_MATCH)
            pass "PostgreSQL rc policy already matches"
            ;;
        ABSENT)
            sor_postgresql_install_absent
            ;;
        OWNED_DRIFT)
            fail "PostgreSQL rc policy is FI-owned but has drifted"
            ;;
        FOREIGN_COLLISION)
            fail "PostgreSQL rc policy collides with non-FI state"
            ;;
        UNKNOWN)
            fail "PostgreSQL rc policy could not be classified safely"
            ;;
        *)
            fail "unexpected PostgreSQL policy state: $state"
            ;;
    esac

    pass "FI System-of-Record PostgreSQL policy apply complete"
}

verify_sor_postgresql()
{
    sor_postgresql_require_host
    sor_postgresql_require_prerequisites

    state=$(sor_postgresql_classify)

    [ "$state" = "OWNED_MATCH" ] ||
        fail "PostgreSQL rc policy is not OWNED_MATCH: $state"

    pass "FI System-of-Record PostgreSQL policy verification complete"
}
