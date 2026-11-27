#!/bin/sh

# FI FreeBSD production jail-local runtime identity helper.
#
# This file is sourced by fi-bootstrap.sh. It intentionally performs no work
# merely by being sourced.

FI_IDENTITY_HOME="/nonexistent"
FI_IDENTITY_SHELL="/usr/sbin/nologin"

apply_identities()
{
    identity_require_host

    identity_root_base=$(get_value FI_JAIL_ROOT_BASE)
    identity_uid=$(get_value FI_RUNTIME_UID)
    identity_gid=$(get_value FI_RUNTIME_GID)

    identity_receiver_root="$identity_root_base/fi-receiver"
    identity_ingest_root="$identity_root_base/fi-ingest"

    identity_require_prerequisites \
        "$identity_receiver_root" \
        "$identity_ingest_root"

    identity_require_host_clear "$identity_uid" "$identity_gid"

    identity_receiver_state=$(
        identity_classify_account \
            "$identity_receiver_root" \
            "fi-receiver" \
            "fi-receiver" \
            "$identity_uid" \
            "$identity_gid"
    ) || fail "unable to classify fi-receiver identity"

    identity_ingest_state=$(
        identity_classify_account \
            "$identity_ingest_root" \
            "fi-ingest" \
            "fi-ingest" \
            "$identity_uid" \
            "$identity_gid"
    ) || fail "unable to classify fi-ingest identity"

    identity_apply_precheck "fi-receiver" "$identity_receiver_state"
    identity_apply_precheck "fi-ingest" "$identity_ingest_state"

    pass "production identity layer preclassification complete"

    identity_apply_one \
        "$identity_receiver_root" \
        "fi-receiver" \
        "fi-receiver" \
        "$identity_uid" \
        "$identity_gid"

    identity_apply_one \
        "$identity_ingest_root" \
        "fi-ingest" \
        "fi-ingest" \
        "$identity_uid" \
        "$identity_gid"

    pass "FI production jail-local identity apply complete"
}

identity_apply_one()
{
    identity_apply_root=$1
    identity_apply_user=$2
    identity_apply_group=$3
    identity_apply_uid=$4
    identity_apply_gid=$5

    identity_apply_state=$(
        identity_classify_account \
            "$identity_apply_root" \
            "$identity_apply_user" \
            "$identity_apply_group" \
            "$identity_apply_uid" \
            "$identity_apply_gid"
    ) || fail "unable to reclassify FI identity: $identity_apply_user"

    case "$identity_apply_state" in
        OWNED_MATCH)
            pass "FI identity already matches: $identity_apply_user"
            return 0
            ;;
        ABSENT)
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI identity differs from requested state: $identity_apply_user"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: FI identity UID/GID collides with another identity: $identity_apply_user"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe identity state: $identity_apply_user"
            ;;
        *)
            fail "invalid identity classification for $identity_apply_user: $identity_apply_state"
            ;;
    esac

    identity_create_account \
        "$identity_apply_root" \
        "$identity_apply_user" \
        "$identity_apply_group" \
        "$identity_apply_uid" \
        "$identity_apply_gid" ||
        fail "failed to create FI jail-local identity: $identity_apply_user"

    identity_apply_state=$(
        identity_classify_account \
            "$identity_apply_root" \
            "$identity_apply_user" \
            "$identity_apply_group" \
            "$identity_apply_uid" \
            "$identity_apply_gid"
    ) || fail "unable to verify newly-created FI identity: $identity_apply_user"

    [ "$identity_apply_state" = "OWNED_MATCH" ] ||
        fail "newly-created FI identity did not verify as OWNED_MATCH: $identity_apply_user"

    pass "created and verified FI identity: $identity_apply_user"
}

identity_apply_precheck()
{
    identity_precheck_name=$1
    identity_precheck_state=$2

    case "$identity_precheck_state" in
        ABSENT|OWNED_MATCH)
            return 0
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI identity differs from requested state: $identity_precheck_name"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: FI identity UID/GID collides with another identity: $identity_precheck_name"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe identity state: $identity_precheck_name"
            ;;
        *)
            fail "invalid identity classification for $identity_precheck_name: $identity_precheck_state"
            ;;
    esac
}

identity_classify_account()
{
    identity_classify_root=$1
    identity_classify_user=$2
    identity_classify_group=$3
    identity_classify_uid=$4
    identity_classify_gid=$5

    identity_classify_master="$identity_classify_root/etc/master.passwd"
    identity_classify_group_file="$identity_classify_root/etc/group"

    [ -f "$identity_classify_master" ] &&
        [ -r "$identity_classify_master" ] &&
        [ -f "$identity_classify_group_file" ] &&
        [ -r "$identity_classify_group_file" ] || {
            printf '%s\n' "UNKNOWN"
            return 0
        }

    identity_classify_user_name=$(
        identity_lookup_user_name \
            "$identity_classify_master" \
            "$identity_classify_user"
    )
    identity_classify_user_name_rc=$?

    identity_classify_user_uid=$(
        identity_lookup_user_uid \
            "$identity_classify_master" \
            "$identity_classify_uid"
    )
    identity_classify_user_uid_rc=$?

    identity_classify_group_name=$(
        identity_lookup_group_name \
            "$identity_classify_group_file" \
            "$identity_classify_group"
    )
    identity_classify_group_name_rc=$?

    identity_classify_group_gid=$(
        identity_lookup_group_gid \
            "$identity_classify_group_file" \
            "$identity_classify_gid"
    )
    identity_classify_group_gid_rc=$?

    for identity_classify_rc in \
        "$identity_classify_user_name_rc" \
        "$identity_classify_user_uid_rc" \
        "$identity_classify_group_name_rc" \
        "$identity_classify_group_gid_rc"
    do
        case "$identity_classify_rc" in
            0|1)
                ;;
            *)
                printf '%s\n' "UNKNOWN"
                return 0
                ;;
        esac
    done

    if [ "$identity_classify_user_uid_rc" -eq 0 ]; then
        identity_classify_found_user=$(
            identity_field "$identity_classify_user_uid" 1
        ) || {
            printf '%s\n' "UNKNOWN"
            return 0
        }

        if [ "$identity_classify_found_user" != "$identity_classify_user" ]; then
            printf '%s\n' "FOREIGN_COLLISION"
            return 0
        fi
    fi

    if [ "$identity_classify_group_gid_rc" -eq 0 ]; then
        identity_classify_found_group=$(
            identity_field "$identity_classify_group_gid" 1
        ) || {
            printf '%s\n' "UNKNOWN"
            return 0
        }

        if [ "$identity_classify_found_group" != "$identity_classify_group" ]; then
            printf '%s\n' "FOREIGN_COLLISION"
            return 0
        fi
    fi

    if \
        [ "$identity_classify_user_name_rc" -eq 1 ] &&
        [ "$identity_classify_group_name_rc" -eq 1 ]
    then
        if \
            [ "$identity_classify_user_uid_rc" -eq 1 ] &&
            [ "$identity_classify_group_gid_rc" -eq 1 ]
        then
            printf '%s\n' "ABSENT"
        else
            printf '%s\n' "FOREIGN_COLLISION"
        fi

        return 0
    fi

    if \
        [ "$identity_classify_user_name_rc" -ne 0 ] ||
        [ "$identity_classify_group_name_rc" -ne 0 ]
    then
        printf '%s\n' "OWNED_DRIFT"
        return 0
    fi

    identity_classify_password=$(
        identity_field "$identity_classify_user_name" 2
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    identity_classify_actual_uid=$(
        identity_field "$identity_classify_user_name" 3
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    identity_classify_actual_gid=$(
        identity_field "$identity_classify_user_name" 4
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    identity_classify_home=$(
        identity_field "$identity_classify_user_name" 9
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    identity_classify_shell=$(
        identity_field "$identity_classify_user_name" 10
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    identity_classify_actual_group_gid=$(
        identity_field "$identity_classify_group_name" 3
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    [ "$identity_classify_actual_uid" = "$identity_classify_uid" ] || {
        printf '%s\n' "OWNED_DRIFT"
        return 0
    }

    [ "$identity_classify_actual_gid" = "$identity_classify_gid" ] || {
        printf '%s\n' "OWNED_DRIFT"
        return 0
    }

    [ "$identity_classify_actual_group_gid" = "$identity_classify_gid" ] || {
        printf '%s\n' "OWNED_DRIFT"
        return 0
    }

    [ "$identity_classify_home" = "$FI_IDENTITY_HOME" ] || {
        printf '%s\n' "OWNED_DRIFT"
        return 0
    }

    [ "$identity_classify_shell" = "$FI_IDENTITY_SHELL" ] || {
        printf '%s\n' "OWNED_DRIFT"
        return 0
    }

    case "$identity_classify_password" in
        \**)
            ;;
        *)
            printf '%s\n' "OWNED_DRIFT"
            return 0
            ;;
    esac

    printf '%s\n' "OWNED_MATCH"
}

identity_create_account()
{
    identity_create_root=$1
    identity_create_user=$2
    identity_create_group=$3
    identity_create_uid=$4
    identity_create_gid=$5

    pw -R "$identity_create_root" \
        groupadd \
        -n "$identity_create_group" \
        -g "$identity_create_gid" ||
        return 1

    pw -R "$identity_create_root" \
        useradd \
        -n "$identity_create_user" \
        -u "$identity_create_uid" \
        -g "$identity_create_group" \
        -d "$FI_IDENTITY_HOME" \
        -s "$FI_IDENTITY_SHELL" \
        -w no ||
        return 1

    return 0
}

identity_field()
{
    identity_field_line=$1
    identity_field_number=$2

    printf '%s\n' "$identity_field_line" |
        awk -F: -v field="$identity_field_number" '
            NF >= field {
                print $field
                found = 1
            }

            END {
                if (!found) {
                    exit 1
                }
            }
        '
}

identity_lookup_group_gid()
{
    identity_lookup_file=$1
    identity_lookup_value=$2

    awk -F: -v value="$identity_lookup_value" '
        $3 == value {
            count++
            line = $0
        }

        END {
            if (count == 1) {
                print line
                exit 0
            }

            if (count == 0) {
                exit 1
            }

            exit 2
        }
    ' "$identity_lookup_file"
}

identity_lookup_group_name()
{
    identity_lookup_file=$1
    identity_lookup_value=$2

    awk -F: -v value="$identity_lookup_value" '
        $1 == value {
            count++
            line = $0
        }

        END {
            if (count == 1) {
                print line
                exit 0
            }

            if (count == 0) {
                exit 1
            }

            exit 2
        }
    ' "$identity_lookup_file"
}

identity_lookup_user_name()
{
    identity_lookup_file=$1
    identity_lookup_value=$2

    awk -F: -v value="$identity_lookup_value" '
        $1 == value {
            count++
            line = $0
        }

        END {
            if (count == 1) {
                print line
                exit 0
            }

            if (count == 0) {
                exit 1
            }

            exit 2
        }
    ' "$identity_lookup_file"
}

identity_lookup_user_uid()
{
    identity_lookup_file=$1
    identity_lookup_value=$2

    awk -F: -v value="$identity_lookup_value" '
        $3 == value {
            count++
            line = $0
        }

        END {
            if (count == 1) {
                print line
                exit 0
            }

            if (count == 0) {
                exit 1
            }

            exit 2
        }
    ' "$identity_lookup_file"
}

identity_require_commands()
{
    for identity_command in \
        awk \
        hostname \
        id \
        pw \
        uname
    do
        command -v "$identity_command" >/dev/null 2>&1 ||
            fail "required identity deployment command not found: $identity_command"
    done
}

identity_require_host()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "identity operation must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "identity operation requires FreeBSD"

    identity_expected_hostname=$(get_value FI_HOSTNAME)
    identity_actual_hostname=$(hostname)

    [ "$identity_actual_hostname" = "$identity_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $identity_expected_hostname, observed $identity_actual_hostname"

    pass "deployment hostname matches: $identity_actual_hostname"
}

identity_require_host_clear()
{
    identity_host_uid=$1
    identity_host_gid=$2

    [ -r /etc/master.passwd ] &&
        [ -r /etc/group ] ||
        fail "unable to inspect host identity databases"

    if awk -F: -v uid="$identity_host_uid" '
        $1 == "fi-receiver" ||
        $1 == "fi-ingest" ||
        $3 == uid {
            found = 1
        }

        END {
            exit found ? 0 : 1
        }
    ' /etc/master.passwd
    then
        fail "host FI runtime user name or configured UID is already in use"
    fi

    if awk -F: -v gid="$identity_host_gid" '
        $1 == "fi-receiver" ||
        $1 == "fi-ingest" ||
        $3 == gid {
            found = 1
        }

        END {
            exit found ? 0 : 1
        }
    ' /etc/group
    then
        fail "host FI runtime group name or configured GID is already in use"
    fi

    pass "host remains clear of FI runtime identities and configured UID/GID"
}

identity_require_prerequisites()
{
    identity_receiver_root=$1
    identity_ingest_root=$2

    for identity_root in \
        "$identity_receiver_root" \
        "$identity_ingest_root"
    do
        [ -d "$identity_root" ] ||
            fail "production jail root does not exist: $identity_root"

        [ -f "$identity_root/etc/master.passwd" ] ||
            fail "jail master.passwd does not exist: $identity_root/etc/master.passwd"

        [ -f "$identity_root/etc/group" ] ||
            fail "jail group database does not exist: $identity_root/etc/group"
    done
}
