#!/bin/sh

# FI FreeBSD production devfs ruleset helper.
#
# This file is sourced by fi-bootstrap.sh. It intentionally performs no work
# merely by being sourced.

devfs_apply_precheck()
{
    devfs_precheck_description=$1
    devfs_precheck_state=$2

    case "$devfs_precheck_state" in
        ABSENT|OWNED_MATCH)
            return 0
            ;;
        FOREIGN_COLLISION)
            fail "$devfs_precheck_description collides with an existing non-FI ruleset"
            ;;
        UNKNOWN)
            fail "$devfs_precheck_description could not be classified safely"
            ;;
        *)
            fail "$devfs_precheck_description returned unexpected state: $devfs_precheck_state"
            ;;
    esac
}

devfs_classify_ruleset()
{
    devfs_classify_ruleset_number=$1

    devfs_classify_sets=$(devfs rule showsets 2>/dev/null)
    devfs_classify_sets_rc=$?

    if [ "$devfs_classify_sets_rc" -ne 0 ]; then
        printf '%s\n' "UNKNOWN"
        return 0
    fi

    if ! printf '%s\n' "$devfs_classify_sets" |
        awk -v wanted="$devfs_classify_ruleset_number" '
            {
                for (i = 1; i <= NF; i++) {
                    if ($i == wanted) {
                        found = 1
                    }
                }
            }

            END {
                exit found ? 0 : 1
            }
        '
    then
        printf '%s\n' "ABSENT"
        return 0
    fi

    devfs_classify_raw=$(devfs rule -s "$devfs_classify_ruleset_number" show 2>/dev/null)
    devfs_classify_show_rc=$?

    if [ "$devfs_classify_show_rc" -ne 0 ]; then
        printf '%s\n' "UNKNOWN"
        return 0
    fi

    devfs_classify_actual=$(
        printf '%s\n' "$devfs_classify_raw" |
            devfs_normalize_rules
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    devfs_classify_expected=$(devfs_expected_rules) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    if [ "$devfs_classify_actual" = "$devfs_classify_expected" ]; then
        printf '%s\n' "OWNED_MATCH"
    else
        printf '%s\n' "FOREIGN_COLLISION"
    fi
}

devfs_create_ruleset()
{
    devfs_create_ruleset_number=$1

    devfs rule -s "$devfs_create_ruleset_number" add 100 hide ||
        fail "unable to add FI devfs hide-all rule"

    devfs rule -s "$devfs_create_ruleset_number" add 200 path null unhide ||
        fail "unable to add FI devfs null rule"

    devfs rule -s "$devfs_create_ruleset_number" add 300 path zero unhide ||
        fail "unable to add FI devfs zero rule"

    devfs rule -s "$devfs_create_ruleset_number" add 400 path random unhide ||
        fail "unable to add FI devfs random rule"

    devfs rule -s "$devfs_create_ruleset_number" add 500 path urandom unhide ||
        fail "unable to add FI devfs urandom rule"
}

devfs_expected_rules()
{
    printf '%s\n' \
        "hide" \
        "path null unhide" \
        "path zero unhide" \
        "path random unhide" \
        "path urandom unhide"
}

devfs_normalize_rules()
{
    awk '
        NF == 0 {
            next
        }

        {
            start = 1

            if ($1 ~ /^[0-9]+$/) {
                start = 2
            }

            if (start > NF) {
                next
            }

            normalized = $start

            for (i = start + 1; i <= NF; i++) {
                normalized = normalized " " $i
            }

            print normalized
        }
    '
}

devfs_require_commands()
{
    for devfs_command in \
        awk \
        devfs \
        hostname \
        id \
        uname
    do
        command -v "$devfs_command" >/dev/null 2>&1 ||
            fail "required devfs deployment command not found: $devfs_command"
    done
}

devfs_require_host()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "devfs operation must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "devfs operation requires FreeBSD"

    devfs_expected_hostname=$(get_value FI_HOSTNAME)
    devfs_actual_hostname=$(hostname)

    [ "$devfs_actual_hostname" = "$devfs_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $devfs_expected_hostname, observed $devfs_actual_hostname"

    pass "deployment hostname matches: $devfs_actual_hostname"
}

apply_devfs()
{
    devfs_require_host

    devfs_ruleset_number=$(get_value FI_DEVFS_RULESET)

    devfs_initial_state=$(
        devfs_classify_ruleset "$devfs_ruleset_number"
    ) || fail "unable to classify FI production devfs ruleset"

    devfs_apply_precheck \
        "FI production devfs ruleset $devfs_ruleset_number" \
        "$devfs_initial_state"

    case "$devfs_initial_state" in
        OWNED_MATCH)
            pass "FI production devfs ruleset already matches: $devfs_ruleset_number"
            return 0
            ;;
        ABSENT)
            ;;
        *)
            fail "unexpected FI production devfs state: $devfs_initial_state"
            ;;
    esac

    devfs_recheck_state=$(
        devfs_classify_ruleset "$devfs_ruleset_number"
    ) || fail "unable to reclassify FI production devfs ruleset"

    [ "$devfs_recheck_state" = "ABSENT" ] ||
        fail \
            "FI production devfs ruleset changed before creation: $devfs_ruleset_number ($devfs_recheck_state)"

    devfs_create_ruleset "$devfs_ruleset_number"

    devfs_final_state=$(
        devfs_classify_ruleset "$devfs_ruleset_number"
    ) || fail "unable to verify FI production devfs ruleset after creation"

    [ "$devfs_final_state" = "OWNED_MATCH" ] ||
        fail \
            "FI production devfs ruleset failed post-create verification: $devfs_ruleset_number ($devfs_final_state)"

    pass "created and verified FI production devfs ruleset: $devfs_ruleset_number"
}

verify_devfs()
{
    devfs_require_host

    devfs_ruleset_number=$(get_value FI_DEVFS_RULESET)

    devfs_verify_state=$(
        devfs_classify_ruleset "$devfs_ruleset_number"
    ) || fail "unable to classify FI production devfs ruleset"

    [ "$devfs_verify_state" = "OWNED_MATCH" ] ||
        fail \
            "FI production devfs ruleset is not OWNED_MATCH: $devfs_ruleset_number ($devfs_verify_state)"

    pass "verified FI production devfs ruleset: $devfs_ruleset_number"
}
