#!/bin/sh

# FI FreeBSD production lifecycle-file apply helper.
#
# This file is sourced by fi-bootstrap.sh. Sourcing it performs no mutation.

LIFECYCLE_FILE_MARKER="# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1"
LIFECYCLE_PLAN=""
LIFECYCLE_PLAN_ROOT=""

lifecycle_apply_precheck()
{
    lifecycle_precheck_description=$1
    lifecycle_precheck_state=$2

    case "$lifecycle_precheck_state" in
        ABSENT|OWNED_MATCH|DIRECTORY_MATCH)
            return 0
            ;;
        OWNED_DRIFT)
            fail "$lifecycle_precheck_description is FI-owned but has drifted"
            ;;
        FOREIGN_COLLISION)
            fail "$lifecycle_precheck_description collides with non-FI state"
            ;;
        UNKNOWN)
            fail "$lifecycle_precheck_description could not be classified safely"
            ;;
        *)
            fail "$lifecycle_precheck_description returned unexpected state: $lifecycle_precheck_state"
            ;;
    esac
}

lifecycle_cleanup_expected()
{
    host_file_cleanup_expected
    LIFECYCLE_PLAN=""
    LIFECYCLE_PLAN_ROOT=""
}

lifecycle_global_jail_policy_precheck()
{
    lifecycle_jail_enable=$(
        sysrc -n jail_enable 2>/dev/null
    ) || fail "unable to inspect global jail_enable policy"

    lifecycle_jail_list=$(
        sysrc -n jail_list 2>/dev/null
    ) || fail "unable to inspect global jail_list policy"

    lifecycle_jail_enable_normalized=$(
        printf '%s\n' "$lifecycle_jail_enable" |
            tr '[:lower:]' '[:upper:]'
    )

    case "$lifecycle_jail_enable_normalized" in
        NO|FALSE|OFF|0)
            pass "global FreeBSD jail autostart is disabled"
            return 0
            ;;
        YES|TRUE|ON|1)
            ;;
        *)
            fail "global jail_enable has unrecognized value: $lifecycle_jail_enable"
            ;;
    esac

    [ -n "$lifecycle_jail_list" ] ||
        fail "enabled global jail policy selects _ALL and would claim FI production jails"

    case " $lifecycle_jail_list " in
        *" _ALL "*)
            fail "enabled global jail policy explicitly selects _ALL"
            ;;
    esac

    for lifecycle_fi_jail in \
        fi-sor-db \
        fi-ingest \
        fi-receiver
    do
        case " $lifecycle_jail_list " in
            *" $lifecycle_fi_jail "*)
                fail "enabled global jail policy already claims FI production jail: $lifecycle_fi_jail"
                ;;
        esac
    done

    pass "enabled global jail policy does not claim FI production jails"
}

lifecycle_parent_classify()
{
    lifecycle_parent_target=$1
    lifecycle_parent_uid=$2
    lifecycle_parent_gid=$3
    lifecycle_parent_mode=$4

    if [ ! -e "$lifecycle_parent_target" ] &&
        [ ! -L "$lifecycle_parent_target" ]
    then
        printf '%s\n' "ABSENT"
        return 0
    fi

    if [ -L "$lifecycle_parent_target" ] ||
        [ ! -d "$lifecycle_parent_target" ]
    then
        printf '%s\n' "FOREIGN_COLLISION"
        return 0
    fi

    lifecycle_parent_metadata=$(
        stat -f '%u:%g:%#Lp' "$lifecycle_parent_target" 2>/dev/null
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    lifecycle_parent_expected="${lifecycle_parent_uid}:${lifecycle_parent_gid}:${lifecycle_parent_mode}"

    if [ "$lifecycle_parent_metadata" = "$lifecycle_parent_expected" ]; then
        printf '%s\n' "DIRECTORY_MATCH"
    else
        printf '%s\n' "FOREIGN_COLLISION"
    fi
}

lifecycle_parent_install_absent()
{
    lifecycle_parent_target=$1
    lifecycle_parent_uid=$2
    lifecycle_parent_gid=$3
    lifecycle_parent_mode=$4
    lifecycle_parent_role=$5

    lifecycle_parent_state=$(
        lifecycle_parent_classify \
            "$lifecycle_parent_target" \
            "$lifecycle_parent_uid" \
            "$lifecycle_parent_gid" \
            "$lifecycle_parent_mode"
    ) || fail "unable to reclassify lifecycle parent: $lifecycle_parent_role"

    [ "$lifecycle_parent_state" = "ABSENT" ] ||
        fail "lifecycle parent changed before creation: $lifecycle_parent_role ($lifecycle_parent_state)"

    lifecycle_parent_parent=${lifecycle_parent_target%/*}

    [ -d "$lifecycle_parent_parent" ] &&
    [ ! -L "$lifecycle_parent_parent" ] ||
        fail "lifecycle parent container is unavailable: $lifecycle_parent_parent"

    mkdir "$lifecycle_parent_target" ||
        fail "unable to create lifecycle parent directory: $lifecycle_parent_role"

    chown \
        "${lifecycle_parent_uid}:${lifecycle_parent_gid}" \
        "$lifecycle_parent_target" ||
        fail "unable to set lifecycle parent ownership: $lifecycle_parent_role"

    chmod "$lifecycle_parent_mode" "$lifecycle_parent_target" ||
        fail "unable to set lifecycle parent mode: $lifecycle_parent_role"

    lifecycle_parent_final_state=$(
        lifecycle_parent_classify \
            "$lifecycle_parent_target" \
            "$lifecycle_parent_uid" \
            "$lifecycle_parent_gid" \
            "$lifecycle_parent_mode"
    ) || fail "unable to verify lifecycle parent: $lifecycle_parent_role"

    [ "$lifecycle_parent_final_state" = "DIRECTORY_MATCH" ] ||
        fail "created lifecycle parent failed verification: $lifecycle_parent_role ($lifecycle_parent_final_state)"

    pass "created and verified lifecycle parent: $lifecycle_parent_target"
}

lifecycle_parent_map()
{
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "local-rc-directory" \
        "/usr/local/etc/rc.d" \
        "0" "0" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "rc-conf-directory" \
        "/etc/rc.conf.d" \
        "0" "0" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "devfs-rc-conf-directory" \
        "/etc/rc.conf.d/devfs" \
        "0" "0" "0755"
}

lifecycle_prepare_expected()
{
    lifecycle_use_marker

    host_file_prepare_expected

    LIFECYCLE_PLAN_ROOT=$HOST_FILE_PLAN_ROOT
    LIFECYCLE_PLAN=$HOST_FILE_PLAN
}

lifecycle_require_commands()
{
    host_file_require_commands

    for lifecycle_command in \
        sysrc \
        tr
    do
        command -v "$lifecycle_command" >/dev/null 2>&1 ||
            fail "required lifecycle deployment command not found: $lifecycle_command"
    done
}

lifecycle_require_host()
{
    host_file_require_host
}

lifecycle_resource_map()
{
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fi-pf-controller" \
        "$LIFECYCLE_PLAN/rc.d.fi_pf" \
        "/usr/local/etc/rc.d/fi_pf" \
        "0" "0" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fi-jails-controller" \
        "$LIFECYCLE_PLAN/rc.d.fi_jails" \
        "/usr/local/etc/rc.d/fi_jails" \
        "0" "0" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fi-pf-enable-policy" \
        "$LIFECYCLE_PLAN/rc.conf.d.fi_pf" \
        "/etc/rc.conf.d/fi_pf" \
        "0" "0" "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fi-jails-enable-policy" \
        "$LIFECYCLE_PLAN/rc.conf.d.fi_jails" \
        "/etc/rc.conf.d/fi_jails" \
        "0" "0" "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "devfs-boot-policy" \
        "$LIFECYCLE_PLAN/rc.conf.d.devfs.90-fi" \
        "/etc/rc.conf.d/devfs/90-fi" \
        "0" "0" "0644"
}

lifecycle_use_marker()
{
    HOST_FILE_MARKER=$LIFECYCLE_FILE_MARKER
}

apply_lifecycle()
{
    lifecycle_require_host
    lifecycle_global_jail_policy_precheck
    lifecycle_prepare_expected

    lifecycle_parent_map_file="$LIFECYCLE_PLAN_ROOT/parents"
    lifecycle_resource_map_file="$LIFECYCLE_PLAN_ROOT/resources"

    lifecycle_parent_map > "$lifecycle_parent_map_file" ||
        fail "unable to build lifecycle parent map"

    lifecycle_resource_map > "$lifecycle_resource_map_file" ||
        fail "unable to build lifecycle resource map"

    lifecycle_tab=$(printf '\t')

    while IFS="$lifecycle_tab" read -r \
        lifecycle_parent_role \
        lifecycle_parent_target \
        lifecycle_parent_uid \
        lifecycle_parent_gid \
        lifecycle_parent_mode
    do
        lifecycle_parent_initial_state=$(
            lifecycle_parent_classify \
                "$lifecycle_parent_target" \
                "$lifecycle_parent_uid" \
                "$lifecycle_parent_gid" \
                "$lifecycle_parent_mode"
        ) || fail "unable to classify lifecycle parent: $lifecycle_parent_role"

        lifecycle_apply_precheck \
            "lifecycle parent $lifecycle_parent_role" \
            "$lifecycle_parent_initial_state"
    done < "$lifecycle_parent_map_file"

    while IFS="$lifecycle_tab" read -r \
        lifecycle_role \
        lifecycle_expected \
        lifecycle_target \
        lifecycle_uid \
        lifecycle_gid \
        lifecycle_mode
    do
        lifecycle_initial_state=$(
            host_file_classify \
                "$lifecycle_expected" \
                "$lifecycle_target" \
                "$lifecycle_uid" \
                "$lifecycle_gid" \
                "$lifecycle_mode"
        ) || fail "unable to classify lifecycle file: $lifecycle_role"

        lifecycle_apply_precheck \
            "lifecycle file $lifecycle_role" \
            "$lifecycle_initial_state"
    done < "$lifecycle_resource_map_file"

    while IFS="$lifecycle_tab" read -r \
        lifecycle_parent_role \
        lifecycle_parent_target \
        lifecycle_parent_uid \
        lifecycle_parent_gid \
        lifecycle_parent_mode
    do
        lifecycle_parent_apply_state=$(
            lifecycle_parent_classify \
                "$lifecycle_parent_target" \
                "$lifecycle_parent_uid" \
                "$lifecycle_parent_gid" \
                "$lifecycle_parent_mode"
        ) || fail "unable to reclassify lifecycle parent: $lifecycle_parent_role"

        case "$lifecycle_parent_apply_state" in
            DIRECTORY_MATCH)
                pass "lifecycle parent already matches: $lifecycle_parent_target"
                ;;
            ABSENT)
                lifecycle_parent_install_absent \
                    "$lifecycle_parent_target" \
                    "$lifecycle_parent_uid" \
                    "$lifecycle_parent_gid" \
                    "$lifecycle_parent_mode" \
                    "$lifecycle_parent_role"
                ;;
            *)
                fail "lifecycle parent changed after preclassification: $lifecycle_parent_role ($lifecycle_parent_apply_state)"
                ;;
        esac
    done < "$lifecycle_parent_map_file"

    while IFS="$lifecycle_tab" read -r \
        lifecycle_role \
        lifecycle_expected \
        lifecycle_target \
        lifecycle_uid \
        lifecycle_gid \
        lifecycle_mode
    do
        lifecycle_apply_state=$(
            host_file_classify \
                "$lifecycle_expected" \
                "$lifecycle_target" \
                "$lifecycle_uid" \
                "$lifecycle_gid" \
                "$lifecycle_mode"
        ) || fail "unable to reclassify lifecycle file: $lifecycle_role"

        case "$lifecycle_apply_state" in
            OWNED_MATCH)
                pass "lifecycle file already matches: $lifecycle_target"
                ;;
            ABSENT)
                host_file_install_absent \
                    "$lifecycle_expected" \
                    "$lifecycle_target" \
                    "$lifecycle_uid" \
                    "$lifecycle_gid" \
                    "$lifecycle_mode" \
                    "$lifecycle_role"
                ;;
            *)
                fail "lifecycle file changed after preclassification: $lifecycle_role ($lifecycle_apply_state)"
                ;;
        esac
    done < "$lifecycle_resource_map_file"

    verify_lifecycle_internal

    lifecycle_cleanup_expected

    pass "FI FreeBSD lifecycle apply acceptance complete"
}

update_lifecycle()
{
    lifecycle_prior_plan=$1

    lifecycle_require_host
    lifecycle_global_jail_policy_precheck

    [ -n "$lifecycle_prior_plan" ] ||
        fail "approved prior lifecycle plan is required"

    [ -d "$lifecycle_prior_plan" ] &&
    [ ! -L "$lifecycle_prior_plan" ] ||
        fail "approved prior lifecycle plan is unavailable: $lifecycle_prior_plan"

    lifecycle_prepare_expected

    lifecycle_parent_map_file="$LIFECYCLE_PLAN_ROOT/parents"
    lifecycle_resource_map_file="$LIFECYCLE_PLAN_ROOT/resources"

    lifecycle_parent_map > "$lifecycle_parent_map_file" ||
        fail "unable to build lifecycle parent map"

    lifecycle_resource_map > "$lifecycle_resource_map_file" ||
        fail "unable to build lifecycle resource map"

    lifecycle_tab=$(printf '\t')

    # Existing lifecycle parent directories are authority for an update.
    # update-lifecycle never creates or repairs parent directories.
    while IFS="$lifecycle_tab" read -r \
        lifecycle_parent_role \
        lifecycle_parent_target \
        lifecycle_parent_uid \
        lifecycle_parent_gid \
        lifecycle_parent_mode
    do
        lifecycle_parent_state=$(
            lifecycle_parent_classify \
                "$lifecycle_parent_target" \
                "$lifecycle_parent_uid" \
                "$lifecycle_parent_gid" \
                "$lifecycle_parent_mode"
        ) || fail \
            "unable to classify lifecycle update parent: $lifecycle_parent_role"

        [ "$lifecycle_parent_state" = "DIRECTORY_MATCH" ] ||
            fail \
                "lifecycle update parent is not exact: $lifecycle_parent_role ($lifecycle_parent_state)"
    done < "$lifecycle_parent_map_file"

    # --------------------------------------------------------
    # Complete-layer preclassification before first mutation.
    # --------------------------------------------------------

    while IFS="$lifecycle_tab" read -r \
        lifecycle_role \
        lifecycle_expected \
        lifecycle_target \
        lifecycle_uid \
        lifecycle_gid \
        lifecycle_mode
    do
        lifecycle_prior_expected="$lifecycle_prior_plan/${lifecycle_expected##*/}"

        if [ -e "$lifecycle_prior_expected" ] ||
            [ -L "$lifecycle_prior_expected" ]
        then
            [ -f "$lifecycle_prior_expected" ] &&
            [ ! -L "$lifecycle_prior_expected" ] ||
                fail \
                    "approved prior lifecycle resource is not a regular file: $lifecycle_role"

            lifecycle_prior_present=1
        else
            lifecycle_prior_present=0
        fi

        lifecycle_update_state=$(
            host_file_classify \
                "$lifecycle_expected" \
                "$lifecycle_target" \
                "$lifecycle_uid" \
                "$lifecycle_gid" \
                "$lifecycle_mode"
        ) || fail \
            "unable to classify lifecycle resource for update: $lifecycle_role"

        case "$lifecycle_update_state" in
            OWNED_MATCH)
                # Already at the new reviewed version.
                ;;

            OWNED_DRIFT)
                [ "$lifecycle_prior_present" -eq 1 ] ||
                    fail \
                        "lifecycle resource exists but has no approved prior version: $lifecycle_role"

                lifecycle_prior_state=$(
                    host_file_classify \
                        "$lifecycle_prior_expected" \
                        "$lifecycle_target" \
                        "$lifecycle_uid" \
                        "$lifecycle_gid" \
                        "$lifecycle_mode"
                ) || fail \
                    "unable to classify lifecycle resource against approved prior: $lifecycle_role"

                [ "$lifecycle_prior_state" = "OWNED_MATCH" ] ||
                    fail \
                        "lifecycle resource does not match approved prior version: $lifecycle_role ($lifecycle_prior_state)"
                ;;

            ABSENT)
                [ "$lifecycle_prior_present" -eq 0 ] ||
                    fail \
                        "approved prior lifecycle resource is unexpectedly absent live: $lifecycle_role"
                ;;

            FOREIGN_COLLISION)
                fail \
                    "lifecycle update collides with non-FI state: $lifecycle_role"
                ;;

            UNKNOWN)
                fail \
                    "lifecycle update resource could not be classified safely: $lifecycle_role"
                ;;

            *)
                fail \
                    "unexpected lifecycle update state: $lifecycle_role ($lifecycle_update_state)"
                ;;
        esac
    done < "$lifecycle_resource_map_file"

    # --------------------------------------------------------
    # Mutation pass. Every resource has already been accepted.
    # --------------------------------------------------------

    lifecycle_use_marker

    while IFS="$lifecycle_tab" read -r \
        lifecycle_role \
        lifecycle_expected \
        lifecycle_target \
        lifecycle_uid \
        lifecycle_gid \
        lifecycle_mode
    do
        lifecycle_prior_expected="$lifecycle_prior_plan/${lifecycle_expected##*/}"

        if [ -e "$lifecycle_prior_expected" ] ||
            [ -L "$lifecycle_prior_expected" ]
        then
            [ -f "$lifecycle_prior_expected" ] &&
            [ ! -L "$lifecycle_prior_expected" ] ||
                fail \
                    "approved prior lifecycle resource changed type: $lifecycle_role"

            lifecycle_prior_present=1
        else
            lifecycle_prior_present=0
        fi

        lifecycle_update_state=$(
            host_file_classify \
                "$lifecycle_expected" \
                "$lifecycle_target" \
                "$lifecycle_uid" \
                "$lifecycle_gid" \
                "$lifecycle_mode"
        ) || fail \
            "unable to reclassify lifecycle resource for update: $lifecycle_role"

        case "$lifecycle_update_state" in
            OWNED_MATCH)
                pass \
                    "lifecycle resource already matches new version: $lifecycle_target"
                ;;

            OWNED_DRIFT)
                [ "$lifecycle_prior_present" -eq 1 ] ||
                    fail \
                        "lifecycle resource lost approved prior authority: $lifecycle_role"

                lifecycle_prior_state=$(
                    host_file_classify \
                        "$lifecycle_prior_expected" \
                        "$lifecycle_target" \
                        "$lifecycle_uid" \
                        "$lifecycle_gid" \
                        "$lifecycle_mode"
                ) || fail \
                    "unable to reclassify approved prior lifecycle resource: $lifecycle_role"

                [ "$lifecycle_prior_state" = "OWNED_MATCH" ] ||
                    fail \
                        "lifecycle resource changed after update preclassification: $lifecycle_role ($lifecycle_prior_state)"

                lifecycle_prior_sha256=$(
                    sha256 -q "$lifecycle_prior_expected"
                ) || fail \
                    "unable to hash approved prior lifecycle resource: $lifecycle_role"

                host_file_replace_owned \
                    "$lifecycle_expected" \
                    "$lifecycle_target" \
                    "$lifecycle_uid" \
                    "$lifecycle_gid" \
                    "$lifecycle_mode" \
                    "$lifecycle_role" \
                    "$lifecycle_prior_sha256"
                ;;

            ABSENT)
                [ "$lifecycle_prior_present" -eq 0 ] ||
                    fail \
                        "old lifecycle resource disappeared after preclassification: $lifecycle_role"

                host_file_install_absent \
                    "$lifecycle_expected" \
                    "$lifecycle_target" \
                    "$lifecycle_uid" \
                    "$lifecycle_gid" \
                    "$lifecycle_mode" \
                    "$lifecycle_role"
                ;;

            *)
                fail \
                    "lifecycle resource changed after update preclassification: $lifecycle_role ($lifecycle_update_state)"
                ;;
        esac
    done < "$lifecycle_resource_map_file"

    verify_lifecycle_internal

    lifecycle_cleanup_expected

    pass "FI FreeBSD lifecycle update acceptance complete"
}

verify_lifecycle_internal()
{
    lifecycle_tab=$(printf '\t')

    while IFS="$lifecycle_tab" read -r \
        lifecycle_parent_role \
        lifecycle_parent_target \
        lifecycle_parent_uid \
        lifecycle_parent_gid \
        lifecycle_parent_mode
    do
        lifecycle_parent_verify_state=$(
            lifecycle_parent_classify \
                "$lifecycle_parent_target" \
                "$lifecycle_parent_uid" \
                "$lifecycle_parent_gid" \
                "$lifecycle_parent_mode"
        ) || fail "unable to verify lifecycle parent: $lifecycle_parent_role"

        [ "$lifecycle_parent_verify_state" = "DIRECTORY_MATCH" ] ||
            fail "lifecycle parent is not DIRECTORY_MATCH: $lifecycle_parent_role ($lifecycle_parent_verify_state)"
    done < "$lifecycle_parent_map_file"

    while IFS="$lifecycle_tab" read -r \
        lifecycle_role \
        lifecycle_expected \
        lifecycle_target \
        lifecycle_uid \
        lifecycle_gid \
        lifecycle_mode
    do
        lifecycle_verify_state=$(
            host_file_classify \
                "$lifecycle_expected" \
                "$lifecycle_target" \
                "$lifecycle_uid" \
                "$lifecycle_gid" \
                "$lifecycle_mode"
        ) || fail "unable to verify lifecycle file: $lifecycle_role"

        [ "$lifecycle_verify_state" = "OWNED_MATCH" ] ||
            fail "lifecycle file is not OWNED_MATCH: $lifecycle_role ($lifecycle_verify_state)"
    done < "$lifecycle_resource_map_file"
}

verify_lifecycle()
{
    lifecycle_require_host
    lifecycle_global_jail_policy_precheck
    lifecycle_prepare_expected

    lifecycle_parent_map_file="$LIFECYCLE_PLAN_ROOT/parents"
    lifecycle_resource_map_file="$LIFECYCLE_PLAN_ROOT/resources"

    lifecycle_parent_map > "$lifecycle_parent_map_file" ||
        fail "unable to build lifecycle parent map"

    lifecycle_resource_map > "$lifecycle_resource_map_file" ||
        fail "unable to build lifecycle resource map"

    verify_lifecycle_internal

    lifecycle_cleanup_expected

    pass "FI FreeBSD lifecycle verification acceptance complete"
}
