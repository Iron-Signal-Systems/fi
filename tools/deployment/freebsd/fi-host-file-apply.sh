#!/bin/sh

# FI FreeBSD deterministic production host-file helper.
#
# This file is sourced by fi-bootstrap.sh. It intentionally performs no work
# merely by being sourced.

HOST_FILE_MARKER="# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1"
HOST_FILE_PLAN=""
HOST_FILE_PLAN_ROOT=""

host_file_apply_precheck()
{
    host_file_precheck_description=$1
    host_file_precheck_state=$2

    case "$host_file_precheck_state" in
        ABSENT|OWNED_MATCH)
            return 0
            ;;
        OWNED_DRIFT)
            fail "$host_file_precheck_description is FI-owned but has drifted"
            ;;
        FOREIGN_COLLISION)
            fail "$host_file_precheck_description collides with a non-FI resource"
            ;;
        UNKNOWN)
            fail "$host_file_precheck_description could not be classified safely"
            ;;
        *)
            fail "$host_file_precheck_description returned unexpected state: $host_file_precheck_state"
            ;;
    esac
}

host_file_classify()
{
    host_file_expected=$1
    host_file_target=$2
    host_file_expected_uid=$3
    host_file_expected_gid=$4
    host_file_expected_mode=$5

    [ -f "$host_file_expected" ] || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    grep -Fqx "$HOST_FILE_MARKER" "$host_file_expected" 2>/dev/null
    host_file_expected_marker_rc=$?

    case "$host_file_expected_marker_rc" in
        0)
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            return 0
            ;;
    esac

    if [ ! -e "$host_file_target" ] && [ ! -L "$host_file_target" ]; then
        printf '%s\n' "ABSENT"
        return 0
    fi

    if [ -L "$host_file_target" ] || [ ! -f "$host_file_target" ]; then
        printf '%s\n' "FOREIGN_COLLISION"
        return 0
    fi

    grep -Fqx "$HOST_FILE_MARKER" "$host_file_target" 2>/dev/null
    host_file_target_marker_rc=$?

    case "$host_file_target_marker_rc" in
        0)
            ;;
        1)
            printf '%s\n' "FOREIGN_COLLISION"
            return 0
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            return 0
            ;;
    esac

    host_file_actual_metadata=$(
        stat -f '%u:%g:%OMp:%#Lp:%l' "$host_file_target" 2>/dev/null
    ) || {
        printf '%s\n' "UNKNOWN"
        return 0
    }

    cmp -s "$host_file_expected" "$host_file_target"
    host_file_cmp_rc=$?

    case "$host_file_cmp_rc" in
        0)
            ;;
        1)
            printf '%s\n' "OWNED_DRIFT"
            return 0
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            return 0
            ;;
    esac

    host_file_expected_metadata="${host_file_expected_uid}:${host_file_expected_gid}:0:${host_file_expected_mode}:1"

    if [ "$host_file_actual_metadata" != "$host_file_expected_metadata" ]; then
        printf '%s\n' "OWNED_DRIFT"
        return 0
    fi

    printf '%s\n' "OWNED_MATCH"
}

host_file_cleanup_expected()
{
    if [ -n "$HOST_FILE_PLAN_ROOT" ] &&
        [ -d "$HOST_FILE_PLAN_ROOT" ]
    then
        rm -rf "$HOST_FILE_PLAN_ROOT" ||
            fail "unable to remove temporary host-file render workspace"
    fi

    HOST_FILE_PLAN=""
    HOST_FILE_PLAN_ROOT=""
}

host_file_install_absent()
{
    host_file_install_expected=$1
    host_file_install_target=$2
    host_file_install_uid=$3
    host_file_install_gid=$4
    host_file_install_mode=$5
    host_file_install_role=$6

    host_file_install_state=$(
        host_file_classify \
            "$host_file_install_expected" \
            "$host_file_install_target" \
            "$host_file_install_uid" \
            "$host_file_install_gid" \
            "$host_file_install_mode"
    ) || fail "unable to reclassify host file before creation: $host_file_install_role"

    [ "$host_file_install_state" = "ABSENT" ] ||
        fail \
            "host file changed before creation: $host_file_install_role ($host_file_install_state)"

    host_file_require_parent "$host_file_install_target"

    host_file_install_parent=${host_file_install_target%/*}
    host_file_install_name=${host_file_install_target##*/}

    host_file_install_temp=$(
        mktemp \
            "$host_file_install_parent/.${host_file_install_name}.fi.XXXXXX"
    ) || fail "unable to create temporary host file: $host_file_install_role"

    if ! cat "$host_file_install_expected" > "$host_file_install_temp"; then
        rm -f "$host_file_install_temp"
        fail "unable to populate temporary host file: $host_file_install_role"
    fi

    if ! chown \
        "${host_file_install_uid}:${host_file_install_gid}" \
        "$host_file_install_temp"
    then
        rm -f "$host_file_install_temp"
        fail "unable to set host-file ownership: $host_file_install_role"
    fi

    if ! chmod "$host_file_install_mode" "$host_file_install_temp"; then
        rm -f "$host_file_install_temp"
        fail "unable to set host-file mode: $host_file_install_role"
    fi

    host_file_install_temp_state=$(
        host_file_classify \
            "$host_file_install_expected" \
            "$host_file_install_temp" \
            "$host_file_install_uid" \
            "$host_file_install_gid" \
            "$host_file_install_mode"
    ) || {
        rm -f "$host_file_install_temp"
        fail "unable to verify temporary host file: $host_file_install_role"
    }

    [ "$host_file_install_temp_state" = "OWNED_MATCH" ] || {
        rm -f "$host_file_install_temp"
        fail \
            "temporary host file failed exact verification: $host_file_install_role ($host_file_install_temp_state)"
    }

    if ! ln "$host_file_install_temp" "$host_file_install_target"; then
        rm -f "$host_file_install_temp"
        fail \
            "unable to publish host file without overwrite: $host_file_install_role"
    fi

    rm -f "$host_file_install_temp" ||
        fail "unable to remove temporary publication link: $host_file_install_role"

    host_file_install_final_state=$(
        host_file_classify \
            "$host_file_install_expected" \
            "$host_file_install_target" \
            "$host_file_install_uid" \
            "$host_file_install_gid" \
            "$host_file_install_mode"
    ) || fail "unable to verify created host file: $host_file_install_role"

    [ "$host_file_install_final_state" = "OWNED_MATCH" ] ||
        fail \
            "created host file failed verification: $host_file_install_role ($host_file_install_final_state)"

    pass "created and verified FI host file: $host_file_install_target"
}

host_file_replace_owned()
{
    host_file_replace_expected=$1
    host_file_replace_target=$2
    host_file_replace_uid=$3
    host_file_replace_gid=$4
    host_file_replace_mode=$5
    host_file_replace_role=$6
    host_file_replace_prior_sha256=$7

    host_file_replace_state=$(
        host_file_classify \
            "$host_file_replace_expected" \
            "$host_file_replace_target" \
            "$host_file_replace_uid" \
            "$host_file_replace_gid" \
            "$host_file_replace_mode"
    ) || fail "unable to reclassify host file before update: $host_file_replace_role"

    [ "$host_file_replace_state" = "OWNED_DRIFT" ] ||
        fail \
            "host file changed before update: $host_file_replace_role ($host_file_replace_state)"

    host_file_replace_metadata=$(
        stat -f '%u:%g:%OMp:%#Lp:%l' \
            "$host_file_replace_target" 2>/dev/null
    ) || fail "unable to inspect update target metadata: $host_file_replace_role"

    host_file_replace_expected_metadata="${host_file_replace_uid}:${host_file_replace_gid}:0:${host_file_replace_mode}:1"

    [ "$host_file_replace_metadata" = "$host_file_replace_expected_metadata" ] ||
        fail \
            "host file has non-content drift and is not eligible for update: $host_file_replace_role"

    host_file_replace_current_sha256=$(
        sha256 -q "$host_file_replace_target"
    ) || fail "unable to hash current host file: $host_file_replace_role"

    [ "$host_file_replace_current_sha256" = "$host_file_replace_prior_sha256" ] ||
        fail \
            "host file does not match approved prior version: $host_file_replace_role"

    host_file_require_parent "$host_file_replace_target"

    host_file_replace_parent=${host_file_replace_target%/*}
    host_file_replace_name=${host_file_replace_target##*/}

    host_file_replace_temp=$(
        mktemp \
            "$host_file_replace_parent/.${host_file_replace_name}.fi-update.XXXXXX"
    ) || fail "unable to create update file: $host_file_replace_role"

    if ! cat "$host_file_replace_expected" > "$host_file_replace_temp"; then
        rm -f "$host_file_replace_temp"
        fail "unable to populate update file: $host_file_replace_role"
    fi

    if ! chown \
        "${host_file_replace_uid}:${host_file_replace_gid}" \
        "$host_file_replace_temp"
    then
        rm -f "$host_file_replace_temp"
        fail "unable to set update-file ownership: $host_file_replace_role"
    fi

    if ! chmod "$host_file_replace_mode" "$host_file_replace_temp"; then
        rm -f "$host_file_replace_temp"
        fail "unable to set update-file mode: $host_file_replace_role"
    fi

    host_file_replace_temp_state=$(
        host_file_classify \
            "$host_file_replace_expected" \
            "$host_file_replace_temp" \
            "$host_file_replace_uid" \
            "$host_file_replace_gid" \
            "$host_file_replace_mode"
    ) || {
        rm -f "$host_file_replace_temp"
        fail "unable to verify update file: $host_file_replace_role"
    }

    [ "$host_file_replace_temp_state" = "OWNED_MATCH" ] || {
        rm -f "$host_file_replace_temp"
        fail \
            "update file failed exact verification: $host_file_replace_role ($host_file_replace_temp_state)"
    }

    host_file_replace_state=$(
        host_file_classify \
            "$host_file_replace_expected" \
            "$host_file_replace_target" \
            "$host_file_replace_uid" \
            "$host_file_replace_gid" \
            "$host_file_replace_mode"
    ) || {
        rm -f "$host_file_replace_temp"
        fail "unable to reclassify destination before publication: $host_file_replace_role"
    }

    [ "$host_file_replace_state" = "OWNED_DRIFT" ] || {
        rm -f "$host_file_replace_temp"
        fail \
            "host file changed before publication: $host_file_replace_role ($host_file_replace_state)"
    }

    host_file_replace_metadata=$(
        stat -f '%u:%g:%OMp:%#Lp:%l' \
            "$host_file_replace_target" 2>/dev/null
    ) || {
        rm -f "$host_file_replace_temp"
        fail "unable to recheck update target metadata: $host_file_replace_role"
    }

    [ "$host_file_replace_metadata" = "$host_file_replace_expected_metadata" ] || {
        rm -f "$host_file_replace_temp"
        fail \
            "host file metadata changed before publication: $host_file_replace_role"
    }

    host_file_replace_current_sha256=$(
        sha256 -q "$host_file_replace_target"
    ) || {
        rm -f "$host_file_replace_temp"
        fail "unable to rehash update target: $host_file_replace_role"
    }

    [ "$host_file_replace_current_sha256" = "$host_file_replace_prior_sha256" ] || {
        rm -f "$host_file_replace_temp"
        fail \
            "host file contents changed before publication: $host_file_replace_role"
    }

    mv -f "$host_file_replace_temp" "$host_file_replace_target" ||
        fail "unable to publish updated host file: $host_file_replace_role"

    host_file_replace_final_state=$(
        host_file_classify \
            "$host_file_replace_expected" \
            "$host_file_replace_target" \
            "$host_file_replace_uid" \
            "$host_file_replace_gid" \
            "$host_file_replace_mode"
    ) || fail "unable to verify updated host file: $host_file_replace_role"

    [ "$host_file_replace_final_state" = "OWNED_MATCH" ] ||
        fail \
            "updated host file failed verification: $host_file_replace_role ($host_file_replace_final_state)"

    pass "updated and verified FI host file: $host_file_replace_target"
}

host_file_prepare_expected()
{
    HOST_FILE_PLAN_ROOT=$(
        mktemp -d "${TMPDIR:-/tmp}/fi-host-file-plan.XXXXXX"
    ) || fail "unable to create host-file render workspace"

    HOST_FILE_PLAN="$HOST_FILE_PLAN_ROOT/plan"

    host_file_saved_output_dir=$OUTPUT_DIR
    OUTPUT_DIR=$HOST_FILE_PLAN

    render_plan >/dev/null

    OUTPUT_DIR=$host_file_saved_output_dir
}

host_file_require_commands()
{
    for host_file_command in \
        cat \
        chmod \
        chown \
        cmp \
        grep \
        hostname \
        id \
        ln \
        mkdir \
        mktemp \
        mv \
        rm \
        sha256 \
        sort \
        stat \
        uname
    do
        command -v "$host_file_command" >/dev/null 2>&1 ||
            fail "required host-file deployment command not found: $host_file_command"
    done
}

host_file_require_host()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "host-file operation must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "host-file operation requires FreeBSD"

    host_file_expected_hostname=$(get_value FI_HOSTNAME)
    host_file_actual_hostname=$(hostname)

    [ "$host_file_actual_hostname" = "$host_file_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $host_file_expected_hostname, observed $host_file_actual_hostname"

    pass "deployment hostname matches: $host_file_actual_hostname"
}

host_file_require_parent()
{
    host_file_parent_target=$1
    host_file_parent=${host_file_parent_target%/*}

    [ -n "$host_file_parent" ] ||
        fail "host-file destination has no parent: $host_file_parent_target"

    [ ! -L "$host_file_parent" ] ||
        fail "host-file parent is a symbolic link: $host_file_parent"

    [ -d "$host_file_parent" ] ||
        fail "host-file parent directory is absent: $host_file_parent"
}

host_file_resource_map()
{
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "jail-config-receiver" \
        "$HOST_FILE_PLAN/fi-receiver.conf" \
        "/etc/jail.conf.d/fi-receiver.conf" \
        "0" "0" "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "jail-config-ingest" \
        "$HOST_FILE_PLAN/fi-ingest.conf" \
        "/etc/jail.conf.d/fi-ingest.conf" \
        "0" "0" "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "jail-config-sor-db" \
        "$HOST_FILE_PLAN/fi-sor-db.conf" \
        "/etc/jail.conf.d/fi-sor-db.conf" \
        "0" "0" "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fstab-receiver" \
        "$HOST_FILE_PLAN/fstab.fi-receiver" \
        "$(get_value FI_RECEIVER_FSTAB)" \
        "0" "0" "0600"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fstab-ingest" \
        "$HOST_FILE_PLAN/fstab.fi-ingest" \
        "$(get_value FI_INGEST_FSTAB)" \
        "0" "0" "0600"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "fstab-sor-db" \
        "$HOST_FILE_PLAN/fstab.fi-sor-db" \
        "$(get_value FI_SOR_DB_FSTAB)" \
        "0" "0" "0600"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "devfs-rules" \
        "$HOST_FILE_PLAN/devfs.rules.fi" \
        "/etc/devfs.rules.fi" \
        "0" "0" "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "vnet-helper" \
        "$HOST_FILE_PLAN/fi-vnet-pair" \
        "/usr/local/libexec/fi-vnet-pair" \
        "0" "0" "0555"
}

apply_host_files()
{
    host_file_require_host
    host_file_prepare_expected

    host_file_map="$HOST_FILE_PLAN_ROOT/resources"
    host_file_resource_map > "$host_file_map" ||
        fail "unable to build host-file resource map"

    host_file_tab=$(printf '\t')

    while IFS="$host_file_tab" read -r \
        host_file_role \
        host_file_expected \
        host_file_target \
        host_file_uid \
        host_file_gid \
        host_file_mode
    do
        host_file_initial_state=$(
            host_file_classify \
                "$host_file_expected" \
                "$host_file_target" \
                "$host_file_uid" \
                "$host_file_gid" \
                "$host_file_mode"
        ) || fail "unable to classify host file: $host_file_role"

        host_file_apply_precheck \
            "FI host file $host_file_role" \
            "$host_file_initial_state"
    done < "$host_file_map"

    while IFS="$host_file_tab" read -r \
        host_file_role \
        host_file_expected \
        host_file_target \
        host_file_uid \
        host_file_gid \
        host_file_mode
    do
        host_file_apply_state=$(
            host_file_classify \
                "$host_file_expected" \
                "$host_file_target" \
                "$host_file_uid" \
                "$host_file_gid" \
                "$host_file_mode"
        ) || fail "unable to reclassify host file: $host_file_role"

        case "$host_file_apply_state" in
            OWNED_MATCH)
                pass "FI host file already matches: $host_file_target"
                ;;
            ABSENT)
                host_file_install_absent \
                    "$host_file_expected" \
                    "$host_file_target" \
                    "$host_file_uid" \
                    "$host_file_gid" \
                    "$host_file_mode" \
                    "$host_file_role"
                ;;
            *)
                fail \
                    "FI host file changed after preclassification: $host_file_role ($host_file_apply_state)"
                ;;
        esac
    done < "$host_file_map"

    while IFS="$host_file_tab" read -r \
        host_file_role \
        host_file_expected \
        host_file_target \
        host_file_uid \
        host_file_gid \
        host_file_mode
    do
        host_file_final_state=$(
            host_file_classify \
                "$host_file_expected" \
                "$host_file_target" \
                "$host_file_uid" \
                "$host_file_gid" \
                "$host_file_mode"
        ) || fail "unable to verify host file: $host_file_role"

        [ "$host_file_final_state" = "OWNED_MATCH" ] ||
            fail \
                "FI host file failed final verification: $host_file_role ($host_file_final_state)"
    done < "$host_file_map"

    host_file_cleanup_expected

    pass "FI FreeBSD host-file apply acceptance complete"
}

update_host_files()
{
    host_file_prior_plan=$1

    host_file_require_host

    [ -n "$host_file_prior_plan" ] ||
        fail "approved prior host-file plan is required"

    [ -d "$host_file_prior_plan" ] ||
        fail "approved prior host-file plan is absent: $host_file_prior_plan"

    host_file_prepare_expected

    host_file_map="$HOST_FILE_PLAN_ROOT/resources"
    host_file_resource_map > "$host_file_map" ||
        fail "unable to build host-file resource map"

    host_file_tab=$(printf '\t')

    # Preclassify the complete layer before first mutation.
    while IFS="$host_file_tab" read -r \
        host_file_role \
        host_file_expected \
        host_file_target \
        host_file_uid \
        host_file_gid \
        host_file_mode
    do
        host_file_prior_expected="$host_file_prior_plan/${host_file_expected##*/}"

        [ -f "$host_file_prior_expected" ] ||
            fail \
                "approved prior host file is absent: $host_file_role ($host_file_prior_expected)"

        host_file_update_state=$(
            host_file_classify \
                "$host_file_expected" \
                "$host_file_target" \
                "$host_file_uid" \
                "$host_file_gid" \
                "$host_file_mode"
        ) || fail "unable to classify host file for update: $host_file_role"

        case "$host_file_update_state" in
            OWNED_MATCH)
                ;;
            OWNED_DRIFT)
                host_file_prior_state=$(
                    host_file_classify \
                        "$host_file_prior_expected" \
                        "$host_file_target" \
                        "$host_file_uid" \
                        "$host_file_gid" \
                        "$host_file_mode"
                ) || fail \
                    "unable to classify host file against approved prior version: $host_file_role"

                [ "$host_file_prior_state" = "OWNED_MATCH" ] ||
                    fail \
                        "host file does not match approved prior version: $host_file_role ($host_file_prior_state)"
                ;;
            ABSENT)
                fail \
                    "host file is absent and is not eligible for update: $host_file_role"
                ;;
            FOREIGN_COLLISION)
                fail \
                    "host file collides with a non-FI resource: $host_file_role"
                ;;
            UNKNOWN)
                fail \
                    "host file could not be classified safely: $host_file_role"
                ;;
            *)
                fail \
                    "unexpected host-file update state: $host_file_role ($host_file_update_state)"
                ;;
        esac
    done < "$host_file_map"

    # Update only files that exactly match the approved prior plan.
    while IFS="$host_file_tab" read -r \
        host_file_role \
        host_file_expected \
        host_file_target \
        host_file_uid \
        host_file_gid \
        host_file_mode
    do
        host_file_prior_expected="$host_file_prior_plan/${host_file_expected##*/}"

        host_file_update_state=$(
            host_file_classify \
                "$host_file_expected" \
                "$host_file_target" \
                "$host_file_uid" \
                "$host_file_gid" \
                "$host_file_mode"
        ) || fail "unable to reclassify host file for update: $host_file_role"

        case "$host_file_update_state" in
            OWNED_MATCH)
                pass "FI host file already matches new version: $host_file_target"
                ;;
            OWNED_DRIFT)
                host_file_prior_state=$(
                    host_file_classify \
                        "$host_file_prior_expected" \
                        "$host_file_target" \
                        "$host_file_uid" \
                        "$host_file_gid" \
                        "$host_file_mode"
                ) || fail \
                    "unable to reclassify approved prior version: $host_file_role"

                [ "$host_file_prior_state" = "OWNED_MATCH" ] ||
                    fail \
                        "host file changed after update preclassification: $host_file_role ($host_file_prior_state)"

                host_file_prior_sha256=$(
                    sha256 -q "$host_file_prior_expected"
                ) || fail \
                    "unable to hash approved prior host file: $host_file_role"

                host_file_replace_owned \
                    "$host_file_expected" \
                    "$host_file_target" \
                    "$host_file_uid" \
                    "$host_file_gid" \
                    "$host_file_mode" \
                    "$host_file_role" \
                    "$host_file_prior_sha256"
                ;;
            *)
                fail \
                    "host file changed after update preclassification: $host_file_role ($host_file_update_state)"
                ;;
        esac
    done < "$host_file_map"

    # Final exact-state verification.
    while IFS="$host_file_tab" read -r \
        host_file_role \
        host_file_expected \
        host_file_target \
        host_file_uid \
        host_file_gid \
        host_file_mode
    do
        host_file_final_state=$(
            host_file_classify \
                "$host_file_expected" \
                "$host_file_target" \
                "$host_file_uid" \
                "$host_file_gid" \
                "$host_file_mode"
        ) || fail "unable to verify updated host file: $host_file_role"

        [ "$host_file_final_state" = "OWNED_MATCH" ] ||
            fail \
                "updated host file failed final verification: $host_file_role ($host_file_final_state)"
    done < "$host_file_map"

    host_file_cleanup_expected

    pass "FI FreeBSD host-file update acceptance complete"
}

verify_host_files()
{
    host_file_require_host
    host_file_prepare_expected

    host_file_map="$HOST_FILE_PLAN_ROOT/resources"
    host_file_resource_map > "$host_file_map" ||
        fail "unable to build host-file resource map"

    host_file_tab=$(printf '\t')

    while IFS="$host_file_tab" read -r \
        host_file_role \
        host_file_expected \
        host_file_target \
        host_file_uid \
        host_file_gid \
        host_file_mode
    do
        host_file_verify_state=$(
            host_file_classify \
                "$host_file_expected" \
                "$host_file_target" \
                "$host_file_uid" \
                "$host_file_gid" \
                "$host_file_mode"
        ) || fail "unable to classify host file: $host_file_role"

        [ "$host_file_verify_state" = "OWNED_MATCH" ] ||
            fail \
                "FI host file is not OWNED_MATCH: $host_file_role ($host_file_verify_state)"
    done < "$host_file_map"

    host_file_cleanup_expected

    pass "FI FreeBSD host-file verification acceptance complete"
}
