#!/bin/sh

# FI FreeBSD application-runtime service-file apply helper.
#
# This file is sourced by fi-bootstrap.sh. Sourcing performs no mutation.
#
# Scope:
#   - exact application-jail service parent directories
#   - receiver supervisor + rc.d + rc.conf.d
#   - ingest runner + rc.d + rc.conf.d
#
# Explicitly outside this layer:
#   - FI binaries
#   - PKI/trust material
#   - PostgreSQL credentials
#   - service start/stop state

RUNTIME_FILE_MARKER="# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1"
RUNTIME_PLAN=""
RUNTIME_PLAN_ROOT=""
RUNTIME_SAVED_HOST_FILE_MARKER=""

runtime_cleanup_expected()
{
    host_file_cleanup_expected

    if [ -n "$RUNTIME_SAVED_HOST_FILE_MARKER" ]; then
        HOST_FILE_MARKER=$RUNTIME_SAVED_HOST_FILE_MARKER
    fi

    RUNTIME_PLAN=""
    RUNTIME_PLAN_ROOT=""
    RUNTIME_SAVED_HOST_FILE_MARKER=""
}

runtime_prepare_expected()
{
    RUNTIME_SAVED_HOST_FILE_MARKER=$HOST_FILE_MARKER
    HOST_FILE_MARKER=$RUNTIME_FILE_MARKER

    host_file_prepare_expected

    RUNTIME_PLAN_ROOT=$HOST_FILE_PLAN_ROOT
    RUNTIME_PLAN=$HOST_FILE_PLAN
}

runtime_require_commands()
{
    host_file_require_commands

    for runtime_command in \
        chmod \
        chown \
        mkdir \
        stat
    do
        command -v "$runtime_command" >/dev/null 2>&1 ||
            fail "required runtime deployment command not found: $runtime_command"
    done
}

runtime_require_host()
{
    host_file_require_host
}

runtime_parent_map()
{
    receiver_root=$(get_value FI_RECEIVER_ROOT)
    ingest_root=$(get_value FI_INGEST_ROOT)

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "receiver-local-libexec" \
        "$receiver_root/usr/local/libexec" \
        "0" "0" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "receiver-local-rc-directory" \
        "$receiver_root/usr/local/etc/rc.d" \
        "0" "0" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "receiver-rc-conf-directory" \
        "$receiver_root/etc/rc.conf.d" \
        "0" "0" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "ingest-local-libexec" \
        "$ingest_root/usr/local/libexec" \
        "0" "0" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "ingest-local-rc-directory" \
        "$ingest_root/usr/local/etc/rc.d" \
        "0" "0" "0755"

    printf '%s\t%s\t%s\t%s\t%s\n' \
        "ingest-rc-conf-directory" \
        "$ingest_root/etc/rc.conf.d" \
        "0" "0" "0755"
}

runtime_resource_map()
{
    receiver_root=$(get_value FI_RECEIVER_ROOT)
    ingest_root=$(get_value FI_INGEST_ROOT)

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "receiver-supervisor" \
        "$RUNTIME_PLAN/fi-receiver-supervisor" \
        "$receiver_root/usr/local/libexec/fi-receiver-supervisor" \
        "0" "0" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "receiver-rc-service" \
        "$RUNTIME_PLAN/rc.d.fi_receiver" \
        "$receiver_root/usr/local/etc/rc.d/fi_receiver" \
        "0" "0" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "receiver-runtime-config" \
        "$RUNTIME_PLAN/rc.conf.d.fi_receiver" \
        "$receiver_root/etc/rc.conf.d/fi_receiver" \
        "0" "0" "0644"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "ingest-runner" \
        "$RUNTIME_PLAN/fi-ingest-worker-run" \
        "$ingest_root/usr/local/libexec/fi-ingest-worker-run" \
        "0" "0" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "ingest-rc-service" \
        "$RUNTIME_PLAN/rc.d.fi_ingest_worker" \
        "$ingest_root/usr/local/etc/rc.d/fi_ingest_worker" \
        "0" "0" "0555"

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "ingest-runtime-config" \
        "$RUNTIME_PLAN/rc.conf.d.fi_ingest_worker" \
        "$ingest_root/etc/rc.conf.d/fi_ingest_worker" \
        "0" "0" "0644"
}

runtime_target_metadata_exact()
{
    runtime_metadata_target=$1
    runtime_metadata_uid=$2
    runtime_metadata_gid=$3
    runtime_metadata_mode=$4

    [ -f "$runtime_metadata_target" ] &&
    [ ! -L "$runtime_metadata_target" ] ||
        return 1

    runtime_metadata_actual=$(
        stat -f '%u:%g:%OMp:%#Lp:%l' \
            "$runtime_metadata_target" \
            2>/dev/null
    ) || return 1

    runtime_metadata_expected="${runtime_metadata_uid}:${runtime_metadata_gid}:0:${runtime_metadata_mode}:1"

    [ "$runtime_metadata_actual" = "$runtime_metadata_expected" ]
}

runtime_approved_prior_exact()
{
    runtime_prior_file=$1
    runtime_prior_target=$2
    runtime_prior_uid=$3
    runtime_prior_gid=$4
    runtime_prior_mode=$5

    [ -f "$runtime_prior_file" ] &&
    [ ! -L "$runtime_prior_file" ] ||
        return 1

    [ -f "$runtime_prior_target" ] &&
    [ ! -L "$runtime_prior_target" ] ||
        return 1

    runtime_target_metadata_exact \
        "$runtime_prior_target" \
        "$runtime_prior_uid" \
        "$runtime_prior_gid" \
        "$runtime_prior_mode" ||
        return 1

    runtime_prior_sha256=$(
        sha256 -q "$runtime_prior_file"
    ) || return 1

    runtime_live_sha256=$(
        sha256 -q "$runtime_prior_target"
    ) || return 1

    [ "$runtime_prior_sha256" = "$runtime_live_sha256" ] ||
        return 1

    cmp -s \
        "$runtime_prior_file" \
        "$runtime_prior_target"
}

runtime_replace_approved_prior()
{
    runtime_replace_expected=$1
    runtime_replace_target=$2
    runtime_replace_prior=$3
    runtime_replace_uid=$4
    runtime_replace_gid=$5
    runtime_replace_mode=$6
    runtime_replace_role=$7

    [ "$runtime_replace_prior" != "$runtime_replace_target" ] ||
        fail \
            "approved prior runtime file must be separate from live target: $runtime_replace_role"

    runtime_approved_prior_exact \
        "$runtime_replace_prior" \
        "$runtime_replace_target" \
        "$runtime_replace_uid" \
        "$runtime_replace_gid" \
        "$runtime_replace_mode" ||
        fail \
            "live runtime file does not match approved prior: $runtime_replace_role"

    runtime_replace_prior_sha256=$(
        sha256 -q "$runtime_replace_prior"
    ) || fail \
        "unable to hash approved prior runtime file: $runtime_replace_role"

    host_file_require_parent "$runtime_replace_target"

    runtime_replace_parent=${runtime_replace_target%/*}
    runtime_replace_name=${runtime_replace_target##*/}

    runtime_replace_temp=$(
        mktemp \
            "$runtime_replace_parent/.${runtime_replace_name}.fi-runtime.XXXXXX"
    ) || fail \
        "unable to allocate runtime adoption candidate: $runtime_replace_role"

    if ! cat "$runtime_replace_expected" > "$runtime_replace_temp"; then
        rm -f "$runtime_replace_temp"
        fail \
            "unable to populate runtime adoption candidate: $runtime_replace_role"
    fi

    if ! chown \
        "${runtime_replace_uid}:${runtime_replace_gid}" \
        "$runtime_replace_temp"
    then
        rm -f "$runtime_replace_temp"
        fail \
            "unable to set runtime adoption ownership: $runtime_replace_role"
    fi

    if ! chmod \
        "$runtime_replace_mode" \
        "$runtime_replace_temp"
    then
        rm -f "$runtime_replace_temp"
        fail \
            "unable to set runtime adoption mode: $runtime_replace_role"
    fi

    runtime_replace_candidate_state=$(
        host_file_classify \
            "$runtime_replace_expected" \
            "$runtime_replace_temp" \
            "$runtime_replace_uid" \
            "$runtime_replace_gid" \
            "$runtime_replace_mode"
    ) || {
        rm -f "$runtime_replace_temp"
        fail \
            "unable to classify runtime adoption candidate: $runtime_replace_role"
    }

    [ "$runtime_replace_candidate_state" = "OWNED_MATCH" ] || {
        rm -f "$runtime_replace_temp"
        fail \
            "runtime adoption candidate is not exact: $runtime_replace_role ($runtime_replace_candidate_state)"
    }

    # Revalidate approved authority immediately before publication.
    runtime_replace_prior_sha256_now=$(
        sha256 -q "$runtime_replace_prior"
    ) || {
        rm -f "$runtime_replace_temp"
        fail \
            "unable to rehash approved prior runtime file: $runtime_replace_role"
    }

    [ "$runtime_replace_prior_sha256_now" = "$runtime_replace_prior_sha256" ] || {
        rm -f "$runtime_replace_temp"
        fail \
            "approved prior runtime file changed during adoption: $runtime_replace_role"
    }

    runtime_approved_prior_exact \
        "$runtime_replace_prior" \
        "$runtime_replace_target" \
        "$runtime_replace_uid" \
        "$runtime_replace_gid" \
        "$runtime_replace_mode" || {
        rm -f "$runtime_replace_temp"
        fail \
            "live runtime file changed before adoption publication: $runtime_replace_role"
    }

    mv -f \
        "$runtime_replace_temp" \
        "$runtime_replace_target" ||
        fail \
            "unable to publish adopted runtime file: $runtime_replace_role"

    runtime_replace_final_state=$(
        host_file_classify \
            "$runtime_replace_expected" \
            "$runtime_replace_target" \
            "$runtime_replace_uid" \
            "$runtime_replace_gid" \
            "$runtime_replace_mode"
    ) || fail \
        "unable to verify adopted runtime file: $runtime_replace_role"

    [ "$runtime_replace_final_state" = "OWNED_MATCH" ] ||
        fail \
            "adopted runtime file failed verification: $runtime_replace_role ($runtime_replace_final_state)"

    pass "published and verified FI runtime file: $runtime_replace_target"
}

runtime_verify_internal()
{
    runtime_parent_map_file="$RUNTIME_PLAN_ROOT/runtime-parents"
    runtime_resource_map_file="$RUNTIME_PLAN_ROOT/runtime-resources"

    runtime_parent_map > "$runtime_parent_map_file" ||
        fail "unable to build runtime parent map"

    runtime_resource_map > "$runtime_resource_map_file" ||
        fail "unable to build runtime resource map"

    runtime_tab=$(printf '\t')

    while IFS="$runtime_tab" read -r \
        runtime_parent_role \
        runtime_parent_target \
        runtime_parent_uid \
        runtime_parent_gid \
        runtime_parent_mode
    do
        runtime_parent_state=$(
            lifecycle_parent_classify \
                "$runtime_parent_target" \
                "$runtime_parent_uid" \
                "$runtime_parent_gid" \
                "$runtime_parent_mode"
        ) || fail "unable to classify runtime parent: $runtime_parent_role"

        [ "$runtime_parent_state" = "DIRECTORY_MATCH" ] ||
            fail \
                "runtime parent is not exact: $runtime_parent_role ($runtime_parent_state)"

        pass "runtime parent verified: $runtime_parent_target"
    done < "$runtime_parent_map_file"

    while IFS="$runtime_tab" read -r \
        runtime_role \
        runtime_expected \
        runtime_target \
        runtime_uid \
        runtime_gid \
        runtime_mode
    do
        runtime_state=$(
            host_file_classify \
                "$runtime_expected" \
                "$runtime_target" \
                "$runtime_uid" \
                "$runtime_gid" \
                "$runtime_mode"
        ) || fail "unable to classify runtime file: $runtime_role"

        [ "$runtime_state" = "OWNED_MATCH" ] ||
            fail \
                "runtime file is not exact: $runtime_role ($runtime_state)"

        pass "runtime file verified: $runtime_target"
    done < "$runtime_resource_map_file"
}

apply_runtime()
{
    runtime_require_host
    runtime_prepare_expected

    runtime_parent_map_file="$RUNTIME_PLAN_ROOT/runtime-parents"
    runtime_resource_map_file="$RUNTIME_PLAN_ROOT/runtime-resources"

    runtime_parent_map > "$runtime_parent_map_file" ||
        fail "unable to build runtime parent map"

    runtime_resource_map > "$runtime_resource_map_file" ||
        fail "unable to build runtime resource map"

    runtime_tab=$(printf '\t')

    # Complete preclassification before the first mutation.
    while IFS="$runtime_tab" read -r \
        runtime_parent_role \
        runtime_parent_target \
        runtime_parent_uid \
        runtime_parent_gid \
        runtime_parent_mode
    do
        runtime_parent_state=$(
            lifecycle_parent_classify \
                "$runtime_parent_target" \
                "$runtime_parent_uid" \
                "$runtime_parent_gid" \
                "$runtime_parent_mode"
        ) || fail "unable to classify runtime parent: $runtime_parent_role"

        lifecycle_apply_precheck \
            "runtime parent $runtime_parent_role" \
            "$runtime_parent_state"
    done < "$runtime_parent_map_file"

    while IFS="$runtime_tab" read -r \
        runtime_role \
        runtime_expected \
        runtime_target \
        runtime_uid \
        runtime_gid \
        runtime_mode
    do
        runtime_state=$(
            host_file_classify \
                "$runtime_expected" \
                "$runtime_target" \
                "$runtime_uid" \
                "$runtime_gid" \
                "$runtime_mode"
        ) || fail "unable to classify runtime file: $runtime_role"

        host_file_apply_precheck \
            "runtime file $runtime_role" \
            "$runtime_state"
    done < "$runtime_resource_map_file"

    # Parent mutation.
    while IFS="$runtime_tab" read -r \
        runtime_parent_role \
        runtime_parent_target \
        runtime_parent_uid \
        runtime_parent_gid \
        runtime_parent_mode
    do
        runtime_parent_state=$(
            lifecycle_parent_classify \
                "$runtime_parent_target" \
                "$runtime_parent_uid" \
                "$runtime_parent_gid" \
                "$runtime_parent_mode"
        ) || fail "unable to reclassify runtime parent: $runtime_parent_role"

        case "$runtime_parent_state" in
            DIRECTORY_MATCH)
                pass "runtime parent already matches: $runtime_parent_target"
                ;;
            ABSENT)
                lifecycle_parent_install_absent \
                    "$runtime_parent_target" \
                    "$runtime_parent_uid" \
                    "$runtime_parent_gid" \
                    "$runtime_parent_mode" \
                    "$runtime_parent_role"
                ;;
            *)
                fail \
                    "runtime parent changed after preclassification: $runtime_parent_role ($runtime_parent_state)"
                ;;
        esac
    done < "$runtime_parent_map_file"

    # Runtime service-file mutation.
    while IFS="$runtime_tab" read -r \
        runtime_role \
        runtime_expected \
        runtime_target \
        runtime_uid \
        runtime_gid \
        runtime_mode
    do
        runtime_state=$(
            host_file_classify \
                "$runtime_expected" \
                "$runtime_target" \
                "$runtime_uid" \
                "$runtime_gid" \
                "$runtime_mode"
        ) || fail "unable to reclassify runtime file: $runtime_role"

        case "$runtime_state" in
            OWNED_MATCH)
                pass "runtime file already matches: $runtime_target"
                ;;
            ABSENT)
                host_file_install_absent \
                    "$runtime_expected" \
                    "$runtime_target" \
                    "$runtime_uid" \
                    "$runtime_gid" \
                    "$runtime_mode" \
                    "$runtime_role"
                ;;
            *)
                fail \
                    "runtime file changed after preclassification: $runtime_role ($runtime_state)"
                ;;
        esac
    done < "$runtime_resource_map_file"

    runtime_verify_internal
    runtime_cleanup_expected

    pass "FI FreeBSD application runtime apply acceptance complete"
}

adopt_runtime()
{
    runtime_approved_prior_dir=$1

    runtime_require_host

    [ -n "$runtime_approved_prior_dir" ] ||
        fail "approved prior runtime directory is required"

    [ -d "$runtime_approved_prior_dir" ] &&
    [ ! -L "$runtime_approved_prior_dir" ] ||
        fail \
            "approved prior runtime directory is unavailable: $runtime_approved_prior_dir"

    runtime_prepare_expected

    runtime_parent_map_file="$RUNTIME_PLAN_ROOT/runtime-parents"
    runtime_resource_map_file="$RUNTIME_PLAN_ROOT/runtime-resources"

    runtime_parent_map > "$runtime_parent_map_file" ||
        fail "unable to build runtime parent map"

    runtime_resource_map > "$runtime_resource_map_file" ||
        fail "unable to build runtime resource map"

    runtime_tab=$(printf '\t')

    # Existing parent directories are authority for adoption.
    # Adoption never creates or repairs them.
    while IFS="$runtime_tab" read -r \
        runtime_parent_role \
        runtime_parent_target \
        runtime_parent_uid \
        runtime_parent_gid \
        runtime_parent_mode
    do
        runtime_parent_state=$(
            lifecycle_parent_classify \
                "$runtime_parent_target" \
                "$runtime_parent_uid" \
                "$runtime_parent_gid" \
                "$runtime_parent_mode"
        ) || fail \
            "unable to classify runtime adoption parent: $runtime_parent_role"

        [ "$runtime_parent_state" = "DIRECTORY_MATCH" ] ||
            fail \
                "runtime adoption parent is not exact: $runtime_parent_role ($runtime_parent_state)"
    done < "$runtime_parent_map_file"

    # Complete-layer preclassification before replacing anything.
    while IFS="$runtime_tab" read -r \
        runtime_role \
        runtime_expected \
        runtime_target \
        runtime_uid \
        runtime_gid \
        runtime_mode
    do
        runtime_prior="$runtime_approved_prior_dir/${runtime_expected##*/}"

        runtime_state=$(
            host_file_classify \
                "$runtime_expected" \
                "$runtime_target" \
                "$runtime_uid" \
                "$runtime_gid" \
                "$runtime_mode"
        ) || fail \
            "unable to classify runtime resource for adoption: $runtime_role"

        case "$runtime_state" in
            OWNED_MATCH)
                ;;

            FOREIGN_COLLISION)
                [ -f "$runtime_prior" ] &&
                [ ! -L "$runtime_prior" ] ||
                    fail \
                        "approved prior runtime file is unavailable: $runtime_role"

                runtime_approved_prior_exact \
                    "$runtime_prior" \
                    "$runtime_target" \
                    "$runtime_uid" \
                    "$runtime_gid" \
                    "$runtime_mode" ||
                    fail \
                        "live runtime file does not match approved prior: $runtime_role"
                ;;

            ABSENT)
                fail \
                    "runtime adoption target is absent; use apply-runtime: $runtime_role"
                ;;

            OWNED_DRIFT)
                fail \
                    "FI-owned runtime drift is not eligible for adoption: $runtime_role"
                ;;

            UNKNOWN)
                fail \
                    "runtime resource could not be classified safely for adoption: $runtime_role"
                ;;

            *)
                fail \
                    "unexpected runtime adoption state: $runtime_role ($runtime_state)"
                ;;
        esac
    done < "$runtime_resource_map_file"

    # Publication pass. Every resource has already been accepted.
    while IFS="$runtime_tab" read -r \
        runtime_role \
        runtime_expected \
        runtime_target \
        runtime_uid \
        runtime_gid \
        runtime_mode
    do
        runtime_prior="$runtime_approved_prior_dir/${runtime_expected##*/}"

        runtime_state=$(
            host_file_classify \
                "$runtime_expected" \
                "$runtime_target" \
                "$runtime_uid" \
                "$runtime_gid" \
                "$runtime_mode"
        ) || fail \
            "unable to reclassify runtime resource for adoption: $runtime_role"

        case "$runtime_state" in
            OWNED_MATCH)
                pass \
                    "runtime file already adopted: $runtime_target"
                ;;

            FOREIGN_COLLISION)
                runtime_replace_approved_prior \
                    "$runtime_expected" \
                    "$runtime_target" \
                    "$runtime_prior" \
                    "$runtime_uid" \
                    "$runtime_gid" \
                    "$runtime_mode" \
                    "$runtime_role"
                ;;

            *)
                fail \
                    "runtime resource changed after adoption preclassification: $runtime_role ($runtime_state)"
                ;;
        esac
    done < "$runtime_resource_map_file"

    runtime_verify_internal
    runtime_cleanup_expected

    pass "FI FreeBSD application runtime adoption complete"
}

update_runtime()
{
    runtime_approved_prior_dir=$1

    runtime_require_host

    [ -n "$runtime_approved_prior_dir" ] ||
        fail "approved prior FI runtime directory is required"

    [ -d "$runtime_approved_prior_dir" ] &&
    [ ! -L "$runtime_approved_prior_dir" ] ||
        fail \
            "approved prior FI runtime directory is unavailable: $runtime_approved_prior_dir"

    runtime_prepare_expected

    runtime_parent_map_file="$RUNTIME_PLAN_ROOT/runtime-parents"
    runtime_resource_map_file="$RUNTIME_PLAN_ROOT/runtime-resources"

    runtime_parent_map > "$runtime_parent_map_file" ||
        fail "unable to build runtime parent map"

    runtime_resource_map > "$runtime_resource_map_file" ||
        fail "unable to build runtime resource map"

    runtime_tab=$(printf '\t')

    # Runtime updates never create or repair service parent directories.
    while IFS="$runtime_tab" read -r \
        runtime_parent_role \
        runtime_parent_target \
        runtime_parent_uid \
        runtime_parent_gid \
        runtime_parent_mode
    do
        runtime_parent_state=$(
            lifecycle_parent_classify \
                "$runtime_parent_target" \
                "$runtime_parent_uid" \
                "$runtime_parent_gid" \
                "$runtime_parent_mode"
        ) || fail \
            "unable to classify runtime update parent: $runtime_parent_role"

        [ "$runtime_parent_state" = "DIRECTORY_MATCH" ] ||
            fail \
                "runtime update parent is not exact: $runtime_parent_role ($runtime_parent_state)"
    done < "$runtime_parent_map_file"

    # Complete-layer preclassification before the first replacement.
    while IFS="$runtime_tab" read -r \
        runtime_role \
        runtime_expected \
        runtime_target \
        runtime_uid \
        runtime_gid \
        runtime_mode
    do
        runtime_prior="$runtime_approved_prior_dir/${runtime_expected##*/}"

        runtime_state=$(
            host_file_classify \
                "$runtime_expected" \
                "$runtime_target" \
                "$runtime_uid" \
                "$runtime_gid" \
                "$runtime_mode"
        ) || fail \
            "unable to classify runtime resource for update: $runtime_role"

        case "$runtime_state" in
            OWNED_MATCH)
                ;;

            OWNED_DRIFT)
                [ -f "$runtime_prior" ] &&
                [ ! -L "$runtime_prior" ] ||
                    fail \
                        "approved prior FI runtime file is unavailable: $runtime_role"

                runtime_prior_state=$(
                    host_file_classify \
                        "$runtime_prior" \
                        "$runtime_target" \
                        "$runtime_uid" \
                        "$runtime_gid" \
                        "$runtime_mode"
                ) || fail \
                    "unable to classify live runtime against approved prior: $runtime_role"

                [ "$runtime_prior_state" = "OWNED_MATCH" ] ||
                    fail \
                        "live FI runtime does not match approved prior: $runtime_role ($runtime_prior_state)"
                ;;

            ABSENT)
                fail \
                    "FI runtime target is absent; update-runtime will not create it: $runtime_role"
                ;;

            FOREIGN_COLLISION)
                fail \
                    "update-runtime will not replace foreign runtime state: $runtime_role"
                ;;

            UNKNOWN)
                fail \
                    "FI runtime could not be classified safely for update: $runtime_role"
                ;;

            *)
                fail \
                    "unexpected runtime update state: $runtime_role ($runtime_state)"
                ;;
        esac
    done < "$runtime_resource_map_file"

    # Publication pass. Every changed target must still match the approved
    # prior managed version immediately before replacement.
    while IFS="$runtime_tab" read -r \
        runtime_role \
        runtime_expected \
        runtime_target \
        runtime_uid \
        runtime_gid \
        runtime_mode
    do
        runtime_prior="$runtime_approved_prior_dir/${runtime_expected##*/}"

        runtime_state=$(
            host_file_classify \
                "$runtime_expected" \
                "$runtime_target" \
                "$runtime_uid" \
                "$runtime_gid" \
                "$runtime_mode"
        ) || fail \
            "unable to reclassify runtime resource for update: $runtime_role"

        case "$runtime_state" in
            OWNED_MATCH)
                pass \
                    "FI runtime file already matches new version: $runtime_target"
                ;;

            OWNED_DRIFT)
                runtime_prior_state=$(
                    host_file_classify \
                        "$runtime_prior" \
                        "$runtime_target" \
                        "$runtime_uid" \
                        "$runtime_gid" \
                        "$runtime_mode"
                ) || fail \
                    "unable to reclassify live runtime against approved prior: $runtime_role"

                [ "$runtime_prior_state" = "OWNED_MATCH" ] ||
                    fail \
                        "live FI runtime changed after update preclassification: $runtime_role ($runtime_prior_state)"

                runtime_replace_approved_prior \
                    "$runtime_expected" \
                    "$runtime_target" \
                    "$runtime_prior" \
                    "$runtime_uid" \
                    "$runtime_gid" \
                    "$runtime_mode" \
                    "$runtime_role"
                ;;

            *)
                fail \
                    "runtime resource changed after update preclassification: $runtime_role ($runtime_state)"
                ;;
        esac
    done < "$runtime_resource_map_file"

    runtime_verify_internal
    runtime_cleanup_expected

    pass "FI FreeBSD application runtime update complete"
}

verify_runtime()
{
    runtime_require_host
    runtime_prepare_expected

    runtime_verify_internal
    runtime_cleanup_expected

    pass "FI FreeBSD application runtime verification complete"
}
