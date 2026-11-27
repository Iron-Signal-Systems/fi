#!/bin/sh

# FI FreeBSD production filesystem directory helper.
#
# This file is sourced by fi-bootstrap.sh. It intentionally performs no work
# merely by being sourced.

FI_DIRECTORY_SCHEMA_PROPERTY="org.ironsignal.fi:directory-schema"
FI_DIRECTORY_SCHEMA_VERSION="1"

apply_directories()
{
    directory_require_host

    directory_uid=$(get_value FI_RUNTIME_UID)
    directory_gid=$(get_value FI_RUNTIME_GID)
    directory_pool=$(get_value FI_ZPOOL)
    directory_jail_dataset_root=$(get_value FI_JAIL_DATASET_ROOT)
    directory_template_snapshot=$(get_value FI_JAIL_TEMPLATE_SNAPSHOT)

    directory_receiver_root=$(get_value FI_RECEIVER_ROOT)
    directory_ingest_root=$(get_value FI_INGEST_ROOT)
    directory_sor_root=$(get_value FI_SOR_DB_ROOT)

    directory_custody_path=$(get_value FI_CUSTODY_GENERATION_HOST)
    directory_transport_custody_path=$(get_value FI_CUSTODY_TRANSPORT_HOST)
    directory_recorded_path=$(get_value FI_RECORDED_HOST)
    directory_ready_path=$(get_value FI_READY_HOST)
    directory_receiver_config_path=$(get_value FI_RECEIVER_CONFIG_HOST)
    directory_ingest_config_path=$(get_value FI_INGEST_CONFIG_HOST)

    directory_require_prerequisites

    directory_custody_state=$(
        directory_classify_host_source \
            "$directory_pool/fi/custody/generation" \
            "$directory_custody_path" \
            "$directory_uid" \
            "$directory_gid" \
            "0700"
    ) || fail "unable to classify custody generation directory"

    directory_transport_custody_state=$(
        directory_classify_host_source \
            "$directory_pool/fi/custody/transport" \
            "$directory_transport_custody_path" \
            "$directory_uid" \
            "$directory_gid" \
            "0700"
    ) || fail "unable to classify transport custody directory"

    directory_recorded_state=$(
        directory_classify_host_source \
            "$directory_pool/fi/recorded" \
            "$directory_recorded_path" \
            "$directory_uid" \
            "$directory_gid" \
            "0700"
    ) || fail "unable to classify recorded directory"

    directory_ready_state=$(
        directory_classify_host_source \
            "$directory_pool/fi/ready" \
            "$directory_ready_path" \
            "$directory_uid" \
            "$directory_gid" \
            "0700"
    ) || fail "unable to classify READY directory"

    directory_receiver_config_state=$(
        directory_classify_host_source \
            "$directory_pool/fi/config/receiver" \
            "$directory_receiver_config_path" \
            "0" \
            "$directory_gid" \
            "0750"
    ) || fail "unable to classify receiver configuration directory"

    directory_ingest_config_state=$(
        directory_classify_host_source \
            "$directory_pool/fi/config/ingest" \
            "$directory_ingest_config_path" \
            "0" \
            "$directory_gid" \
            "0750"
    ) || fail "unable to classify ingest configuration directory"

    directory_receiver_state=$(
        directory_classify_jail_root \
            "$directory_jail_dataset_root/fi-receiver" \
            "$directory_receiver_root" \
            "receiver" \
            "$directory_uid" \
            "$directory_gid"
    ) || fail "unable to classify receiver jail directories"

    directory_ingest_state=$(
        directory_classify_jail_root \
            "$directory_jail_dataset_root/fi-ingest" \
            "$directory_ingest_root" \
            "ingest" \
            "$directory_uid" \
            "$directory_gid"
    ) || fail "unable to classify ingest jail directories"

    directory_sor_state=$(
        directory_classify_jail_root \
            "$directory_jail_dataset_root/fi-sor-db" \
            "$directory_sor_root" \
            "sor" \
            "$directory_uid" \
            "$directory_gid"
    ) || fail "unable to classify System-of-Record jail directories"

    directory_apply_precheck \
        "custody generation directory" \
        "$directory_custody_state"

    directory_apply_precheck \
        "transport custody directory" \
        "$directory_transport_custody_state"

    directory_apply_precheck \
        "recorded directory" \
        "$directory_recorded_state"

    directory_apply_precheck \
        "READY directory" \
        "$directory_ready_state"

    directory_apply_precheck \
        "receiver configuration directory" \
        "$directory_receiver_config_state"

    directory_apply_precheck \
        "ingest configuration directory" \
        "$directory_ingest_config_state"

    directory_apply_precheck \
        "receiver jail directories" \
        "$directory_receiver_state"

    directory_apply_precheck \
        "ingest jail directories" \
        "$directory_ingest_state"

    directory_apply_precheck \
        "System-of-Record jail directories" \
        "$directory_sor_state"

    pass "production directory layer preclassification complete"

    directory_apply_host_source \
        "$directory_pool/fi/custody/generation" \
        "$directory_custody_path" \
        "$directory_uid" \
        "$directory_gid" \
        "0700" \
        "custody generation directory"

    directory_apply_host_source \
        "$directory_pool/fi/custody/transport" \
        "$directory_transport_custody_path" \
        "$directory_uid" \
        "$directory_gid" \
        "0700" \
        "transport custody directory"

    directory_apply_host_source \
        "$directory_pool/fi/recorded" \
        "$directory_recorded_path" \
        "$directory_uid" \
        "$directory_gid" \
        "0700" \
        "recorded directory"

    directory_apply_host_source \
        "$directory_pool/fi/ready" \
        "$directory_ready_path" \
        "$directory_uid" \
        "$directory_gid" \
        "0700" \
        "READY directory"

    directory_apply_host_source \
        "$directory_pool/fi/config/receiver" \
        "$directory_receiver_config_path" \
        "0" \
        "$directory_gid" \
        "0750" \
        "receiver configuration directory"

    directory_apply_host_source \
        "$directory_pool/fi/config/ingest" \
        "$directory_ingest_config_path" \
        "0" \
        "$directory_gid" \
        "0750" \
        "ingest configuration directory"

    directory_apply_jail_root \
        "$directory_jail_dataset_root/fi-receiver" \
        "$directory_receiver_root" \
        "receiver" \
        "$directory_uid" \
        "$directory_gid"

    directory_apply_jail_root \
        "$directory_jail_dataset_root/fi-ingest" \
        "$directory_ingest_root" \
        "ingest" \
        "$directory_uid" \
        "$directory_gid"

    directory_apply_jail_root \
        "$directory_jail_dataset_root/fi-sor-db" \
        "$directory_sor_root" \
        "sor" \
        "$directory_uid" \
        "$directory_gid"

    pass "FI production filesystem directory apply complete"
}

directory_apply_host_source()
{
    directory_apply_dataset=$1
    directory_apply_path=$2
    directory_apply_uid=$3
    directory_apply_gid=$4
    directory_apply_mode=$5
    directory_apply_name=$6

    directory_apply_state=$(
        directory_classify_host_source \
            "$directory_apply_dataset" \
            "$directory_apply_path" \
            "$directory_apply_uid" \
            "$directory_apply_gid" \
            "$directory_apply_mode"
    ) || fail "unable to reclassify $directory_apply_name"

    case "$directory_apply_state" in
        OWNED_MATCH)
            pass "FI directory already matches: $directory_apply_name"
            return 0
            ;;
        ABSENT)
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI directory differs from requested state: $directory_apply_name"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: unsafe FI directory path: $directory_apply_name"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe FI directory state: $directory_apply_name"
            ;;
        *)
            fail "invalid directory classification for $directory_apply_name: $directory_apply_state"
            ;;
    esac

    directory_initialize_host_source \
        "$directory_apply_dataset" \
        "$directory_apply_path" \
        "$directory_apply_uid" \
        "$directory_apply_gid" \
        "$directory_apply_mode" ||
        fail "failed to initialize $directory_apply_name"

    directory_apply_state=$(
        directory_classify_host_source \
            "$directory_apply_dataset" \
            "$directory_apply_path" \
            "$directory_apply_uid" \
            "$directory_apply_gid" \
            "$directory_apply_mode"
    ) || fail "unable to verify initialized $directory_apply_name"

    [ "$directory_apply_state" = "OWNED_MATCH" ] ||
        fail "initialized FI directory did not verify as OWNED_MATCH: $directory_apply_name"

    pass "initialized and verified FI directory: $directory_apply_name"
}

directory_apply_jail_root()
{
    directory_apply_dataset=$1
    directory_apply_root=$2
    directory_apply_role=$3
    directory_apply_uid=$4
    directory_apply_gid=$5

    directory_apply_state=$(
        directory_classify_jail_root \
            "$directory_apply_dataset" \
            "$directory_apply_root" \
            "$directory_apply_role" \
            "$directory_apply_uid" \
            "$directory_apply_gid"
    ) || fail "unable to reclassify $directory_apply_role jail directories"

    case "$directory_apply_state" in
        OWNED_MATCH)
            pass "FI jail directories already match: $directory_apply_role"
            return 0
            ;;
        ABSENT)
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI jail directories differ from requested state: $directory_apply_role"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: unsafe FI jail directory path: $directory_apply_role"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe FI jail directory state: $directory_apply_role"
            ;;
        *)
            fail "invalid jail directory classification for $directory_apply_role: $directory_apply_state"
            ;;
    esac

    directory_create_jail_paths \
        "$directory_apply_root" \
        "$directory_apply_role" \
        "$directory_apply_uid" \
        "$directory_apply_gid" ||
        fail "failed to create $directory_apply_role jail directories"

    directory_set_marker "$directory_apply_dataset" ||
        fail "failed to mark $directory_apply_role jail directory initialization"

    directory_apply_state=$(
        directory_classify_jail_root \
            "$directory_apply_dataset" \
            "$directory_apply_root" \
            "$directory_apply_role" \
            "$directory_apply_uid" \
            "$directory_apply_gid"
    ) || fail "unable to verify $directory_apply_role jail directories"

    [ "$directory_apply_state" = "OWNED_MATCH" ] ||
        fail "new FI jail directories did not verify as OWNED_MATCH: $directory_apply_role"

    pass "created and verified FI jail directories: $directory_apply_role"
}

directory_apply_precheck()
{
    directory_precheck_name=$1
    directory_precheck_state=$2

    case "$directory_precheck_state" in
        ABSENT|OWNED_MATCH)
            return 0
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI directory differs from requested state: $directory_precheck_name"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: unsafe FI directory path: $directory_precheck_name"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe FI directory state: $directory_precheck_name"
            ;;
        *)
            fail "invalid directory classification for $directory_precheck_name: $directory_precheck_state"
            ;;
    esac
}

directory_classify_host_source()
{
    directory_classify_dataset=$1
    directory_classify_path=$2
    directory_classify_uid=$3
    directory_classify_gid=$4
    directory_classify_mode=$5

    directory_local_marker_status "$directory_classify_dataset"
    directory_marker_rc=$?

    case "$directory_marker_rc" in
        0)
            directory_path_exact \
                "$directory_classify_path" \
                "$directory_classify_uid" \
                "$directory_classify_gid" \
                "$directory_classify_mode"

            directory_path_rc=$?

            case "$directory_path_rc" in
                0)
                    printf '%s\n' "OWNED_MATCH"
                    ;;
                1)
                    printf '%s\n' "OWNED_DRIFT"
                    ;;
                *)
                    printf '%s\n' "UNKNOWN"
                    ;;
            esac
            ;;
        1)
            if [ -L "$directory_classify_path" ]; then
                printf '%s\n' "FOREIGN_COLLISION"
            elif [ -d "$directory_classify_path" ]; then
                printf '%s\n' "ABSENT"
            elif [ -e "$directory_classify_path" ]; then
                printf '%s\n' "FOREIGN_COLLISION"
            else
                printf '%s\n' "UNKNOWN"
            fi
            ;;
        2)
            printf '%s\n' "OWNED_DRIFT"
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            ;;
    esac
}

directory_classify_jail_root()
{
    directory_classify_dataset=$1
    directory_classify_root=$2
    directory_classify_role=$3
    directory_classify_uid=$4
    directory_classify_gid=$5

    directory_local_marker_status "$directory_classify_dataset"
    directory_marker_rc=$?

    case "$directory_marker_rc" in
        0)
            directory_jail_paths_exact_state \
                "$directory_classify_root" \
                "$directory_classify_role" \
                "$directory_classify_uid" \
                "$directory_classify_gid"
            ;;
        1)
            directory_jail_paths_absent_state \
                "$directory_classify_root" \
                "$directory_classify_role"
            ;;
        2)
            printf '%s\n' "OWNED_DRIFT"
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            ;;
    esac
}

directory_create_jail_paths()
{
    directory_create_root=$1
    directory_create_role=$2
    directory_create_uid=$3
    directory_create_gid=$4

    case "$directory_create_role" in
        receiver)
            directory_create_paths \
                "$directory_create_root/var/db/fi" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody/generation" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody/transport" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody/recorded" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody/ready" "0" "0" "0755" \
                "$directory_create_root/usr/local/etc/fi" "0" "0" "0755" \
                "$directory_create_root/var/run/fi" \
                    "$directory_create_uid" \
                    "$directory_create_gid" \
                    "0700"
            ;;
        ingest)
            directory_create_paths \
                "$directory_create_root/var/db/fi" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody/generation" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody/recorded" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/custody/ready" "0" "0" "0755" \
                "$directory_create_root/usr/local/etc/fi" "0" "0" "0755" \
                "$directory_create_root/var/run/fi" \
                    "$directory_create_uid" \
                    "$directory_create_gid" \
                    "0700"
            ;;
        sor)
            directory_create_paths \
                "$directory_create_root/var/db/fi" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/sor" "0" "0" "0755" \
                "$directory_create_root/var/db/fi/sor/postgres" "0" "0" "0755"
            ;;
        *)
            return 1
            ;;
    esac
}

directory_create_paths()
{
    while [ "$#" -gt 0 ]; do
        [ "$#" -ge 4 ] || return 1

        directory_create_path=$1
        directory_create_uid=$2
        directory_create_gid=$3
        directory_create_mode=$4
        shift 4

        if [ -e "$directory_create_path" ] || [ -L "$directory_create_path" ]; then
            return 1
        fi

        mkdir "$directory_create_path" || return 1
        chown "$directory_create_uid:$directory_create_gid" \
            "$directory_create_path" || return 1
        chmod "$directory_create_mode" "$directory_create_path" || return 1

        directory_path_exact \
            "$directory_create_path" \
            "$directory_create_uid" \
            "$directory_create_gid" \
            "$directory_create_mode" ||
            return 1
    done

    return 0
}

directory_initialize_host_source()
{
    directory_initialize_dataset=$1
    directory_initialize_path=$2
    directory_initialize_uid=$3
    directory_initialize_gid=$4
    directory_initialize_mode=$5

    [ -d "$directory_initialize_path" ] &&
        [ ! -L "$directory_initialize_path" ] ||
        return 1

    chown "$directory_initialize_uid:$directory_initialize_gid" \
        "$directory_initialize_path" ||
        return 1

    chmod "$directory_initialize_mode" "$directory_initialize_path" ||
        return 1

    directory_path_exact \
        "$directory_initialize_path" \
        "$directory_initialize_uid" \
        "$directory_initialize_gid" \
        "$directory_initialize_mode" ||
        return 1

    directory_set_marker "$directory_initialize_dataset"
}

directory_jail_paths_absent_state()
{
    directory_absent_root=$1
    directory_absent_role=$2

    case "$directory_absent_role" in
        receiver)
            directory_paths_absent_state \
                "$directory_absent_root/var/db/fi" \
                "$directory_absent_root/var/db/fi/custody" \
                "$directory_absent_root/var/db/fi/custody/generation" \
                "$directory_absent_root/var/db/fi/custody/transport" \
                "$directory_absent_root/var/db/fi/custody/recorded" \
                "$directory_absent_root/var/db/fi/custody/ready" \
                "$directory_absent_root/usr/local/etc/fi" \
                "$directory_absent_root/var/run/fi"
            ;;
        ingest)
            directory_paths_absent_state \
                "$directory_absent_root/var/db/fi" \
                "$directory_absent_root/var/db/fi/custody" \
                "$directory_absent_root/var/db/fi/custody/generation" \
                "$directory_absent_root/var/db/fi/custody/recorded" \
                "$directory_absent_root/var/db/fi/custody/ready" \
                "$directory_absent_root/usr/local/etc/fi" \
                "$directory_absent_root/var/run/fi"
            ;;
        sor)
            directory_paths_absent_state \
                "$directory_absent_root/var/db/fi" \
                "$directory_absent_root/var/db/fi/sor" \
                "$directory_absent_root/var/db/fi/sor/postgres"
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            ;;
    esac
}

directory_jail_paths_exact_state()
{
    directory_exact_root=$1
    directory_exact_role=$2
    directory_exact_uid=$3
    directory_exact_gid=$4

    case "$directory_exact_role" in
        receiver)
            directory_paths_exact_state \
                "$directory_exact_root/var/db/fi" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody/generation" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody/transport" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody/recorded" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody/ready" "0" "0" "0755" \
                "$directory_exact_root/usr/local/etc/fi" "0" "0" "0755" \
                "$directory_exact_root/var/run/fi" \
                    "$directory_exact_uid" \
                    "$directory_exact_gid" \
                    "0700"
            ;;
        ingest)
            directory_paths_exact_state \
                "$directory_exact_root/var/db/fi" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody/generation" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody/recorded" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/custody/ready" "0" "0" "0755" \
                "$directory_exact_root/usr/local/etc/fi" "0" "0" "0755" \
                "$directory_exact_root/var/run/fi" \
                    "$directory_exact_uid" \
                    "$directory_exact_gid" \
                    "0700"
            ;;
        sor)
            directory_paths_exact_state \
                "$directory_exact_root/var/db/fi" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/sor" "0" "0" "0755" \
                "$directory_exact_root/var/db/fi/sor/postgres" "0" "0" "0755"
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            ;;
    esac
}

directory_local_marker_status()
{
    directory_marker_dataset=$1

    directory_marker_result=$(
        zfs get \
            -H \
            -o value,source \
            "$FI_DIRECTORY_SCHEMA_PROPERTY" \
            "$directory_marker_dataset" \
            2>/dev/null
    )

    directory_marker_rc=$?

    [ "$directory_marker_rc" -eq 0 ] || return 3

    set -- $directory_marker_result

    [ "$#" -ge 2 ] || return 3

    directory_marker_value=$1
    directory_marker_source=$2

    if [ "$directory_marker_source" = "local" ]; then
        [ "$directory_marker_value" = "$FI_DIRECTORY_SCHEMA_VERSION" ] &&
            return 0

        return 2
    fi

    return 1
}

directory_path_exact()
{
    directory_exact_path=$1
    directory_exact_uid=$2
    directory_exact_gid=$3
    directory_exact_mode=$4

    [ ! -L "$directory_exact_path" ] || return 1
    [ -e "$directory_exact_path" ] || return 1

    directory_exact_result=$(
        stat -f '%u %g %Lp %HT' "$directory_exact_path" 2>/dev/null
    ) || return 2

    set -- $directory_exact_result

    [ "$#" -eq 4 ] || return 2

    directory_actual_uid=$1
    directory_actual_gid=$2
    directory_actual_mode=$3
    directory_actual_type=$4
    directory_expected_mode=${directory_exact_mode#0}

    [ "$directory_actual_type" = "Directory" ] || return 1
    [ "$directory_actual_uid" = "$directory_exact_uid" ] || return 1
    [ "$directory_actual_gid" = "$directory_exact_gid" ] || return 1
    [ "$directory_actual_mode" = "$directory_expected_mode" ] || return 1

    return 0
}

directory_paths_absent_state()
{
    for directory_absent_path in "$@"; do
        if [ -e "$directory_absent_path" ] || [ -L "$directory_absent_path" ]; then
            printf '%s\n' "FOREIGN_COLLISION"
            return 0
        fi
    done

    printf '%s\n' "ABSENT"
}

directory_paths_exact_state()
{
    while [ "$#" -gt 0 ]; do
        [ "$#" -ge 4 ] || {
            printf '%s\n' "UNKNOWN"
            return 0
        }

        directory_exact_path=$1
        directory_exact_uid=$2
        directory_exact_gid=$3
        directory_exact_mode=$4
        shift 4

        directory_path_exact \
            "$directory_exact_path" \
            "$directory_exact_uid" \
            "$directory_exact_gid" \
            "$directory_exact_mode"

        directory_exact_rc=$?

        case "$directory_exact_rc" in
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
    done

    printf '%s\n' "OWNED_MATCH"
}

directory_require_commands()
{
    for directory_command in \
        chmod \
        chown \
        hostname \
        id \
        mkdir \
        stat \
        uname \
        zfs
    do
        command -v "$directory_command" >/dev/null 2>&1 ||
            fail "required directory deployment command not found: $directory_command"
    done
}

directory_require_host()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "directory operation must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "directory operation requires FreeBSD"

    directory_expected_hostname=$(get_value FI_HOSTNAME)
    directory_actual_hostname=$(hostname)

    [ "$directory_actual_hostname" = "$directory_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $directory_expected_hostname, observed $directory_actual_hostname"

    pass "deployment hostname matches: $directory_actual_hostname"
}

directory_require_prerequisites()
{
    directory_require_zfs_owned \
        "$directory_pool/fi/custody/generation" \
        "custody-generation" \
        "$directory_custody_path"

    directory_require_zfs_owned \
        "$directory_pool/fi/custody/transport" \
        "custody-transport" \
        "$directory_transport_custody_path"

    directory_require_zfs_owned \
        "$directory_pool/fi/recorded" \
        "recorded" \
        "$directory_recorded_path"

    directory_require_zfs_owned \
        "$directory_pool/fi/ready" \
        "ready" \
        "$directory_ready_path"

    directory_require_zfs_owned \
        "$directory_pool/fi/config/receiver" \
        "config-receiver" \
        "$directory_receiver_config_path"

    directory_require_zfs_owned \
        "$directory_pool/fi/config/ingest" \
        "config-ingest" \
        "$directory_ingest_config_path"

    directory_require_jail_root_owned \
        "$directory_jail_dataset_root/fi-receiver" \
        "$directory_receiver_root" \
        "jail-root-receiver"

    directory_require_jail_root_owned \
        "$directory_jail_dataset_root/fi-ingest" \
        "$directory_ingest_root" \
        "jail-root-ingest"

    directory_require_jail_root_owned \
        "$directory_jail_dataset_root/fi-sor-db" \
        "$directory_sor_root" \
        "jail-root-sor-db"

    pass "directory layer prerequisites verified"
}

directory_require_jail_root_owned()
{
    directory_required_dataset=$1
    directory_required_root=$2
    directory_required_role=$3

    directory_required_state=$(
        jail_root_classify_dataset \
            "$directory_required_dataset" \
            "$directory_required_root" \
            "$directory_required_role" \
            "$directory_template_snapshot" \
            "$directory_jail_dataset_root"
    ) || fail "unable to classify prerequisite jail root: $directory_required_dataset"

    [ "$directory_required_state" = "OWNED_MATCH" ] ||
        fail \
            "directory prerequisite jail root is not OWNED_MATCH: $directory_required_dataset ($directory_required_state)"
}

directory_require_zfs_owned()
{
    directory_required_dataset=$1
    directory_required_role=$2
    directory_required_mountpoint=$3

    directory_required_state=$(
        zfs_apply_classify_dataset \
            "$directory_required_dataset" \
            "$directory_required_role" \
            "$directory_required_mountpoint" \
            "on" \
            "yes"
    ) || fail "unable to classify prerequisite ZFS dataset: $directory_required_dataset"

    [ "$directory_required_state" = "OWNED_MATCH" ] ||
        fail \
            "directory prerequisite ZFS dataset is not OWNED_MATCH: $directory_required_dataset ($directory_required_state)"
}

directory_set_marker()
{
    directory_marker_dataset=$1

    zfs set \
        "$FI_DIRECTORY_SCHEMA_PROPERTY=$FI_DIRECTORY_SCHEMA_VERSION" \
        "$directory_marker_dataset"
}
