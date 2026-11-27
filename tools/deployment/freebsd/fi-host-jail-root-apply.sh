#!/bin/sh

# FI FreeBSD production jail-root ZFS clone apply helper.
#
# This file is sourced by the deployment bootstrap. It intentionally does not
# execute deployment work when sourced.

FI_JAIL_ZFS_MANAGED_PROPERTY="org.ironsignal.fi:managed"
FI_JAIL_ZFS_ROLE_PROPERTY="org.ironsignal.fi:role"
FI_JAIL_ZFS_SCHEMA_PROPERTY="org.ironsignal.fi:schema"
FI_JAIL_ZFS_SCHEMA_VERSION="1"

apply_jail_roots()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "jail-root apply must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "jail-root apply requires FreeBSD"

    jail_root_expected_hostname=$(get_value FI_HOSTNAME)
    jail_root_actual_hostname=$(hostname)

    [ "$jail_root_actual_hostname" = "$jail_root_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $jail_root_expected_hostname, observed $jail_root_actual_hostname"

    pass "deployment hostname matches: $jail_root_actual_hostname"

    jail_root_dataset_root=$(get_value FI_JAIL_DATASET_ROOT)
    jail_root_root_base=$(get_value FI_JAIL_ROOT_BASE)
    jail_root_snapshot=$(get_value FI_JAIL_TEMPLATE_SNAPSHOT)

    jail_root_require_prerequisites \
        "$jail_root_dataset_root" \
        "$jail_root_root_base" \
        "$jail_root_snapshot"

    jail_root_receiver_dataset="$jail_root_dataset_root/fi-receiver"
    jail_root_ingest_dataset="$jail_root_dataset_root/fi-ingest"
    jail_root_sor_db_dataset="$jail_root_dataset_root/fi-sor-db"

    jail_root_receiver_path="$jail_root_root_base/fi-receiver"
    jail_root_ingest_path="$jail_root_root_base/fi-ingest"
    jail_root_sor_db_path="$jail_root_root_base/fi-sor-db"

    jail_root_receiver_state=$(
        jail_root_classify_dataset \
            "$jail_root_receiver_dataset" \
            "$jail_root_receiver_path" \
            "jail-root-receiver" \
            "$jail_root_snapshot" \
            "$jail_root_dataset_root"
    ) || fail "unable to classify production jail root: $jail_root_receiver_dataset"

    jail_root_ingest_state=$(
        jail_root_classify_dataset \
            "$jail_root_ingest_dataset" \
            "$jail_root_ingest_path" \
            "jail-root-ingest" \
            "$jail_root_snapshot" \
            "$jail_root_dataset_root"
    ) || fail "unable to classify production jail root: $jail_root_ingest_dataset"

    jail_root_sor_db_state=$(
        jail_root_classify_dataset \
            "$jail_root_sor_db_dataset" \
            "$jail_root_sor_db_path" \
            "jail-root-sor-db" \
            "$jail_root_snapshot" \
            "$jail_root_dataset_root"
    ) || fail "unable to classify production jail root: $jail_root_sor_db_dataset"

    jail_root_apply_precheck_state \
        "$jail_root_receiver_dataset" \
        "$jail_root_receiver_state"

    jail_root_apply_precheck_state \
        "$jail_root_ingest_dataset" \
        "$jail_root_ingest_state"

    jail_root_apply_precheck_state \
        "$jail_root_sor_db_dataset" \
        "$jail_root_sor_db_state"

    pass "production jail-root layer preclassification complete"

    jail_root_apply_one \
        "$jail_root_receiver_dataset" \
        "$jail_root_receiver_path" \
        "jail-root-receiver" \
        "$jail_root_snapshot" \
        "$jail_root_dataset_root"

    jail_root_apply_one \
        "$jail_root_ingest_dataset" \
        "$jail_root_ingest_path" \
        "jail-root-ingest" \
        "$jail_root_snapshot" \
        "$jail_root_dataset_root"

    jail_root_apply_one \
        "$jail_root_sor_db_dataset" \
        "$jail_root_sor_db_path" \
        "jail-root-sor-db" \
        "$jail_root_snapshot" \
        "$jail_root_dataset_root"

    pass "FI production jail-root clone apply complete"
}

jail_root_apply_one()
{
    jail_root_apply_dataset=$1
    jail_root_apply_path=$2
    jail_root_apply_role=$3
    jail_root_apply_snapshot=$4
    jail_root_apply_parent=$5

    jail_root_apply_state=$(
        jail_root_classify_dataset \
            "$jail_root_apply_dataset" \
            "$jail_root_apply_path" \
            "$jail_root_apply_role" \
            "$jail_root_apply_snapshot" \
            "$jail_root_apply_parent"
    ) || fail "unable to reclassify production jail root: $jail_root_apply_dataset"

    case "$jail_root_apply_state" in
        OWNED_MATCH)
            pass "FI jail root already matches: $jail_root_apply_dataset"
            return 0
            ;;
        ABSENT)
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI jail root differs from requested state: $jail_root_apply_dataset"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: jail-root destination is not authoritatively FI-owned: $jail_root_apply_dataset"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe jail-root state: $jail_root_apply_dataset"
            ;;
        *)
            fail "invalid jail-root classification for $jail_root_apply_dataset: $jail_root_apply_state"
            ;;
    esac

    jail_root_clone_dataset \
        "$jail_root_apply_snapshot" \
        "$jail_root_apply_dataset" \
        "$jail_root_apply_path" \
        "$jail_root_apply_role" ||
        fail "failed to create FI production jail-root clone: $jail_root_apply_dataset"

    jail_root_apply_state=$(
        jail_root_classify_dataset \
            "$jail_root_apply_dataset" \
            "$jail_root_apply_path" \
            "$jail_root_apply_role" \
            "$jail_root_apply_snapshot" \
            "$jail_root_apply_parent"
    ) || fail "unable to verify newly-created production jail root: $jail_root_apply_dataset"

    [ "$jail_root_apply_state" = "OWNED_MATCH" ] ||
        fail \
            "newly-created FI jail root did not verify as OWNED_MATCH: $jail_root_apply_dataset"

    pass "created and verified FI jail root: $jail_root_apply_dataset"
}

jail_root_apply_precheck_state()
{
    jail_root_precheck_dataset=$1
    jail_root_precheck_state=$2

    case "$jail_root_precheck_state" in
        ABSENT|OWNED_MATCH)
            return 0
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI jail root differs from requested state: $jail_root_precheck_dataset"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: jail-root destination is not authoritatively FI-owned: $jail_root_precheck_dataset"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe jail-root state: $jail_root_precheck_dataset"
            ;;
        *)
            fail "invalid jail-root classification for $jail_root_precheck_dataset: $jail_root_precheck_state"
            ;;
    esac
}

jail_root_classify_dataset()
{
    jail_root_classify_dataset_name=$1
    jail_root_classify_path=$2
    jail_root_classify_role=$3
    jail_root_classify_snapshot=$4
    jail_root_classify_parent=$5

    jail_root_dataset_presence \
        "$jail_root_classify_dataset_name" \
        "$jail_root_classify_parent"

    jail_root_classify_presence=$?

    case "$jail_root_classify_presence" in
        0)
            ;;
        1)
            jail_root_path_presence "$jail_root_classify_path"
            jail_root_classify_path_presence=$?

            case "$jail_root_classify_path_presence" in
                0)
                    printf '%s\n' "FOREIGN_COLLISION"
                    return 0
                    ;;
                1)
                    printf '%s\n' "ABSENT"
                    return 0
                    ;;
                *)
                    printf '%s\n' "UNKNOWN"
                    return 0
                    ;;
            esac
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            return 0
            ;;
    esac

    jail_root_local_property_status \
        "$jail_root_classify_dataset_name" \
        "$FI_JAIL_ZFS_MANAGED_PROPERTY" \
        "1"

    jail_root_classify_status=$?

    case "$jail_root_classify_status" in
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

    for jail_root_classify_spec in \
        "$FI_JAIL_ZFS_SCHEMA_PROPERTY|$FI_JAIL_ZFS_SCHEMA_VERSION" \
        "$FI_JAIL_ZFS_ROLE_PROPERTY|$jail_root_classify_role" \
        "mountpoint|$jail_root_classify_path" \
        "canmount|on" \
        "readonly|off" \
        "atime|off" \
        "exec|on" \
        "setuid|on" \
        "devices|on"
    do
        jail_root_classify_property=${jail_root_classify_spec%%|*}
        jail_root_classify_expected=${jail_root_classify_spec#*|}

        jail_root_local_property_status \
            "$jail_root_classify_dataset_name" \
            "$jail_root_classify_property" \
            "$jail_root_classify_expected"

        jail_root_classify_status=$?

        case "$jail_root_classify_status" in
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

    jail_root_origin_status \
        "$jail_root_classify_dataset_name" \
        "$jail_root_classify_snapshot"

    jail_root_classify_status=$?

    case "$jail_root_classify_status" in
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

    jail_root_runtime_property_status \
        "$jail_root_classify_dataset_name" \
        "mounted" \
        "yes"

    jail_root_classify_status=$?

    case "$jail_root_classify_status" in
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
}

jail_root_clone_dataset()
{
    jail_root_clone_snapshot=$1
    jail_root_clone_dataset=$2
    jail_root_clone_path=$3
    jail_root_clone_role=$4

    zfs clone \
        -o "$FI_JAIL_ZFS_MANAGED_PROPERTY=1" \
        -o "$FI_JAIL_ZFS_SCHEMA_PROPERTY=$FI_JAIL_ZFS_SCHEMA_VERSION" \
        -o "$FI_JAIL_ZFS_ROLE_PROPERTY=$jail_root_clone_role" \
        -o "mountpoint=$jail_root_clone_path" \
        -o "canmount=on" \
        -o "readonly=off" \
        -o "atime=off" \
        -o "exec=on" \
        -o "setuid=on" \
        -o "devices=on" \
        "$jail_root_clone_snapshot" \
        "$jail_root_clone_dataset"
}

jail_root_dataset_presence()
{
    jail_root_presence_dataset=$1
    jail_root_presence_parent=$2

    jail_root_presence_names=$(
        zfs list -r -H -o name "$jail_root_presence_parent" 2>/dev/null
    ) || return 2

    if printf '%s\n' "$jail_root_presence_names" |
        grep -Fxq "$jail_root_presence_dataset"
    then
        return 0
    fi

    return 1
}

jail_root_local_property_status()
{
    jail_root_local_dataset=$1
    jail_root_local_property=$2
    jail_root_local_expected=$3

    jail_root_local_actual=$(
        zfs get -H -o value,source \
            "$jail_root_local_property" \
            "$jail_root_local_dataset" \
            2>/dev/null
    ) || return 2

    jail_root_local_wanted=$(
        printf '%s\t%s' "$jail_root_local_expected" "local"
    )

    [ "$jail_root_local_actual" = "$jail_root_local_wanted" ]
}

jail_root_origin_status()
{
    jail_root_origin_dataset=$1
    jail_root_origin_expected=$2

    jail_root_origin_actual=$(
        zfs get -H -o value origin "$jail_root_origin_dataset" 2>/dev/null
    ) || return 2

    [ "$jail_root_origin_actual" = "$jail_root_origin_expected" ]
}

jail_root_path_presence()
{
    jail_root_path=$1

    if [ -e "$jail_root_path" ] || [ -L "$jail_root_path" ]; then
        return 0
    fi

    return 1
}

jail_root_require_commands()
{
    for jail_root_command in \
        grep \
        hostname \
        id \
        uname \
        zfs
    do
        command -v "$jail_root_command" >/dev/null 2>&1 ||
            fail "required jail-root deployment command not found: $jail_root_command"
    done
}

jail_root_require_prerequisites()
{
    jail_root_prereq_dataset_root=$1
    jail_root_prereq_root_base=$2
    jail_root_prereq_snapshot=$3

    zfs list -H -o name "$jail_root_prereq_dataset_root" >/dev/null 2>&1 ||
        fail "configured jail dataset root does not exist: $jail_root_prereq_dataset_root"

    jail_root_prereq_mountpoint=$(
        zfs get -H -o value mountpoint \
            "$jail_root_prereq_dataset_root" \
            2>/dev/null
    ) || fail "unable to inspect jail dataset root mountpoint: $jail_root_prereq_dataset_root"

    [ "$jail_root_prereq_mountpoint" = "$jail_root_prereq_root_base" ] ||
        fail \
            "jail dataset root mountpoint mismatch: expected $jail_root_prereq_root_base, observed $jail_root_prereq_mountpoint"

    zfs list -H -t snapshot -o name "$jail_root_prereq_snapshot" >/dev/null 2>&1 ||
        fail "configured jail template snapshot does not exist: $jail_root_prereq_snapshot"
}

jail_root_runtime_property_status()
{
    jail_root_runtime_dataset=$1
    jail_root_runtime_property=$2
    jail_root_runtime_expected=$3

    jail_root_runtime_actual=$(
        zfs get -H -o value \
            "$jail_root_runtime_property" \
            "$jail_root_runtime_dataset" \
            2>/dev/null
    ) || return 2

    [ "$jail_root_runtime_actual" = "$jail_root_runtime_expected" ]
}

verify_jail_roots()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "jail-root verification must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "jail-root verification requires FreeBSD"

    jail_root_verify_expected_hostname=$(get_value FI_HOSTNAME)
    jail_root_verify_actual_hostname=$(hostname)

    [ "$jail_root_verify_actual_hostname" = "$jail_root_verify_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $jail_root_verify_expected_hostname, observed $jail_root_verify_actual_hostname"

    pass "deployment hostname matches: $jail_root_verify_actual_hostname"

    jail_root_verify_dataset_root=$(get_value FI_JAIL_DATASET_ROOT)
    jail_root_verify_root_base=$(get_value FI_JAIL_ROOT_BASE)
    jail_root_verify_snapshot=$(get_value FI_JAIL_TEMPLATE_SNAPSHOT)

    jail_root_require_prerequisites \
        "$jail_root_verify_dataset_root" \
        "$jail_root_verify_root_base" \
        "$jail_root_verify_snapshot"

    jail_root_verify_one \
        "$jail_root_verify_dataset_root/fi-receiver" \
        "$jail_root_verify_root_base/fi-receiver" \
        "jail-root-receiver" \
        "$jail_root_verify_snapshot" \
        "$jail_root_verify_dataset_root"

    jail_root_verify_one \
        "$jail_root_verify_dataset_root/fi-ingest" \
        "$jail_root_verify_root_base/fi-ingest" \
        "jail-root-ingest" \
        "$jail_root_verify_snapshot" \
        "$jail_root_verify_dataset_root"

    jail_root_verify_one \
        "$jail_root_verify_dataset_root/fi-sor-db" \
        "$jail_root_verify_root_base/fi-sor-db" \
        "jail-root-sor-db" \
        "$jail_root_verify_snapshot" \
        "$jail_root_verify_dataset_root"

    pass "FI production jail-root verification complete"
}

jail_root_verify_one()
{
    jail_root_verify_dataset=$1
    jail_root_verify_path=$2
    jail_root_verify_role=$3
    jail_root_verify_snapshot=$4
    jail_root_verify_parent=$5

    jail_root_verify_state=$(
        jail_root_classify_dataset \
            "$jail_root_verify_dataset" \
            "$jail_root_verify_path" \
            "$jail_root_verify_role" \
            "$jail_root_verify_snapshot" \
            "$jail_root_verify_parent"
    ) || fail "unable to classify FI jail root: $jail_root_verify_dataset"

    case "$jail_root_verify_state" in
        OWNED_MATCH)
            pass "FI jail root verified: $jail_root_verify_dataset"
            ;;
        ABSENT)
            fail "ABSENT: required FI jail root does not exist: $jail_root_verify_dataset"
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI jail root differs from requested state: $jail_root_verify_dataset"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: jail root is not authoritatively FI-owned: $jail_root_verify_dataset"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe jail-root state: $jail_root_verify_dataset"
            ;;
        *)
            fail "invalid jail-root classification for $jail_root_verify_dataset: $jail_root_verify_state"
            ;;
    esac
}

preflight_jail_roots()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "jail-root preflight must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "jail-root preflight requires FreeBSD"

    jail_root_preflight_expected_hostname=$(get_value FI_HOSTNAME)
    jail_root_preflight_actual_hostname=$(hostname)

    [ "$jail_root_preflight_actual_hostname" = "$jail_root_preflight_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $jail_root_preflight_expected_hostname, observed $jail_root_preflight_actual_hostname"

    pass "deployment hostname matches: $jail_root_preflight_actual_hostname"

    jail_root_preflight_dataset_root=$(get_value FI_JAIL_DATASET_ROOT)
    jail_root_preflight_root_base=$(get_value FI_JAIL_ROOT_BASE)
    jail_root_preflight_snapshot=$(get_value FI_JAIL_TEMPLATE_SNAPSHOT)

    jail_root_require_prerequisites \
        "$jail_root_preflight_dataset_root" \
        "$jail_root_preflight_root_base" \
        "$jail_root_preflight_snapshot"

    jail_root_preflight_one \
        "$jail_root_preflight_dataset_root/fi-receiver" \
        "$jail_root_preflight_root_base/fi-receiver" \
        "jail-root-receiver" \
        "$jail_root_preflight_snapshot" \
        "$jail_root_preflight_dataset_root"

    jail_root_preflight_one \
        "$jail_root_preflight_dataset_root/fi-ingest" \
        "$jail_root_preflight_root_base/fi-ingest" \
        "jail-root-ingest" \
        "$jail_root_preflight_snapshot" \
        "$jail_root_preflight_dataset_root"

    jail_root_preflight_one \
        "$jail_root_preflight_dataset_root/fi-sor-db" \
        "$jail_root_preflight_root_base/fi-sor-db" \
        "jail-root-sor-db" \
        "$jail_root_preflight_snapshot" \
        "$jail_root_preflight_dataset_root"

    pass "FI production jail-root preflight complete"
}

jail_root_preflight_one()
{
    jail_root_preflight_dataset=$1
    jail_root_preflight_path=$2
    jail_root_preflight_role=$3
    jail_root_preflight_snapshot=$4
    jail_root_preflight_parent=$5

    jail_root_preflight_state=$(
        jail_root_classify_dataset \
            "$jail_root_preflight_dataset" \
            "$jail_root_preflight_path" \
            "$jail_root_preflight_role" \
            "$jail_root_preflight_snapshot" \
            "$jail_root_preflight_parent"
    ) || fail "unable to classify FI jail root: $jail_root_preflight_dataset"

    case "$jail_root_preflight_state" in
        ABSENT)
            pass "FI jail root ready to create: $jail_root_preflight_dataset"
            ;;
        OWNED_MATCH)
            pass "FI jail root already matches: $jail_root_preflight_dataset"
            ;;
        OWNED_DRIFT)
            fail "OWNED_DRIFT: FI jail root differs from requested state: $jail_root_preflight_dataset"
            ;;
        FOREIGN_COLLISION)
            fail "FOREIGN_COLLISION: jail root is not authoritatively FI-owned: $jail_root_preflight_dataset"
            ;;
        UNKNOWN)
            fail "UNKNOWN: unable to establish safe jail-root state: $jail_root_preflight_dataset"
            ;;
        *)
            fail "invalid jail-root classification for $jail_root_preflight_dataset: $jail_root_preflight_state"
            ;;
    esac
}
