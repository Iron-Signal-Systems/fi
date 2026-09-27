# FI FreeBSD production ZFS apply helpers.
#
# This file is trusted program code. It is not directly executable and is not
# wired only through the narrowly scoped fi-bootstrap.sh apply-zfs command.
#
# Deployment configuration remains strict parsed data and is never sourced as
# shell code.

FI_ZFS_MANAGED_PROPERTY="org.ironsignal.fi:managed"
FI_ZFS_ROLE_PROPERTY="org.ironsignal.fi:role"
FI_ZFS_SCHEMA_PROPERTY="org.ironsignal.fi:schema"
FI_ZFS_SCHEMA_VERSION="1"

apply_zfs_hierarchy()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "ZFS apply must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "ZFS apply requires FreeBSD"

    zfs_apply_expected_hostname=$(get_value FI_HOSTNAME)
    zfs_apply_actual_hostname=$(hostname)

    [ "$zfs_apply_actual_hostname" = "$zfs_apply_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $zfs_apply_expected_hostname, observed $zfs_apply_actual_hostname"

    pass "deployment hostname matches: $zfs_apply_actual_hostname"

    zfs_apply_pool=$(get_value FI_ZPOOL)
    zfs_apply_root="$zfs_apply_pool/fi"

    zpool list -H -o name "$zfs_apply_pool" >/dev/null 2>&1 ||
        fail "configured ZFS pool does not exist: $zfs_apply_pool"

    zfs list -H -o name "$zfs_apply_root" >/dev/null 2>&1 ||
        fail "FI ZFS root does not exist: $zfs_apply_root"

    zfs_apply_root_mountpoint=$(
        zfs get -H -o value mountpoint "$zfs_apply_root" 2>/dev/null
    ) || fail "unable to inspect FI ZFS root mountpoint: $zfs_apply_root"

    [ "$zfs_apply_root_mountpoint" = "/var/db/fi" ] ||
        fail \
            "FI ZFS root mountpoint mismatch: expected /var/db/fi, observed $zfs_apply_root_mountpoint"

    # First pass: prove the entire ZFS layer is safe before any mutation.

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/custody" \
        "custody-parent" \
        "none" \
        "off" \
        "no"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/custody/generation" \
        "custody-generation" \
        "/var/db/fi/custody/generation" \
        "on" \
        "yes"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/recorded" \
        "recorded" \
        "/var/db/fi/custody/recorded" \
        "on" \
        "yes"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/ready" \
        "ready" \
        "/var/db/fi/custody/ready" \
        "on" \
        "yes"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/config" \
        "config-parent" \
        "none" \
        "off" \
        "no"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/config/receiver" \
        "config-receiver" \
        "/var/db/fi/config/receiver" \
        "on" \
        "yes"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/config/ingest" \
        "config-ingest" \
        "/var/db/fi/config/ingest" \
        "on" \
        "yes"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/sor" \
        "sor-parent" \
        "none" \
        "off" \
        "no"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/sor/postgres" \
        "sor-postgres" \
        "/var/db/fi/sor/postgres" \
        "on" \
        "yes"

    zfs_apply_precheck_dataset \
        "$zfs_apply_root/backups" \
        "backups" \
        "/var/db/fi/backups" \
        "on" \
        "yes"

    pass "FI production ZFS hierarchy preclassification complete"

    # Second pass: each resource is reclassified immediately before any create.

    zfs_apply_dataset \
        "$zfs_apply_root/custody" \
        "custody-parent" \
        "none" \
        "off" \
        "no"

    zfs_apply_dataset \
        "$zfs_apply_root/custody/generation" \
        "custody-generation" \
        "/var/db/fi/custody/generation" \
        "on" \
        "yes"

    zfs_apply_dataset \
        "$zfs_apply_root/recorded" \
        "recorded" \
        "/var/db/fi/custody/recorded" \
        "on" \
        "yes"

    zfs_apply_dataset \
        "$zfs_apply_root/ready" \
        "ready" \
        "/var/db/fi/custody/ready" \
        "on" \
        "yes"

    zfs_apply_dataset \
        "$zfs_apply_root/config" \
        "config-parent" \
        "none" \
        "off" \
        "no"

    zfs_apply_dataset \
        "$zfs_apply_root/config/receiver" \
        "config-receiver" \
        "/var/db/fi/config/receiver" \
        "on" \
        "yes"

    zfs_apply_dataset \
        "$zfs_apply_root/config/ingest" \
        "config-ingest" \
        "/var/db/fi/config/ingest" \
        "on" \
        "yes"

    zfs_apply_dataset \
        "$zfs_apply_root/sor" \
        "sor-parent" \
        "none" \
        "off" \
        "no"

    zfs_apply_dataset \
        "$zfs_apply_root/sor/postgres" \
        "sor-postgres" \
        "/var/db/fi/sor/postgres" \
        "on" \
        "yes"

    zfs_apply_dataset \
        "$zfs_apply_root/backups" \
        "backups" \
        "/var/db/fi/backups" \
        "on" \
        "yes"

    pass "FI production ZFS hierarchy apply complete"
}

zfs_apply_precheck_dataset()
{
    zfs_apply_precheck_name=$1
    zfs_apply_precheck_role=$2
    zfs_apply_precheck_mountpoint=$3
    zfs_apply_precheck_canmount=$4
    zfs_apply_precheck_mounted=$5

    zfs_apply_precheck_state=$(
        zfs_apply_classify_dataset \
            "$zfs_apply_precheck_name" \
            "$zfs_apply_precheck_role" \
            "$zfs_apply_precheck_mountpoint" \
            "$zfs_apply_precheck_canmount" \
            "$zfs_apply_precheck_mounted"
    ) || fail \
        "unable to classify FI ZFS dataset during precheck: $zfs_apply_precheck_name"

    case "$zfs_apply_precheck_state" in
        ABSENT)
            if [ "$zfs_apply_precheck_mountpoint" != "none" ]; then
                if \
                    [ -e "$zfs_apply_precheck_mountpoint" ] ||
                    [ -L "$zfs_apply_precheck_mountpoint" ]
                then
                    fail \
                        "FOREIGN_COLLISION: mountpoint path already exists before ZFS apply: $zfs_apply_precheck_mountpoint"
                fi
            fi

            pass "FI ZFS dataset ready to create: $zfs_apply_precheck_name"
            ;;
        OWNED_MATCH)
            pass "FI ZFS dataset precheck matches: $zfs_apply_precheck_name"
            ;;
        OWNED_DRIFT)
            fail \
                "OWNED_DRIFT: FI ZFS dataset differs from requested state: $zfs_apply_precheck_name"
            ;;
        FOREIGN_COLLISION)
            fail \
                "FOREIGN_COLLISION: ZFS dataset is not authoritatively FI-owned: $zfs_apply_precheck_name"
            ;;
        UNKNOWN)
            fail \
                "UNKNOWN: unable to establish safe ZFS dataset state: $zfs_apply_precheck_name"
            ;;
        *)
            fail \
                "invalid ZFS classification during precheck for $zfs_apply_precheck_name: $zfs_apply_precheck_state"
            ;;
    esac
}
zfs_apply_classify_dataset()
{
    zfs_apply_dataset=$1
    zfs_apply_role=$2
    zfs_apply_mountpoint=$3
    zfs_apply_canmount=$4
    zfs_apply_mounted=$5

    zfs_apply_dataset_exists "$zfs_apply_dataset"
    zfs_apply_rc=$?

    case "$zfs_apply_rc" in
        0)
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

    zfs_apply_local_property_status \
        "$zfs_apply_dataset" \
        "$FI_ZFS_MANAGED_PROPERTY" \
        "1"

    zfs_apply_rc=$?

    case "$zfs_apply_rc" in
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

    zfs_apply_required_state=$(
        zfs_apply_required_properties_state \
            "$zfs_apply_dataset" \
            "$FI_ZFS_SCHEMA_PROPERTY" "$FI_ZFS_SCHEMA_VERSION" \
            "$FI_ZFS_ROLE_PROPERTY" "$zfs_apply_role" \
            "mountpoint" "$zfs_apply_mountpoint" \
            "canmount" "$zfs_apply_canmount" \
            "atime" "off" \
            "exec" "off" \
            "setuid" "off" \
            "devices" "off"
    )

    zfs_apply_rc=$?

    case "$zfs_apply_rc" in
        0)
            ;;
        1|2)
            printf '%s\n' "$zfs_apply_required_state"
            return 0
            ;;
        *)
            printf '%s\n' "UNKNOWN"
            return 0
            ;;
    esac

    zfs_apply_runtime_property_status \
        "$zfs_apply_dataset" \
        "mounted" \
        "$zfs_apply_mounted"

    zfs_apply_rc=$?

    case "$zfs_apply_rc" in
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

    printf '%s\n' "OWNED_MATCH"
}

zfs_apply_create_dataset()
{
    zfs_apply_dataset=$1
    zfs_apply_role=$2
    zfs_apply_mountpoint=$3
    zfs_apply_canmount=$4

    if [ "$zfs_apply_mountpoint" != "none" ]; then
        if \
            [ -e "$zfs_apply_mountpoint" ] ||
            [ -L "$zfs_apply_mountpoint" ]
        then
            fail \
                "FOREIGN_COLLISION: mountpoint path already exists before ZFS creation: $zfs_apply_mountpoint"
        fi
    fi

    zfs create \
        -o "$FI_ZFS_MANAGED_PROPERTY=1" \
        -o "$FI_ZFS_SCHEMA_PROPERTY=$FI_ZFS_SCHEMA_VERSION" \
        -o "$FI_ZFS_ROLE_PROPERTY=$zfs_apply_role" \
        -o "mountpoint=$zfs_apply_mountpoint" \
        -o "canmount=$zfs_apply_canmount" \
        -o "atime=off" \
        -o "exec=off" \
        -o "setuid=off" \
        -o "devices=off" \
        "$zfs_apply_dataset" ||
        fail "unable to create FI ZFS dataset: $zfs_apply_dataset"

    pass "created FI ZFS dataset: $zfs_apply_dataset"
}

zfs_apply_dataset()
{
    zfs_apply_dataset_name=$1
    zfs_apply_dataset_role=$2
    zfs_apply_dataset_mountpoint=$3
    zfs_apply_dataset_canmount=$4
    zfs_apply_dataset_mounted=$5

    zfs_apply_state=$(
        zfs_apply_classify_dataset \
            "$zfs_apply_dataset_name" \
            "$zfs_apply_dataset_role" \
            "$zfs_apply_dataset_mountpoint" \
            "$zfs_apply_dataset_canmount" \
            "$zfs_apply_dataset_mounted"
    ) || fail "unable to classify FI ZFS dataset: $zfs_apply_dataset_name"

    case "$zfs_apply_state" in
        ABSENT)
            zfs_apply_create_dataset \
                "$zfs_apply_dataset_name" \
                "$zfs_apply_dataset_role" \
                "$zfs_apply_dataset_mountpoint" \
                "$zfs_apply_dataset_canmount"

            zfs_apply_post_state=$(
                zfs_apply_classify_dataset \
                    "$zfs_apply_dataset_name" \
                    "$zfs_apply_dataset_role" \
                    "$zfs_apply_dataset_mountpoint" \
                    "$zfs_apply_dataset_canmount" \
                    "$zfs_apply_dataset_mounted"
            ) || fail \
                "unable to verify newly created FI ZFS dataset: $zfs_apply_dataset_name"

            [ "$zfs_apply_post_state" = "OWNED_MATCH" ] ||
                fail \
                    "new FI ZFS dataset did not verify as OWNED_MATCH: $zfs_apply_dataset_name ($zfs_apply_post_state)"

            pass "verified FI ZFS dataset: $zfs_apply_dataset_name"
            ;;
        OWNED_MATCH)
            pass "FI ZFS dataset already matches: $zfs_apply_dataset_name"
            ;;
        OWNED_DRIFT)
            fail \
                "OWNED_DRIFT: FI ZFS dataset differs from requested state: $zfs_apply_dataset_name"
            ;;
        FOREIGN_COLLISION)
            fail \
                "FOREIGN_COLLISION: ZFS dataset is not authoritatively FI-owned: $zfs_apply_dataset_name"
            ;;
        UNKNOWN)
            fail \
                "UNKNOWN: unable to establish safe ZFS dataset state: $zfs_apply_dataset_name"
            ;;
        *)
            fail \
                "invalid ZFS classification for $zfs_apply_dataset_name: $zfs_apply_state"
            ;;
    esac
}

zfs_apply_dataset_exists()
{
    zfs_apply_dataset=$1

    zfs_apply_list=$(
        zfs list \
            -H \
            -t filesystem \
            -o name \
            2>/dev/null
    )

    zfs_apply_rc=$?

    [ "$zfs_apply_rc" -eq 0 ] ||
        return 2

    if printf '%s\n' "$zfs_apply_list" |
        grep -Fqx "$zfs_apply_dataset"
    then
        return 0
    fi

    return 1
}

zfs_apply_local_property_status()
{
    zfs_apply_dataset=$1
    zfs_apply_property=$2
    zfs_apply_expected=$3

    zfs_apply_result=$(
        zfs get \
            -H \
            -o value,source \
            "$zfs_apply_property" \
            "$zfs_apply_dataset" \
            2>/dev/null
    )

    zfs_apply_rc=$?

    [ "$zfs_apply_rc" -eq 0 ] ||
        return 2

    zfs_apply_actual_value=$(
        printf '%s\n' "$zfs_apply_result" |
            awk '{print $1}'
    )

    zfs_apply_actual_source=$(
        printf '%s\n' "$zfs_apply_result" |
            awk '{print $2}'
    )

    if \
        [ "$zfs_apply_actual_value" = "$zfs_apply_expected" ] &&
        [ "$zfs_apply_actual_source" = "local" ]
    then
        return 0
    fi

    return 1
}

zfs_apply_require_commands()
{
    for zfs_apply_required_command in \
        awk \
        grep \
        hostname \
        id \
        uname \
        zfs \
        zpool
    do
        require_command "$zfs_apply_required_command"
    done
}

zfs_apply_required_properties_state()
{
    zfs_apply_dataset=$1
    shift

    while [ "$#" -gt 0 ]; do
        [ "$#" -ge 2 ] || {
            printf '%s\n' "UNKNOWN"
            return 2
        }

        zfs_apply_property=$1
        zfs_apply_expected=$2
        shift 2

        zfs_apply_local_property_status \
            "$zfs_apply_dataset" \
            "$zfs_apply_property" \
            "$zfs_apply_expected"

        zfs_apply_rc=$?

        case "$zfs_apply_rc" in
            0)
                ;;
            1)
                printf '%s\n' "OWNED_DRIFT"
                return 1
                ;;
            *)
                printf '%s\n' "UNKNOWN"
                return 2
                ;;
        esac
    done

    return 0
}

zfs_apply_runtime_property_status()
{
    zfs_apply_dataset=$1
    zfs_apply_property=$2
    zfs_apply_expected=$3

    zfs_apply_actual=$(
        zfs get \
            -H \
            -o value \
            "$zfs_apply_property" \
            "$zfs_apply_dataset" \
            2>/dev/null
    )

    zfs_apply_rc=$?

    [ "$zfs_apply_rc" -eq 0 ] ||
        return 2

    [ "$zfs_apply_actual" = "$zfs_apply_expected" ]
}
