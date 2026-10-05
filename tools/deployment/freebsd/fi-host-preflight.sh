# FI FreeBSD host-state preflight helpers.
#
# This file is trusted program code sourced by fi-bootstrap.sh only for the
# preflight command. Deployment configuration remains strict parsed data and is
# never sourced as shell code.

preflight_require_commands()
{
    for preflight_required_command in \
        devfs \
        freebsd-version \
        hostname \
        getent \
        id \
        ifconfig \
        jls \
        pfctl \
        sysctl \
        sysrc \
        uname \
        zfs \
        zpool
    do
        require_command "$preflight_required_command"
    done
}

preflight_ipv4_in_network()
{
    preflight_network=$1
    preflight_address=$2

    awk \
        -v network="$preflight_network" \
        -v address="$preflight_address" '
        BEGIN {
            split(network, network_parts, "/")
            split(address, address_octets, ".")
            split(network_parts[1], network_octets, ".")

            prefix = network_parts[2]
            block = 2 ^ (32 - prefix)

            network_number = \
                (network_octets[1] * 16777216) + \
                (network_octets[2] * 65536) + \
                (network_octets[3] * 256) + \
                network_octets[4]

            address_number = \
                (address_octets[1] * 16777216) + \
                (address_octets[2] * 65536) + \
                (address_octets[3] * 256) + \
                address_octets[4]

            if (int(network_number / block) != int(address_number / block)) {
                exit 1
            }

            exit 0
        }
    ' </dev/null
}

preflight_bridge()
{
    preflight_bridge_key=$1
    preflight_network_key=$2

    preflight_bridge_name=$(get_value "$preflight_bridge_key")
    preflight_network_value=$(get_value "$preflight_network_key")

    ifconfig "$preflight_bridge_name" >/dev/null 2>&1 ||
        fail "configured bridge does not exist: $preflight_bridge_name"

    ifconfig "$preflight_bridge_name" |
        grep -Eq '^[[:space:]]*groups:.*bridge' ||
        fail "configured interface is not a bridge: $preflight_bridge_name"

    preflight_bridge_match=0

    for preflight_bridge_address in $(
        ifconfig "$preflight_bridge_name" |
            awk '$1 == "inet" { print $2 }'
    )
    do
        if preflight_ipv4_in_network \
            "$preflight_network_value" \
            "$preflight_bridge_address"
        then
            preflight_bridge_match=1
            break
        fi
    done

    [ "$preflight_bridge_match" -eq 1 ] ||
        fail "bridge $preflight_bridge_name has no IPv4 address in $preflight_network_value"

    pass "bridge $preflight_bridge_name matches $preflight_network_value"
}

preflight_dataset_absent()
{
    preflight_dataset=$1

    if zfs list -H -o name "$preflight_dataset" >/dev/null 2>&1; then
        fail "planned deployment dataset already exists: $preflight_dataset"
    fi

    pass "dataset name available: $preflight_dataset"
}

preflight_interface_absent()
{
    preflight_interface=$1

    if ifconfig "$preflight_interface" >/dev/null 2>&1; then
        fail "planned VNET interface already exists: $preflight_interface"
    fi

    pass "interface name available: $preflight_interface"
}

preflight_jail_absent()
{
    preflight_jail=$1

    if jls -j "$preflight_jail" >/dev/null 2>&1; then
        fail "planned production jail is already running: $preflight_jail"
    fi

    pass "jail name available: $preflight_jail"
}

preflight_path_absent()
{
    preflight_path=$1

    if [ -e "$preflight_path" ] || [ -L "$preflight_path" ]; then
        fail "planned deployment path already exists: $preflight_path"
    fi

    pass "path available: $preflight_path"
}

preflight_host()
{
    [ "$(id -u)" -eq 0 ] ||
        fail "preflight must run as root on the intended FreeBSD host"

    [ "$(uname -s)" = "FreeBSD" ] ||
        fail "preflight requires a FreeBSD host"

    preflight_expected_hostname=$(get_value FI_HOSTNAME)
    preflight_actual_hostname=$(hostname)

    [ "$preflight_actual_hostname" = "$preflight_expected_hostname" ] ||
        fail \
            "deployment hostname mismatch: expected $preflight_expected_hostname, observed $preflight_actual_hostname"

    pass "deployment hostname matches: $preflight_actual_hostname"

    preflight_zpool=$(get_value FI_ZPOOL)

    zpool list -H -o name "$preflight_zpool" >/dev/null 2>&1 ||
        fail "configured ZFS pool does not exist: $preflight_zpool"

    pass "ZFS pool exists: $preflight_zpool"

    preflight_jail_dataset_root=$(get_value FI_JAIL_DATASET_ROOT)
    preflight_jail_root_base=$(get_value FI_JAIL_ROOT_BASE)

    zfs list -H -o name "$preflight_jail_dataset_root" >/dev/null 2>&1 ||
        fail "configured jail dataset root does not exist: $preflight_jail_dataset_root"

    preflight_actual_mountpoint=$(
        zfs get -H -o value mountpoint "$preflight_jail_dataset_root"
    ) ||
        fail "unable to inspect jail dataset root mountpoint"

    [ "$preflight_actual_mountpoint" = "$preflight_jail_root_base" ] ||
        fail "jail dataset root mountpoint mismatch: expected $preflight_jail_root_base, found $preflight_actual_mountpoint"

    pass "jail dataset root and mountpoint match"

    preflight_snapshot=$(get_value FI_JAIL_TEMPLATE_SNAPSHOT)

    zfs list -H -t snapshot -o name "$preflight_snapshot" >/dev/null 2>&1 ||
        fail "configured jail template snapshot does not exist: $preflight_snapshot"

    preflight_template_dataset=${preflight_snapshot%@*}

    preflight_template_readonly=$(
        zfs get -H -o value readonly "$preflight_template_dataset"
    ) ||
        fail "unable to inspect jail template readonly property"

    [ "$preflight_template_readonly" = "on" ] ||
        fail "jail template dataset is not readonly: $preflight_template_dataset"

    preflight_host_release=$(freebsd-version)
    preflight_host_release_base=${preflight_host_release%%-p*}
    preflight_template_release=${preflight_template_dataset##*/}

    [ "$preflight_host_release_base" = "$preflight_template_release" ] ||
        fail "host/template release mismatch: host $preflight_host_release, template $preflight_template_release"

    pass "template snapshot exists, is readonly, and matches host release"

    preflight_fi_dataset_root="${preflight_zpool}/fi"

    zfs list -H -o name "$preflight_fi_dataset_root" >/dev/null 2>&1 ||
        fail "FI dataset root does not exist: $preflight_fi_dataset_root"

    preflight_fi_mountpoint=$(
        zfs get -H -o value mountpoint "$preflight_fi_dataset_root"
    ) ||
        fail "unable to inspect FI dataset root mountpoint"

    [ "$preflight_fi_mountpoint" = "/var/db/fi" ] ||
        fail "FI dataset root must mount at /var/db/fi: found $preflight_fi_mountpoint"

    pass "FI dataset root exists at /var/db/fi"

    [ "$(sysrc -n pf_enable 2>/dev/null)" = "YES" ] ||
        fail "PF is not enabled persistently"

    pfctl -s info 2>/dev/null |
        grep -Eq '^Status:[[:space:]]+Enabled' ||
        fail "PF is not enabled at runtime"

    [ "$(sysrc -n gateway_enable 2>/dev/null)" = "YES" ] ||
        fail "IPv4 forwarding is not enabled persistently"

    [ "$(sysctl -n net.inet.ip.forwarding)" -eq 1 ] ||
        fail "IPv4 forwarding is not enabled at runtime"

    pass "PF and IPv4 forwarding are enabled persistently and at runtime"

    preflight_cloned_interfaces=$(
        sysrc -n cloned_interfaces 2>/dev/null
    )

    for preflight_bridge_key in FI_MGMT_BRIDGE FI_WORK_BRIDGE
    do
        preflight_bridge_name=$(get_value "$preflight_bridge_key")

        case " $preflight_cloned_interfaces " in
            *" $preflight_bridge_name "*)
                ;;
            *)
                fail "configured bridge is not persistent in cloned_interfaces: $preflight_bridge_name"
                ;;
        esac
    done

    pass "configured bridges are persistent"

    preflight_bridge FI_MGMT_BRIDGE FI_MGMT_NETWORK
    preflight_bridge FI_WORK_BRIDGE FI_WORK_NETWORK

    [ -f /etc/jail.conf ] ||
        fail "/etc/jail.conf is absent"

    grep -Eq \
        '^[[:space:]]*\.include[[:space:]]+"/etc/jail\.conf\.d/\*\.conf";[[:space:]]*$' \
        /etc/jail.conf ||
        fail "/etc/jail.conf does not include /etc/jail.conf.d/*.conf"

    pass "jail configuration include is present"

    printf '[INFO] current jail_enable=%s; production boot policy is not applied by preflight\n' \
        "$(sysrc -n jail_enable 2>/dev/null || printf 'not_set')"

    preflight_uid=$(get_value FI_RUNTIME_UID)
    preflight_gid=$(get_value FI_RUNTIME_GID)

    if getent passwd "$preflight_uid" >/dev/null 2>&1; then
        fail "configured FI runtime UID is already allocated: $preflight_uid"
    fi

    if getent group "$preflight_gid" >/dev/null 2>&1; then
        fail "configured FI runtime GID is already allocated: $preflight_gid"
    fi

    pass "configured FI runtime UID/GID are available"

    preflight_devfs_ruleset=$(get_value FI_DEVFS_RULESET)

    preflight_devfs_sets=$(devfs rule showsets 2>/dev/null) ||
        fail "unable to inspect existing devfs rulesets"

    if printf "%s\n" "$preflight_devfs_sets" |
        grep -qx "$preflight_devfs_ruleset"
    then
        fail "configured FI production devfs ruleset already exists: $preflight_devfs_ruleset"
    fi

    pass "configured FI production devfs ruleset number is available"

    for preflight_jail in fi-receiver fi-ingest fi-sor-db
    do
        preflight_jail_absent "$preflight_jail"
    done

    for preflight_root_key in \
        FI_RECEIVER_ROOT \
        FI_INGEST_ROOT \
        FI_SOR_DB_ROOT
    do
        preflight_path_absent "$(get_value "$preflight_root_key")"
    done

    for preflight_jail_dataset in \
        "$preflight_jail_dataset_root/fi-receiver" \
        "$preflight_jail_dataset_root/fi-ingest" \
        "$preflight_jail_dataset_root/fi-sor-db"
    do
        preflight_dataset_absent "$preflight_jail_dataset"
    done

    for preflight_config_path in \
        /etc/jail.conf.d/fi-receiver.conf \
        /etc/jail.conf.d/fi-ingest.conf \
        /etc/jail.conf.d/fi-sor-db.conf
    do
        preflight_path_absent "$preflight_config_path"
    done

    for preflight_fstab_key in \
        FI_RECEIVER_FSTAB \
        FI_INGEST_FSTAB \
        FI_SOR_DB_FSTAB
    do
        preflight_path_absent "$(get_value "$preflight_fstab_key")"
    done

    for preflight_host_file_path in \
        /etc/devfs.rules.fi \
        /usr/local/libexec/fi-vnet-pair
    do
        preflight_path_absent "$preflight_host_file_path"
    done

    for preflight_storage_key in \
        FI_CUSTODY_GENERATION_HOST \
        FI_CUSTODY_TRANSPORT_HOST \
        FI_RECORDED_HOST \
        FI_READY_HOST \
        FI_RECEIVER_CONFIG_HOST \
        FI_INGEST_CONFIG_HOST \
        FI_SOR_POSTGRES_HOST
    do
        preflight_path_absent "$(get_value "$preflight_storage_key")"
    done

    preflight_path_absent "$preflight_fi_mountpoint/backups"

    for preflight_storage_dataset in \
        "$preflight_fi_dataset_root/custody" \
        "$preflight_fi_dataset_root/custody/generation" \
        "$preflight_fi_dataset_root/custody/transport" \
        "$preflight_fi_dataset_root/recorded" \
        "$preflight_fi_dataset_root/ready" \
        "$preflight_fi_dataset_root/config" \
        "$preflight_fi_dataset_root/config/receiver" \
        "$preflight_fi_dataset_root/config/ingest" \
        "$preflight_fi_dataset_root/sor" \
        "$preflight_fi_dataset_root/sor/postgres" \
        "$preflight_fi_dataset_root/backups"
    do
        preflight_dataset_absent "$preflight_storage_dataset"
    done

    for preflight_interface_key in \
        FI_RECEIVER_EXTERNAL_BRIDGE \
        FI_RECEIVER_EXTERNAL_HOST_IF \
        FI_RECEIVER_EXTERNAL_JAIL_IF \
        FI_RECEIVER_MGMT_HOST_IF \
        FI_RECEIVER_MGMT_JAIL_IF \
        FI_RECEIVER_WORK_HOST_IF \
        FI_RECEIVER_WORK_JAIL_IF \
        FI_INGEST_MGMT_HOST_IF \
        FI_INGEST_MGMT_JAIL_IF \
        FI_INGEST_WORK_HOST_IF \
        FI_INGEST_WORK_JAIL_IF \
        FI_SOR_DB_MGMT_HOST_IF \
        FI_SOR_DB_MGMT_JAIL_IF \
        FI_SOR_DB_WORK_HOST_IF \
        FI_SOR_DB_WORK_JAIL_IF
    do
        preflight_interface_absent "$(get_value "$preflight_interface_key")"
    done

    pass "FI FreeBSD host preflight complete"
}
