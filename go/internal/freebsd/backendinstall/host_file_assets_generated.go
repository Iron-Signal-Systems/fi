// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Code generated from accepted FreeBSD deployment assets. DO NOT EDIT.

package backendinstall

// Source: tools/deployment/freebsd/jail.conf.d/fi-receiver.conf.template
// SHA256: 7b6c768e214d75465e3268c04a3c96aa675db510398c5534134e950a4eef2192
const hostFileAssetReceiverJail = `# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: jail-config-receiver
fi-receiver {
    path = "@FI_RECEIVER_ROOT@";
    host.hostname = "fi-receiver";

    persist;

    exec.prestart = "/usr/local/libexec/fi-vnet-pair create-receiver @FI_RECEIVER_EXTERNAL_IF@ @FI_RECEIVER_EXTERNAL_BRIDGE@ @FI_RECEIVER_EXTERNAL_HOST_IF@ @FI_RECEIVER_EXTERNAL_JAIL_IF@ jail:fi-receiver:external @FI_RECEIVER_MGMT_HOST_IF@ @FI_RECEIVER_MGMT_JAIL_IF@ @FI_MGMT_BRIDGE@ jail:fi-receiver:mgmt @FI_RECEIVER_WORK_HOST_IF@ @FI_RECEIVER_WORK_JAIL_IF@ @FI_WORK_BRIDGE@ jail:fi-receiver:work";

    vnet;
    vnet.interface = "@FI_RECEIVER_EXTERNAL_JAIL_IF@";
    vnet.interface += "@FI_RECEIVER_MGMT_JAIL_IF@";
    vnet.interface += "@FI_RECEIVER_WORK_JAIL_IF@";

    exec.start = "/sbin/ifconfig @FI_RECEIVER_EXTERNAL_JAIL_IF@ inet @FI_RECEIVER_EXTERNAL_ADDRESS@ up";
    exec.start += "/sbin/ifconfig @FI_RECEIVER_MGMT_JAIL_IF@ inet @FI_RECEIVER_MGMT_ADDRESS@ up";
    exec.start += "/sbin/ifconfig @FI_RECEIVER_WORK_JAIL_IF@ inet @FI_RECEIVER_WORK_ADDRESS@ up";
    exec.start += "/sbin/route add default @FI_RECEIVER_EXTERNAL_GATEWAY@";
    exec.start += "/bin/sh /etc/rc";

    exec.stop = "/bin/sh /etc/rc.shutdown jail";

    exec.poststop = "/usr/local/libexec/fi-vnet-pair destroy-receiver @FI_RECEIVER_EXTERNAL_IF@ @FI_RECEIVER_EXTERNAL_BRIDGE@ @FI_RECEIVER_EXTERNAL_HOST_IF@ @FI_RECEIVER_EXTERNAL_JAIL_IF@ @FI_RECEIVER_MGMT_HOST_IF@ @FI_RECEIVER_MGMT_JAIL_IF@ @FI_MGMT_BRIDGE@ @FI_RECEIVER_WORK_HOST_IF@ @FI_RECEIVER_WORK_JAIL_IF@ @FI_WORK_BRIDGE@";

    exec.consolelog = "/var/log/jail_console_${name}.log";

    mount.fstab = "@FI_RECEIVER_FSTAB@";
    mount.devfs;
    devfs_ruleset = @FI_DEVFS_RULESET@;

    children.max = 0;
    enforce_statfs = 2;

    allow.nomount;
    allow.noraw_sockets;

    exec.clean;
}
`

// Source: tools/deployment/freebsd/jail.conf.d/fi-ingest.conf.template
// SHA256: df4dbb7079eab96829c96b5d2212367a90a604b85b848373bc156c0aa3b9c969
const hostFileAssetIngestJail = `# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: jail-config-ingest
fi-ingest {
    path = "@FI_INGEST_ROOT@";
    host.hostname = "fi-ingest";

    persist;

    exec.prestart = "/usr/local/libexec/fi-vnet-pair create-dual @FI_INGEST_MGMT_HOST_IF@ @FI_INGEST_MGMT_JAIL_IF@ @FI_MGMT_BRIDGE@ jail:fi-ingest:mgmt @FI_INGEST_WORK_HOST_IF@ @FI_INGEST_WORK_JAIL_IF@ @FI_WORK_BRIDGE@ jail:fi-ingest:work";

    vnet;
    vnet.interface = "@FI_INGEST_MGMT_JAIL_IF@";
    vnet.interface += "@FI_INGEST_WORK_JAIL_IF@";

    exec.start = "/sbin/ifconfig @FI_INGEST_MGMT_JAIL_IF@ inet @FI_INGEST_MGMT_ADDRESS@ up";
    exec.start += "/sbin/ifconfig @FI_INGEST_WORK_JAIL_IF@ inet @FI_INGEST_WORK_ADDRESS@ up";
    exec.start += "/sbin/route add default @FI_MGMT_GATEWAY@";
    exec.start += "/bin/sh /etc/rc";

    exec.stop = "/bin/sh /etc/rc.shutdown jail";

    exec.poststop = "/usr/local/libexec/fi-vnet-pair destroy-dual @FI_INGEST_MGMT_HOST_IF@ @FI_INGEST_MGMT_JAIL_IF@ @FI_MGMT_BRIDGE@ @FI_INGEST_WORK_HOST_IF@ @FI_INGEST_WORK_JAIL_IF@ @FI_WORK_BRIDGE@";

    exec.consolelog = "/var/log/jail_console_${name}.log";

    mount.fstab = "@FI_INGEST_FSTAB@";
    mount.devfs;
    devfs_ruleset = @FI_DEVFS_RULESET@;

    children.max = 0;
    enforce_statfs = 2;

    allow.nomount;
    allow.noraw_sockets;

    exec.clean;
}
`

// Source: tools/deployment/freebsd/jail.conf.d/fi-sor-db.conf.template
// SHA256: 8fcf27c2e4a975c36ed9d9341056d89fa8267529a9a434ab8378d3117a0f413c
const hostFileAssetSORJail = `# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: jail-config-sor-db
fi-sor-db {
    path = "@FI_SOR_DB_ROOT@";
    host.hostname = "fi-sor-db";

    persist;

    exec.prestart = "/usr/local/libexec/fi-vnet-pair create-dual @FI_SOR_DB_MGMT_HOST_IF@ @FI_SOR_DB_MGMT_JAIL_IF@ @FI_MGMT_BRIDGE@ jail:fi-sor-db:mgmt @FI_SOR_DB_WORK_HOST_IF@ @FI_SOR_DB_WORK_JAIL_IF@ @FI_WORK_BRIDGE@ jail:fi-sor-db:work";

    vnet;

    # PostgreSQL receives private, jail-local System V IPC namespaces.
    sysvmsg = new;
    sysvsem = new;
    sysvshm = new;
    vnet.interface = "@FI_SOR_DB_MGMT_JAIL_IF@";
    vnet.interface += "@FI_SOR_DB_WORK_JAIL_IF@";

    exec.start = "/sbin/ifconfig @FI_SOR_DB_MGMT_JAIL_IF@ inet @FI_SOR_DB_MGMT_ADDRESS@ up";
    exec.start += "/sbin/ifconfig @FI_SOR_DB_WORK_JAIL_IF@ inet @FI_SOR_DB_WORK_ADDRESS@ up";
    exec.start += "/sbin/route add default @FI_MGMT_GATEWAY@";
    exec.start += "/bin/sh /etc/rc";

    exec.stop = "/bin/sh /etc/rc.shutdown jail";

    exec.poststop = "/usr/local/libexec/fi-vnet-pair destroy-dual @FI_SOR_DB_MGMT_HOST_IF@ @FI_SOR_DB_MGMT_JAIL_IF@ @FI_MGMT_BRIDGE@ @FI_SOR_DB_WORK_HOST_IF@ @FI_SOR_DB_WORK_JAIL_IF@ @FI_WORK_BRIDGE@";

    exec.consolelog = "/var/log/jail_console_${name}.log";

    mount.fstab = "@FI_SOR_DB_FSTAB@";
    mount.devfs;
    devfs_ruleset = @FI_DEVFS_RULESET@;

    children.max = 0;
    enforce_statfs = 2;

    allow.nomount;
    allow.noraw_sockets;

    exec.clean;
}
`

// Source: tools/deployment/freebsd/fstab.d/fi-receiver.fstab.template
// SHA256: 452c651245b013e263e460751300d38be7464ad3b6a8c201ce91266610f73c62
const hostFileAssetReceiverFstab = `# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: fstab-receiver
# FI receiver host-controlled mounts.
#
# Tokens are rendered by deployment tooling before installation.
#
# source                                      destination                                                   type    opts  dump pass
@FI_CUSTODY_GENERATION_HOST@                  @FI_RECEIVER_ROOT@/var/db/fi/custody/generation               nullfs  rw    0    0
@FI_CUSTODY_TRANSPORT_HOST@                   @FI_RECEIVER_ROOT@/var/db/fi/custody/transport                nullfs  rw    0    0
@FI_RECORDED_HOST@                            @FI_RECEIVER_ROOT@/var/db/fi/custody/recorded                 nullfs  rw    0    0
@FI_READY_HOST@                               @FI_RECEIVER_ROOT@/var/db/fi/custody/ready                    nullfs  rw    0    0
@FI_RECEIVER_CONFIG_HOST@                     @FI_RECEIVER_ROOT@/usr/local/etc/fi                           nullfs  ro    0    0
`

// Source: tools/deployment/freebsd/fstab.d/fi-ingest.fstab.template
// SHA256: 415b631538254838234ef513c772d6f48602585853549173aa49541776046236
const hostFileAssetIngestFstab = `# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: fstab-ingest
# FI ingest host-controlled mounts.
#
# Tokens are rendered by deployment tooling before installation.
#
# source                                      destination                                                   type    opts  dump pass
@FI_CUSTODY_GENERATION_HOST@                  @FI_INGEST_ROOT@/var/db/fi/custody/generation                 nullfs  ro    0    0
@FI_RECORDED_HOST@                            @FI_INGEST_ROOT@/var/db/fi/custody/recorded                   nullfs  ro    0    0
@FI_READY_HOST@                               @FI_INGEST_ROOT@/var/db/fi/custody/ready                      nullfs  rw    0    0
@FI_INGEST_CONFIG_HOST@                       @FI_INGEST_ROOT@/usr/local/etc/fi                             nullfs  ro    0    0
`

// Source: tools/deployment/freebsd/fstab.d/fi-sor-db.fstab.template
// SHA256: 91d6d291437c84575b87d29340f1297d7ab16eab45751c3018fb494d892594ef
const hostFileAssetSORFstab = `# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: fstab-sor-db
# FI System of Record PostgreSQL host-controlled mount.
#
# Tokens are rendered by deployment tooling before installation.
#
# source                                      destination                                                   type    opts  dump pass
@FI_SOR_POSTGRES_HOST@                        @FI_SOR_DB_ROOT@/var/db/fi/sor/postgres                        nullfs  rw    0    0
`

// Source: tools/deployment/freebsd/devfs.d/fi-production.rules.template
// SHA256: 02429bd595052efb2eaae2180e58435c63dfd03c248ba5cf9cd612cb7cc943c1
const hostFileAssetDevfsRules = `# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: devfs-rules
#
# Dedicated FI production devfs rules.
# Loading/activation is controlled by the later lifecycle-policy layer.

[fi_production=@FI_DEVFS_RULESET@]
add hide
add path null unhide
add path zero unhide
add path random unhide
add path urandom unhide
`

// Source: tools/deployment/freebsd/fi-vnet-pair.sh
// SHA256: 01caa253d7e598793429dc9730be47aa91b342a9fb99e91230bb4d86e4802456
const hostFileAssetVNETHelper = `#!/bin/sh
# FI-MANAGED: ironsignal-fi-freebsd-host-file-v1
# FI-ROLE: vnet-helper

fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

vnet_interface_state()
{
    vnet_state_name=$1

    vnet_state_names=$(/sbin/ifconfig -l 2>/dev/null) ||
        return 2

    case " $vnet_state_names " in
        *" $vnet_state_name "*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

vnet_require_absent()
{
    vnet_absent_name=$1

    vnet_interface_state "$vnet_absent_name"
    vnet_absent_state=$?

    case "$vnet_absent_state" in
        0)
            printf '[FAIL] configured VNET interface already exists: %s\n' \
                "$vnet_absent_name" >&2
            return 1
            ;;
        1)
            return 0
            ;;
        *)
            printf '[FAIL] unable to inspect VNET interface namespace\n' >&2
            return 1
            ;;
    esac
}

vnet_require_bridge()
{
    vnet_bridge=$1

    /sbin/ifconfig "$vnet_bridge" >/dev/null 2>&1 || {
        printf '[FAIL] configured bridge does not exist: %s\n' \
            "$vnet_bridge" >&2
        return 1
    }

    return 0
}

vnet_require_dedicated_interface()
{
    vnet_dedicated_if=$1
    vnet_mgmt_bridge=$2
    vnet_work_bridge=$3

    /sbin/ifconfig "$vnet_dedicated_if" >/dev/null 2>&1 || {
        printf '[FAIL] dedicated VNET interface does not exist: %s\n' \
            "$vnet_dedicated_if" >&2
        return 1
    }

    if /sbin/ifconfig "$vnet_dedicated_if" |
        /usr/bin/awk '
            $1 == "inet" || $1 == "inet6" {
                found = 1
            }

            END {
                exit found ? 0 : 1
            }
        '
    then
        printf '[FAIL] dedicated VNET interface has a host address: %s\n' \
            "$vnet_dedicated_if" >&2
        return 1
    fi

    for vnet_dedicated_bridge in \
        "$vnet_mgmt_bridge" \
        "$vnet_work_bridge"
    do
        vnet_require_bridge "$vnet_dedicated_bridge" || return 1

        if /sbin/ifconfig "$vnet_dedicated_bridge" |
            /usr/bin/awk -v interface="$vnet_dedicated_if" '
                $1 == "member:" && $2 == interface {
                    found = 1
                }

                END {
                    exit found ? 0 : 1
                }
            '
        then
            printf '[FAIL] dedicated VNET interface is a member of %s: %s\n' \
                "$vnet_dedicated_bridge" \
                "$vnet_dedicated_if" >&2
            return 1
        fi
    done

    printf '[PASS] dedicated VNET interface ready: %s\n' \
        "$vnet_dedicated_if"

    return 0
}

vnet_create_pair()
{
    vnet_host_if=$1
    vnet_jail_if=$2
    vnet_bridge=$3
    vnet_description=$4

    vnet_require_absent "$vnet_host_if" || return 1
    vnet_require_absent "$vnet_jail_if" || return 1
    vnet_require_bridge "$vnet_bridge" || return 1

    vnet_created=$(/sbin/ifconfig epair create) || {
        printf '[FAIL] unable to create epair\n' >&2
        return 1
    }

    case "$vnet_created" in
        epair*a)
            ;;
        *)
            /sbin/ifconfig "$vnet_created" destroy >/dev/null 2>&1 || true
            printf '[FAIL] unexpected epair clone name: %s\n' \
                "$vnet_created" >&2
            return 1
            ;;
    esac

    vnet_peer=${vnet_created%a}b

    /sbin/ifconfig "$vnet_peer" name "$vnet_jail_if" || {
        /sbin/ifconfig "$vnet_created" destroy >/dev/null 2>&1 || true
        printf '[FAIL] unable to rename jail-side epair to %s\n' \
            "$vnet_jail_if" >&2
        return 1
    }

    /sbin/ifconfig "$vnet_created" name "$vnet_host_if" || {
        /sbin/ifconfig "$vnet_jail_if" destroy >/dev/null 2>&1 || true
        printf '[FAIL] unable to rename host-side epair to %s\n' \
            "$vnet_host_if" >&2
        return 1
    }

    /sbin/ifconfig "$vnet_host_if" up descr "$vnet_description" || {
        /sbin/ifconfig "$vnet_host_if" destroy >/dev/null 2>&1 || true
        printf '[FAIL] unable to configure host-side epair: %s\n' \
            "$vnet_host_if" >&2
        return 1
    }

    /sbin/ifconfig "$vnet_bridge" addm "$vnet_host_if" up || {
        /sbin/ifconfig "$vnet_host_if" destroy >/dev/null 2>&1 || true
        printf '[FAIL] unable to attach %s to %s\n' \
            "$vnet_host_if" "$vnet_bridge" >&2
        return 1
    }

    printf '[PASS] VNET pair created: %s / %s -> %s\n' \
        "$vnet_host_if" \
        "$vnet_jail_if" \
        "$vnet_bridge"

    return 0
}

vnet_destroy_pair()
{
    vnet_host_if=$1
    vnet_jail_if=$2
    vnet_bridge=$3

    vnet_interface_state "$vnet_host_if"
    vnet_host_state=$?

    case "$vnet_host_state" in
        0)
            ;;
        1)
            vnet_interface_state "$vnet_jail_if"
            vnet_jail_state=$?

            case "$vnet_jail_state" in
                0)
                    printf '[FAIL] host VNET endpoint absent while jail endpoint remains: %s\n' \
                        "$vnet_jail_if" >&2
                    return 1
                    ;;
                1)
                    printf '[PASS] VNET pair already absent: %s / %s\n' \
                        "$vnet_host_if" "$vnet_jail_if"
                    return 0
                    ;;
                *)
                    printf '[FAIL] unable to inspect VNET interface namespace\n' >&2
                    return 1
                    ;;
            esac
            ;;
        *)
            printf '[FAIL] unable to inspect VNET interface namespace\n' >&2
            return 1
            ;;
    esac

    /sbin/ifconfig "$vnet_bridge" deletem "$vnet_host_if" \
        >/dev/null 2>&1 || true

    /sbin/ifconfig "$vnet_host_if" destroy || {
        printf '[FAIL] unable to destroy VNET pair through %s\n' \
            "$vnet_host_if" >&2
        return 1
    }

    vnet_interface_state "$vnet_jail_if"
    vnet_jail_state=$?

    case "$vnet_jail_state" in
        1)
            ;;
        0)
            printf '[FAIL] jail VNET endpoint remained after pair destruction: %s\n' \
                "$vnet_jail_if" >&2
            return 1
            ;;
        *)
            printf '[FAIL] unable to verify VNET pair destruction\n' >&2
            return 1
            ;;
    esac

    printf '[PASS] VNET pair removed: %s / %s\n' \
        "$vnet_host_if" "$vnet_jail_if"

    return 0
}

vnet_create_dual()
{
    vnet_mgmt_host=$1
    vnet_mgmt_jail=$2
    vnet_mgmt_bridge=$3
    vnet_mgmt_description=$4
    vnet_work_host=$5
    vnet_work_jail=$6
    vnet_work_bridge=$7
    vnet_work_description=$8

    # Layer-wide preclassification before the first mutation.
    vnet_require_absent "$vnet_mgmt_host" || return 1
    vnet_require_absent "$vnet_mgmt_jail" || return 1
    vnet_require_absent "$vnet_work_host" || return 1
    vnet_require_absent "$vnet_work_jail" || return 1
    vnet_require_bridge "$vnet_mgmt_bridge" || return 1
    vnet_require_bridge "$vnet_work_bridge" || return 1

    vnet_create_pair \
        "$vnet_mgmt_host" \
        "$vnet_mgmt_jail" \
        "$vnet_mgmt_bridge" \
        "$vnet_mgmt_description" ||
        return 1

    if ! vnet_create_pair \
        "$vnet_work_host" \
        "$vnet_work_jail" \
        "$vnet_work_bridge" \
        "$vnet_work_description"
    then
        printf '[INFO] rolling back management VNET pair after workload failure\n' >&2

        vnet_destroy_pair \
            "$vnet_mgmt_host" \
            "$vnet_mgmt_jail" \
            "$vnet_mgmt_bridge" \
            >/dev/null 2>&1 || true

        return 1
    fi

    printf '[PASS] dual VNET provisioning complete\n'
}

vnet_create_external()
{
    vnet_external_physical=$1
    vnet_external_bridge=$2
    vnet_external_host=$3
    vnet_external_jail=$4
    vnet_external_description=$5

    vnet_require_absent "$vnet_external_bridge" || return 1
    vnet_require_absent "$vnet_external_host" || return 1
    vnet_require_absent "$vnet_external_jail" || return 1

    /sbin/ifconfig "$vnet_external_bridge" create || {
        printf '[FAIL] unable to create external bridge: %s\n' \
            "$vnet_external_bridge" >&2
        return 1
    }

    /sbin/ifconfig "$vnet_external_physical" up || {
        /sbin/ifconfig "$vnet_external_bridge" destroy \
            >/dev/null 2>&1 || true
        printf '[FAIL] unable to bring external interface up: %s\n' \
            "$vnet_external_physical" >&2
        return 1
    }

    /sbin/ifconfig "$vnet_external_bridge" \
        addm "$vnet_external_physical" up || {
        /sbin/ifconfig "$vnet_external_bridge" destroy \
            >/dev/null 2>&1 || true
        printf '[FAIL] unable to attach %s to %s\n' \
            "$vnet_external_physical" \
            "$vnet_external_bridge" >&2
        return 1
    }

    if ! vnet_create_pair \
        "$vnet_external_host" \
        "$vnet_external_jail" \
        "$vnet_external_bridge" \
        "$vnet_external_description"
    then
        /sbin/ifconfig "$vnet_external_bridge" \
            deletem "$vnet_external_physical" \
            >/dev/null 2>&1 || true

        /sbin/ifconfig "$vnet_external_bridge" destroy \
            >/dev/null 2>&1 || true

        return 1
    fi

    printf '[PASS] receiver external bridge provisioning complete\n'
}

vnet_create_receiver()
{
    vnet_receiver_external=$1
    vnet_receiver_external_bridge=$2
    vnet_receiver_external_host=$3
    vnet_receiver_external_jail=$4
    vnet_receiver_external_description=$5
    vnet_receiver_mgmt_host=$6
    vnet_receiver_mgmt_jail=$7
    vnet_receiver_mgmt_bridge=$8
    vnet_receiver_mgmt_description=$9
    vnet_receiver_work_host=${10}
    vnet_receiver_work_jail=${11}
    vnet_receiver_work_bridge=${12}
    vnet_receiver_work_description=${13}

    # Classify the complete receiver network layer before first mutation.
    vnet_require_dedicated_interface \
        "$vnet_receiver_external" \
        "$vnet_receiver_mgmt_bridge" \
        "$vnet_receiver_work_bridge" ||
        return 1

    vnet_require_absent "$vnet_receiver_external_bridge" || return 1
    vnet_require_absent "$vnet_receiver_external_host" || return 1
    vnet_require_absent "$vnet_receiver_external_jail" || return 1

    vnet_require_absent "$vnet_receiver_mgmt_host" || return 1
    vnet_require_absent "$vnet_receiver_mgmt_jail" || return 1
    vnet_require_absent "$vnet_receiver_work_host" || return 1
    vnet_require_absent "$vnet_receiver_work_jail" || return 1

    vnet_require_bridge "$vnet_receiver_mgmt_bridge" || return 1
    vnet_require_bridge "$vnet_receiver_work_bridge" || return 1

    vnet_create_external \
        "$vnet_receiver_external" \
        "$vnet_receiver_external_bridge" \
        "$vnet_receiver_external_host" \
        "$vnet_receiver_external_jail" \
        "$vnet_receiver_external_description" ||
        return 1

    if ! vnet_create_dual \
        "$vnet_receiver_mgmt_host" \
        "$vnet_receiver_mgmt_jail" \
        "$vnet_receiver_mgmt_bridge" \
        "$vnet_receiver_mgmt_description" \
        "$vnet_receiver_work_host" \
        "$vnet_receiver_work_jail" \
        "$vnet_receiver_work_bridge" \
        "$vnet_receiver_work_description"
    then
        printf '[INFO] rolling back receiver external network after dual VNET failure\n' >&2

        vnet_destroy_external \
            "$vnet_receiver_external" \
            "$vnet_receiver_external_bridge" \
            "$vnet_receiver_external_host" \
            "$vnet_receiver_external_jail" \
            >/dev/null 2>&1 || true

        return 1
    fi

    printf '[PASS] receiver VNET provisioning complete\n'
}

vnet_destroy_dual()
{
    vnet_mgmt_host=$1
    vnet_mgmt_jail=$2
    vnet_mgmt_bridge=$3
    vnet_work_host=$4
    vnet_work_jail=$5
    vnet_work_bridge=$6

    vnet_destroy_status=0

    vnet_destroy_pair \
        "$vnet_work_host" \
        "$vnet_work_jail" \
        "$vnet_work_bridge" ||
        vnet_destroy_status=1

    vnet_destroy_pair \
        "$vnet_mgmt_host" \
        "$vnet_mgmt_jail" \
        "$vnet_mgmt_bridge" ||
        vnet_destroy_status=1

    [ "$vnet_destroy_status" -eq 0 ]
}

vnet_destroy_external()
{
    vnet_external_physical=$1
    vnet_external_bridge=$2
    vnet_external_host=$3
    vnet_external_jail=$4

    vnet_external_destroy_status=0

    vnet_interface_state "$vnet_external_bridge"
    vnet_external_bridge_state=$?

    case "$vnet_external_bridge_state" in
        0)
            vnet_destroy_pair \
                "$vnet_external_host" \
                "$vnet_external_jail" \
                "$vnet_external_bridge" ||
                vnet_external_destroy_status=1

            /sbin/ifconfig "$vnet_external_bridge" \
                deletem "$vnet_external_physical" \
                >/dev/null 2>&1 || true

            /sbin/ifconfig "$vnet_external_bridge" destroy || {
                printf '[FAIL] unable to destroy external bridge: %s\n' \
                    "$vnet_external_bridge" >&2
                vnet_external_destroy_status=1
            }
            ;;
        1)
            vnet_interface_state "$vnet_external_host"
            vnet_external_host_state=$?

            vnet_interface_state "$vnet_external_jail"
            vnet_external_jail_state=$?

            if [ "$vnet_external_host_state" -eq 0 ] ||
                [ "$vnet_external_jail_state" -eq 0 ]
            then
                printf '[FAIL] external bridge absent while receiver epair remains\n' >&2
                vnet_external_destroy_status=1
            else
                printf '[PASS] receiver external bridge already absent: %s\n' \
                    "$vnet_external_bridge"
            fi
            ;;
        *)
            printf '[FAIL] unable to inspect receiver external bridge\n' >&2
            vnet_external_destroy_status=1
            ;;
    esac

    /sbin/ifconfig "$vnet_external_physical" >/dev/null 2>&1 || {
        printf '[FAIL] receiver external physical interface is absent: %s\n' \
            "$vnet_external_physical" >&2
        vnet_external_destroy_status=1
    }

    [ "$vnet_external_destroy_status" -eq 0 ]
}

vnet_destroy_receiver()
{
    vnet_receiver_external=$1
    vnet_receiver_external_bridge=$2
    vnet_receiver_external_host=$3
    vnet_receiver_external_jail=$4
    vnet_receiver_mgmt_host=$5
    vnet_receiver_mgmt_jail=$6
    vnet_receiver_mgmt_bridge=$7
    vnet_receiver_work_host=$8
    vnet_receiver_work_jail=$9
    vnet_receiver_work_bridge=${10}

    vnet_receiver_destroy_status=0

    vnet_destroy_dual \
        "$vnet_receiver_mgmt_host" \
        "$vnet_receiver_mgmt_jail" \
        "$vnet_receiver_mgmt_bridge" \
        "$vnet_receiver_work_host" \
        "$vnet_receiver_work_jail" \
        "$vnet_receiver_work_bridge" ||
        vnet_receiver_destroy_status=1

    vnet_destroy_external \
        "$vnet_receiver_external" \
        "$vnet_receiver_external_bridge" \
        "$vnet_receiver_external_host" \
        "$vnet_receiver_external_jail" ||
        vnet_receiver_destroy_status=1

    vnet_require_dedicated_interface \
        "$vnet_receiver_external" \
        "$vnet_receiver_mgmt_bridge" \
        "$vnet_receiver_work_bridge" ||
        vnet_receiver_destroy_status=1

    [ "$vnet_receiver_destroy_status" -eq 0 ] &&
        printf '[PASS] receiver VNET cleanup complete\n'

    [ "$vnet_receiver_destroy_status" -eq 0 ]
}

[ "$(id -u)" -eq 0 ] ||
    fail "VNET provisioning must run as root"

[ "$(uname -s)" = "FreeBSD" ] ||
    fail "VNET provisioning requires FreeBSD"

[ "$#" -ge 1 ] ||
    fail "usage: fi-vnet-pair.sh create-dual|create-receiver|destroy-dual|destroy-receiver ..."

case "$1" in
    create-dual)
        [ "$#" -eq 9 ] ||
            fail "create-dual requires management and workload endpoint definitions"

        vnet_create_dual \
            "$2" "$3" "$4" "$5" \
            "$6" "$7" "$8" "$9" ||
            fail "dual VNET provisioning failed"
        ;;

    create-receiver)
        [ "$#" -eq 14 ] ||
            fail "create-receiver requires external, management, and workload endpoint definitions"

        vnet_create_receiver \
            "$2" "$3" "$4" "$5" "$6" \
            "$7" "$8" "$9" "${10}" \
            "${11}" "${12}" "${13}" "${14}" ||
            fail "receiver VNET provisioning failed"
        ;;

    destroy-dual)
        [ "$#" -eq 7 ] ||
            fail "destroy-dual requires management and workload endpoint definitions"

        vnet_destroy_dual \
            "$2" "$3" "$4" \
            "$5" "$6" "$7" ||
            fail "dual VNET cleanup failed"
        ;;

    destroy-receiver)
        [ "$#" -eq 11 ] ||
            fail "destroy-receiver requires external, management, and workload endpoint definitions"

        vnet_destroy_receiver \
            "$2" "$3" "$4" "$5" \
            "$6" "$7" "$8" \
            "$9" "${10}" "${11}" ||
            fail "receiver VNET cleanup failed"
        ;;

    *)
        fail "unsupported VNET operation: $1"
        ;;
esac
`
