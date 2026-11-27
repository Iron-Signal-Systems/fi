// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Code generated from accepted FreeBSD lifecycle templates. DO NOT EDIT.

package backendinstall

// Source: tools/deployment/freebsd/lifecycle.d/devfs.rc.conf.template
// SHA256: e80d4d102ee44a0c45fa2d96f74b5df439e998862bd10586394b14c7976817ed
const lifecycleAssetDevfsRC = `# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1
# FI-ROLE: devfs-boot-policy

devfs_load_rulesets="YES"

case " ${devfs_rulesets} " in
    *" /etc/devfs.rules.fi "*)
        ;;
    *)
        devfs_rulesets="${devfs_rulesets} /etc/devfs.rules.fi"
        ;;
esac
`

// Source: tools/deployment/freebsd/lifecycle.d/fi-jails.rc.conf.template
// SHA256: 4ef8265a2b82890952b93f97ebd22c462f09db318bb7a38ed8cffe65390ccbcc
const lifecycleAssetFIJailsRC = `# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1
# FI-ROLE: fi-jails-enable-policy

fi_jails_enable="YES"
`

// Source: tools/deployment/freebsd/lifecycle.d/fi-jails.rc.d.template
// SHA256: fe3f71ff9f4255c128e4a7b8a74a952edc45e7494b5a00cb908b700c9148d926
const lifecycleAssetFIJailsService = `#!/bin/sh

# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1
# FI-ROLE: fi-jails-controller
#
# PROVIDE: fi_jails
# REQUIRE: jail fi_pf
# BEFORE: securelevel
# KEYWORD: shutdown

. /etc/rc.subr

name="fi_jails"
desc="FI production jail lifecycle"
rcvar="fi_jails_enable"

start_cmd="fi_jails_start"
stop_cmd="fi_jails_stop"
status_cmd="fi_jails_status"
extra_commands="status"

: ${fi_jails_enable:="NO"}

fi_jails_is_running()
{
    /usr/sbin/jls -j "$1" >/dev/null 2>&1
}

fi_jails_start_one()
{
    fi_jail_name=$1

    if fi_jails_is_running "$fi_jail_name"; then
        echo "$fi_jail_name already running"
        return 0
    fi

    /etc/rc.d/jail onestart "$fi_jail_name"

    if ! fi_jails_is_running "$fi_jail_name"; then
        warn "FI production jail failed to start: $fi_jail_name"
        return 1
    fi

    return 0
}

fi_jails_stop_one()
{
    fi_jail_name=$1

    if ! fi_jails_is_running "$fi_jail_name"; then
        echo "$fi_jail_name already stopped"
        return 0
    fi

    /etc/rc.d/jail onestop "$fi_jail_name"

    if fi_jails_is_running "$fi_jail_name"; then
        warn "FI production jail failed to stop: $fi_jail_name"
        return 1
    fi

    return 0
}

fi_jails_pf_ready()
{
    /usr/local/etc/rc.d/fi_pf onestatus >/dev/null 2>&1
}

fi_jails_start()
{
    if ! fi_jails_pf_ready; then
        warn "FI PF runtime policy is not ready; production jails will not start"
        return 1
    fi

    for fi_jail_name in \
        fi-sor-db \
        fi-ingest \
        fi-receiver
    do
        fi_jails_start_one "$fi_jail_name" || return 1
    done

    return 0
}

fi_jails_stop()
{
    for fi_jail_name in \
        fi-receiver \
        fi-ingest \
        fi-sor-db
    do
        fi_jails_stop_one "$fi_jail_name" || return 1
    done

    return 0
}

fi_jails_status()
{
    fi_jails_status_rc=0

    for fi_jail_name in \
        fi-sor-db \
        fi-ingest \
        fi-receiver
    do
        if fi_jails_is_running "$fi_jail_name"; then
            echo "$fi_jail_name is running"
        else
            echo "$fi_jail_name is not running"
            fi_jails_status_rc=1
        fi
    done

    return "$fi_jails_status_rc"
}

load_rc_config "$name"
run_rc_command "$1"
`

// Source: tools/deployment/freebsd/lifecycle.d/fi-pf.rc.conf.template
// SHA256: 2c9ca05c5fdc58c85a69d4edc7008cb1e9988274eb787e637d590bd5e18be403
const lifecycleAssetFIPFRC = `# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1
# FI-ROLE: fi-pf-enable-policy

fi_pf_enable="YES"
fi_pf_rules="/etc/pf.conf"
fi_pf_expected_sha256="@FI_PF_POLICY_SHA256@"
fi_pf_sor_db_work_ip="@FI_SOR_DB_WORK_IP@"

fi_pf_pfil_member="1"
fi_pf_pfil_bridge="0"
fi_pf_pfil_onlyip="1"
`

// Source: tools/deployment/freebsd/lifecycle.d/fi-pf.rc.d.template
// SHA256: 53ab6c9f6e8da8bb2452de91c278e2463f640fcf2e55a4709a6b81f495d54ff6
const lifecycleAssetFIPFService = `#!/bin/sh

# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1
# FI-ROLE: fi-pf-controller
#
# PROVIDE: fi_pf
# REQUIRE: pf
# BEFORE: fi_jails

. /etc/rc.subr

name="fi_pf"
desc="FI packet-filter runtime policy"
rcvar="fi_pf_enable"

start_cmd="fi_pf_start"
stop_cmd="fi_pf_stop"
status_cmd="fi_pf_status"
extra_commands="status"

: ${fi_pf_enable:="NO"}
: ${fi_pf_rules:="/etc/pf.conf"}

fi_pf_runtime_snapshot="/var/run/fi_pf.runtime"

fi_pf_validate_config()
{
    [ "$fi_pf_rules" = "/etc/pf.conf" ] || {
        warn "FI PF rules path is not exact"
        return 1
    }

    printf '%s\n' "$fi_pf_expected_sha256" |
        grep -Eq '^[0-9a-f]{64}$' || {
            warn "FI PF expected SHA-256 is invalid"
            return 1
        }

    printf '%s\n' "$fi_pf_sor_db_work_ip" |
        grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || {
            warn "FI PF System of Record address is invalid"
            return 1
        }

    [ "$fi_pf_pfil_member" = "1" ] &&
    [ "$fi_pf_pfil_bridge" = "0" ] &&
    [ "$fi_pf_pfil_onlyip" = "1" ] || {
        warn "FI PF bridge filtering contract is not exact"
        return 1
    }

    return 0
}

fi_pf_validate_persistent()
{
    [ -f "$fi_pf_rules" ] &&
    [ ! -L "$fi_pf_rules" ] || {
        warn "FI PF persistent rules file is unavailable"
        return 1
    }

    fi_pf_metadata=$(
        stat -f '%u:%g:%OMp:%#Lp:%l' "$fi_pf_rules" 2>/dev/null
    ) || {
        warn "unable to inspect FI PF persistent rules metadata"
        return 1
    }

    [ "$fi_pf_metadata" = "0:0:0:0644:1" ] || {
        warn "FI PF persistent rules metadata is not exact"
        return 1
    }

    grep -Fqx \
        '# FI-MANAGED: ironsignal-fi-freebsd-pf-v1' \
        "$fi_pf_rules" || {
            warn "FI PF persistent rules lack ownership marker"
            return 1
        }

    grep -Fqx \
        '# FI-ROLE: host-packet-filter-policy' \
        "$fi_pf_rules" || {
            warn "FI PF persistent rules lack role marker"
            return 1
        }

    fi_pf_actual_sha256=$(
        sha256 -q "$fi_pf_rules"
    ) || {
        warn "unable to hash FI PF persistent rules"
        return 1
    }

    [ "$fi_pf_actual_sha256" = "$fi_pf_expected_sha256" ] || {
        warn "FI PF persistent rules differ from expected policy"
        return 1
    }

    pfctl -nf "$fi_pf_rules" >/dev/null 2>&1 || {
        warn "FI PF persistent rules failed syntax validation"
        return 1
    }

    return 0
}

fi_pf_is_enabled()
{
    pfctl -s Running >/dev/null 2>&1
}

fi_pf_sysctls_match()
{
    [ "$(sysctl -n net.link.bridge.pfil_member 2>/dev/null)" = \
        "$fi_pf_pfil_member" ] &&
    [ "$(sysctl -n net.link.bridge.pfil_bridge 2>/dev/null)" = \
        "$fi_pf_pfil_bridge" ] &&
    [ "$(sysctl -n net.link.bridge.pfil_onlyip 2>/dev/null)" = \
        "$fi_pf_pfil_onlyip" ]
}

fi_pf_filter_hash()
{
    fi_pf_filter_rules=$(
        pfctl -sr 2>/dev/null
    ) || return 1

    printf '%s\n' "$fi_pf_filter_rules" | sha256 -q
}

fi_pf_nat_hash()
{
    fi_pf_nat_rules=$(
        pfctl -sn 2>/dev/null
    ) || return 1

    printf '%s\n' "$fi_pf_nat_rules" | sha256 -q
}

fi_pf_snapshot_valid()
{
    [ -f "$fi_pf_runtime_snapshot" ] &&
    [ ! -L "$fi_pf_runtime_snapshot" ] ||
        return 1

    fi_pf_snapshot_metadata=$(
        stat -f '%u:%g:%OMp:%#Lp:%l' \
            "$fi_pf_runtime_snapshot" 2>/dev/null
    ) || return 1

    [ "$fi_pf_snapshot_metadata" = "0:0:0:0600:1" ] ||
        return 1

    fi_pf_current_filter_hash=$(fi_pf_filter_hash) ||
        return 1

    fi_pf_current_nat_hash=$(fi_pf_nat_hash) ||
        return 1

    grep -Fqx \
        "filter_sha256=$fi_pf_current_filter_hash" \
        "$fi_pf_runtime_snapshot" &&
    grep -Fqx \
        "nat_sha256=$fi_pf_current_nat_hash" \
        "$fi_pf_runtime_snapshot"
}

fi_pf_snapshot_path_safe()
{
    if [ ! -e "$fi_pf_runtime_snapshot" ] &&
       [ ! -L "$fi_pf_runtime_snapshot" ]
    then
        return 0
    fi

    [ -f "$fi_pf_runtime_snapshot" ] &&
    [ ! -L "$fi_pf_runtime_snapshot" ] || {
        warn "FI PF runtime snapshot path is not a regular file"
        return 1
    }

    fi_pf_snapshot_path_metadata=$(
        stat -f '%u:%g:%OMp:%#Lp:%l' \
            "$fi_pf_runtime_snapshot" 2>/dev/null
    ) || {
        warn "unable to inspect FI PF runtime snapshot metadata"
        return 1
    }

    [ "$fi_pf_snapshot_path_metadata" = "0:0:0:0600:1" ] || {
        warn "FI PF runtime snapshot metadata is not exact"
        return 1
    }

    return 0
}

fi_pf_capture_snapshot()
{
    fi_pf_filter_sha256=$(fi_pf_filter_hash) ||
        return 1

    fi_pf_nat_sha256=$(fi_pf_nat_hash) ||
        return 1

    fi_pf_snapshot_temp=$(
        mktemp "${fi_pf_runtime_snapshot}.XXXXXX"
    ) || return 1

    printf '%s\n' \
        "filter_sha256=$fi_pf_filter_sha256" \
        "nat_sha256=$fi_pf_nat_sha256" \
        > "$fi_pf_snapshot_temp" || {
            rm -f "$fi_pf_snapshot_temp"
            return 1
        }

    chown 0:0 "$fi_pf_snapshot_temp" || {
        rm -f "$fi_pf_snapshot_temp"
        return 1
    }

    chmod 0600 "$fi_pf_snapshot_temp" || {
        rm -f "$fi_pf_snapshot_temp"
        return 1
    }

    mv -f \
        "$fi_pf_snapshot_temp" \
        "$fi_pf_runtime_snapshot" ||
        return 1

    return 0
}

fi_pf_status_internal()
{
    fi_pf_validate_config &&
    fi_pf_validate_persistent &&
    fi_pf_is_enabled &&
    fi_pf_sysctls_match &&
    fi_pf_snapshot_valid
}

fi_pf_start()
{
    if fi_pf_status_internal >/dev/null 2>&1; then
        echo "FI PF runtime policy already ready"
        return 0
    fi

    fi_pf_validate_config ||
        return 1

    fi_pf_validate_persistent ||
        return 1

    fi_pf_is_enabled || {
        warn "base PF service is not enabled at runtime"
        return 1
    }

    fi_pf_snapshot_path_safe ||
        return 1

    # Load the already validated policy before enabling bridge-member
    # filtering.
    pfctl -f "$fi_pf_rules" || {
        warn "unable to load FI PF policy"
        return 1
    }

    # Remove all pre-policy states involving the System of Record so an
    # existing state cannot bypass the new authorization boundary.
    pfctl \
        -k 0.0.0.0/0 \
        -k "$fi_pf_sor_db_work_ip" \
        >/dev/null || {
            warn "unable to clear PF states targeting the System of Record"
            return 1
        }

    pfctl \
        -k "$fi_pf_sor_db_work_ip" \
        >/dev/null || {
            warn "unable to clear PF states originating from the System of Record"
            return 1
        }

    # Establish non-member settings first. Member filtering is enabled last.
    sysctl \
        "net.link.bridge.pfil_bridge=$fi_pf_pfil_bridge" \
        >/dev/null || {
            warn "unable to set bridge pfil_bridge"
            return 1
        }

    sysctl \
        "net.link.bridge.pfil_onlyip=$fi_pf_pfil_onlyip" \
        >/dev/null || {
            warn "unable to set bridge pfil_onlyip"
            return 1
        }

    sysctl \
        "net.link.bridge.pfil_member=$fi_pf_pfil_member" \
        >/dev/null || {
            warn "unable to enable bridge member filtering"
            return 1
        }

    fi_pf_sysctls_match || {
        warn "FI PF bridge filtering did not reach exact runtime state"
        return 1
    }

    fi_pf_capture_snapshot || {
        warn "unable to capture FI PF runtime policy snapshot"
        return 1
    }

    fi_pf_status_internal || {
        warn "FI PF runtime policy failed final verification"
        return 1
    }

    echo "FI PF runtime policy ready"
    return 0
}

fi_pf_stop()
{
    echo "FI PF runtime policy remains active by design"
    return 0
}

fi_pf_status()
{
    if fi_pf_status_internal; then
        echo "FI PF runtime policy is ready"
        return 0
    fi

    warn "FI PF runtime policy is not ready"
    return 1
}

load_rc_config "$name"
run_rc_command "$1"
`

// Source: tools/deployment/freebsd/lifecycle.d/pf.rc.conf.template
// SHA256: 7005e444ac48b29408a7c724208dba6b869694f9e59a151816e0cc15ad99bf4d
const lifecycleAssetPFRC = `# FI-MANAGED: ironsignal-fi-freebsd-lifecycle-v1
# FI-ROLE: pf-boot-policy

pf_enable="YES"
pf_rules="/etc/pf.conf"
`
