#!/bin/sh

# FI FreeBSD backend deployment bootstrap.
#
# The current implementation supports non-mutating "plan" and "preflight"
# phases only.
#
# Configuration is parsed as strict KEY="VALUE" data. It is never sourced as
# shell code.

umask 077

PROGRAM=${0##*/}
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)

CONFIG_MAP=""
OUTPUT_DIR=""

fail()
{
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

pass()
{
    printf '[PASS] %s\n' "$*"
}

usage()
{
    cat <<EOF_USAGE
Usage:
    $PROGRAM plan <config-file> <output-directory>
    $PROGRAM preflight <config-file>

Current commands:

    plan
        Validate FI FreeBSD deployment configuration and render the jail/fstab
        deployment plan without modifying the host.

    preflight
        Validate the intended FreeBSD host against deployment configuration
        without modifying host state.

The plan output directory must not already exist.

Preflight must run as root on the intended FreeBSD host.

No apply operation is implemented by this checkpoint.
EOF_USAGE
}

cleanup()
{
    if [ -n "$CONFIG_MAP" ] && [ -f "$CONFIG_MAP" ]; then
        rm -f "$CONFIG_MAP"
    fi
}

trap cleanup EXIT HUP INT TERM

require_command()
{
    command -v "$1" >/dev/null 2>&1 ||
        fail "required command not found: $1"
}

is_allowed_key()
{
    case "$1" in
        FI_ZPOOL|FI_RUNTIME_UID|FI_RUNTIME_GID|FI_MGMT_BRIDGE|FI_WORK_BRIDGE|FI_MGMT_NETWORK|FI_WORK_NETWORK|FI_RECEIVER_MGMT_ADDRESS|FI_RECEIVER_WORK_ADDRESS|FI_INGEST_MGMT_ADDRESS|FI_INGEST_WORK_ADDRESS|FI_SOR_DB_MGMT_ADDRESS|FI_SOR_DB_WORK_ADDRESS|FI_JAIL_DATASET_ROOT|FI_JAIL_ROOT_BASE|FI_JAIL_TEMPLATE_SNAPSHOT|FI_RECEIVER_ROOT|FI_INGEST_ROOT|FI_SOR_DB_ROOT|FI_CUSTODY_GENERATION_HOST|FI_RECORDED_HOST|FI_READY_HOST|FI_RECEIVER_CONFIG_HOST|FI_INGEST_CONFIG_HOST|FI_SOR_POSTGRES_HOST|FI_RECEIVER_FSTAB|FI_INGEST_FSTAB|FI_SOR_DB_FSTAB|FI_DEVFS_RULESET|FI_RECEIVER_MGMT_HOST_IF|FI_RECEIVER_MGMT_JAIL_IF|FI_RECEIVER_WORK_HOST_IF|FI_RECEIVER_WORK_JAIL_IF|FI_INGEST_MGMT_HOST_IF|FI_INGEST_MGMT_JAIL_IF|FI_INGEST_WORK_HOST_IF|FI_INGEST_WORK_JAIL_IF|FI_SOR_DB_MGMT_HOST_IF|FI_SOR_DB_MGMT_JAIL_IF|FI_SOR_DB_WORK_HOST_IF|FI_SOR_DB_WORK_JAIL_IF)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}
get_value()
{
    awk -v requested_key="$1" '
        BEGIN {
            tab = sprintf("%c", 9)
        }

        {
            separator = index($0, tab)

            if (separator == 0) {
                next
            }

            key = substr($0, 1, separator - 1)

            if (key == requested_key) {
                print substr($0, separator + 1)
                exit
            }
        }
    ' "$CONFIG_MAP"
}
require_value()
{
    required_value=$(get_value "$1")

    if [ -z "$required_value" ]; then
        fail "required configuration value is empty or absent: $1"
    fi
}

validate_unsigned_nonzero()
{
    numeric_name=$1
    numeric_value=$(get_value "$numeric_name")

    case "$numeric_value" in
        '' | *[!0-9]*)
            fail "$numeric_name must be a non-zero decimal integer"
            ;;
    esac

    if [ "$numeric_value" -eq 0 ]; then
        fail "$numeric_name must be greater than zero"
    fi
}

validate_absolute_path()
{
    path_name=$1
    path_value=$(get_value "$path_name")

    printf '%s\n' "$path_value" |
        grep -Eq '^/[A-Za-z0-9._/@:-]+$' ||
        fail "$path_name is not an accepted absolute path: $path_value"
}

validate_dataset_name()
{
    dataset_name=$1
    dataset_value=$(get_value "$dataset_name")

    printf '%s\n' "$dataset_value" |
        grep -Eq '^[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)+$' ||
        fail "$dataset_name is not an accepted ZFS dataset name: $dataset_value"
}

validate_snapshot_name()
{
    snapshot_value=$(get_value FI_JAIL_TEMPLATE_SNAPSHOT)

    printf '%s\n' "$snapshot_value" |
        grep -Eq '^[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)+@[A-Za-z0-9_.:-]+$' ||
        fail "FI_JAIL_TEMPLATE_SNAPSHOT is not an accepted ZFS snapshot name"
}

validate_interface_name()
{
    interface_key=$1
    interface_value=$(get_value "$interface_key")

    printf '%s\n' "$interface_value" |
        grep -Eq '^[A-Za-z0-9_.:-]+$' ||
        fail "$interface_key contains invalid interface-name characters"

    if [ "${#interface_value}" -gt 15 ]; then
        fail "$interface_key exceeds the FreeBSD interface-name limit: $interface_value"
    fi
}

validate_pool_name()
{
    pool_value=$(get_value FI_ZPOOL)

    printf '%s\n' "$pool_value" |
        grep -Eq '^[A-Za-z][A-Za-z0-9_.:-]*$' ||
        fail "FI_ZPOOL is not an accepted pool name: $pool_value"
}

validate_ipv4_cidr()
{
    cidr_key=$1
    cidr_value=$(get_value "$cidr_key")

    printf '%s\n' "$cidr_value" |
        awk -F '[./]' '
            NF != 5 {
                exit 1
            }

            {
                for (i = 1; i <= 4; i++) {
                    if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) {
                        exit 1
                    }
                }

                if ($5 !~ /^[0-9]+$/ || $5 < 1 || $5 > 32) {
                    exit 1
                }
            }
        ' ||
        fail "$cidr_key is not a valid IPv4 CIDR value: $cidr_value"
}

validate_network_address()
{
    network_key=$1
    network_value=$(get_value "$network_key")

    printf '%s\n' "$network_value" |
        awk -F '[./]' '
            function ip_number(a, b, c, d) {
                return (a * 16777216) + (b * 65536) + (c * 256) + d
            }

            {
                prefix = $5
                block = 2 ^ (32 - prefix)
                address = ip_number($1, $2, $3, $4)

                if ((address % block) != 0) {
                    exit 1
                }
            }
        ' ||
        fail "$network_key is not a canonical network address: $network_value"
}

validate_address_in_network()
{
    network_key=$1
    address_key=$2

    network_value=$(get_value "$network_key")
    address_value=$(get_value "$address_key")

    awk \
        -v network="$network_value" \
        -v address="$address_value" '
        BEGIN {
            split(network, network_parts, "/")
            split(address, address_parts, "/")

            split(network_parts[1], network_octets, ".")
            split(address_parts[1], address_octets, ".")

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
    ' ||
        fail "$address_key is not contained in $network_key"
}
assert_distinct_values()
{
    distinct_description=$1
    shift

    seen_values=""

    for distinct_key in "$@"; do
        distinct_value=$(get_value "$distinct_key")

        case "|$seen_values|" in
            *"|$distinct_value|"*)
                fail "$distinct_description contains duplicate value: $distinct_value"
                ;;
        esac

        if [ -z "$seen_values" ]; then
            seen_values=$distinct_value
        else
            seen_values="${seen_values}|${distinct_value}"
        fi
    done
}

assert_path_beneath()
{
    parent_key=$1
    child_key=$2

    parent_value=$(get_value "$parent_key")
    child_value=$(get_value "$child_key")

    case "$child_value" in
        "$parent_value"/*)
            ;;
        *)
            fail "$child_key is not beneath $parent_key"
            ;;
    esac
}

parse_config()
{
    config_file=$1

    [ -f "$config_file" ] ||
        fail "configuration file not found: $config_file"

    CONFIG_MAP=$(mktemp "${TMPDIR:-/tmp}/fi-config-map.XXXXXX") ||
        fail "unable to create temporary configuration map"

    while IFS= read -r raw_line || [ -n "$raw_line" ]; do
        config_line=$(
            printf '%s\n' "$raw_line" |
                sed \
                    -e 's/^[[:space:]]*//' \
                    -e 's/[[:space:]]*$//'
        )

        case "$config_line" in
            '' | \#*)
                continue
                ;;
        esac

        printf '%s\n' "$config_line" |
            grep -Eq '^FI_[A-Z0-9_]+="[^"]*"$' ||
            fail "invalid configuration syntax: $config_line"

        config_key=${config_line%%=*}
        config_quoted_value=${config_line#*=}
        config_value=${config_quoted_value#\"}
        config_value=${config_value%\"}

        is_allowed_key "$config_key" ||
            fail "unknown configuration key: $config_key"

        if grep -q "^${config_key}" "$CONFIG_MAP"; then
            fail "duplicate configuration key: $config_key"
        fi

        printf '%s\n' "$config_value" |
            grep -Eq '^[A-Za-z0-9_./@:-]*$' ||
            fail "unsafe or unsupported characters in $config_key"

        printf '%s\t%s\n' "$config_key" "$config_value" >> "$CONFIG_MAP" ||
            fail "unable to record configuration value: $config_key"
    done < "$config_file"
}

validate_required_values()
{
    for required_key in \
        FI_ZPOOL \
        FI_RUNTIME_UID \
        FI_RUNTIME_GID \
        FI_MGMT_BRIDGE \
        FI_WORK_BRIDGE \
        FI_MGMT_NETWORK \
        FI_WORK_NETWORK \
        FI_RECEIVER_MGMT_ADDRESS \
        FI_RECEIVER_WORK_ADDRESS \
        FI_INGEST_MGMT_ADDRESS \
        FI_INGEST_WORK_ADDRESS \
        FI_SOR_DB_MGMT_ADDRESS \
        FI_SOR_DB_WORK_ADDRESS \
        FI_JAIL_DATASET_ROOT \
        FI_JAIL_ROOT_BASE \
        FI_JAIL_TEMPLATE_SNAPSHOT \
        FI_RECEIVER_ROOT \
        FI_INGEST_ROOT \
        FI_SOR_DB_ROOT \
        FI_CUSTODY_GENERATION_HOST \
        FI_RECORDED_HOST \
        FI_READY_HOST \
        FI_RECEIVER_CONFIG_HOST \
        FI_INGEST_CONFIG_HOST \
        FI_SOR_POSTGRES_HOST \
        FI_RECEIVER_FSTAB \
        FI_INGEST_FSTAB \
        FI_SOR_DB_FSTAB \
        FI_DEVFS_RULESET \
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
        require_value "$required_key"
    done
}

validate_config()
{
    validate_required_values

    validate_pool_name
    validate_unsigned_nonzero FI_RUNTIME_UID
    validate_unsigned_nonzero FI_RUNTIME_GID
    validate_unsigned_nonzero FI_DEVFS_RULESET

    validate_interface_name FI_MGMT_BRIDGE
    validate_interface_name FI_WORK_BRIDGE

    for interface_key in \
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
        validate_interface_name "$interface_key"
    done

    assert_distinct_values \
        "VNET endpoint names" \
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

    mgmt_bridge=$(get_value FI_MGMT_BRIDGE)
    work_bridge=$(get_value FI_WORK_BRIDGE)

    [ "$mgmt_bridge" != "$work_bridge" ] ||
        fail "management and workload bridges must be distinct"

    for interface_key in \
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
        interface_value=$(get_value "$interface_key")

        [ "$interface_value" != "$mgmt_bridge" ] ||
            fail "$interface_key conflicts with FI_MGMT_BRIDGE"

        [ "$interface_value" != "$work_bridge" ] ||
            fail "$interface_key conflicts with FI_WORK_BRIDGE"
    done

    for cidr_key in \
        FI_MGMT_NETWORK \
        FI_WORK_NETWORK \
        FI_RECEIVER_MGMT_ADDRESS \
        FI_RECEIVER_WORK_ADDRESS \
        FI_INGEST_MGMT_ADDRESS \
        FI_INGEST_WORK_ADDRESS \
        FI_SOR_DB_MGMT_ADDRESS \
        FI_SOR_DB_WORK_ADDRESS
    do
        validate_ipv4_cidr "$cidr_key"
    done

    validate_network_address FI_MGMT_NETWORK
    validate_network_address FI_WORK_NETWORK

    [ "$(get_value FI_MGMT_NETWORK)" != "$(get_value FI_WORK_NETWORK)" ] ||
        fail "management and workload networks must be distinct"

    validate_address_in_network FI_MGMT_NETWORK FI_RECEIVER_MGMT_ADDRESS
    validate_address_in_network FI_WORK_NETWORK FI_RECEIVER_WORK_ADDRESS
    validate_address_in_network FI_MGMT_NETWORK FI_INGEST_MGMT_ADDRESS
    validate_address_in_network FI_WORK_NETWORK FI_INGEST_WORK_ADDRESS
    validate_address_in_network FI_MGMT_NETWORK FI_SOR_DB_MGMT_ADDRESS
    validate_address_in_network FI_WORK_NETWORK FI_SOR_DB_WORK_ADDRESS

    assert_distinct_values \
        "jail interface addresses" \
        FI_RECEIVER_MGMT_ADDRESS \
        FI_RECEIVER_WORK_ADDRESS \
        FI_INGEST_MGMT_ADDRESS \
        FI_INGEST_WORK_ADDRESS \
        FI_SOR_DB_MGMT_ADDRESS \
        FI_SOR_DB_WORK_ADDRESS

    validate_dataset_name FI_JAIL_DATASET_ROOT
    validate_snapshot_name

    for path_key in \
        FI_JAIL_ROOT_BASE \
        FI_RECEIVER_ROOT \
        FI_INGEST_ROOT \
        FI_SOR_DB_ROOT \
        FI_CUSTODY_GENERATION_HOST \
        FI_RECORDED_HOST \
        FI_READY_HOST \
        FI_RECEIVER_CONFIG_HOST \
        FI_INGEST_CONFIG_HOST \
        FI_SOR_POSTGRES_HOST \
        FI_RECEIVER_FSTAB \
        FI_INGEST_FSTAB \
        FI_SOR_DB_FSTAB
    do
        validate_absolute_path "$path_key"
    done

    assert_path_beneath FI_JAIL_ROOT_BASE FI_RECEIVER_ROOT
    assert_path_beneath FI_JAIL_ROOT_BASE FI_INGEST_ROOT
    assert_path_beneath FI_JAIL_ROOT_BASE FI_SOR_DB_ROOT

    assert_distinct_values \
        "production jail roots" \
        FI_RECEIVER_ROOT \
        FI_INGEST_ROOT \
        FI_SOR_DB_ROOT

    assert_distinct_values \
        "host-side fstab paths" \
        FI_RECEIVER_FSTAB \
        FI_INGEST_FSTAB \
        FI_SOR_DB_FSTAB

    zpool_value=$(get_value FI_ZPOOL)
    jail_dataset_root=$(get_value FI_JAIL_DATASET_ROOT)

    case "$jail_dataset_root" in
        "$zpool_value"/*)
            ;;
        *)
            fail "FI_JAIL_DATASET_ROOT is not beneath FI_ZPOOL"
            ;;
    esac

    pass "configuration grammar and value constraints"
}

validate_template_tokens()
{
    template_file=$1

    template_tokens=$(
        grep -Eo '@FI_[A-Z0-9_]+@' "$template_file" |
            sort -u
    )

    for template_token in $template_tokens; do
        template_key=${template_token#@}
        template_key=${template_key%@}

        template_value=$(get_value "$template_key")

        [ -n "$template_value" ] ||
            fail "$template_file uses unresolved configuration key: $template_key"
    done
}

render_template()
{
    source_template=$1
    destination_file=$2

    validate_template_tokens "$source_template"

    awk -v map_file="$CONFIG_MAP" '
        BEGIN {
            while ((getline map_line < map_file) > 0) {
                tab_position = index(map_line, "\t")

                if (tab_position == 0) {
                    exit 90
                }

                key = substr(map_line, 1, tab_position - 1)
                value = substr(map_line, tab_position + 1)

                values[key] = value
            }

            close(map_file)
        }

        {
            rendered = $0

            while (match(rendered, /@FI_[A-Z0-9_]+@/)) {
                token = substr(rendered, RSTART, RLENGTH)
                key = substr(token, 2, RLENGTH - 2)

                if (!(key in values) || values[key] == "") {
                    print "unresolved template key: " key > "/dev/stderr"
                    exit 91
                }

                rendered = substr(rendered, 1, RSTART - 1) values[key] substr(rendered, RSTART + RLENGTH)
            }

            print rendered
        }
    ' "$source_template" > "$destination_file" ||
        fail "unable to render template: $source_template"

    if grep -Eq '@FI_[A-Z0-9_]+@' "$destination_file"; then
        fail "rendered file still contains FI template tokens: $destination_file"
    fi
}

render_plan()
{
    [ ! -e "$OUTPUT_DIR" ] ||
        fail "output directory already exists: $OUTPUT_DIR"

    mkdir -p "$OUTPUT_DIR" ||
        fail "unable to create output directory: $OUTPUT_DIR"

    render_template \
        "$SCRIPT_DIR/jail.conf.d/fi-receiver.conf.template" \
        "$OUTPUT_DIR/fi-receiver.conf"

    render_template \
        "$SCRIPT_DIR/jail.conf.d/fi-ingest.conf.template" \
        "$OUTPUT_DIR/fi-ingest.conf"

    render_template \
        "$SCRIPT_DIR/jail.conf.d/fi-sor-db.conf.template" \
        "$OUTPUT_DIR/fi-sor-db.conf"

    render_template \
        "$SCRIPT_DIR/fstab.d/fi-receiver.fstab.template" \
        "$OUTPUT_DIR/fstab.fi-receiver"

    render_template \
        "$SCRIPT_DIR/fstab.d/fi-ingest.fstab.template" \
        "$OUTPUT_DIR/fstab.fi-ingest"

    render_template \
        "$SCRIPT_DIR/fstab.d/fi-sor-db.fstab.template" \
        "$OUTPUT_DIR/fstab.fi-sor-db"

    : > "$OUTPUT_DIR/MANIFEST.sha256" ||
        fail "unable to create render manifest"

    for rendered_name in \
        fi-receiver.conf \
        fi-ingest.conf \
        fi-sor-db.conf \
        fstab.fi-receiver \
        fstab.fi-ingest \
        fstab.fi-sor-db
    do
        rendered_hash=$(sha256 -q "$OUTPUT_DIR/$rendered_name") ||
            fail "unable to hash rendered file: $rendered_name"

        printf '%s  %s\n' "$rendered_hash" "$rendered_name" \
            >> "$OUTPUT_DIR/MANIFEST.sha256" ||
            fail "unable to write render manifest"
    done

    pass "templates rendered without unresolved tokens"
    pass "deterministic render manifest created"

    printf 'Plan directory: %s\n' "$OUTPUT_DIR"
}

main()
{
    if [ "$#" -lt 1 ]; then
        usage
        exit 2
    fi

    mode=$1

    case "$mode" in
        plan)
            if [ "$#" -ne 3 ]; then
                usage
                exit 2
            fi

            config_file=$2
            OUTPUT_DIR=$3
            ;;
        preflight)
            if [ "$#" -ne 2 ]; then
                usage
                exit 2
            fi

            config_file=$2
            ;;
        *)
            fail "unsupported command: $mode"
            ;;
    esac

    for required_command in \
        awk \
        grep \
        mktemp \
        sed
    do
        require_command "$required_command"
    done

    case "$mode" in
        plan)
            require_command mkdir
            require_command sha256
            require_command sort
            ;;
        preflight)
            [ -f "$SCRIPT_DIR/fi-host-preflight.sh" ] ||
                fail "preflight helper not found: $SCRIPT_DIR/fi-host-preflight.sh"

            . "$SCRIPT_DIR/fi-host-preflight.sh"
            preflight_require_commands
            ;;
    esac

    parse_config "$config_file"
    validate_config

    case "$mode" in
        plan)
            render_plan
            ;;
        preflight)
            preflight_host
            ;;
    esac
}

main "$@"
