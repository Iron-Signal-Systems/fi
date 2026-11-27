#!/bin/sh

# FI FreeBSD persistent PF policy apply/adoption helper.
#
# This file is sourced by fi-bootstrap.sh.
# Sourcing it performs no mutation.
#
# This layer manages only persistent /etc/pf.conf contents.
# It does not reload PF, alter PF state, or change bridge pfil sysctls.

PF_FILE_MARKER="# FI-MANAGED: ironsignal-fi-freebsd-pf-v1"
PF_FILE_ROLE="host-packet-filter-policy"

PF_TARGET="/etc/pf.conf"
PF_UID="0"
PF_GID="0"
PF_MODE="0644"

PF_EXPECTED=""

pf_use_marker()
{
    HOST_FILE_MARKER=$PF_FILE_MARKER
}

pf_require_commands()
{
    host_file_require_commands

    for pf_command in \
        cat \
        chmod \
        chown \
        cmp \
        mktemp \
        mv \
        pfctl \
        rm \
        sha256 \
        stat
    do
        command -v "$pf_command" >/dev/null 2>&1 ||
            fail "required PF deployment command not found: $pf_command"
    done
}

pf_require_host()
{
    host_file_require_host
}

pf_prepare_expected()
{
    pf_use_marker
    host_file_prepare_expected

    PF_EXPECTED="$HOST_FILE_PLAN/pf.conf"

    [ -f "$PF_EXPECTED" ] ||
        fail "rendered PF policy is absent: $PF_EXPECTED"
}

pf_cleanup_expected()
{
    host_file_cleanup_expected
    PF_EXPECTED=""
}

pf_policy_file_valid()
{
    pf_policy_file=$1

    [ -f "$pf_policy_file" ] &&
    [ ! -L "$pf_policy_file" ] &&
    grep -Fqx "$PF_FILE_MARKER" "$pf_policy_file" &&
    grep -Fqx "# FI-ROLE: $PF_FILE_ROLE" "$pf_policy_file" &&
    pfctl -nf "$pf_policy_file" >/dev/null 2>&1
}

pf_validate_policy_file()
{
    pf_policy_file=$1

    pf_policy_file_valid "$pf_policy_file" ||
        fail "PF policy failed ownership or syntax validation: $pf_policy_file"
}

pf_target_metadata_exact()
{
    pf_metadata_target=$1
    pf_metadata_uid=$2
    pf_metadata_gid=$3
    pf_metadata_mode=$4

    [ -f "$pf_metadata_target" ] &&
    [ ! -L "$pf_metadata_target" ] ||
        return 1

    pf_metadata_actual=$(
        stat -f '%u:%g:%OMp:%#Lp:%l' "$pf_metadata_target" 2>/dev/null
    ) || return 1

    pf_metadata_expected="${pf_metadata_uid}:${pf_metadata_gid}:0:${pf_metadata_mode}:1"

    [ "$pf_metadata_actual" = "$pf_metadata_expected" ]
}

pf_replace_approved_prior()
{
    pf_replace_expected=$1
    pf_replace_target=$2
    pf_replace_prior=$3
    pf_replace_uid=$4
    pf_replace_gid=$5
    pf_replace_mode=$6

    [ -n "$pf_replace_prior" ] ||
        fail "approved prior PF file is required"

    [ "$pf_replace_prior" != "$pf_replace_target" ] ||
        fail "approved prior PF file must be separate from live PF target"

    [ -f "$pf_replace_prior" ] &&
    [ ! -L "$pf_replace_prior" ] ||
        fail "approved prior PF file is not a regular file: $pf_replace_prior"

    [ -f "$pf_replace_target" ] &&
    [ ! -L "$pf_replace_target" ] ||
        fail "live PF target is not a regular file"

    pf_replace_prior_sha256=$(
        sha256 -q "$pf_replace_prior"
    ) || fail "unable to hash approved prior PF file"

    pf_replace_live_sha256=$(
        sha256 -q "$pf_replace_target"
    ) || fail "unable to hash live PF target"

    [ "$pf_replace_live_sha256" = "$pf_replace_prior_sha256" ] ||
        fail "live PF policy does not match approved prior PF file"

    cmp -s "$pf_replace_prior" "$pf_replace_target" ||
        fail "live PF policy is not byte-identical to approved prior PF file"

    pf_target_metadata_exact \
        "$pf_replace_target" \
        "$pf_replace_uid" \
        "$pf_replace_gid" \
        "$pf_replace_mode" ||
        fail "live prior PF policy has metadata drift and is not eligible for adoption"

    host_file_require_parent "$pf_replace_target"

    pf_replace_temp=$(
        mktemp "${pf_replace_target}.fi-pf.XXXXXX"
    ) || fail "unable to allocate same-directory PF replacement file"

    cat "$pf_replace_expected" > "$pf_replace_temp" || {
        rm -f "$pf_replace_temp"
        fail "unable to write PF replacement candidate"
    }

    chown \
        "${pf_replace_uid}:${pf_replace_gid}" \
        "$pf_replace_temp" || {
        rm -f "$pf_replace_temp"
        fail "unable to set PF replacement ownership"
    }

    chmod "$pf_replace_mode" "$pf_replace_temp" || {
        rm -f "$pf_replace_temp"
        fail "unable to set PF replacement mode"
    }

    pf_policy_file_valid "$pf_replace_temp" || {
        rm -f "$pf_replace_temp"
        fail "PF replacement candidate failed ownership or syntax validation"
    }

    pf_use_marker

    pf_replace_temp_state=$(
        host_file_classify \
            "$pf_replace_expected" \
            "$pf_replace_temp" \
            "$pf_replace_uid" \
            "$pf_replace_gid" \
            "$pf_replace_mode"
    ) || {
        rm -f "$pf_replace_temp"
        fail "unable to classify PF replacement candidate"
    }

    [ "$pf_replace_temp_state" = "OWNED_MATCH" ] || {
        rm -f "$pf_replace_temp"
        fail "PF replacement candidate is not exact: $pf_replace_temp_state"
    }

    # Revalidate the approved prior authority and live target immediately
    # before publication.
    pf_replace_prior_sha256_now=$(
        sha256 -q "$pf_replace_prior"
    ) || {
        rm -f "$pf_replace_temp"
        fail "unable to rehash approved prior PF file"
    }

    [ "$pf_replace_prior_sha256_now" = "$pf_replace_prior_sha256" ] || {
        rm -f "$pf_replace_temp"
        fail "approved prior PF file changed during adoption"
    }

    [ -f "$pf_replace_target" ] &&
    [ ! -L "$pf_replace_target" ] || {
        rm -f "$pf_replace_temp"
        fail "live PF target changed type before publication"
    }

    pf_target_metadata_exact \
        "$pf_replace_target" \
        "$pf_replace_uid" \
        "$pf_replace_gid" \
        "$pf_replace_mode" || {
        rm -f "$pf_replace_temp"
        fail "live PF target metadata changed before publication"
    }

    pf_replace_live_sha256_now=$(
        sha256 -q "$pf_replace_target"
    ) || {
        rm -f "$pf_replace_temp"
        fail "unable to rehash live PF target"
    }

    [ "$pf_replace_live_sha256_now" = "$pf_replace_prior_sha256" ] || {
        rm -f "$pf_replace_temp"
        fail "live PF target changed before publication"
    }

    cmp -s "$pf_replace_prior" "$pf_replace_target" || {
        rm -f "$pf_replace_temp"
        fail "live PF target changed before publication"
    }

    mv -f "$pf_replace_temp" "$pf_replace_target" ||
        fail "unable to publish adopted PF policy"

    pf_replace_final_state=$(
        host_file_classify \
            "$pf_replace_expected" \
            "$pf_replace_target" \
            "$pf_replace_uid" \
            "$pf_replace_gid" \
            "$pf_replace_mode"
    ) || fail "unable to verify adopted PF policy"

    [ "$pf_replace_final_state" = "OWNED_MATCH" ] ||
        fail "adopted PF policy failed final verification: $pf_replace_final_state"

    pass "adopted and verified FI PF policy: $pf_replace_target"
}

verify_pf_internal()
{
    pf_use_marker

    pf_verify_state=$(
        host_file_classify \
            "$PF_EXPECTED" \
            "$PF_TARGET" \
            "$PF_UID" \
            "$PF_GID" \
            "$PF_MODE"
    ) || fail "unable to classify persistent PF policy"

    [ "$pf_verify_state" = "OWNED_MATCH" ] ||
        fail "persistent PF policy is not OWNED_MATCH: $pf_verify_state"

    pf_validate_policy_file "$PF_TARGET"
}

apply_pf()
{
    pf_require_host
    pf_prepare_expected
    pf_validate_policy_file "$PF_EXPECTED"

    pf_use_marker

    pf_apply_state=$(
        host_file_classify \
            "$PF_EXPECTED" \
            "$PF_TARGET" \
            "$PF_UID" \
            "$PF_GID" \
            "$PF_MODE"
    ) || fail "unable to classify persistent PF policy"

    case "$pf_apply_state" in
        OWNED_MATCH)
            pass "FI PF policy already matches: $PF_TARGET"
            ;;
        ABSENT)
            host_file_install_absent \
                "$PF_EXPECTED" \
                "$PF_TARGET" \
                "$PF_UID" \
                "$PF_GID" \
                "$PF_MODE" \
                "$PF_FILE_ROLE"
            ;;
        OWNED_DRIFT)
            fail "FI-owned PF policy has drifted"
            ;;
        FOREIGN_COLLISION)
            fail \
                "existing unowned PF policy requires explicit adopt-pf with approved prior file"
            ;;
        UNKNOWN)
            fail "persistent PF policy could not be classified safely"
            ;;
        *)
            fail "unexpected PF policy state: $pf_apply_state"
            ;;
    esac

    verify_pf_internal
    pf_cleanup_expected

    pass "FI FreeBSD PF apply acceptance complete"
}

adopt_pf()
{
    pf_approved_prior=$1

    pf_require_host

    [ -n "$pf_approved_prior" ] ||
        fail "approved prior PF file is required"

    pf_prepare_expected
    pf_validate_policy_file "$PF_EXPECTED"

    pf_use_marker

    pf_adopt_state=$(
        host_file_classify \
            "$PF_EXPECTED" \
            "$PF_TARGET" \
            "$PF_UID" \
            "$PF_GID" \
            "$PF_MODE"
    ) || fail "unable to classify PF policy for adoption"

    case "$pf_adopt_state" in
        OWNED_MATCH)
            pass "FI PF policy already matches: $PF_TARGET"
            ;;
        FOREIGN_COLLISION)
            pf_replace_approved_prior \
                "$PF_EXPECTED" \
                "$PF_TARGET" \
                "$pf_approved_prior" \
                "$PF_UID" \
                "$PF_GID" \
                "$PF_MODE"
            ;;
        ABSENT)
            fail "PF target is absent; use apply-pf rather than adopt-pf"
            ;;
        OWNED_DRIFT)
            fail "FI-owned PF policy has drifted and is not eligible for adoption"
            ;;
        UNKNOWN)
            fail "PF policy could not be classified safely for adoption"
            ;;
        *)
            fail "unexpected PF adoption state: $pf_adopt_state"
            ;;
    esac

    verify_pf_internal
    pf_cleanup_expected

    pass "FI FreeBSD PF adoption acceptance complete"
}

update_pf()
{
    pf_update_prior=$1

    pf_require_host

    [ -n "$pf_update_prior" ] ||
        fail "approved prior FI PF file is required"

    [ -f "$pf_update_prior" ] &&
    [ ! -L "$pf_update_prior" ] ||
        fail "approved prior FI PF file is not a regular file: $pf_update_prior"

    pf_validate_policy_file "$pf_update_prior"

    pf_prepare_expected
    pf_validate_policy_file "$PF_EXPECTED"

    pf_use_marker

    pf_update_state=$(
        host_file_classify \
            "$PF_EXPECTED" \
            "$PF_TARGET" \
            "$PF_UID" \
            "$PF_GID" \
            "$PF_MODE"
    ) || fail "unable to classify persistent PF policy for update"

    case "$pf_update_state" in
        OWNED_MATCH)
            pass "FI PF policy already matches new version: $PF_TARGET"
            ;;

        OWNED_DRIFT)
            pf_update_prior_state=$(
                host_file_classify \
                    "$pf_update_prior" \
                    "$PF_TARGET" \
                    "$PF_UID" \
                    "$PF_GID" \
                    "$PF_MODE"
            ) || fail \
                "unable to classify live PF policy against approved prior"

            [ "$pf_update_prior_state" = "OWNED_MATCH" ] ||
                fail \
                    "live FI PF policy does not match approved prior version: $pf_update_prior_state"

            pf_replace_approved_prior \
                "$PF_EXPECTED" \
                "$PF_TARGET" \
                "$pf_update_prior" \
                "$PF_UID" \
                "$PF_GID" \
                "$PF_MODE"
            ;;

        ABSENT)
            fail "FI PF target is absent; update-pf will not create it"
            ;;

        FOREIGN_COLLISION)
            fail "update-pf will not replace foreign PF policy"
            ;;

        UNKNOWN)
            fail "FI PF policy could not be classified safely for update"
            ;;

        *)
            fail "unexpected PF update state: $pf_update_state"
            ;;
    esac

    verify_pf_internal
    pf_cleanup_expected

    pass "FI FreeBSD PF update acceptance complete"
}

verify_pf()
{
    pf_require_host
    pf_prepare_expected

    verify_pf_internal
    pf_cleanup_expected

    pass "FI FreeBSD PF verification acceptance complete"
}
