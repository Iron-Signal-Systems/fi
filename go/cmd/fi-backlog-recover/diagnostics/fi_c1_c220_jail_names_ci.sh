#!/bin/sh
# CI-only: exercise C220 diagnostic jail selection with mock jls.
# No C220 access, no PostgreSQL connections, and no filesystem writes.
set -eu
root=go/cmd/fi-backlog-recover/diagnostics
fail(){ echo "FI C1 JAIL SELECTOR CI FAIL: $*" >&2; exit 1; }
for basename in \
    fi_c1_development_sor_preflight_c220.sh \
    fi_c1_populated_sor_readiness_c220.sh \
    fi_c1_crl_trust_readiness_c220.sh \
    fi_c1_sor_telemetry_discovery_c220.sh; do
    file="$root/$basename"
    sh -n "$file" || fail "shell syntax: $file"
    grep -F 'for candidate in fi-sor-db fi-sor; do' "$file" >/dev/null ||
        fail "missing explicit real-jail candidates: $file"
    grep -F 'jls -j "$candidate" jid' "$file" >/dev/null ||
        fail "missing actual running jail check: $file"
    grep -F 'sor_jail=$candidate' "$file" >/dev/null ||
        fail "missing selected jail binding: $file"
    grep -F '"$sor_jail"' "$file" >/dev/null ||
        fail "selected jail never used: $file"
    if grep -E '^[[:space:]]*jexec[[:space:]]+(-U[[:space:]]+postgres[[:space:]]+)?fi-sor(-db)?[[:space:]]' "$file"; then
        fail "hardcoded SoR exec bypasses jail resolution: $file"
    fi
    # Extract and execute the EXACT checked-in candidate-selection block,
    # not a separate lookalike implementation. Mock jls returns only
    # requested candidates, so this test is portable to Linux CI.
    selector=$(sed -n "/^sor_jail=''/,/^done$/p" "$file")
    [ -n "$selector" ] || fail "missing jail selection logic: $file"
    (
        fail(){ exit 79; }
        jls(){ [ "$1" = -j ] && [ "$2" = fi-sor-db ] && [ "$3" = jid ]; }
        eval "$selector"
        [ "$sor_jail" = fi-sor-db ]
    ) || fail "did not select uniquely running fi-sor-db: $file"
    (
        fail(){ exit 79; }
        jls(){ [ "$1" = -j ] && [ "$2" = fi-sor ] && [ "$3" = jid ]; }
        eval "$selector"
        [ "$sor_jail" = fi-sor ]
    ) || fail "did not select uniquely running fi-sor: $file"
    if (
        fail(){ exit 79; }
        jls(){ [ "$1" = -j ] && [ "$3" = jid ]; }
        eval "$selector"
    ); then
        fail "ambiguous simultaneous SoR jails accepted: $file"
    fi
    # Discovery is allowed to inventory an offline SoR. Every gate
    # requiring PostgreSQL must stop when neither candidate is running.
    case "$basename" in
    fi_c1_sor_telemetry_discovery_c220.sh) : ;;
    *) grep -F '[ -n "$sor_jail" ] || fail' "$file" >/dev/null ||
        fail "missing fail-closed offline SoR guard: $file" ;;
    esac
done
# Existing private C1 work is a restart constraint, not a clean-stage
# assumption. The same read-only C220 readiness script must retain the
# catalog mirror and all three persisted marker-linkage checks.
readiness="$root/fi_c1_populated_sor_readiness_c220.sh"
for required in \
    'C1_PRIVATE_SCHEMA_MIRROR' \
    'C1_PRIVATE_MARKER_CONSISTENCY' \
    'sources_without_artifact' \
    'typed_without_source' \
    'source_descriptor_mismatches' \
    'typed_marker_mismatches' \
    'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'; do
    grep -F "$required" "$readiness" >/dev/null ||
        fail "C220 partial replay audit lost required read-only evidence: $required"
done
echo "FI C1 C220 READ ONLY JAIL SELECTOR PASS standalone=4 single_jail_names=2 ambiguous_jails=rejected PG_and_trust_gates=fail_closed"
