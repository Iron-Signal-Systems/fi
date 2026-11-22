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
# Abandoned C1 private state is disposable development data. Regression
# guards for the operator-approved C220 deletion path. This test never
# invokes the deletion script; it only parses and checks the source.
discard="$root/fi_c1_discard_private_stage_c220.sh"
sh -n "$discard" || fail "private-stage discard syntax error"
for required in \
  'FI_C1_DISCARD_PRIVATE_STAGE_APPROVED' \
  "current_database()<>'fi'" \
  'r_count<>54114023' \
  'g_count<>6249' \
  'p_tables<>49' \
  'l_tables<>4' \
  'own_gen_count<>1' \
  'typed_total<>2770101' \
  "EXECUTE 'DROP TABLE ' || tables || ' RESTRICT'" \
  'DROP SCHEMA fi_recovery_projection RESTRICT;' \
  'DROP SCHEMA fi_recovery RESTRICT;' \
  "current_setting('data_directory')"; do
    grep -F "$required" "$discard" >/dev/null ||
      fail "C220 private-stage discard lost critical safety gate: $required"
done
if grep -Eq '^[[:space:]]*(DROP|TRUNCATE|DELETE|UPDATE|ALTER)[[:space:]]+(TABLE[[:space:]]+)?fi\.' "$discard"; then
  fail 'C220 private-stage discard touches canonical fi SQL'
fi
# Verify real C220 FI-jail inventory remains observational.
contract="$root/fi_c1_c220_jail_runtime_contract.sh"
sh -n "$contract" || fail "C220 jail runtime inventory syntax"
for required in \
    'jls -h jid name path' \
    'C1_SOR_RUNTIME_IDENTITY=ABSENT' \
    'mount -p' \
    'PRIVATE_STAGE_ABSENT=' \
    'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;' \
    'FI C1 C220 EXISTING JAIL RUNTIME INVENTORY COMPLETE'; do
    grep -F "$required" "$contract" >/dev/null ||
      fail "C220 jail runtime inventory lost read-only proof: $required"
done
if grep -Eq '^[[:space:]]*(mount[[:space:]]+-t|jail[[:space:]]+-c|jail[[:space:]]+-r|sysrc[[:space:]]|service[[:space:]]|pw[[:space:]]+useradd|DROP[[:space:]]|DELETE[[:space:]]|TRUNCATE[[:space:]])' "$contract"; then
    fail 'C220 jail runtime inventory includes state mutation'
fi
# Real C220 fi-sor already owns fi-ingest-socket GID 4100. The only
# approved service-identity operation is a single jailed useradd reusing
# that group, never a host groupadd or PostgreSQL identity alteration.
identity="$root/fi_c1_c220_sor_service_identity.sh"
sh -n "$identity" || fail 'real SoR identity script shell syntax'
for token in \
    'C1_SOR_IDENTITY_AUDIT_COMPLETE read_only=true' \
    'FI_C1_SOR_IDENTITY_APPROVED' \
    'ADD_FI_SOR_USER_REUSE_SOCKET_GID' \
    'uid_collisions' \
    'gid_groups' \
    'jexec fi-sor /usr/sbin/pw useradd fi-sor' \
    '-u 4100 -g fi-ingest-socket' \
    'existing_socket_group_preserved=true'; do
    grep -F -- "$token" "$identity" >/dev/null ||
        fail "real C220 SoR identity lost gate: $token"
done
if grep -E '^[[:space:]]*[^#[:space:]]' "$identity" | grep -Eq '(^|[[:space:]])(groupadd|groupmod|userdel|service|jail -r|mount -t)([[:space:]]|$)'; then
    fail 'C220 account installer contains forbidden group/service/mount mutation'
fi
# The actual C220 has no fi-ingest/fi-sor mount.fstab assignments.
# The C1 plan must target these jails, preserve read-only SoR transport
# and never launch a live mount or jail restart.
mount_plan="$root/fi_c1_c220_ram_mount_plan.sh"
sh -n "$mount_plan" || fail 'C220 real RAM mount planner shell syntax'
for token in \
    'NOAUTO' \
    'fi-c1-fi-ingest.fstab' \
    'fi-c1-fi-sor.fstab' \
    'nullfs rw 0 0' \
    'nullfs ro 0 0' \
    'size=4g,uid=4100,gid=4100,mode=0770' \
    'read_only=true host_changes=false'; do
    grep -F -- "$token" "$mount_plan" >/dev/null ||
        fail "C220 RAM mount plan lost fixed real-jail requirement: $token"
done
# Independent B must see signed custody, recorded receipt, pinned
# trust and registry via fi-sor only, never via an ingest tmpfs copy.
for token in \
    'host_custody=/work/fi-c220-20261114/custody/generation' \
    'host_recorded=/work/fi-c220-20261114/custody/recorded' \
    'host_trust=/work/fi-c220-20261114/config/receiver/pki/trust' \
    'host_sources=/work/fi-c220-20261114/config/receiver/sources' \
    '/var/db/fi/custody/generation nullfs ro 0 0' \
    '/var/db/fi/custody/recorded nullfs ro 0 0' \
    '/usr/local/etc/fi/pki/trust nullfs ro 0 0' \
    '/usr/local/etc/fi/sources nullfs ro 0 0'; do
    grep -F -- "$token" "$mount_plan" >/dev/null ||
        fail "C220 B original signed custody/trust RO mapping missing: $token"
done
if grep -Eq '^[[:space:]]*(mount[[:space:]]+-t|jail[[:space:]]+-r|jail[[:space:]]+-c|sysrc[[:space:]]|service[[:space:]]|pw[[:space:]]|mkdir[[:space:]]|install[[:space:]])' "$mount_plan"; then
    fail 'C220 RAM mount plan must not alter host state'
fi
# The explicit real-jail C1 live mount action must always audit before
# applying. The CI only parses and checks source, never mounts anything.
live="$root/fi_c1_c220_live_mounts.sh"
sh -n "$live" || fail 'C220 live mount installer syntax'
for token in \
    'FI_C1_LIVE_MOUNTS_APPROVED' \
    'ONLY_C1_TMPFS_AND_FIVE_SOR_RO_VIEWS' \
    'FI C1 LIVE MOUNT AUDIT COMPLETE read_only=true' \
    '::text")" = true ]' \
    "to_regnamespace('fi_recovery_projection') IS NULL" \
    'mount -t tmpfs -o' \
    "size=4g,uid=4100,gid=4100,mode=0770,nosuid,noexec" \
    'mount -t nullfs -o rw "$ram" "$ingest_ram"' \
    'mount -t nullfs -o ro "$ram" "$sor_ram"' \
    'mount -t nullfs -o ro "$host_generation" "$sor_generation"' \
    'mount -t nullfs -o ro "$host_recorded" "$sor_recorded"' \
    'mount -t nullfs -o ro "$host_trust" "$sor_trust"' \
    'mount -t nullfs -o ro "$host_sources" "$sor_sources"' \
    'host_persistence=false jail_restarts=0 c1_services_started=false'; do
    grep -F -- "$token" "$live" >/dev/null ||
        fail "C220 live mount operation lost fail-closed condition: $token"
done
if grep -Eq '^[[:space:]]*(sysrc[[:space:]]|service[[:space:]]|jail[[:space:]]+-r|jail[[:space:]]+-c|pw[[:space:]]|psql[[:space:]]|zfs[[:space:]]+destroy)' "$live"; then
    fail 'C220 live mount operation changes unrelated services or SQL'
fi
# Statfs acceptance must validate ALL seven physical mounts including
# original signed trust and source registry, under the actual SoR account.
native="$root/fi_c1_c220_native_acceptance.sh"
sh -n "$native" || fail 'native C220 acceptance shell syntax'
for token in \
    'FI C1 C220 NATIVE MOUNT ACCEPTANCE COMPLETE' \
    'C1_SOR_ORIGINAL_SIGNED_INPUTS_ACCESSIBLE=true' \
    '-host-trust-root' \
    '-host-sources-root' \
    '-sor-trust-path' \
    '-sor-sources-path' \
    'jexec -U fi-sor fi-sor' \
    'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;' \
    'C1_PRIVATE_STAGE_ABSENT='; do
    grep -F -- "$token" "$native" >/dev/null ||
        fail "C220 native acceptance lost a required signed verification gate: $token"
done
# Functional handoff is distinct from read-only native acceptance. It
# may create ONE volatile tmpfs test file only under explicit approval,
# must prove fi-sor RO behavior, and must always clean the created file.
handoff="$root/fi_c1_c220_handoff_proof.sh"
sh -n "$handoff" || fail 'C220 volatile handoff proof syntax'
for token in \
    'FI_C1_HANDOFF_PROOF_APPROVED' \
    'VOLATILE_ONE_FILE_ONLY' \
    'fi_c1_c220_native_acceptance.sh --verify' \
    'jexec -U fi-ingest fi-ingest /usr/bin/mktemp' \
    'jexec -U fi-sor fi-sor /usr/bin/cksum' \
    'jexec -U fi-sor fi-sor /bin/sh -c' \
    'jexec -U fi-ingest fi-ingest /bin/rm -f "$path"' \
    'C1_C220_VOLATILE_HANDOFF_PROOF_PASS'; do
    grep -F -- "$token" "$handoff" >/dev/null ||
        fail "C220 volatile proof lost fail-closed guard: $token"
done
echo "FI C1 C220 READ ONLY JAIL SELECTOR PASS standalone=4 single_jail_names=2 ambiguous_jails=rejected PG_and_trust_gates=fail_closed"
