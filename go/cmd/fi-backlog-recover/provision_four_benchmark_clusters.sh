#!/bin/sh
# Run inside fi-dev as jwood. Creates FOUR NEW independent PostgreSQL 18
# clusters with existing FI migrations and the tested PRIVATE schema emitter.
# NEVER touches or clones existing test/production clusters.
set -eu
umask 077
fail() { printf 'FI BENCHMARK PROVISION STOP: %s\n' "$*" >&2; exit 1; }
: "${FI_BENCH_NEW_CLUSTER_ROOT:?set NEW /home/jwood/fi-window-bench-<unique> absolute directory}"
: "${FI_BENCH_BINARY_SHA256:?set verified hash of the backend benchmark executable}"
: "${FI_BENCH_HOST_BINARY_PATH:=/home/jwood/fi-real-backlog-20261101/fi-backlog-recover-window-profiles}"
case "$FI_BENCH_HOST_BINARY_PATH" in
  /*) ;;
  *) fail "FI_BENCH_HOST_BINARY_PATH must be an absolute FreeBSD HOST path";;
esac
case "$FI_BENCH_NEW_CLUSTER_ROOT" in
  /home/jwood/fi-window-bench-[A-Za-z0-9]*)
    case "$FI_BENCH_NEW_CLUSTER_ROOT" in
      *..*|*//*|*' '*|*'*'*|*'?'*|*'['*|*']'*) fail "unsafe cluster directory";;
    esac
    ;;
  *) fail "root must start /home/jwood/fi-window-bench- with a unique suffix";;
esac
[ ! -e "$FI_BENCH_NEW_CLUSTER_ROOT" ] || fail "destination already exists; refusing to modify"
[ "$(id -un)" = "jwood" ] || fail "must run as jwood inside fi-dev"
[ "$(sysctl -n security.jail.jailed)" = "1" ] || fail "must run inside a FreeBSD jail"
[ "$(psql --version)" = "psql (PostgreSQL) 18.6" ] || fail "requires verified PostgreSQL 18.6 tools"
case "$FI_BENCH_BINARY_SHA256" in
  *[!a-f0-9]*|'') fail "SHA256 must be lowercase hexadecimal";;
esac
[ "${#FI_BENCH_BINARY_SHA256}" -eq 64 ] || fail "SHA256 must be 64 hex chars"

repo=/home/jwood/src/fi
schema_dir="$repo/database/schema"
ledger="$repo/go/internal/recordingest/backlog_artifact_ledger_schema.sql"
for name in 0001_relational.sql 0002_source_families.sql 0003_usn_relational_identity.sql 0004_security_field_name_index.sql 0005_usn_capture_binding.sql; do
    [ -r "$schema_dir/$name" ] || fail "missing canonical migration $name"
done
[ -r "$ledger" ] || fail "missing private ledger SQL"
for tool in initdb pg_ctl psql createdb go; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing $tool"
done

# Use a separate port family for every fresh benchmark dataset.
base_port=${FI_BENCH_BASE_PORT:-55431}
case "$base_port" in
  55431|55531|55631|55731) ;;
  *) fail "FI_BENCH_BASE_PORT must be 55431,55531,55631,or 55731";;
esac
w32_port=$base_port
w64_port=$((base_port + 1))
w96_port=$((base_port + 2))
w128_port=$((base_port + 3))
mkdir -m 700 "$FI_BENCH_NEW_CLUSTER_ROOT"
root=$FI_BENCH_NEW_CLUSTER_ROOT
# The same generator used for acceptance tests; no hand-authored shadow tables.
(cd "$repo/go" && go run ./cmd/fi-backlog-recovery-schema \
    -ledger-sql="$ledger" -migrations-dir="$schema_dir") > "$root/private_schema.sql" ||
    fail "FI private schema generator failed"
grep 'CREATE SCHEMA fi_recovery;' "$root/private_schema.sql" >/dev/null ||
    fail "private SQL missing ledger schema"
grep 'CREATE SCHEMA fi_recovery_projection' "$root/private_schema.sql" >/dev/null ||
    fail "private SQL missing typed schema"

for entry in "W32:$w32_port" "W64:$w64_port" "W96:$w96_port" "W128:$w128_port"; do
    profile=${entry%:*}
    port=${entry#*:}
    dir="$root/$profile"
    sock="$dir/socket"
    mkdir -m 700 "$dir" "$sock"
    initdb -D "$dir/data" -U fi_m1_admin -A trust --no-instructions > "$dir/initdb.log" 2>&1 ||
        fail "$profile initdb failed; nothing on existing clusters was changed"
    # Socket-only, under a private 0700 directory. No TCP listener.
    pg_ctl -D "$dir/data" -l "$dir/postgres.log" \
      -o "-p $port -k $sock -c listen_addresses= -c unix_socket_permissions=0700" \
      -w start > "$dir/start.log" 2>&1 ||
        fail "$profile server start failed; see $dir/start.log"
    admin="host=$sock port=$port user=fi_m1_admin dbname=postgres sslmode=disable"
    psql "$admin" -X -q -v ON_ERROR_STOP=1 \
      -c 'CREATE ROLE fi_owner NOLOGIN' \
      -c 'CREATE ROLE fi_ingest LOGIN' > "$dir/roles.log" 2>&1 ||
        fail "$profile role installation failed"
    createdb -h "$sock" -p "$port" -U fi_m1_admin -O fi_owner fi ||
        fail "$profile FI database creation failed"
    adminfi="host=$sock port=$port user=fi_m1_admin dbname=fi sslmode=disable"
    for name in 0001_relational.sql 0002_source_families.sql 0003_usn_relational_identity.sql 0004_security_field_name_index.sql 0005_usn_capture_binding.sql; do
        psql "$adminfi" -X -q -v ON_ERROR_STOP=1 -f "$schema_dir/$name" >> "$dir/migrate.log" 2>&1 ||
            fail "$profile canonical migration $name failed"
    done
    psql "$adminfi" -X -q -v ON_ERROR_STOP=1 -f "$root/private_schema.sql" > "$dir/private-schema.log" 2>&1 ||
        fail "$profile private schema installation failed"

    ingest="host=$sock port=$port user=fi_ingest dbname=fi sslmode=disable"
    check=$(psql "$ingest" -X -qAt -v ON_ERROR_STOP=1 -c "
SELECT count(*) FROM pg_tables WHERE schemaname='fi'
") || fail "$profile cannot inspect schema as fi_ingest"
    [ "$check" = 49 ] || fail "$profile fi schema has $check tables, expected 49"
    check=$(psql "$ingest" -X -qAt -v ON_ERROR_STOP=1 -c "
SELECT CASE WHEN
 to_regclass('fi_recovery.verified_artifact_window') IS NOT NULL AND
 to_regclass('fi_recovery.typed_window') IS NOT NULL AND
 to_regclass('fi_recovery_projection.source_batch') IS NOT NULL AND
 NOT EXISTS(SELECT 1 FROM fi.recorded_generation)
 THEN 'READY' ELSE 'INVALID' END
") || fail "$profile cannot inspect private schema"
    [ "$check" = READY ] || fail "$profile private schema not empty/ready"
    printf 'FI BENCHMARK CLUSTER profile=%s port=%s state=READY socket=%s\n' "$profile" "$port" "$sock"
done

# Create a host-readable config containing four unique host-visible socket
# paths. The host runner's psql jail bridge rewrites the prefix for fi-dev.
envfile="$root/fi-four-profiles.env"
{
    printf "FI_BENCH_BINARY='%s'\n" "$FI_BENCH_HOST_BINARY_PATH"
    printf "FI_BENCH_BINARY_SHA256='%s'\n" "$FI_BENCH_BINARY_SHA256"
    printf "FI_BENCH_OUTPUT_ROOT='%s'\n" "/var/tmp/fi-window-chunks-$(date -u '+%Y%m%dT%H%M%SZ')"
    printf "FI_BENCH_CUSTODY_ROOT='%s'\n" '/var/db/fi/custody/generation'
    printf "FI_BENCH_RECORDED_ROOT='%s'\n" '/var/db/fi/custody/recorded'
    printf "FI_BENCH_SOURCE_NAMESPACES='%s'\n" 'false'
    printf "FI_BENCH_PSQL_JAIL='%s'\n" 'fi-dev'
    for entry in "W32:$w32_port" "W64:$w64_port" "W96:$w96_port" "W128:$w128_port"; do
        profile=${entry%:*}
        port=${entry#*:}
        printf "FI_BENCH_%s_DSN='host=/usr/local/jails/containers/fi-dev%s/%s/socket port=%s user=fi_ingest dbname=fi sslmode=disable'\n" \
           "$profile" "$root" "$profile" "$port"
    done
    printf "FI_BENCH_ISOLATED_CLUSTERS_CONFIRMED='%s'\n" 'NO'
    for entry in "W32:$w32_port" "W64:$w64_port" "W96:$w96_port" "W128:$w128_port"; do
        profile=${entry%:*}
        port=${entry#*:}
        printf "FI_BENCH_%s_PORT='%s'\n" "$profile" "$port"
    done
} > "$envfile"
chmod 600 "$envfile"
printf 'FI BENCHMARK PROVISION COMPLETE: four NEW isolated PostgreSQL clusters only\n'
printf 'BENCHMARK CONFIG INSIDE JAIL: %s\n' "$envfile"
printf 'REVIEW ON HOST; SET FI_BENCH_ISOLATED_CLUSTERS_CONFIRMED=YES ONLY AFTER VERIFYING ALL FOUR NEW DATA DIRECTORIES\n'
