#!/bin/sh
# FI DEVELOPMENT ONLY: build an independent EMPTY PostgreSQL 18.6 seed
# using FI's five canonical migrations and audited private-schema generator.
# Executes as jwood inside fi-dev. Never clones any W128 checkpoint.
set -eu
umask 077
die(){ printf 'FI W256 NEW SEED STOP: %s\n' "$*" >&2; exit 1; }

[ "$#" = 2 ] || die 'usage: $0 /home/jwood/fi-w256-seed-TIMESTAMP 55870'
root=$1
port=$2
[ "$(id -un)" = jwood ] && [ "$(sysctl -n security.jail.jailed)" = 1 ] ||
 die 'must run as jwood inside fi-dev'
case "$root" in /home/jwood/fi-w256-seed-[0-9]*) ;; *) die 'invalid fresh W256 seed root';; esac
case "$root:$port" in *..*|*' '*|*'*'*|*'?'*|*'['*|*']'*) die 'unsafe root or port';; esac
[ "$port" = 55870 ] || die 'W256 seed port must be 55870'
[ ! -e "$root" ] || die 'seed root already exists; will not overwrite'
[ "$(psql --version)" = 'psql (PostgreSQL) 18.6' ] || die 'PostgreSQL 18.6 required'

repo=/home/jwood/fi-deferred-experiment
[ -f "$repo/.git" ] || die 'must use separate detached FI experiment worktree'
[ -z "$(cd "$repo" && git branch --show-current)" ] || die 'experiment worktree must be detached'
[ -z "$(cd "$repo" && git status --porcelain --untracked-files=no)" ] ||
 die 'experiment worktree contains uncommitted modifications'
schema="$repo/database/schema"
ledger="$repo/go/internal/recordingest/backlog_artifact_ledger_schema.sql"
partition_sql="$repo/go/cmd/fi-backlog-recover/testdata/private_w256_empty_field_partition.sql"
[ -r "$ledger" ] && [ -r "$partition_sql" ] || die 'missing audited FI fixture schema'
for name in 0001_relational.sql 0002_source_families.sql 0003_usn_relational_identity.sql 0004_security_field_name_index.sql 0005_usn_capture_binding.sql; do
 [ -r "$schema/$name" ] || die "missing canonical FI migration $name"
done
for tool in go initdb pg_ctl psql createdb; do
 command -v "$tool" >/dev/null 2>&1 || die "missing $tool"
done

mkdir -m 700 "$root"
sock="$root/socket"
mkdir -m 700 "$sock"
printf 'FI W256 NEW SEED git_commit=%s database=fi fixture=empty origin=canonical_migrations+private_schema\n' "$(cd "$repo" && git rev-parse HEAD)" > "$root/provision.log"

(cd "$repo/go" && GOAMD64=v1 go run ./cmd/fi-backlog-recovery-schema \
 -ledger-sql="$ledger" -migrations-dir="$schema") > "$root/private_schema.sql" ||
 die 'FI private-schema generation failed'
grep -q 'CREATE SCHEMA fi_recovery;' "$root/private_schema.sql" ||
 die 'generated private recovery ledger missing'
grep -q 'CREATE SCHEMA fi_recovery_projection' "$root/private_schema.sql" ||
 die 'generated private relational schema missing'

initdb -D "$root/data" -U fi_m1_admin -A trust --no-instructions > "$root/initdb.log" 2>&1 ||
 die 'new PostgreSQL 18 cluster initdb failed'
pg_ctl -D "$root/data" -l "$root/postgres.log" \
 -o "-p $port -k $sock -c listen_addresses= -c unix_socket_permissions=0700 -c max_wal_size=8GB -c track_io_timing=off -c track_wal_io_timing=off" \
 -w start > "$root/start.log" 2>&1 ||
 die 'new isolated PostgreSQL cluster failed to start'
postgres="host=$sock port=$port user=fi_m1_admin dbname=postgres sslmode=disable"
psql "$postgres" -X -q -v ON_ERROR_STOP=1 \
 -c 'CREATE ROLE fi_owner NOLOGIN' \
 -c 'CREATE ROLE fi_ingest LOGIN' > "$root/roles.log" 2>&1 ||
 die 'new isolated FI roles failed'
createdb -h "$sock" -p "$port" -U fi_m1_admin -O fi_owner fi ||
 die 'isolated database creation failed'
admin="host=$sock port=$port user=fi_m1_admin dbname=fi sslmode=disable"
for name in 0001_relational.sql 0002_source_families.sql 0003_usn_relational_identity.sql 0004_security_field_name_index.sql 0005_usn_capture_binding.sql; do
 psql "$admin" -X -q -v ON_ERROR_STOP=1 -f "$schema/$name" >> "$root/migrations.log" 2>&1 ||
  die "canonical FI schema migration $name failed"
done
psql "$admin" -X -q -v ON_ERROR_STOP=1 -f "$root/private_schema.sql" > "$root/private-schema.log" 2>&1 ||
 die 'generated private recovery schema failed'
psql "$admin" -X -q -v ON_ERROR_STOP=1 -f "$partition_sql" > "$root/partition-schema.log" 2>&1 ||
 die 'W256 private field partition setup failed'
ingest="host=$sock port=$port user=fi_ingest dbname=fi sslmode=disable"
check(){ psql "$ingest" -X -qAt -v ON_ERROR_STOP=1 -c "$1"; }
[ "$(check "SELECT count(*) FROM pg_tables WHERE schemaname='fi'")" = 49 ] ||
 die 'canonical FI test schema does not have 49 tables'
[ "$(check "SELECT count(*) FROM fi_recovery.typed_window")" = 0 ] &&
[ "$(check "SELECT count(*) FROM fi_recovery.source_window")" = 0 ] &&
[ "$(check "SELECT count(*) FROM fi_recovery.verified_artifact_window")" = 0 ] ||
 die 'new W256 checkpoint chain is not empty'
[ "$(check "SELECT count(*) FROM fi.recorded_generation")" = 0 ] &&
[ "$(check "SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'")" = 0 ] ||
 die 'unexpected authoritative or Accepted rows'
[ "$(check "SELECT count(*) FROM pg_partitioned_table WHERE partrelid='fi_recovery_projection.windows_security_event_field'::regclass")" = 1 ] ||
 die 'new W256 private Security field table is not partitioned'
[ "$(check "SELECT count(*) FROM pg_inherits WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass")" = 1 ] ||
 die 'expected one W0 seed partition'
for setting in fsync synchronous_commit full_page_writes; do
 [ "$(check "SHOW $setting")" = on ] || die "PostgreSQL $setting is not enabled"
done
printf 'FI W256 NEW SEED READY root=%s port=%s status=empty_fresh_private_schema W128_prefix=rejected\n' "$root" "$port"
