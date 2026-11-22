#!/bin/sh
# C1 isolated FreeBSD 15.1 / PostgreSQL 18 acceptance fixture.
# Only the disposable GitHub VM is authorized. NEVER C220.
# Initializes a new private PostgreSQL cluster in mktemp and executes
# existing signed-replay and 49-table atomic DDL/rollback Go test gates.
set -eu
umask 077
fail(){ echo "FI C1 FREEBSD NATIVE PG18 BLOCKED: $*" >&2; exit 1; }
[ "$(uname -s)" = FreeBSD ] || fail "FreeBSD kernel required"
[ "${GITHUB_ACTIONS:-}" = true ] || fail "explicit disposable VM authorization required"
[ "$(hostname -s)" != c220 ] || fail "physical C220 forbidden"
[ "$(id -u)" -eq 0 ] || fail "disposable FreeBSD VM root required"
command -v go >/dev/null 2>&1 || fail "native Go compiler missing"
[ -x /usr/local/bin/initdb ] || fail "PostgreSQL 18 initdb binary missing"
[ -x /usr/local/bin/pg_ctl ] || fail "PostgreSQL 18 pg_ctl binary missing"
[ -x /usr/local/bin/psql ] || fail "PostgreSQL 18 psql binary missing"
id postgres >/dev/null 2>&1 || fail "PostgreSQL system account missing"
base=$(mktemp -d /var/tmp/fi-c1-pg18-vm.XXXXXXXX) ||
  fail "cannot allocate disposable PG18 source"
# The PostgreSQL service user needs traversal of this disposable root
# for PGDATA and its WAL/error log; the directory stays mode 0700.
chown postgres:postgres "$base"
data="$base/pgdata"
log="$base/postgresql.log"
mkdir -m 0700 "$data"
chown postgres:postgres "$data"
started=0
offline_started=0
cleanup(){
    if [ "$offline_started" -eq 1 ];then
        su -m postgres -c "/usr/local/bin/pg_ctl -D '$offline_data' -m immediate -w stop" || :
    fi
    if [ "$started" -eq 1 ];then
        su -m postgres -c "/usr/local/bin/pg_ctl -D '$data' -m immediate -w stop" || :
    fi
    rm -rf "$base"
}
trap cleanup EXIT HUP INT TERM
su -m postgres -c "/usr/local/bin/initdb -D '$data' -A trust --locale=C --encoding=UTF8 --no-instructions" ||
  fail "cannot create disposable PostgreSQL 18 cluster"
su -m postgres -c "/usr/local/bin/pg_ctl -D '$data' -l '$log' -o '-h 127.0.0.1 -p 5432 -c fsync=on -c synchronous_commit=on -c full_page_writes=on' -w start" ||
  { cat "$log" >&2 || :; fail "disposable PostgreSQL 18 server startup"; }
started=1
version=$(psql -X -w -h 127.0.0.1 -p 5432 -U postgres -d postgres -At -v ON_ERROR_STOP=1 -c 'SHOW server_version_num') ||
  fail "cannot query local PostgreSQL identity"
case "$version" in
18????) : ;;
*) fail "unexpected PostgreSQL version $version; PostgreSQL 18 required" ;;
esac
# Every statement is sent through the normal PostgreSQL protocol.
# Keep the HERE-DOC terminator on its own line; a shell "|| fail" must
# never be interpreted as SQL fixture input.
psql -X -w -h 127.0.0.1 -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE fi_c1_test WITH LOGIN;
CREATE DATABASE fi_c1_replay_integration OWNER fi_c1_test;
-- Disposable VM only: this role must match the PostgreSQL Docker
-- POSTGRES_USER fixture's administrative capabilities for offline DDL.
CREATE ROLE fi_c1_schema_test WITH LOGIN SUPERUSER;
CREATE DATABASE fi OWNER fi_c1_schema_test;
SQL
# Verify both disposable DB identities and admin capability before
# downloading Go modules; role creation mistakes fail within seconds.
for role in fi_c1_test fi_c1_schema_test;do
  [ "$(psql -X -w -h 127.0.0.1 -p 5432 -U postgres -d postgres -At \
      -v ON_ERROR_STOP=1 \
      -c "SELECT count(*) FROM pg_roles WHERE rolname='$role'")" = 1 ] ||
      fail "disposable PostgreSQL missing fixture role $role"
done
[ "$(psql -X -w -h 127.0.0.1 -p 5432 -U postgres -d postgres -At \
    -v ON_ERROR_STOP=1 \
    -c "SELECT rolsuper FROM pg_roles WHERE rolname='fi_c1_schema_test'")" = t ] ||
    fail "isolated private-schema admin is not a PostgreSQL SUPERUSER"
for db in fi fi_c1_replay_integration;do
  [ "$(psql -X -w -h 127.0.0.1 -p 5432 -U postgres -d postgres -At \
      -v ON_ERROR_STOP=1 \
      -c "SELECT count(*) FROM pg_database WHERE datname='$db'")" = 1 ] ||
      fail "disposable PostgreSQL missing fixture database $db"
done

cd go
export GITHUB_ACTIONS=true
export FI_C1_REPLAY_CI_ALLOW_ISOLATED_WRITES=1
export FI_C1_REPLAY_PG_DSN='host=127.0.0.1 port=5432 user=fi_c1_test dbname=fi_c1_replay_integration sslmode=disable'
go test -tags 'fi_c1_sor_dev fi_c1_replay_pg_integration' -count=1 \
  -run '^TestC1RecoveredSourceParentAndTypedRootPostgres18$' \
  -v ./internal/recordingest ||
  fail "actual FreeBSD PostgreSQL 18 partial SourceParent/typed recovery proof"
unset FI_C1_REPLAY_CI_ALLOW_ISOLATED_WRITES FI_C1_REPLAY_PG_DSN
export FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE=1
export FI_C1_SCHEMA_CI_ADMIN_DSN='host=127.0.0.1 port=5432 user=fi_c1_schema_test dbname=fi sslmode=disable'
go test -tags 'fi_c1_sor_dev fi_c1_schema_pg_integration' -count=1 \
  -run '^TestC1PrivateSchemaRealPostgres18AtomicDDL$' \
  -v ./internal/recordingest ||
  fail "actual FreeBSD PostgreSQL 18 atomic private DDL/rollback proof"

# A completely separate Go process writes a REAL receiver-signed generation
# and commits its SourceParent, leaving typed SQL and canonical Accepted
# absent. The shell then kills THIS DISPOSABLE CLUSTER with pg_ctl immediate;
# the next Go process cannot use any in-memory worker state.
export FI_C1_CI_CRASH_ROOT="$base/signed-crash"
export FI_C1_CI_CRASH_PHASE=before
go test -tags 'fi_c1_sor_dev fi_c1_schema_pg_integration' -count=1 \
  -run '^TestC1SignedPostgres18ImmediateCrashRecovery$' -v ./internal/recordingest ||
  fail "original signed SourceParent failed before actual PostgreSQL crash"
unset FI_C1_CI_CRASH_PHASE
su -m postgres -c "/usr/local/bin/pg_ctl -D '$data' -m immediate -w stop" ||
  fail "disposable PostgreSQL 18 immediate-stop failed"
started=0
su -m postgres -c "/usr/local/bin/pg_ctl -D '$data' -l '$log' -o '-h 127.0.0.1 -p 5432 -c fsync=on -c synchronous_commit=on -c full_page_writes=on' -w start" ||
  { cat "$log" >&2 || :; fail "disposable PostgreSQL18 WAL crash recovery failed"; }
started=1
for setting in fsync synchronous_commit full_page_writes;do
  value=$(psql -X -w -h 127.0.0.1 -p 5432 -U postgres -d fi -At -v ON_ERROR_STOP=1 -c "SHOW $setting") ||
    fail "read $setting after PostgreSQL crash recovery"
  [ "$value" = on ] || fail "recovered PostgreSQL durability setting $setting not on"
done
export FI_C1_CI_CRASH_PHASE=after
go test -tags 'fi_c1_sor_dev fi_c1_schema_pg_integration' -count=1 \
  -run '^TestC1SignedPostgres18ImmediateCrashRecovery$' -v ./internal/recordingest ||
  fail "real signed C1 PostgreSQL WAL crash recovery, typed replay and exact Accepted"
unset FI_C1_CI_CRASH_ROOT FI_C1_CI_CRASH_PHASE

# Dedicated second PostgreSQL18 cluster, not a schema inside the first
# test cluster. Its FI database starts with just the genuine canonical
# migration graph; the one-shot C1 governed offline installer must prove
# full atomic rollback, then installation and a rejected repeated install.
offline_data="$base/offline-pgdata"
offline_socket="$base/offline-socket"
offline_log="$base/offline-postgres.log"
mkdir -m 0700 "$offline_data" "$offline_socket" ||
  fail "allocate separate disposable offline governed SQL cluster"
chown postgres:postgres "$offline_data" "$offline_socket"
su -m postgres -c "/usr/local/bin/initdb -D '$offline_data' -A trust --locale=C --encoding=UTF8 --no-instructions" ||
  fail "initialize separate offline governed SQL database"
su -m postgres -c "/usr/local/bin/pg_ctl -D '$offline_data' -l '$offline_log' -o '-h 127.0.0.1 -k $offline_socket -p 5434 -c fsync=on -c synchronous_commit=on -c full_page_writes=on' -w start" ||
  { cat "$offline_log" >&2 || :; fail "start separate offline governed SQL PostgreSQL18"; }
offline_started=1
psql -X -w -h "$offline_socket" -p 5434 -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE fi_c1_schema_test WITH LOGIN SUPERUSER;
CREATE DATABASE fi OWNER fi_c1_schema_test;
SQL
export FI_C1_CI_OFFLINE_INSTALL_APPROVED=ISOLATED_SECOND_PG18_CLUSTER_ONLY
export FI_C1_CI_OFFLINE_INSTALL_DSN="host=$offline_socket port=5434 dbname=fi user=fi_c1_schema_test sslmode=disable"
go test -tags 'fi_c1_sor_dev fi_c1_schema_pg_integration' -count=1 \
  -run '^TestC1GovernedPendingOfflineInstallerFreshPostgres18$' \
  -v ./internal/recordingest ||
  fail "governed existing-SoR offline Pending and publisher role install, rollback or idempotence"
unset FI_C1_CI_OFFLINE_INSTALL_APPROVED FI_C1_CI_OFFLINE_INSTALL_DSN
su -m postgres -c "/usr/local/bin/pg_ctl -D '$offline_data' -m immediate -w stop" ||
  fail "stop separate offline SQL fixture"
offline_started=0

echo "FI C1 NATIVE FREEBSD PG18 PASS partial_powerloss_reconciliation=true real_postgresql_immediate_stop=true signed_crash_typed_replay=true accepted_exactly_once=true governed_offline_installer=true governed_atomic_rollback=true private_schema_atomic_rollback=true fsync=true synchronous_commit=true full_page_writes=true C220_untouched=true"
