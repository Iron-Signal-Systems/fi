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
cleanup(){
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
CREATE ROLE fi_c1_schema_test WITH LOGIN;
CREATE DATABASE fi OWNER fi_c1_schema_test;
SQL

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
echo "FI C1 NATIVE FREEBSD PG18 PASS partial_powerloss_reconciliation=true private_schema_atomic_rollback=true fsync=true synchronous_commit=true full_page_writes=true C220_untouched=true"
