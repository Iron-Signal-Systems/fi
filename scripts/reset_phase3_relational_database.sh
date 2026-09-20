#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB=fi
SOCKET=/run/postgresql

echo '===== FI PHASE 3 RELATIONAL DATABASE RESET ====='
echo 'WARNING: this permanently drops the PostgreSQL database named fi.'
echo 'Recorder custody under /var/lib/fi/custody is not touched.'
echo
sudo -v

echo '===== TERMINATE FI DATABASE SESSIONS ====='
sudo -iu postgres psql -X -v ON_ERROR_STOP=1 -d postgres <<SQL
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = '$DB'
  AND pid <> pg_backend_pid();
SQL

echo '===== DROP OLD FI DATABASE ====='
sudo -iu postgres dropdb --if-exists "$DB"

echo '===== CREATE EMPTY FI DATABASE ====='
sudo -iu postgres createdb --owner=fi_owner --template=template0 --encoding=UTF8 --locale=C.UTF-8 "$DB"

echo '===== DATABASE ACCESS BOUNDARY ====='
sudo -iu postgres psql -X -v ON_ERROR_STOP=1 -d "$DB" <<'SQL'
REVOKE ALL ON DATABASE fi FROM PUBLIC;
GRANT CONNECT ON DATABASE fi TO fi_ingest;
SQL

echo '===== APPLY RELATIONAL SCHEMA ====='
{
    printf '%s\n' 'SET ROLE fi_owner;'
    cat "$ROOT/database/schema/0001_relational.sql"
    cat "$ROOT/database/schema/0002_source_families.sql"
    cat "$ROOT/database/schema/0003_usn_relational_identity.sql"
    printf '%s\n' 'RESET ROLE;'
} | sudo -iu postgres psql -X -v ON_ERROR_STOP=1 -h "$SOCKET" -d "$DB"

echo '===== RELATIONAL RESET COMPLETE ====='
