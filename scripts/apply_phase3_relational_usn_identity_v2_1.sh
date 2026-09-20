#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB=fi
SOCKET=/run/postgresql

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

echo
echo '===== PRECONDITION: USN RELATIONAL TABLES EMPTY ====='
sudo -iu postgres psql -X -v ON_ERROR_STOP=1 -h "$SOCKET" -d "$DB" <<'SQL'
SELECT
    (SELECT count(*) FROM fi.usn_object_observation) AS usn_object_observation,
    (SELECT count(*) FROM fi.usn_object_change) AS usn_object_change;
SQL

read -r object_count change_count < <(
    sudo -iu postgres psql -X -A -t -h "$SOCKET" -d "$DB" -c \
      "SELECT (SELECT count(*) FROM fi.usn_object_observation), (SELECT count(*) FROM fi.usn_object_change);" \
      | tr '|' ' '
)

if [[ "$object_count" != "0" || "$change_count" != "0" ]]; then
    echo 'ERROR: USN relational tables are not empty; refusing identity rewrite.' >&2
    false
fi

echo
echo '===== APPLY USN RELATIONAL IDENTITY CORRECTION ====='
{
    printf '%s\n' 'SET ROLE fi_owner;'
    cat "$ROOT/database/schema/0003_usn_relational_identity.sql"
    printf '%s\n' 'RESET ROLE;'
} | sudo -iu postgres psql -X -v ON_ERROR_STOP=1 -h "$SOCKET" -d "$DB"

echo
echo '===== VERIFY ====='
"$ROOT/scripts/phase3_relational_usn_identity_gate.sh"
