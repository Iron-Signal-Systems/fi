#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$ROOT/database/schema/0002_source_families.sql"
GATE="$ROOT/scripts/phase3_relational_sources_gate.sh"

printf '%s\n' '===== FI PHASE 3 RELATIONAL SOURCE-FAMILY EXTENSION ====='
printf '%s\n' 'This is non-destructive and requires the empty relational v1 foundation.'
printf '\n'

sudo -v

foundation="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 -c "SELECT COALESCE(to_regclass('fi.source_record')::text,'')")"
if [[ "$foundation" != "fi.source_record" ]]; then
    printf 'ERROR: fi.source_record foundation is missing\n' >&2
    exit 1
fi

existing="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 -c "SELECT COALESCE(to_regclass('fi.collector_identity')::text,'')")"
if [[ -n "$existing" ]]; then
    printf '%s\n' '0002 source-family schema already appears present; running gate only.'
    exec "$GATE"
fi

source_records="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM fi.source_record")"
if [[ "$source_records" != "0" ]]; then
    printf 'ERROR: expected empty relational database before source-family extension; source_record=%s\n' "$source_records" >&2
    exit 1
fi

printf '%s\n' '===== APPLY 0002 SOURCE-FAMILY RELATIONAL MODEL ====='
{
    printf '%s\n' 'SET ROLE fi_owner;'
    cat "$SCHEMA"
    printf '%s\n' 'RESET ROLE;'
} | sudo -iu postgres psql -X -v ON_ERROR_STOP=1 -d fi

printf '\n%s\n' '===== RUN SOURCE-FAMILY GATE ====='
exec "$GATE"
