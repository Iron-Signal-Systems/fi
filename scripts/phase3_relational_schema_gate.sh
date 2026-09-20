#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

printf '%s\n' '===== RELATIONAL TABLES ====='
sudo -iu postgres psql -X -d fi -v ON_ERROR_STOP=1 <<'SQL'
SELECT schemaname, tablename, tableowner
FROM pg_tables
WHERE schemaname = 'fi'
ORDER BY tablename;

SELECT
    count(*) FILTER (WHERE data_type IN ('json','jsonb')) AS json_columns,
    count(*) AS total_columns
FROM information_schema.columns
WHERE table_schema = 'fi';

SELECT
    table_name,
    column_name,
    data_type
FROM information_schema.columns
WHERE table_schema = 'fi'
  AND data_type IN ('json','jsonb')
ORDER BY table_name, ordinal_position;
SQL

json_columns="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.columns WHERE table_schema='fi' AND data_type IN ('json','jsonb')")"
if [[ "$json_columns" != "0" ]]; then
    printf 'ERROR: relational schema contains %s JSON/JSONB columns\n' "$json_columns" >&2
    exit 1
fi

printf '%s\n' '===== FI_INGEST RIGHTS ====='
sudo -iu postgres psql -X -d fi -v ON_ERROR_STOP=1 <<'SQL'
SELECT
    has_schema_privilege('fi_ingest','fi','USAGE') AS schema_usage,
    has_table_privilege('fi_ingest','fi.source_record','SELECT') AS source_record_select,
    has_table_privilege('fi_ingest','fi.source_record','INSERT') AS source_record_insert,
    has_table_privilege('fi_ingest','fi.source_record','UPDATE') AS source_record_update,
    has_table_privilege('fi_ingest','fi.source_record','DELETE') AS source_record_delete;
SQL

rights="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 -c "SELECT has_table_privilege('fi_ingest','fi.source_record','SELECT')::text || '|' || has_table_privilege('fi_ingest','fi.source_record','INSERT')::text || '|' || has_table_privilege('fi_ingest','fi.source_record','UPDATE')::text || '|' || has_table_privilege('fi_ingest','fi.source_record','DELETE')::text")"
if [[ "$rights" != "true|true|false|false" ]]; then
    printf 'ERROR: unexpected fi_ingest source_record rights: %s\n' "$rights" >&2
    exit 1
fi

printf '%s\n' '===== EMPTY STATE ====='
sudo -u fi-receiver psql -X -h /run/postgresql -U fi_ingest -d fi -v ON_ERROR_STOP=1 <<'SQL'
SELECT 'recorded_generation=' || count(*) FROM fi.recorded_generation;
SELECT 'source_batch=' || count(*) FROM fi.source_batch;
SELECT 'source_record=' || count(*) FROM fi.source_record;
SELECT 'file_observation=' || count(*) FROM fi.file_observation;
SELECT 'ingest_journal=' || count(*) FROM fi.ingest_journal;
SQL

printf '%s\n' 'PASS: empty relational Phase 3 schema is installed, contains no JSON/JSONB storage, and fi_ingest retains append-only runtime authority.'
