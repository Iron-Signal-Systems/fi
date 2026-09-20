#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "ERROR: $*" >&2
    false
}

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

printf '%s\n' '===== RELATIONAL TABLES ====='
sudo -iu postgres psql -X -d fi -v ON_ERROR_STOP=1 <<'SQL'
SELECT schemaname, tablename, tableowner
FROM pg_tables
WHERE schemaname = 'fi'
ORDER BY tablename;

SELECT
    count(*) FILTER (
        WHERE data_type IN ('json','jsonb','xml')
    ) AS semi_structured_columns,
    count(*) AS total_columns
FROM information_schema.columns
WHERE table_schema = 'fi';
SQL

table_count="$(
  sudo -iu postgres \
    psql -X -At -d fi -v ON_ERROR_STOP=1 \
      -c "SELECT count(*) FROM pg_tables WHERE schemaname='fi'"
)"
[ "$table_count" = '49' ] || fail "FI relational table count is $table_count; expected 49"

semi_structured="$(
  sudo -iu postgres \
    psql -X -At -d fi -v ON_ERROR_STOP=1 \
      -c "SELECT count(*) FROM information_schema.columns WHERE table_schema='fi' AND data_type IN ('json','jsonb','xml')"
)"
[ "$semi_structured" = '0' ] || fail "FI relational schema contains $semi_structured JSON/JSONB/XML columns"

bad_owner="$(
  sudo -iu postgres \
    psql -X -At -d fi -v ON_ERROR_STOP=1 \
      -c "SELECT count(*) FROM pg_tables WHERE schemaname='fi' AND tableowner <> 'fi_owner'"
)"
[ "$bad_owner" = '0' ] || fail "$bad_owner FI tables are not owned by fi_owner"

printf '%s\n' '===== FI_INGEST APPEND-ONLY BOUNDARY ====='
sudo -iu postgres psql -X -d fi -v ON_ERROR_STOP=1 <<'SQL'
WITH tables AS (
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'fi'
)
SELECT
    count(*) AS table_count,
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'SELECT'
        )
    ) AS selectable,
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'INSERT'
        )
    ) AS insertable,
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'UPDATE'
        )
    ) AS updatable,
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'DELETE'
        )
    ) AS deletable,
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'TRUNCATE'
        )
    ) AS truncatable
FROM tables;
SQL

rights="$(
  sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 <<'SQL'
WITH tables AS (
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'fi'
)
SELECT
    has_schema_privilege('fi_ingest','fi','USAGE')::text || '|' ||
    count(*)::text || '|' ||
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'SELECT'
        )
    )::text || '|' ||
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'INSERT'
        )
    )::text || '|' ||
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'UPDATE'
        )
    )::text || '|' ||
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'DELETE'
        )
    )::text || '|' ||
    count(*) FILTER (
        WHERE has_table_privilege(
            'fi_ingest',
            format('fi.%I', tablename),
            'TRUNCATE'
        )
    )::text
FROM tables;
SQL
)"

[ "$rights" = 'true|49|49|49|0|0|0' ] || fail "unexpected fi_ingest rights summary: $rights"

printf '%s\n' '===== CURRENT RELATIONAL STATE ====='
sudo -u fi-receiver \
  psql \
    -X \
    -h /run/postgresql \
    -U fi_ingest \
    -d fi \
    -v ON_ERROR_STOP=1 <<'SQL'
SELECT 'recorded_generation=' || count(*) FROM fi.recorded_generation;
SELECT 'source_batch=' || count(*) FROM fi.source_batch;
SELECT 'source_record=' || count(*) FROM fi.source_record;
SELECT 'file_observation=' || count(*) FROM fi.file_observation;
SELECT 'ingest_journal=' || count(*) FROM fi.ingest_journal;
SQL

printf '%s\n' \
  'PASS: the active FI Phase 3 database has exactly 49 relational tables, no JSON/JSONB/XML columns, fi_owner ownership, and SELECT/INSERT-only fi_ingest table authority.'
