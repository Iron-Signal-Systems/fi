#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

printf '%s\n' '===== SOURCE-RECORD RELATIONAL COVERAGE ====='
sudo -iu postgres psql -X -d fi -v ON_ERROR_STOP=1 <<'SQL'
WITH expected(record_kind, relation_name) AS (
    VALUES
        ('CollectorIdentity',                 'collector_identity'),
        ('DirectoryPrincipalSnapshot',        'directory_principal_snapshot'),
        ('FileObservation',                   'file_observation'),
        ('LocalPrincipalSnapshot',            'local_principal_snapshot'),
        ('NTFSCollectionError',               'ntfs_collection_error'),
        ('SMBShareSnapshot',                  'smb_share_snapshot'),
        ('SupportingSourceCollectionError',   'supporting_source_collection_error'),
        ('USNContinuityGap',                  'usn_continuity_gap'),
        ('USNObjectObservation',              'usn_object_observation'),
        ('USNReadBoundary',                   'usn_read_boundary'),
        ('WindowsSecurityContinuityGap',      'windows_security_continuity_gap'),
        ('WindowsSecurityCoverage',           'windows_security_coverage'),
        ('WindowsSecurityEvent',              'windows_security_event')
)
SELECT
    record_kind,
    'fi.' || relation_name AS relational_target,
    to_regclass('fi.' || relation_name) IS NOT NULL AS present
FROM expected
ORDER BY record_kind;
SQL

missing="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 <<'SQL'
WITH expected(relation_name) AS (
    VALUES
        ('collector_identity'),
        ('directory_principal_snapshot'),
        ('file_observation'),
        ('local_principal_snapshot'),
        ('ntfs_collection_error'),
        ('smb_share_snapshot'),
        ('supporting_source_collection_error'),
        ('usn_continuity_gap'),
        ('usn_object_observation'),
        ('usn_read_boundary'),
        ('windows_security_continuity_gap'),
        ('windows_security_coverage'),
        ('windows_security_event')
)
SELECT count(*)
FROM expected
WHERE to_regclass('fi.' || relation_name) IS NULL;
SQL
)"
if [[ "$missing" != "0" ]]; then
    printf 'ERROR: %s source-record relational targets are missing\n' "$missing" >&2
    exit 1
fi

printf '%s\n' '===== RELATIONAL SHAPE ====='
sudo -iu postgres psql -X -d fi -v ON_ERROR_STOP=1 <<'SQL'
SELECT count(*) AS fi_tables
FROM pg_tables
WHERE schemaname = 'fi';

SELECT
    count(*) FILTER (WHERE data_type IN ('json','jsonb','xml')) AS semi_structured_columns,
    count(*) AS total_columns
FROM information_schema.columns
WHERE table_schema = 'fi';

SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'fi'
  AND data_type IN ('json','jsonb','xml')
ORDER BY table_name, ordinal_position;
SQL

table_count="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_tables WHERE schemaname='fi'")"
if [[ "$table_count" != "49" ]]; then
    printf 'ERROR: FI relational table count is %s, expected 49\n' "$table_count" >&2
    exit 1
fi

semi="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM information_schema.columns WHERE table_schema='fi' AND data_type IN ('json','jsonb','xml')")"
if [[ "$semi" != "0" ]]; then
    printf 'ERROR: FI relational schema contains %s JSON/JSONB/XML columns\n' "$semi" >&2
    exit 1
fi

printf '%s\n' '===== TABLE OWNERSHIP ====='
bad_owner="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_tables WHERE schemaname='fi' AND tableowner <> 'fi_owner'")"
if [[ "$bad_owner" != "0" ]]; then
    printf 'ERROR: %s FI tables are not owned by fi_owner\n' "$bad_owner" >&2
    exit 1
fi
printf 'fi_owner_tables=%s\n' "$table_count"

printf '%s\n' '===== FI_INGEST APPEND-ONLY BOUNDARY ====='
sudo -iu postgres psql -X -d fi -v ON_ERROR_STOP=1 <<'SQL'
WITH tables AS (
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'fi'
)
SELECT
    count(*) AS table_count,
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'SELECT')) AS selectable,
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'INSERT')) AS insertable,
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'UPDATE')) AS updatable,
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'DELETE')) AS deletable,
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'TRUNCATE')) AS truncatable
FROM tables;
SQL

rights="$(sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 <<'SQL'
WITH tables AS (
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'fi'
)
SELECT
    count(*)::text || '|' ||
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'SELECT'))::text || '|' ||
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'INSERT'))::text || '|' ||
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'UPDATE'))::text || '|' ||
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'DELETE'))::text || '|' ||
    count(*) FILTER (WHERE has_table_privilege('fi_ingest', format('fi.%I', tablename), 'TRUNCATE'))::text
FROM tables;
SQL
)"
if [[ "$rights" != "49|49|49|0|0|0" ]]; then
    printf 'ERROR: unexpected fi_ingest rights summary: %s\n' "$rights" >&2
    exit 1
fi

printf '%s\n' '===== EMPTY DATABASE STATE ====='
sudo -u fi-receiver psql -X -h /run/postgresql -U fi_ingest -d fi -v ON_ERROR_STOP=1 <<'SQL'
SELECT 'recorded_generation=' || count(*) FROM fi.recorded_generation;
SELECT 'source_batch=' || count(*) FROM fi.source_batch;
SELECT 'source_record=' || count(*) FROM fi.source_record;
SELECT 'file_observation=' || count(*) FROM fi.file_observation;
SELECT 'collector_identity=' || count(*) FROM fi.collector_identity;
SELECT 'smb_share_snapshot=' || count(*) FROM fi.smb_share_snapshot;
SELECT 'local_principal_snapshot=' || count(*) FROM fi.local_principal_snapshot;
SELECT 'directory_principal_snapshot=' || count(*) FROM fi.directory_principal_snapshot;
SELECT 'usn_read_boundary=' || count(*) FROM fi.usn_read_boundary;
SELECT 'windows_security_event=' || count(*) FROM fi.windows_security_event;
SELECT 'ingest_journal=' || count(*) FROM fi.ingest_journal;
SQL

source_records="$(sudo -u fi-receiver psql -X -h /run/postgresql -U fi_ingest -d fi -At -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM fi.source_record")"
if [[ "$source_records" != "0" ]]; then
    printf 'ERROR: source_record is not empty: %s\n' "$source_records" >&2
    exit 1
fi

printf '%s\n' 'PASS: all 13 collector-emitted record kinds now have explicit relational targets; FI has 49 typed tables, no JSON/JSONB/XML storage, and fi_ingest remains append-only.'
