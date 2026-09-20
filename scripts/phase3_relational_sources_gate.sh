#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "ERROR: $*" >&2
    false
}

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

printf '%s\n' '===== SOURCE-RECORD RELATIONAL TARGETS ====='
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

missing_relations="$(
  sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 <<'SQL'
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

[ "$missing_relations" = '0' ] || fail "$missing_relations source-record relational targets are missing"

printf '%s\n' '===== CURRENT RECORD-KIND COVERAGE ====='
sudo -u fi-receiver \
  psql \
    -X \
    -h /run/postgresql \
    -U fi_ingest \
    -d fi \
    -v ON_ERROR_STOP=1 <<'SQL'
SELECT record_kind, count(*)
FROM fi.source_record
GROUP BY record_kind
ORDER BY record_kind;
SQL

unsupported="$(
  sudo -u fi-receiver \
    psql \
      -X \
      -h /run/postgresql \
      -U fi_ingest \
      -d fi \
      -At \
      -v ON_ERROR_STOP=1 <<'SQL'
WITH expected(record_kind) AS (
    VALUES
        ('CollectorIdentity'),
        ('DirectoryPrincipalSnapshot'),
        ('FileObservation'),
        ('LocalPrincipalSnapshot'),
        ('NTFSCollectionError'),
        ('SMBShareSnapshot'),
        ('SupportingSourceCollectionError'),
        ('USNContinuityGap'),
        ('USNObjectObservation'),
        ('USNReadBoundary'),
        ('WindowsSecurityContinuityGap'),
        ('WindowsSecurityCoverage'),
        ('WindowsSecurityEvent')
)
SELECT count(*)
FROM fi.source_record sr
LEFT JOIN expected e
  ON e.record_kind = sr.record_kind
WHERE e.record_kind IS NULL;
SQL
)"

[ "$unsupported" = '0' ] || fail "$unsupported source records use an unsupported record kind"

missing_projection="$(
  sudo -u fi-receiver \
    psql \
      -X \
      -h /run/postgresql \
      -U fi_ingest \
      -d fi \
      -At \
      -v ON_ERROR_STOP=1 <<'SQL'
SELECT count(*)
FROM fi.source_record sr
WHERE CASE sr.record_kind
    WHEN 'CollectorIdentity' THEN NOT EXISTS (
        SELECT 1 FROM fi.collector_identity x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'DirectoryPrincipalSnapshot' THEN NOT EXISTS (
        SELECT 1 FROM fi.directory_principal_snapshot x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'FileObservation' THEN NOT EXISTS (
        SELECT 1 FROM fi.file_observation x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'LocalPrincipalSnapshot' THEN NOT EXISTS (
        SELECT 1 FROM fi.local_principal_snapshot x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'NTFSCollectionError' THEN NOT EXISTS (
        SELECT 1 FROM fi.ntfs_collection_error x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'SMBShareSnapshot' THEN NOT EXISTS (
        SELECT 1 FROM fi.smb_share_snapshot x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'SupportingSourceCollectionError' THEN NOT EXISTS (
        SELECT 1 FROM fi.supporting_source_collection_error x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'USNContinuityGap' THEN NOT EXISTS (
        SELECT 1 FROM fi.usn_continuity_gap x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'USNObjectObservation' THEN NOT EXISTS (
        SELECT 1 FROM fi.usn_object_observation x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'USNReadBoundary' THEN NOT EXISTS (
        SELECT 1 FROM fi.usn_read_boundary x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'WindowsSecurityContinuityGap' THEN NOT EXISTS (
        SELECT 1 FROM fi.windows_security_continuity_gap x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'WindowsSecurityCoverage' THEN NOT EXISTS (
        SELECT 1 FROM fi.windows_security_coverage x
        WHERE x.source_record_id = sr.source_record_id
    )
    WHEN 'WindowsSecurityEvent' THEN NOT EXISTS (
        SELECT 1 FROM fi.windows_security_event x
        WHERE x.source_record_id = sr.source_record_id
    )
    ELSE true
END;
SQL
)"

[ "$missing_projection" = '0' ] || fail "$missing_projection source records lack their required typed relational projection"

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

rights="$(
  sudo -iu postgres psql -X -At -d fi -v ON_ERROR_STOP=1 <<'SQL'
WITH tables AS (
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'fi'
)
SELECT
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

[ "$rights" = '49|49|49|0|0|0' ] || fail "unexpected fi_ingest rights summary: $rights"

printf '\n%s\n' \
  'PASS: all 13 supported collector record kinds have explicit typed relational targets; current rows use only supported kinds, every committed source record has its required typed projection, the FI schema remains 49-table relational-only storage, and fi_ingest remains append-only.'
