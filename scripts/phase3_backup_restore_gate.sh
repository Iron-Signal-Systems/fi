#!/usr/bin/env bash
set -euo pipefail

SOURCE_DB="${1:-fi}"
RESTORE_DB="fi_phase3_restore_gate_$$"
DUMP_PATH="/tmp/fi-phase3-backup-restore.$$.dump"
LIST_PATH="/tmp/fi-phase3-backup-restore.$$.list"

cleanup() {
    sudo -iu postgres \
      dropdb \
        --if-exists \
        "$RESTORE_DB" \
        >/dev/null 2>&1 || true

    sudo rm -f \
      "$DUMP_PATH" \
      "$LIST_PATH"
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    false
}

read_state() {
    local database="$1"

    sudo -iu postgres \
      psql \
        -X \
        -v ON_ERROR_STOP=1 \
        -At \
        -d "$database" <<'SQL'
SELECT 'relational_table_count=' || count(*)
FROM pg_tables
WHERE schemaname = 'fi';

SELECT 'semi_structured_column_count=' || count(*)
FROM information_schema.columns
WHERE table_schema = 'fi'
  AND data_type IN ('json','jsonb','xml');

SELECT 'recorded_generation_count=' || count(*)
FROM fi.recorded_generation;

SELECT 'source_batch_count=' || count(*)
FROM fi.source_batch;

SELECT 'source_record_count=' || count(*)
FROM fi.source_record;

SELECT 'source_record_declared_bytes=' || COALESCE(sum(record_bytes), 0)
FROM fi.source_record;

SELECT 'ingest_journal_count=' || count(*)
FROM fi.ingest_journal;

SELECT 'generation_child_mismatches=' || count(*)
FROM fi.recorded_generation rg
LEFT JOIN (
    SELECT
        recorded_generation_id,
        count(*) AS batch_count,
        COALESCE(sum(data_bytes), 0) AS data_bytes,
        COALESCE(sum(record_count), 0) AS record_count
    FROM fi.source_batch
    GROUP BY recorded_generation_id
) sb
  ON sb.recorded_generation_id = rg.recorded_generation_id
WHERE COALESCE(sb.batch_count, 0) <> rg.batch_count
   OR COALESCE(sb.data_bytes, 0) <> rg.data_bytes
   OR COALESCE(sb.record_count, 0) <> rg.record_count;

SELECT 'batch_child_mismatches=' || count(*)
FROM fi.source_batch sb
LEFT JOIN (
    SELECT
        source_batch_id,
        count(*) AS record_count,
        COALESCE(sum(record_bytes), 0) AS record_bytes
    FROM fi.source_record
    GROUP BY source_batch_id
) sr
  ON sr.source_batch_id = sb.source_batch_id
WHERE COALESCE(sr.record_count, 0) <> sb.record_count
   OR COALESCE(sr.record_bytes, 0) <> sb.data_bytes;

SELECT 'missing_typed_projections=' || count(*)
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

SELECT 'sequence_fp=' || encode(
    sha256(
        convert_to(
            COALESCE(
                string_agg(
                    schemaname || '.' || sequencename || ':' ||
                    COALESCE(last_value::text, 'NULL'),
                    E'\n'
                    ORDER BY schemaname, sequencename
                ),
                ''
            ),
            'UTF8'
        )
    ),
    'hex'
)
FROM pg_sequences
WHERE schemaname = 'fi';

SELECT 'owner_fp=' || encode(
    sha256(
        convert_to(
            COALESCE(
                string_agg(
                    tablename || ':' || tableowner,
                    E'\n'
                    ORDER BY tablename
                ),
                ''
            ),
            'UTF8'
        )
    ),
    'hex'
)
FROM pg_tables
WHERE schemaname = 'fi';

WITH tables AS (
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'fi'
)
SELECT
    'fi_ingest_acl=' ||
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
}

schema_fingerprint() {
    local database="$1"

    sudo -iu postgres \
      pg_dump \
        --schema-only \
        --schema=fi \
        --no-owner \
        --no-privileges \
        "$database" \
      | sha256sum \
      | awk '{print $1}'
}

data_fingerprint() {
    local database="$1"

    sudo -iu postgres \
      pg_dump \
        --data-only \
        --schema=fi \
        --no-owner \
        --no-privileges \
        "$database" \
      | sha256sum \
      | awk '{print $1}'
}

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

if pgrep -af 'fi-ingest-worker|fi-live-relational-ingest' >/dev/null 2>&1; then
    echo 'ERROR: a live relational ingest worker appears to be running.' >&2
    echo 'Run the backup/restore gate only in a controlled quiescent window.' >&2
    false
fi

printf '\n%s\n' '===== SOURCE DATABASE STATE BEFORE BACKUP ====='
SOURCE_STATE_BEFORE="$(read_state "$SOURCE_DB")"
printf '%s\n' "$SOURCE_STATE_BEFORE"

if ! grep -qx 'relational_table_count=49' <<<"$SOURCE_STATE_BEFORE" || \
   ! grep -qx 'semi_structured_column_count=0' <<<"$SOURCE_STATE_BEFORE" || \
   ! grep -qx 'generation_child_mismatches=0' <<<"$SOURCE_STATE_BEFORE" || \
   ! grep -qx 'batch_child_mismatches=0' <<<"$SOURCE_STATE_BEFORE" || \
   ! grep -qx 'missing_typed_projections=0' <<<"$SOURCE_STATE_BEFORE" || \
   ! grep -qx 'fi_ingest_acl=true|49|49|49|0|0|0' <<<"$SOURCE_STATE_BEFORE"; then
    echo 'ERROR: source database failed current relational pre-backup checks' >&2
    false
fi

printf '\n%s\n' '===== CREATE CONSISTENT CUSTOM-FORMAT BACKUP ====='

sudo -iu postgres \
  pg_dump \
    --format=custom \
    --file="$DUMP_PATH" \
    "$SOURCE_DB"

sudo -iu postgres \
  pg_restore \
    --list \
    "$DUMP_PATH" \
    >"$LIST_PATH"

ls -lh "$DUMP_PATH"
sha256sum "$DUMP_PATH"

for relation in recorded_generation source_batch source_record ingest_journal; do
    if ! grep -q "TABLE DATA fi $relation" "$LIST_PATH"; then
        echo "ERROR: backup archive is missing fi.$relation table data" >&2
        false
    fi
done

printf '\n%s\n' '===== SOURCE DATABASE STATE AFTER BACKUP ====='
SOURCE_STATE_AFTER="$(read_state "$SOURCE_DB")"
printf '%s\n' "$SOURCE_STATE_AFTER"

if [ "$SOURCE_STATE_BEFORE" != "$SOURCE_STATE_AFTER" ]; then
    echo 'ERROR: source database changed while the backup gate was running.' >&2
    echo 'Run the gate only while relational ingest is quiescent.' >&2
    diff -u \
      <(printf '%s\n' "$SOURCE_STATE_BEFORE") \
      <(printf '%s\n' "$SOURCE_STATE_AFTER") \
      || true
    false
fi

SOURCE_SCHEMA_FP="$(schema_fingerprint "$SOURCE_DB")"
SOURCE_DATA_FP="$(data_fingerprint "$SOURCE_DB")"

printf 'source_schema_fingerprint: %s\n' "$SOURCE_SCHEMA_FP"
printf 'source_data_fingerprint:   %s\n' "$SOURCE_DATA_FP"

printf '\n%s\n' '===== CREATE ISOLATED RESTORE DATABASE ====='

sudo -iu postgres \
  createdb \
    --owner=fi_owner \
    --template=template0 \
    --encoding=UTF8 \
    --locale=C.UTF-8 \
    "$RESTORE_DB"

printf 'restore_database: %s\n' "$RESTORE_DB"

printf '\n%s\n' '===== RESTORE BACKUP ====='

sudo -iu postgres \
  pg_restore \
    --exit-on-error \
    --dbname="$RESTORE_DB" \
    "$DUMP_PATH"

printf '\n%s\n' '===== RESTORED DATABASE STATE ====='
RESTORE_STATE="$(read_state "$RESTORE_DB")"
printf '%s\n' "$RESTORE_STATE"

if [ "$SOURCE_STATE_AFTER" != "$RESTORE_STATE" ]; then
    echo 'ERROR: restored relational state does not match the source state' >&2
    diff -u \
      <(printf '%s\n' "$SOURCE_STATE_AFTER") \
      <(printf '%s\n' "$RESTORE_STATE") \
      || true
    false
fi

RESTORE_SCHEMA_FP="$(schema_fingerprint "$RESTORE_DB")"
RESTORE_DATA_FP="$(data_fingerprint "$RESTORE_DB")"

printf 'restore_schema_fingerprint: %s\n' "$RESTORE_SCHEMA_FP"
printf 'restore_data_fingerprint:   %s\n' "$RESTORE_DATA_FP"

if [ "$SOURCE_SCHEMA_FP" != "$RESTORE_SCHEMA_FP" ]; then
    echo 'ERROR: restored FI schema fingerprint differs from source' >&2
    false
fi

if [ "$SOURCE_DATA_FP" != "$RESTORE_DATA_FP" ]; then
    echo 'ERROR: restored FI relational data fingerprint differs from source' >&2
    false
fi

printf '\n%s\n' '===== RESTORED RUNTIME WRITE-BOUNDARY PROBE ====='

sudo -iu postgres \
  psql \
    -X \
    -v ON_ERROR_STOP=1 \
    -d "$RESTORE_DB" <<'SQL'
BEGIN;
SET LOCAL ROLE fi_ingest;

INSERT INTO fi.ingest_journal (
    attempt_id,
    event_sequence,
    outcome,
    stage,
    reason_code,
    records_seen,
    records_committed,
    ingest_version
)
VALUES (
    'fi-phase3-backup-restore-probe',
    1,
    'Incomplete',
    'BackupRestoreProbe',
    'BACKUP_RESTORE_PROBE',
    0,
    0,
    'fi-postgresql-relational-ingest/0.2'
);

ROLLBACK;
SQL

POST_PROBE_STATE="$(read_state "$RESTORE_DB")"

# PostgreSQL sequences are intentionally non-transactional. The rollback-only
# INSERT above consumes one identity sequence value even though the row is
# rolled back. Compare every state component except sequence_fp.
RESTORE_POST_PROBE_COMPARABLE="$(
    grep -v '^sequence_fp=' <<<"$RESTORE_STATE"
)"

POST_PROBE_COMPARABLE="$(
    grep -v '^sequence_fp=' <<<"$POST_PROBE_STATE"
)"

if [ "$RESTORE_POST_PROBE_COMPARABLE" != "$POST_PROBE_COMPARABLE" ]; then
    echo 'ERROR: rollback-only runtime probe changed restored relational authority' >&2
    diff -u \
      <(printf '%s\n' "$RESTORE_POST_PROBE_COMPARABLE") \
      <(printf '%s\n' "$POST_PROBE_COMPARABLE") \
      || true
    false
fi

printf '\n%s\n' \
  'PASS: current 49-table relational schema, all FI relational rows, lineage hashes, typed-projection coverage, journal history, ownership, sequence state, append-only runtime rights, and rollback behavior survived backup and isolated restore.'
