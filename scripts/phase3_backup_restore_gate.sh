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

read_state() {
    local database="$1"

    sudo -iu postgres \
      psql \
        -X \
        -v ON_ERROR_STOP=1 \
        -At \
        -d "$database" <<'SQL'
SELECT 'recorded_generation_count=' || count(*)
FROM fi.recorded_generation;

SELECT 'source_batch_count=' || count(*)
FROM fi.source_batch;

SELECT 'source_record_count=' || count(*)
FROM fi.source_record;

SELECT 'source_record_raw_bytes=' || COALESCE(sum(octet_length(raw_record_bytes)), 0)
FROM fi.source_record;

SELECT 'ingest_journal_count=' || count(*)
FROM fi.ingest_journal;

SELECT 'receipt_sha_mismatches=' || count(*)
FROM fi.recorded_generation
WHERE receipt_sha256 <> encode(sha256(receipt_raw_bytes), 'hex');

SELECT 'source_record_sha_mismatches=' || count(*)
FROM fi.source_record
WHERE raw_record_sha256 <> encode(sha256(raw_record_bytes), 'hex');

SELECT 'batch_reconstruction_mismatches=' || count(*)
FROM (
    SELECT
        sb.source_batch_id
    FROM fi.source_batch sb
    LEFT JOIN fi.source_record sr
      ON sr.source_batch_id = sb.source_batch_id
    GROUP BY
        sb.source_batch_id,
        sb.record_count,
        sb.data_bytes,
        sb.data_sha256
    HAVING count(sr.source_record_id) <> sb.record_count
        OR COALESCE(sum(octet_length(sr.raw_record_bytes)), 0) <> sb.data_bytes
        OR encode(
            sha256(
                COALESCE(
                    string_agg(
                        sr.raw_record_bytes,
                        ''::bytea
                        ORDER BY sr.record_ordinal
                    ),
                    ''::bytea
                )
            ),
            'hex'
        ) <> sb.data_sha256
) mismatch;

SELECT 'recorded_generation_fp=' || encode(
    sha256(
        convert_to(
            COALESCE(
                string_agg(
                    recorded_generation_id::text || ':' ||
                    source_id || ':' ||
                    generation_id || ':' ||
                    transfer_sha256 || ':' ||
                    receipt_sha256 || ':' ||
                    batch_count::text || ':' ||
                    data_bytes::text || ':' ||
                    record_count::text || ':' ||
                    ingest_version,
                    E'\n'
                    ORDER BY recorded_generation_id
                ),
                ''
            ),
            'UTF8'
        )
    ),
    'hex'
)
FROM fi.recorded_generation;

SELECT 'source_batch_fp=' || encode(
    sha256(
        convert_to(
            COALESCE(
                string_agg(
                    source_batch_id::text || ':' ||
                    recorded_generation_id::text || ':' ||
                    batch_id || ':' ||
                    data_artifact_name || ':' ||
                    manifest_artifact_name || ':' ||
                    record_count::text || ':' ||
                    data_bytes::text || ':' ||
                    data_sha256 || ':' ||
                    manifest_sha256,
                    E'\n'
                    ORDER BY source_batch_id
                ),
                ''
            ),
            'UTF8'
        )
    ),
    'hex'
)
FROM fi.source_batch;

SELECT 'source_record_fp=' || encode(
    sha256(
        convert_to(
            COALESCE(
                string_agg(
                    source_record_id::text || ':' ||
                    source_batch_id::text || ':' ||
                    record_ordinal::text || ':' ||
                    raw_record_sha256 || ':' ||
                    ingest_version,
                    E'\n'
                    ORDER BY source_record_id
                ),
                ''
            ),
            'UTF8'
        )
    ),
    'hex'
)
FROM fi.source_record;

SELECT 'ingest_journal_fp=' || encode(
    sha256(
        convert_to(
            COALESCE(
                string_agg(
                    ingest_journal_id::text || ':' ||
                    attempt_id || ':' ||
                    event_sequence::text || ':' ||
                    to_char(
                        occurred_at AT TIME ZONE 'UTC',
                        'YYYY-MM-DD"T"HH24:MI:SS.US'
                    ) || ':' ||
                    COALESCE(source_id, '') || ':' ||
                    COALESCE(generation_id, '') || ':' ||
                    COALESCE(transfer_sha256, '') || ':' ||
                    outcome || ':' ||
                    stage || ':' ||
                    COALESCE(reason_code, '') || ':' ||
                    encode(
                        sha256(
                            convert_to(
                                COALESCE(detail, ''),
                                'UTF8'
                            )
                        ),
                        'hex'
                    ) || ':' ||
                    COALESCE(records_seen::text, '') || ':' ||
                    COALESCE(records_committed::text, '') || ':' ||
                    ingest_version,
                    E'\n'
                    ORDER BY ingest_journal_id
                ),
                ''
            ),
            'UTF8'
        )
    ),
    'hex'
)
FROM fi.ingest_journal;

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

SELECT 'constraint_fp=' || encode(
    sha256(
        convert_to(
            COALESCE(
                string_agg(
                    c.conrelid::regclass::text || ':' ||
                    c.conname || ':' ||
                    c.contype::text || ':' ||
                    pg_get_constraintdef(c.oid, true),
                    E'\n'
                    ORDER BY c.conrelid::regclass::text, c.conname
                ),
                ''
            ),
            'UTF8'
        )
    ),
    'hex'
)
FROM pg_constraint c
JOIN pg_class cl
  ON cl.oid = c.conrelid
JOIN pg_namespace n
  ON n.oid = cl.relnamespace
WHERE n.nspname = 'fi';

SELECT 'index_fp=' || encode(
    sha256(
        convert_to(
            COALESCE(
                string_agg(
                    tablename || ':' || indexname || ':' || indexdef,
                    E'\n'
                    ORDER BY tablename, indexname
                ),
                ''
            ),
            'UTF8'
        )
    ),
    'hex'
)
FROM pg_indexes
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

SELECT 'fi_ingest_acl=' ||
    has_schema_privilege('fi_ingest', 'fi', 'USAGE')::text || '|' ||
    has_table_privilege('fi_ingest', 'fi.recorded_generation', 'SELECT')::text || '|' ||
    has_table_privilege('fi_ingest', 'fi.recorded_generation', 'INSERT')::text || '|' ||
    has_table_privilege('fi_ingest', 'fi.recorded_generation', 'UPDATE')::text || '|' ||
    has_table_privilege('fi_ingest', 'fi.recorded_generation', 'DELETE')::text;
SQL
}

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

printf '\n%s\n' '===== SOURCE DATABASE STATE ====='
SOURCE_STATE="$(read_state "$SOURCE_DB")"
printf '%s\n' "$SOURCE_STATE"

if ! grep -qx 'receipt_sha_mismatches=0' <<<"$SOURCE_STATE" || \
   ! grep -qx 'source_record_sha_mismatches=0' <<<"$SOURCE_STATE" || \
   ! grep -qx 'batch_reconstruction_mismatches=0' <<<"$SOURCE_STATE"; then
    echo 'ERROR: source database failed pre-backup integrity checks' >&2
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

if ! grep -q 'TABLE DATA fi recorded_generation' "$LIST_PATH" || \
   ! grep -q 'TABLE DATA fi source_batch' "$LIST_PATH" || \
   ! grep -q 'TABLE DATA fi source_record' "$LIST_PATH" || \
   ! grep -q 'TABLE DATA fi ingest_journal' "$LIST_PATH"; then
    echo 'ERROR: backup archive does not contain all Phase 3 authoritative table data' >&2
    false
fi

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

if [ "$SOURCE_STATE" != "$RESTORE_STATE" ]; then
    echo 'ERROR: restored Phase 3 state does not exactly match source state' >&2

    diff -u \
      <(printf '%s\n' "$SOURCE_STATE") \
      <(printf '%s\n' "$RESTORE_STATE") \
      || true

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
    'fi-postgresql-ingest/0.1'
);

ROLLBACK;
SQL

POST_PROBE_STATE="$(read_state "$RESTORE_DB")"

# PostgreSQL sequences are intentionally non-transactional. The rollback-only
# INSERT above is expected to consume one identity sequence value even though
# the journal row itself is rolled back. Sequence preservation was already
# proved by the exact SOURCE_STATE == RESTORE_STATE comparison before this
# probe. After the probe, compare every state component except sequence_fp.
RESTORE_POST_PROBE_COMPARABLE="$(
    grep -v '^sequence_fp=' <<<"$RESTORE_STATE"
)"

POST_PROBE_COMPARABLE="$(
    grep -v '^sequence_fp=' <<<"$POST_PROBE_STATE"
)"

if [ "$RESTORE_POST_PROBE_COMPARABLE" != "$POST_PROBE_COMPARABLE" ]; then
    echo 'ERROR: rollback-only runtime probe changed restored authoritative state' >&2

    diff -u \
      <(printf '%s\n' "$RESTORE_POST_PROBE_COMPARABLE") \
      <(printf '%s\n' "$POST_PROBE_COMPARABLE") \
      || true

    false
fi

printf '\n%s\n' 'PASS: Phase 3 authoritative generations, batches, exact source-record bytes, journal history, identities, constraints, indexes, ownership, sequence restore state, and runtime INSERT boundary survived backup and isolated restore.'
