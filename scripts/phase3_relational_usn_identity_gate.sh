#!/usr/bin/env bash
set -euo pipefail

DB=fi
SOCKET=/run/postgresql

sudo -v

fail() {
    echo "ERROR: $*" >&2
    false
}

scalar() {
    printf '%s\n' "$1" | sudo -iu postgres psql -X -A -t -v ON_ERROR_STOP=1 -h "$SOCKET" -d "$DB"
}

echo '===== USN OBJECT RELATIONAL IDENTITY ====='
sudo -iu postgres psql -X -v ON_ERROR_STOP=1 -h "$SOCKET" -d "$DB" <<'SQL'
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'fi'
  AND table_name = 'usn_object_observation'
ORDER BY ordinal_position;

SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'fi'
  AND table_name = 'usn_object_change'
ORDER BY ordinal_position;
SQL

for column in usn_read_boundary_source_record_id ntfs_object_id; do
    [[ "$(scalar "SELECT count(*) FROM information_schema.columns WHERE table_schema='fi' AND table_name='usn_object_observation' AND column_name='$column' AND is_nullable='NO';")" == "1" ]] \
        || fail "fi.usn_object_observation.$column is missing or nullable"
done

for column in identity_method_version file_reference_number sequence_number; do
    [[ "$(scalar "SELECT count(*) FROM information_schema.columns WHERE table_schema='fi' AND table_name='usn_object_observation' AND column_name='$column';")" == "0" ]] \
        || fail "legacy incomplete USN object identity column remains: $column"
done

for column in file_ntfs_object_id parent_ntfs_object_id; do
    [[ "$(scalar "SELECT count(*) FROM information_schema.columns WHERE table_schema='fi' AND table_name='usn_object_change' AND column_name='$column' AND is_nullable='NO';")" == "1" ]] \
        || fail "fi.usn_object_change.$column is missing or nullable"
done

for column in file_identity_method_version file_reference_number file_sequence_number parent_identity_method_version parent_file_reference_number parent_sequence_number; do
    [[ "$(scalar "SELECT count(*) FROM information_schema.columns WHERE table_schema='fi' AND table_name='usn_object_change' AND column_name='$column';")" == "0" ]] \
        || fail "legacy duplicated USN change identity column remains: $column"
done

fk_count="$(scalar "
SELECT count(*)
FROM pg_constraint c
JOIN pg_class t ON t.oid = c.conrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
WHERE n.nspname='fi'
  AND t.relname IN ('usn_object_observation','usn_object_change')
  AND c.contype='f'
  AND c.conname IN (
      'usn_object_boundary_fk',
      'usn_object_ntfs_object_fk',
      'usn_object_change_file_object_fk',
      'usn_object_change_parent_object_fk'
  );")"
[[ "$fk_count" == "4" ]] || fail "expected four USN identity foreign keys, found $fk_count"

json_count="$(scalar "
SELECT count(*)
FROM information_schema.columns
WHERE table_schema='fi'
  AND data_type IN ('json','jsonb','xml');")"
[[ "$json_count" == "0" ]] || fail "JSON/JSONB/XML storage appeared in FI relational schema"

table_count="$(scalar "SELECT count(*) FROM information_schema.tables WHERE table_schema='fi' AND table_type='BASE TABLE';")"
[[ "$table_count" == "49" ]] || fail "expected 49 FI relational tables, found $table_count"

rights="$(sudo -iu postgres psql -X -A -t -v ON_ERROR_STOP=1 -h "$SOCKET" -d "$DB" <<'SQL'
SELECT
    has_schema_privilege('fi_ingest','fi','USAGE')::text || '|' ||
    has_table_privilege('fi_ingest','fi.usn_object_observation','SELECT')::text || '|' ||
    has_table_privilege('fi_ingest','fi.usn_object_observation','INSERT')::text || '|' ||
    has_table_privilege('fi_ingest','fi.usn_object_observation','UPDATE')::text || '|' ||
    has_table_privilege('fi_ingest','fi.usn_object_observation','DELETE')::text;
SQL
)"
[[ "$rights" == "true|true|true|false|false" ]] || fail "fi_ingest USN table privilege boundary is $rights"

echo
echo 'PASS: USN object/change identity is now volume-qualified through relational NTFS objects and the exact USN read boundary; no incomplete FRN/sequence-only identity remains.'
