-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- FI DEVELOPMENT ONLY. Execute against a BRAND NEW, EMPTY private recovery
-- database after the canonical five migrations and private schema generator.
-- This preserves the exact field FK, PK, CHECK and columns, but makes the
-- private field relation RANGE-partitioned for W256 detached-field COPY.
-- It NEVER modifies canonical fi.* tables.
BEGIN;
DO $guard$
BEGIN
 IF current_database() <> 'fi' OR current_user <> 'fi_m1_admin'
    OR current_setting('server_version_num')::integer < 180000
    OR to_regclass('fi_recovery_projection.windows_security_event_field') IS NULL
    OR (SELECT count(*) FROM fi_recovery.typed_window) <> 0
    OR (SELECT count(*) FROM fi_recovery.verified_artifact_window) <> 0
    OR (SELECT count(*) FROM fi_recovery.source_window) <> 0
    OR (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field) <> 0
    OR (SELECT count(*) FROM fi.recorded_generation) <> 0
    OR (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted') <> 0
    OR EXISTS(SELECT 1 FROM pg_partitioned_table
       WHERE partrelid='fi_recovery_projection.windows_security_event_field'::regclass)
 THEN
    RAISE EXCEPTION 'FI W256 partition prep refuses anything except empty isolated private schema';
 END IF;
END
$guard$;

-- No recorded source data exists here. The original private table is
-- reconstructed as partitioned with the same field columns, PK and FK.
DROP TABLE fi_recovery_projection.windows_security_event_field;
CREATE TABLE fi_recovery_projection.windows_security_event_field (
    source_record_id bigint NOT NULL REFERENCES fi_recovery_projection.windows_security_event(source_record_id),
    field_ordinal integer NOT NULL CHECK (field_ordinal > 0),
    name text NOT NULL,
    value text NOT NULL,
    PRIMARY KEY (source_record_id, field_ordinal)
) PARTITION BY RANGE (source_record_id);
-- The one-time seed writes into W0; after its signed COMMIT the parent
-- range is narrowed exactly, before W1..W4 are even provisioned.
CREATE TABLE fi_recovery_projection.windows_security_event_field_w000000
 PARTITION OF fi_recovery_projection.windows_security_event_field DEFAULT;
GRANT SELECT, INSERT ON fi_recovery_projection.windows_security_event_field TO fi_ingest;
COMMIT;
