-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- W512/2GiB ISOLATED BENCHMARK ONLY.
-- Apply to a NEW, EMPTY PostgreSQL clone whose data_directory starts
-- /home/jwood/fi-window-bench-w512- and whose port is 55983.
-- Never apply to the authoritative SoR, the W128 accepted seed, or a
-- nonempty private projection. Canonical fi.* DDL is not modified.

BEGIN;

DO $guard$
DECLARE
    dirname text := current_setting('data_directory');
BEGIN
    IF current_database() <> 'fi' OR current_user <> 'fi_m1_admin' OR
       current_setting('port') <> '55983' OR
       dirname NOT LIKE '/home/jwood/fi-window-bench-w512-%/data' THEN
        RAISE EXCEPTION 'FI W512 isolated field bootstrap: wrong database, owner, port or data_directory %', dirname;
    END IF;
    IF to_regclass('fi_recovery.typed_window') IS NULL OR
       to_regclass('fi_recovery_projection.windows_security_event_field') IS NULL OR
       to_regclass('fi_recovery_projection.windows_security_event') IS NULL OR
       EXISTS(SELECT 1 FROM fi_recovery.typed_window) OR
       EXISTS(SELECT 1 FROM fi_recovery.source_window) OR
       EXISTS(SELECT 1 FROM fi_recovery.verified_artifact_window) OR
       EXISTS(SELECT 1 FROM fi.recorded_generation) OR
       EXISTS(SELECT 1 FROM fi_recovery_projection.windows_security_event_field) THEN
        RAISE EXCEPTION 'FI W512 isolated field bootstrap: required empty private schema/SoR state is absent';
    END IF;
END;
$guard$;

-- Reconstruct the test-only partitioned field table, while the shadow is
-- absolutely empty. LIKE INCLUDING ALL copies PK, NOT NULL, CHECK and indexes,
-- but does not copy REFERENCES, which is restored explicitly below.
ALTER TABLE fi_recovery_projection.windows_security_event_field
    RENAME TO windows_security_event_field_nonpartitioned_seed_only;

CREATE TABLE fi_recovery_projection.windows_security_event_field
    (LIKE fi_recovery_projection.windows_security_event_field_nonpartitioned_seed_only INCLUDING ALL)
    PARTITION BY RANGE (source_record_id);

ALTER TABLE fi_recovery_projection.windows_security_event_field
    ADD CONSTRAINT windows_security_event_field_source_fk
    FOREIGN KEY (source_record_id)
    REFERENCES fi_recovery_projection.windows_security_event(source_record_id);

DROP TABLE fi_recovery_projection.windows_security_event_field_nonpartitioned_seed_only;

GRANT SELECT, INSERT ON fi_recovery_projection.windows_security_event_field TO fi_ingest;

-- W512 index 0 is initially the sole partition; once the authenticated
-- first-window seed is complete it is bounded and detached/reattached by
-- the separately reviewed postseed SQL. No W128 checkpoints are imported.
CREATE TABLE fi_recovery_projection.windows_security_event_field_w000000
    PARTITION OF fi_recovery_projection.windows_security_event_field
    FOR VALUES FROM (MINVALUE) TO (MAXVALUE);

GRANT SELECT, INSERT ON fi_recovery_projection.windows_security_event_field_w000000 TO fi_ingest;

DO $gate$
BEGIN
    IF (SELECT count(*) FROM pg_inherits
        WHERE inhparent = 'fi_recovery_projection.windows_security_event_field'::regclass) <> 1 OR
       (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field) <> 0 OR
       (SELECT count(*) FROM fi_recovery.typed_window) <> 0 THEN
        RAISE EXCEPTION 'FI W512 fresh field-partition bootstrap postcondition failed';
    END IF;
END;
$gate$;

COMMIT;
