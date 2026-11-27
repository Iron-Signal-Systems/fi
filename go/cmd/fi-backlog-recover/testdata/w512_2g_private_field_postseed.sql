-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- W512/2GiB TEST-ONLY: bound the initial field partition after exactly
-- one fully authenticated W512 private seed checkpoint. This SQL MUST run
-- after the signed seed integrity checks, BEFORE any W512 window-1 replay.
-- The operation scans only the fresh isolated field partition (once).

BEGIN;

DO $postseed$
DECLARE
    dirname text := current_setting('data_directory');
    upper_bound bigint;
    fields_before bigint;
    fields_after bigint;
    projected bigint;
BEGIN
    IF current_database() <> 'fi' OR current_user <> 'fi_m1_admin' OR
       current_setting('port') <> '55983' OR
       dirname NOT LIKE '/home/jwood/fi-window-bench-w512-%/data' THEN
        RAISE EXCEPTION 'FI W512 postseed: wrong database, owner, port or path %', dirname;
    END IF;

    IF (SELECT count(*) FROM fi_recovery.verified_artifact_window) <> 1 OR
       (SELECT count(*) FROM fi_recovery.source_window) <> 1 OR
       (SELECT count(*) FROM fi_recovery.typed_window) <> 1 OR
       (SELECT coalesce(min(window_index),-1) FROM fi_recovery.typed_window) <> 0 OR
       (SELECT count(*) FROM fi.recorded_generation) <> 0 OR
       (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted') <> 0 OR
       (SELECT count(*) FROM pg_inherits
        WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass) <> 1 OR
       NOT EXISTS(SELECT 1 FROM pg_inherits
        WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass
          AND inhrelid='fi_recovery_projection.windows_security_event_field_w000000'::regclass) THEN
        RAISE EXCEPTION 'FI W512 postseed: expected exactly one non-authoritative W512 seed and one initial field partition';
    END IF;

    SELECT count(*), max(source_record_id)+1 INTO fields_before,upper_bound
    FROM fi_recovery_projection.windows_security_event_field_w000000;
    IF fields_before < 1 OR upper_bound IS NULL OR upper_bound < 2 THEN
        RAISE EXCEPTION 'FI W512 postseed: missing source fields or invalid bound';
    END IF;
    SELECT count(*) INTO projected FROM fi_recovery_projection.source_record;
    IF projected <= 0 OR
       (SELECT count(*) FROM fi_recovery.pending_source_record) <> projected THEN
        RAISE EXCEPTION 'FI W512 postseed: source/projection mismatch';
    END IF;

    LOCK TABLE fi_recovery_projection.windows_security_event_field
        IN ACCESS EXCLUSIVE MODE;
    EXECUTE 'ALTER TABLE fi_recovery_projection.windows_security_event_field DETACH PARTITION fi_recovery_projection.windows_security_event_field_w000000';
    EXECUTE format('ALTER TABLE fi_recovery_projection.windows_security_event_field_w000000 ADD CONSTRAINT w512_seed_field_upper_bound CHECK (source_record_id < %s) NOT VALID', upper_bound);
    EXECUTE 'ALTER TABLE fi_recovery_projection.windows_security_event_field_w000000 VALIDATE CONSTRAINT w512_seed_field_upper_bound';
    EXECUTE format('ALTER TABLE fi_recovery_projection.windows_security_event_field ATTACH PARTITION fi_recovery_projection.windows_security_event_field_w000000 FOR VALUES FROM (MINVALUE) TO (%s)', upper_bound);

    SELECT count(*) INTO fields_after
    FROM fi_recovery_projection.windows_security_event_field;
    IF fields_after <> fields_before OR
       (SELECT count(*) FROM pg_inherits WHERE
        inhparent='fi_recovery_projection.windows_security_event_field'::regclass) <> 1 THEN
        RAISE EXCEPTION 'FI W512 postseed: row conservation or attach verification failed';
    END IF;
    RAISE NOTICE 'FI W512 PRIVATE FIELD SEED PARTITION PASS fields=% upper_bound=%', fields_after,upper_bound;
END;
$postseed$;

COMMIT;
