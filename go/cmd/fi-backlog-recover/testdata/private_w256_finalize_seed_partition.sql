-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- FI DEVELOPMENT ONLY. Tighten the W0 seed's DEFAULT child to the exact
-- SOURCE RECORD ID interval after the real signed W256 window-zero commit.
-- Otherwise attaching W1..W4 would rescan a large DEFAULT partition.
BEGIN;
DO $guard$
DECLARE
 n bigint;
 r bigint;
BEGIN
 SELECT count(*),coalesce(sum(committed_records),0) INTO n,r
 FROM fi_recovery.typed_window;
 IF current_database() <> 'fi' OR current_user <> 'fi_m1_admin'
    OR n <> 1 OR r < 200000 OR r > 262144
    OR (SELECT count(*) FROM fi_recovery.typed_window WHERE window_index=0) <> 1
    OR (SELECT count(*) FROM fi_recovery.source_window) <> 1
    OR (SELECT count(*) FROM fi_recovery.verified_artifact_window) <> 1
    OR (SELECT count(*) FROM fi.recorded_generation) <> 0
    OR (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted') <> 0
    OR (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field) = 0
    OR (SELECT count(*) FROM pg_inherits
      WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass) <> 1
    OR NOT EXISTS (SELECT 1 FROM pg_inherits
      WHERE inhparent='fi_recovery_projection.windows_security_event_field'::regclass
        AND inhrelid='fi_recovery_projection.windows_security_event_field_w000000'::regclass)
 THEN
   RAISE EXCEPTION 'FI W256 seed finalizer refuses invalid signed W0 prefix';
 END IF;
END
$guard$;

ALTER TABLE fi_recovery_projection.windows_security_event_field
 DETACH PARTITION fi_recovery_projection.windows_security_event_field_w000000;

DO $tighten$
DECLARE
 lo bigint;
 hi bigint;
 n bigint;
BEGIN
 SELECT min(source_record_id), max(source_record_id)+1,count(*)
 INTO lo,hi,n FROM fi_recovery_projection.windows_security_event_field_w000000;
 IF n <= 0 OR lo IS NULL OR hi IS NULL OR hi <= lo THEN
  RAISE EXCEPTION 'FI W256 seed partition has no valid Security field rows';
 END IF;
 -- Prove this exact interval on the existing signed fields before ATTACH.
 EXECUTE format('ALTER TABLE fi_recovery_projection.windows_security_event_field_w000000 ADD CONSTRAINT w256_seed_range CHECK (source_record_id >= %s AND source_record_id < %s) NOT VALID',lo,hi);
 ALTER TABLE fi_recovery_projection.windows_security_event_field_w000000 VALIDATE CONSTRAINT w256_seed_range;
 EXECUTE format('ALTER TABLE fi_recovery_projection.windows_security_event_field ATTACH PARTITION fi_recovery_projection.windows_security_event_field_w000000 FOR VALUES FROM (%s) TO (%s)',lo,hi);
END
$tighten$;
COMMIT;
