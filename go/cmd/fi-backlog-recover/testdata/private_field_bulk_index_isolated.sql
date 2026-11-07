-- FI DEVELOPMENT ONLY: isolated K64 candidate for deferred index construction.
-- The original finish function and every validation/transaction gate stay intact.
-- INSTALL ONLY on the disposable signed W128 three-window cloned database.
BEGIN;
DO $guard$
BEGIN
 IF current_database() <> 'fi' OR current_user <> 'fi_m1_admin'
    OR current_setting('server_version_num')::integer < 180000
    OR to_regclass('fi_recovery_projection.windows_security_event_field') IS NULL
    OR (SELECT count(*) FROM fi_recovery.typed_window) <> 3
    OR (SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window) <> 390387
    OR (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field) <> 4838850
    OR (SELECT count(*) FROM fi.recorded_generation) <> 0
    OR (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted') <> 0 THEN
   RAISE EXCEPTION 'FI bulk-index refuses non-disposable exact W128 signed seed';
 END IF;
END
$guard$;

CREATE OR REPLACE FUNCTION fi_recovery_projection.begin_security_field_window(p_index integer)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
 rel_name text;
 fq_name text;
BEGIN
 IF p_index < 1 OR p_index > 999999 OR p_index IS NULL THEN
   RAISE EXCEPTION 'FI field window: invalid index';
 END IF;
 rel_name := 'windows_security_event_field_w' || lpad(p_index::text,6,'0');
 fq_name := format('%I.%I','fi_recovery_projection',rel_name);
 IF to_regclass(fq_name) IS NOT NULL THEN
   RAISE EXCEPTION 'FI field window: candidate table already exists %',rel_name;
 END IF;
 IF (SELECT count(*) FROM fi_recovery.typed_window WHERE window_index=p_index) <> 0 THEN
   RAISE EXCEPTION 'FI field window: completion marker already exists';
 END IF;
 -- Leave the COPY destination free of per-row PK and name-index maintenance.
 -- ATTACH PARTITION must create/attach the required parent indexes and
 -- enforce PK uniqueness BEFORE the enclosing window transaction commits.
 -- LIKE still copies NOT NULL, CHECK, column, and storage semantics.
 EXECUTE format('CREATE TABLE %s (LIKE fi_recovery_projection.windows_security_event_field INCLUDING ALL EXCLUDING INDEXES)',fq_name);
 IF EXISTS (SELECT 1 FROM pg_index WHERE indrelid=to_regclass(fq_name)) THEN
   RAISE EXCEPTION 'FI bulk-index: detached COPY table unexpectedly indexed';
 END IF;
 EXECUTE format('GRANT INSERT, SELECT ON %s TO fi_ingest',fq_name);
 RETURN rel_name;
END
$function$;

COMMIT;
