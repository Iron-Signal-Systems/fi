-- FI W256 DEVELOPMENT ONLY.
-- Install against ONE disposable PostgreSQL 18 database containing exactly
-- window 0 of the original signed generation, planned as W256/2GiB.
-- Do not install on canonical FI, an unseeded DB, or a W128 checkpoint chain.
BEGIN;
DO $guard$
DECLARE
    n bigint;
    nrows bigint;
    first_index integer;
    last_index integer;
BEGIN
    SELECT count(*), coalesce(sum(committed_records),0),
           min(window_index), max(window_index)
      INTO n, nrows, first_index, last_index
      FROM fi_recovery.typed_window;
    IF current_database() <> 'fi' OR current_user <> 'fi_m1_admin'
       OR current_setting('server_version_num')::integer < 180000
       OR to_regclass('fi_recovery_projection.windows_security_event_field') IS NULL
       OR n <> 1 OR first_index <> 0 OR last_index <> 0
       OR nrows < 200000 OR nrows > 262144
       OR (SELECT count(*) FROM fi_recovery.source_window) <> 1
       OR (SELECT count(*) FROM fi_recovery.verified_artifact_window) <> 1
       OR (SELECT count(*) FROM fi.recorded_generation) <> 0
       OR (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted') <> 0
       OR to_regprocedure('fi_recovery_projection.finish_security_field_window(integer,bigint)') IS NULL
    THEN
        RAISE EXCEPTION 'FI W256 indexed field COPY refuses non-disposable, non-W256 signed seed';
    END IF;
    -- A W128 indexed 3-window fixture cannot be used as a W256 seed.
    IF EXISTS (SELECT 1 FROM fi_recovery.typed_window WHERE window_index <> 0) THEN
        RAISE EXCEPTION 'FI W256 signed seed must contain only window zero';
    END IF;
END
$guard$;

-- Same partition and FK validation model as the W128 deferred-index trial.
-- Only the detached COPY table excludes per-row index maintenance; the
-- existing finalizer builds all required parent indexes during ATTACH.
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
       RAISE EXCEPTION 'FI W256 field window: candidate table already exists %',rel_name;
    END IF;
    IF (SELECT count(*) FROM fi_recovery.typed_window WHERE window_index=p_index) <> 0 THEN
       RAISE EXCEPTION 'FI W256 field window: completion marker already exists';
    END IF;
    EXECUTE format('CREATE TABLE %s (LIKE fi_recovery_projection.windows_security_event_field INCLUDING ALL EXCLUDING INDEXES)',fq_name);
    IF EXISTS (SELECT 1 FROM pg_index WHERE indrelid=to_regclass(fq_name)) THEN
       RAISE EXCEPTION 'FI W256: detached COPY table unexpectedly indexed';
    END IF;
    EXECUTE format('GRANT INSERT, SELECT ON %s TO fi_ingest',fq_name);
    RETURN rel_name;
END
$function$;

COMMIT;
