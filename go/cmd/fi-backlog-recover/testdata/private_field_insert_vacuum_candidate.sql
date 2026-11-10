-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- FI PRIVATE EXPERIMENT ONLY. Apply exclusively to a freshly restored,
-- verified disposable W128/P3/F3 fi_recovery_projection clone.
--
-- Single independent variable: each NEW detached Security event field leaf
-- gets autovacuum_vacuum_insert_threshold=-1. Do NOT set autovacuum_enabled
-- to false; autovacuum analyze and anti-wraparound protection remain active.
--
-- CREATE OR REPLACE preserves existing function owner, arguments, EXECUTE
-- privileges and SECURITY DEFINER status. The body is the original private
-- fixture's begin function, except for the one guarded reloptions DDL call.
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
    EXECUTE format('CREATE TABLE %s (LIKE fi_recovery_projection.windows_security_event_field INCLUDING ALL)',fq_name);
    -- ONLY candidate variation. New private leaf tables can continue to
    -- receive ANALYZE and required anti-wraparound VACUUM, but do not
    -- schedule a VACUUM solely because INSERT count crossed its threshold.
    EXECUTE format('ALTER TABLE %s SET (autovacuum_vacuum_insert_threshold = -1)',fq_name);
    EXECUTE format('GRANT INSERT, SELECT ON %s TO fi_ingest',fq_name);
    RETURN rel_name;
END
$function$;
