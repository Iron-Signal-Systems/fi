-- FI DEVELOPMENT ONLY: profile the ACTUAL private partition finalizer.
-- Installed ONLY on the disposable K64 PostgreSQL clone by profile30 mode.
-- Retains all original SQL operations and atomic transactional return value.
BEGIN;
DO $guard$
BEGIN
    IF current_database() <> 'fi' OR current_user <> 'fi_m1_admin'
      OR current_setting('server_version_num')::integer < 180000
      OR to_regclass('fi_recovery_projection.windows_security_event_field') IS NULL
      OR to_regclass('fi_recovery.typed_window') IS NULL
      OR (SELECT count(*) FROM fi_recovery.typed_window) <> 3
      OR (SELECT coalesce(sum(committed_records),0) FROM fi_recovery.typed_window) <> 390387
      OR (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field) <> 4838850
      OR (SELECT count(*) FROM fi.recorded_generation) <> 0
      OR (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted') <> 0 THEN
        RAISE EXCEPTION 'FI field profiler refuses non-disposable exact W128 signed seed';
    END IF;
END
$guard$;
CREATE OR REPLACE FUNCTION fi_recovery_projection.finish_security_field_window(p_index integer, p_expected bigint)
 RETURNS bigint
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    rel_name text;
    fq_name text;
    total bigint;
    lower_bound bigint;
    upper_bound bigint;
    run_started timestamptz;
    step_started timestamptz;
    ms_count numeric;
    ms_check_add numeric;
    ms_check_validate numeric;
    ms_fk_add numeric;
    ms_fk_validate numeric;
    ms_attach numeric;
BEGIN
    IF p_index < 1 OR p_index > 999999 OR p_index IS NULL OR p_expected < 0 OR p_expected IS NULL THEN
        RAISE EXCEPTION 'FI field window: invalid finalize parameters';
    END IF;
    rel_name := 'windows_security_event_field_w' || lpad(p_index::text,6,'0');
    fq_name := format('%I.%I','fi_recovery_projection',rel_name);
    IF to_regclass(fq_name) IS NULL THEN
        RAISE EXCEPTION 'FI field window: missing candidate relation %',rel_name;
    END IF;
    -- Retain the existing transaction, SQL, constraints, and verified count.
    -- Clock sampling is confined to this disposable recovery database.
    run_started := clock_timestamp();
    step_started := run_started;
    -- Verify the precise number reported by FI's existing decoded field
    -- writer; an uncommitted window with zero fields needs no partition.
    EXECUTE format('SELECT count(*),min(source_record_id),max(source_record_id)+1 FROM %s',fq_name)
      INTO total,lower_bound,upper_bound;
    ms_count := round((extract(epoch FROM (clock_timestamp()-step_started))*1000)::numeric,3);
    IF total <> p_expected THEN
        RAISE EXCEPTION 'FI field window: copied row count % differs from writer %',total,p_expected;
    END IF;
    IF total=0 THEN
        EXECUTE format('DROP TABLE %s',fq_name);
        RETURN total;
    END IF;
    -- A matching validated CHECK avoids the ATTACH data scan.
    step_started := clock_timestamp();
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I CHECK (source_record_id >= %s AND source_record_id < %s) NOT VALID',
      fq_name,rel_name||'_range',lower_bound,upper_bound);
    ms_check_add := round((extract(epoch FROM (clock_timestamp()-step_started))*1000)::numeric,3);
    step_started := clock_timestamp();
    EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT %I',fq_name,rel_name||'_range');
    ms_check_validate := round((extract(epoch FROM (clock_timestamp()-step_started))*1000)::numeric,3);
    step_started := clock_timestamp();
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (source_record_id) REFERENCES fi_recovery_projection.windows_security_event(source_record_id) NOT VALID',
      fq_name,rel_name||'_parent_fk');
    ms_fk_add := round((extract(epoch FROM (clock_timestamp()-step_started))*1000)::numeric,3);
    step_started := clock_timestamp();
    EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT %I',fq_name,rel_name||'_parent_fk');
    ms_fk_validate := round((extract(epoch FROM (clock_timestamp()-step_started))*1000)::numeric,3);
    step_started := clock_timestamp();
    EXECUTE format('ALTER TABLE fi_recovery_projection.windows_security_event_field ATTACH PARTITION %s FOR VALUES FROM (%s) TO (%s)',
      fq_name,lower_bound,upper_bound);
    ms_attach := round((extract(epoch FROM (clock_timestamp()-step_started))*1000)::numeric,3);
    -- LOG is captured by this disposable cluster's pg_ctl -l server log.
    -- Messages from a rolled-back transaction are NOT proof of commit.
    RAISE LOG 'FI_PRIVATE_FIELD_PROFILE window=% rows=% count_ms=% check_add_ms=% check_validate_ms=% fk_add_ms=% fk_validate_ms=% attach_ms=% total_ms=%',
      p_index,total,ms_count,ms_check_add,ms_check_validate,ms_fk_add,ms_fk_validate,ms_attach,
      round((extract(epoch FROM (clock_timestamp()-run_started))*1000)::numeric,3);
    -- Both validations plus attach are inside the caller's ONE W128 TX.
    RETURN total;
END
$function$

COMMIT;
