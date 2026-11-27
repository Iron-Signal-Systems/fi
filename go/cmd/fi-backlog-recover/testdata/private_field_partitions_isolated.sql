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
    EXECUTE format('GRANT INSERT, SELECT ON %s TO fi_ingest',fq_name);
    RETURN rel_name;
END
$function$

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
BEGIN
    IF p_index < 1 OR p_index > 999999 OR p_index IS NULL OR p_expected < 0 OR p_expected IS NULL THEN
        RAISE EXCEPTION 'FI field window: invalid finalize parameters';
    END IF;
    rel_name := 'windows_security_event_field_w' || lpad(p_index::text,6,'0');
    fq_name := format('%I.%I','fi_recovery_projection',rel_name);
    IF to_regclass(fq_name) IS NULL THEN
        RAISE EXCEPTION 'FI field window: missing candidate relation %',rel_name;
    END IF;
    -- Verify the precise number reported by FI's existing decoded field
    -- writer; an uncommitted window with zero fields needs no partition.
    EXECUTE format('SELECT count(*),min(source_record_id),max(source_record_id)+1 FROM %s',fq_name)
      INTO total,lower_bound,upper_bound;
    IF total <> p_expected THEN
        RAISE EXCEPTION 'FI field window: copied row count % differs from writer %',total,p_expected;
    END IF;
    IF total=0 THEN
        EXECUTE format('DROP TABLE %s',fq_name);
        RETURN total;
    END IF;
    -- A matching validated CHECK avoids the ATTACH data scan.
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I CHECK (source_record_id >= %s AND source_record_id < %s) NOT VALID',
      fq_name,rel_name||'_range',lower_bound,upper_bound);
    EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT %I',fq_name,rel_name||'_range');
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I FOREIGN KEY (source_record_id) REFERENCES fi_recovery_projection.windows_security_event(source_record_id) NOT VALID',
      fq_name,rel_name||'_parent_fk');
    EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT %I',fq_name,rel_name||'_parent_fk');
    EXECUTE format('ALTER TABLE fi_recovery_projection.windows_security_event_field ATTACH PARTITION %s FOR VALUES FROM (%s) TO (%s)',
      fq_name,lower_bound,upper_bound);
    -- Both validations plus attach are inside the caller's ONE W128 TX.
    RETURN total;
END
$function$

