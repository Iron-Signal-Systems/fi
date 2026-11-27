-- DBA-only, additive. Connect to fi_telemetry, NOT fi.
BEGIN;
DO $telemetry_roles$
BEGIN
 IF current_database() <> 'fi_telemetry' OR pg_is_in_recovery() THEN
  RAISE EXCEPTION 'FI telemetry role setup refused: use writable fi_telemetry';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi-telemetry-recorder') THEN
  CREATE ROLE "fi-telemetry-recorder" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi-telemetry-monitor') THEN
  CREATE ROLE "fi-telemetry-monitor" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_roles
   WHERE rolname IN ('fi-telemetry-recorder','fi-telemetry-monitor')
     AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
  RAISE EXCEPTION 'FI telemetry roles have unsafe inherited authority';
 END IF;
END $telemetry_roles$;
GRANT CONNECT ON DATABASE fi_telemetry TO "fi-telemetry-recorder";
GRANT CONNECT ON DATABASE fi TO "fi-telemetry-monitor";
GRANT USAGE ON SCHEMA telemetry_v2 TO "fi-telemetry-recorder";
GRANT SELECT,INSERT ON telemetry_v2.entry TO "fi-telemetry-recorder";
GRANT SELECT,INSERT ON telemetry_v2.delivery_receipt TO "fi-telemetry-recorder";
GRANT pg_read_all_stats TO "fi-telemetry-monitor";
COMMIT;
