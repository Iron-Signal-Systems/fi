-- PostgreSQL 18; run as the PostgreSQL administrator against fi_telemetry ONLY.
-- Additive and versioned: never drop/mutate telemetry.entry or delivery_receipt.
BEGIN;
DO $sor_boundary$
BEGIN
 IF current_database()<>'fi_telemetry' OR pg_is_in_recovery() THEN
   RAISE EXCEPTION 'FI telemetry schema install refused: requires writable fi_telemetry';
 END IF;
END $sor_boundary$;
CREATE SCHEMA IF NOT EXISTS telemetry_v2;
CREATE TABLE IF NOT EXISTS telemetry_v2.entry (
 entry_id char(64) PRIMARY KEY,
 source_host text NOT NULL CHECK(length(source_host) BETWEEN 1 AND 256),
 run_id text NOT NULL CHECK(length(run_id) BETWEEN 1 AND 128),
 stream text NOT NULL CHECK(stream IN ('samples','events')),
 observed_at timestamptz NOT NULL,
 payload jsonb NOT NULL,
 committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS telemetry_v2_entry_observed_at
 ON telemetry_v2.entry (observed_at,source_host,run_id);
CREATE TABLE IF NOT EXISTS telemetry_v2.delivery_receipt (
 batch_sha256 char(64) PRIMARY KEY,
 item_count integer NOT NULL CHECK(item_count BETWEEN 1 AND 256),
 delivered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
COMMIT;
-- DBA: grant USAGE on telemetry_v2 + INSERT/SELECT on ONLY these tables
-- to a dedicated uploader role. Collector has ZERO SQL-write privileges.
-- Do not grant any FI canonical SoR table privileges to telemetry roles.
