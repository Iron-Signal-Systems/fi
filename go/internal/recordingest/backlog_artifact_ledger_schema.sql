-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- FI test-only backlog artifact ledger schema. NOT part of deployed migrations.
--
-- Only the isolated PostgreSQL 18 integration test creates this schema.
-- This records proof of a hashed private FILE COPY, NOT relational ingestion.
-- It does not add anything to fi.recorded_generation or fi.source_record.
BEGIN;
CREATE SCHEMA fi_recovery;
REVOKE ALL ON SCHEMA fi_recovery FROM PUBLIC;
CREATE TABLE fi_recovery.verified_artifact_window (
    receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    window_index integer NOT NULL CHECK (window_index >= 0),
    source_id text NOT NULL CHECK (length(source_id) > 0),
    generation_id text NOT NULL CHECK (length(generation_id) > 0),
    transfer_sha256 bytea NOT NULL CHECK (octet_length(transfer_sha256) = 32),
    descriptor_sha256 bytea NOT NULL CHECK (octet_length(descriptor_sha256) = 32),
    previous_digest_sha256 bytea NOT NULL CHECK (octet_length(previous_digest_sha256) = 32),
    start_batch bigint NOT NULL CHECK (start_batch >= 0),
    end_batch bigint NOT NULL CHECK (end_batch > start_batch),
    start_record bigint NOT NULL CHECK (start_record >= 0),
    end_record bigint NOT NULL CHECK (end_record > start_record),
    data_bytes bigint NOT NULL CHECK (data_bytes > 0),
    verified_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (receipt_sha256, window_index),
    UNIQUE (source_id, generation_id, window_index)
);
REVOKE ALL ON fi_recovery.verified_artifact_window FROM PUBLIC;
GRANT USAGE ON SCHEMA fi_recovery TO fi_ingest;
GRANT SELECT, INSERT ON fi_recovery.verified_artifact_window TO fi_ingest;
COMMIT;
