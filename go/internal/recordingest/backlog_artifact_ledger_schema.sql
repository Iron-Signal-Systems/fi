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
-- Source-record lineage is durable, but remains private to FI recovery.
-- The original JSONL payload remains in signed custody/private stage; never
-- copy it into the relational ledger. Typed projections are NOT present here.
CREATE TABLE fi_recovery.pending_source_record (
    receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
    window_index integer NOT NULL CHECK (window_index >= 0),
    batch_index integer NOT NULL CHECK (batch_index >= 0),
    record_ordinal bigint NOT NULL CHECK (record_ordinal > 0),
    version text NOT NULL,
    record_kind text NOT NULL,
    scope_id text NOT NULL,
    written_at timestamptz NOT NULL,
    written_at_original text NOT NULL CHECK (length(written_at_original) > 0),
    record_bytes integer NOT NULL CHECK (record_bytes > 0),
    record_sha256 bytea NOT NULL CHECK (octet_length(record_sha256)=32),
    PRIMARY KEY (receipt_sha256,batch_index,record_ordinal),
    FOREIGN KEY (receipt_sha256,window_index)
       REFERENCES fi_recovery.verified_artifact_window(receipt_sha256,window_index)
);
CREATE INDEX pending_source_record_window_idx
ON fi_recovery.pending_source_record(receipt_sha256,window_index,batch_index,record_ordinal);

-- This marker is inserted in the SAME transaction as all its source rows.
-- A marker means "source envelope staged", never "generation accepted".
CREATE TABLE fi_recovery.source_window (
    receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
    window_index integer NOT NULL CHECK (window_index >= 0),
    descriptor_sha256 bytea NOT NULL CHECK (octet_length(descriptor_sha256)=32),
    previous_digest_sha256 bytea NOT NULL CHECK (octet_length(previous_digest_sha256)=32),
    start_batch integer NOT NULL CHECK (start_batch >= 0),
    end_batch integer NOT NULL CHECK (end_batch > start_batch),
    start_record bigint NOT NULL CHECK (start_record >= 0),
    end_record bigint NOT NULL CHECK (end_record > start_record),
    staged_records bigint NOT NULL CHECK (staged_records > 0),
    staged_bytes bigint NOT NULL CHECK (staged_bytes > 0),
    rows_digest_sha256 bytea NOT NULL CHECK (octet_length(rows_digest_sha256)=32),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (receipt_sha256,window_index),
    FOREIGN KEY (receipt_sha256,window_index)
       REFERENCES fi_recovery.verified_artifact_window(receipt_sha256,window_index)
);
REVOKE ALL ON fi_recovery.pending_source_record, fi_recovery.source_window FROM PUBLIC;
GRANT SELECT, INSERT ON fi_recovery.pending_source_record, fi_recovery.source_window TO fi_ingest;
COMMIT;
