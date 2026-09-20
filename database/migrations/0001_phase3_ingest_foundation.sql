-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- Phase 3 — Ingest & Recorder
-- Migration 0001: exact recorded-generation and source-record ingest foundation.
--
-- This schema does not replace recorder custody. Recorder-held FIGT objects and
-- durable recorder receipts remain authoritative transport custody. PostgreSQL
-- stores an immutable, queryable System-of-Record representation with lineage
-- back to that custody boundary.

BEGIN;

CREATE SCHEMA IF NOT EXISTS fi;

CREATE TABLE fi.recorded_generation (
    recorded_generation_id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    receipt_version             text NOT NULL,

    descriptor_version          text NOT NULL,
    source_id                   text NOT NULL,
    generation_id               text NOT NULL,
    canonical_version           text NOT NULL,
    data_encoding               text NOT NULL,

    artifact_count              numeric(20,0) NOT NULL CHECK (artifact_count > 0),
    source_bytes                numeric(20,0) NOT NULL CHECK (source_bytes >= 0),

    canonical_bytes             numeric(20,0) NOT NULL CHECK (canonical_bytes > 0),
    canonical_sha256            char(64) NOT NULL,

    encoded_data_bytes          numeric(20,0) NOT NULL CHECK (encoded_data_bytes > 0),
    encoded_data_sha256         char(64) NOT NULL,

    metadata_bytes              numeric(20,0) NOT NULL CHECK (metadata_bytes > 0),
    metadata_sha256             char(64) NOT NULL,

    transfer_bytes              numeric(20,0) NOT NULL CHECK (transfer_bytes > 0),
    transfer_sha256             char(64) NOT NULL,

    batch_count                 numeric(20,0) NOT NULL CHECK (batch_count > 0),
    data_bytes                  numeric(20,0) NOT NULL CHECK (data_bytes > 0),
    record_count                numeric(20,0) NOT NULL CHECK (record_count > 0),

    receipt_raw_bytes           bytea NOT NULL,
    receipt_sha256              char(64) NOT NULL,
    receipt_json                jsonb NOT NULL,

    ingested_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    ingest_version              text NOT NULL,

    CONSTRAINT recorded_generation_source_generation_uq
        UNIQUE (source_id, generation_id),

    CONSTRAINT recorded_generation_transfer_sha256_uq
        UNIQUE (transfer_sha256),

    CONSTRAINT recorded_generation_receipt_sha256_uq
        UNIQUE (receipt_sha256),

    CONSTRAINT recorded_generation_canonical_sha256_format
        CHECK (canonical_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT recorded_generation_encoded_sha256_format
        CHECK (encoded_data_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT recorded_generation_metadata_sha256_format
        CHECK (metadata_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT recorded_generation_transfer_sha256_format
        CHECK (transfer_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT recorded_generation_receipt_sha256_format
        CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE TABLE fi.source_batch (
    source_batch_id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recorded_generation_id      bigint NOT NULL
        REFERENCES fi.recorded_generation(recorded_generation_id),

    manifest_artifact_name      text NOT NULL,
    data_artifact_name          text NOT NULL,

    manifest_version            text NOT NULL,
    batch_id                    text NOT NULL,
    target_batch_size           integer NOT NULL CHECK (target_batch_size > 0),
    record_count                bigint NOT NULL CHECK (record_count > 0),
    data_bytes                  bigint NOT NULL CHECK (data_bytes > 0),
    data_sha256                 char(64) NOT NULL,
    data_file                   text NOT NULL,

    collector_executable_path   text NOT NULL,
    collector_executable_sha256 char(64) NOT NULL,

    created_at_text             text NOT NULL,
    completed_at_text           text NOT NULL,

    manifest_raw_bytes          bytea NOT NULL,
    manifest_sha256             char(64) NOT NULL,
    manifest_json               jsonb NOT NULL,

    ingested_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT source_batch_generation_batch_uq
        UNIQUE (recorded_generation_id, batch_id),

    CONSTRAINT source_batch_generation_manifest_artifact_uq
        UNIQUE (recorded_generation_id, manifest_artifact_name),

    CONSTRAINT source_batch_generation_data_artifact_uq
        UNIQUE (recorded_generation_id, data_artifact_name),

    CONSTRAINT source_batch_data_sha256_format
        CHECK (data_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT source_batch_collector_sha256_format
        CHECK (collector_executable_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT source_batch_manifest_sha256_format
        CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE TABLE fi.source_record (
    source_record_id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_batch_id             bigint NOT NULL
        REFERENCES fi.source_batch(source_batch_id),

    record_ordinal              bigint NOT NULL CHECK (record_ordinal > 0),

    version                     text NOT NULL,
    record_kind                 text NOT NULL,
    scope_id                    text NOT NULL,
    written_at_text             text NOT NULL,
    written_at_utc              timestamptz NOT NULL,

    raw_record_bytes            bytea NOT NULL,
    raw_record_sha256           char(64) NOT NULL,
    record_json                 jsonb NOT NULL,
    payload_json                jsonb NOT NULL,

    ingested_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    ingest_version              text NOT NULL,

    CONSTRAINT source_record_batch_ordinal_uq
        UNIQUE (source_batch_id, record_ordinal),

    CONSTRAINT source_record_raw_sha256_format
        CHECK (raw_record_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT source_record_version_matches_json
        CHECK (record_json ->> 'version' = version),

    CONSTRAINT source_record_kind_matches_json
        CHECK (record_json ->> 'record_kind' = record_kind),

    CONSTRAINT source_record_scope_matches_json
        CHECK (record_json ->> 'scope_id' = scope_id),

    CONSTRAINT source_record_written_at_matches_json
        CHECK (record_json ->> 'written_at' = written_at_text),

    CONSTRAINT source_record_payload_matches_json
        CHECK (record_json -> 'payload' = payload_json)
);

CREATE INDEX source_record_kind_idx
    ON fi.source_record(record_kind);

CREATE INDEX source_record_scope_idx
    ON fi.source_record(scope_id);

CREATE INDEX source_record_written_at_idx
    ON fi.source_record(written_at_utc);

CREATE INDEX source_record_record_json_gin
    ON fi.source_record
    USING gin(record_json jsonb_path_ops);

CREATE INDEX source_record_payload_json_gin
    ON fi.source_record
    USING gin(payload_json jsonb_path_ops);

CREATE TABLE fi.ingest_journal (
    ingest_journal_id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    occurred_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),

    source_id                   text,
    generation_id               text,
    transfer_sha256             char(64),

    outcome                     text NOT NULL,
    stage                       text NOT NULL,
    reason_code                 text,
    detail                      text,

    records_seen                numeric(20,0),
    records_committed           numeric(20,0),

    ingest_version              text NOT NULL,

    CONSTRAINT ingest_journal_outcome_ck
        CHECK (
            outcome IN (
                'Accepted',
                'AlreadyAccepted',
                'Rejected',
                'Failed',
                'Incomplete',
                'Conflict'
            )
        ),

    CONSTRAINT ingest_journal_transfer_sha256_format
        CHECK (
            transfer_sha256 IS NULL OR
            transfer_sha256 ~ '^[0-9a-f]{64}$'
        )
);

CREATE INDEX ingest_journal_source_generation_idx
    ON fi.ingest_journal(source_id, generation_id);

CREATE INDEX ingest_journal_occurred_at_idx
    ON fi.ingest_journal(occurred_at);

COMMIT;
