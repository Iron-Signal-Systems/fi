-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- FI Phase 3 relational foundation v1.
--
-- Recorder custody remains the immutable source representation. PostgreSQL is
-- a rebuildable relational system of record derived from verified custody.
-- No JSON/JSONB source payload copies are stored in this schema.

BEGIN;

CREATE SCHEMA fi AUTHORIZATION fi_owner;
REVOKE ALL ON SCHEMA fi FROM PUBLIC;

CREATE TABLE fi.recorded_generation (
    recorded_generation_id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    receipt_version             text NOT NULL,
    descriptor_version          text NOT NULL,
    source_id                   text NOT NULL,
    generation_id               text NOT NULL,
    canonical_version           text NOT NULL,
    data_encoding               text NOT NULL,
    artifact_count              bigint NOT NULL CHECK (artifact_count > 0),
    source_bytes                bigint NOT NULL CHECK (source_bytes >= 0),
    canonical_bytes             bigint NOT NULL CHECK (canonical_bytes > 0),
    canonical_sha256            bytea NOT NULL CHECK (octet_length(canonical_sha256) = 32),
    encoded_data_bytes          bigint NOT NULL CHECK (encoded_data_bytes > 0),
    encoded_data_sha256         bytea NOT NULL CHECK (octet_length(encoded_data_sha256) = 32),
    metadata_bytes              bigint NOT NULL CHECK (metadata_bytes > 0),
    metadata_sha256             bytea NOT NULL CHECK (octet_length(metadata_sha256) = 32),
    transfer_bytes              bigint NOT NULL CHECK (transfer_bytes > 0),
    transfer_sha256             bytea NOT NULL CHECK (octet_length(transfer_sha256) = 32),
    batch_count                 bigint NOT NULL CHECK (batch_count > 0),
    data_bytes                  bigint NOT NULL CHECK (data_bytes > 0),
    record_count                bigint NOT NULL CHECK (record_count > 0),
    receipt_bytes               bigint NOT NULL CHECK (receipt_bytes > 0),
    receipt_sha256              bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    ingested_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    ingest_version              text NOT NULL,
    CONSTRAINT recorded_generation_source_generation_uq UNIQUE (source_id, generation_id),
    CONSTRAINT recorded_generation_transfer_sha256_uq UNIQUE (transfer_sha256),
    CONSTRAINT recorded_generation_receipt_sha256_uq UNIQUE (receipt_sha256)
);

CREATE TABLE fi.source_batch (
    source_batch_id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recorded_generation_id      bigint NOT NULL REFERENCES fi.recorded_generation(recorded_generation_id),
    manifest_artifact_name      text NOT NULL,
    data_artifact_name          text NOT NULL,
    manifest_version            text NOT NULL,
    batch_id                    text NOT NULL,
    target_batch_size           integer NOT NULL CHECK (target_batch_size > 0),
    record_count                bigint NOT NULL CHECK (record_count > 0),
    data_bytes                  bigint NOT NULL CHECK (data_bytes > 0),
    data_sha256                 bytea NOT NULL CHECK (octet_length(data_sha256) = 32),
    data_file                   text NOT NULL,
    collector_executable_path   text NOT NULL,
    collector_executable_sha256 bytea NOT NULL CHECK (octet_length(collector_executable_sha256) = 32),
    created_at                  timestamptz NOT NULL,
    completed_at                timestamptz NOT NULL,
    manifest_bytes              bigint NOT NULL CHECK (manifest_bytes > 0),
    manifest_sha256             bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    ingested_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT source_batch_generation_batch_uq UNIQUE (recorded_generation_id, batch_id),
    CONSTRAINT source_batch_generation_manifest_artifact_uq UNIQUE (recorded_generation_id, manifest_artifact_name),
    CONSTRAINT source_batch_generation_data_artifact_uq UNIQUE (recorded_generation_id, data_artifact_name)
);

CREATE TABLE fi.source_record (
    source_record_id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_batch_id             bigint NOT NULL REFERENCES fi.source_batch(source_batch_id),
    record_ordinal              bigint NOT NULL CHECK (record_ordinal > 0),
    version                     text NOT NULL,
    record_kind                 text NOT NULL,
    scope_id                    text NOT NULL,
    written_at                  timestamptz NOT NULL,
    record_bytes                integer NOT NULL CHECK (record_bytes > 0),
    record_sha256               bytea NOT NULL CHECK (octet_length(record_sha256) = 32),
    ingested_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    ingest_version              text NOT NULL,
    CONSTRAINT source_record_batch_ordinal_uq UNIQUE (source_batch_id, record_ordinal)
);

CREATE INDEX source_record_kind_time_idx ON fi.source_record(record_kind, written_at);
CREATE INDEX source_record_scope_time_idx ON fi.source_record(scope_id, written_at);

CREATE TABLE fi.ingest_journal (
    ingest_journal_id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attempt_id                  text NOT NULL,
    event_sequence              integer NOT NULL CHECK (event_sequence > 0),
    occurred_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    source_id                   text,
    generation_id               text,
    transfer_sha256             bytea CHECK (transfer_sha256 IS NULL OR octet_length(transfer_sha256) = 32),
    outcome                     text NOT NULL CHECK (outcome IN ('Accepted','AlreadyAccepted','Rejected','Failed','Incomplete','Conflict')),
    stage                       text NOT NULL,
    reason_code                 text,
    detail                      text,
    records_seen                bigint CHECK (records_seen IS NULL OR records_seen >= 0),
    records_committed           bigint CHECK (records_committed IS NULL OR records_committed >= 0),
    ingest_version              text NOT NULL,
    CONSTRAINT ingest_journal_attempt_event_uq UNIQUE (attempt_id, event_sequence)
);

CREATE INDEX ingest_journal_attempt_idx ON fi.ingest_journal(attempt_id, event_sequence);
CREATE INDEX ingest_journal_source_generation_idx ON fi.ingest_journal(source_id, generation_id);
CREATE INDEX ingest_journal_occurred_at_idx ON fi.ingest_journal(occurred_at);

-- NTFS identity. Paths are deliberately not part of object identity.
CREATE TABLE fi.ntfs_volume (
    ntfs_volume_id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id                   text NOT NULL,
    identity_method_version     text NOT NULL,
    volume_guid                 text NOT NULL,
    volume_serial               numeric(20,0) NOT NULL CHECK (volume_serial >= 0),
    CONSTRAINT ntfs_volume_identity_uq UNIQUE (source_id, volume_guid, volume_serial)
);

CREATE TABLE fi.ntfs_object (
    ntfs_object_id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ntfs_volume_id              bigint NOT NULL REFERENCES fi.ntfs_volume(ntfs_volume_id),
    identity_method_version     text NOT NULL,
    file_reference_number       numeric(20,0) NOT NULL CHECK (file_reference_number >= 0),
    sequence_number             numeric(20,0) NOT NULL CHECK (sequence_number >= 0),
    CONSTRAINT ntfs_object_identity_uq UNIQUE (ntfs_volume_id, file_reference_number, sequence_number)
);

CREATE INDEX ntfs_object_frn_idx ON fi.ntfs_object(ntfs_volume_id, file_reference_number);

CREATE TABLE fi.governed_root (
    governed_root_id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id                   text NOT NULL,
    scope_id                    text NOT NULL,
    containment_method_version  text NOT NULL,
    ntfs_volume_id              bigint NOT NULL REFERENCES fi.ntfs_volume(ntfs_volume_id),
    ntfs_object_id              bigint NOT NULL REFERENCES fi.ntfs_object(ntfs_object_id),
    requested_path_utf16le      bytea NOT NULL,
    resolved_path_utf16le       bytea NOT NULL,
    CONSTRAINT governed_root_identity_uq UNIQUE (
        source_id,
        scope_id,
        ntfs_volume_id,
        ntfs_object_id,
        requested_path_utf16le,
        resolved_path_utf16le
    )
);

CREATE INDEX governed_root_scope_idx ON fi.governed_root(source_id, scope_id);

CREATE TABLE fi.file_observation (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    governed_root_id            bigint NOT NULL REFERENCES fi.governed_root(governed_root_id),
    ntfs_object_id              bigint NOT NULL REFERENCES fi.ntfs_object(ntfs_object_id),
    parent_state                text NOT NULL CHECK (parent_state IN ('Error','GovernedRoot','Present')),
    parent_ntfs_object_id       bigint REFERENCES fi.ntfs_object(ntfs_object_id),
    parent_reason_code          text,
    subject_kind                text NOT NULL,
    requested_path_utf16le      bytea NOT NULL,
    resolved_path_utf16le       bytea NOT NULL,
    observed_at                 timestamptz NOT NULL,
    containment_method_version  text NOT NULL,
    collection_entry_method     text NOT NULL,
    collection_method           text NOT NULL,
    observation_status          text NOT NULL,
    CONSTRAINT file_observation_parent_shape_ck CHECK (
        (parent_state = 'Present' AND parent_ntfs_object_id IS NOT NULL AND parent_reason_code IS NULL)
        OR (parent_state = 'GovernedRoot' AND parent_ntfs_object_id IS NULL AND parent_reason_code IS NULL)
        OR (parent_state = 'Error' AND parent_ntfs_object_id IS NULL AND parent_reason_code IS NOT NULL)
    )
);

CREATE INDEX file_observation_object_time_idx ON fi.file_observation(ntfs_object_id, observed_at);
CREATE INDEX file_observation_root_time_idx ON fi.file_observation(governed_root_id, observed_at);

CREATE TABLE fi.file_metadata_observation (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.file_observation(source_record_id),
    logical_size                numeric(20,0) NOT NULL CHECK (logical_size >= 0),
    allocated_size              numeric(20,0) NOT NULL CHECK (allocated_size >= 0),
    creation_time               timestamptz NOT NULL,
    last_write_time             timestamptz NOT NULL,
    change_time                 timestamptz NOT NULL,
    last_access_time            timestamptz NOT NULL,
    raw_attributes              bigint NOT NULL CHECK (raw_attributes >= 0),
    link_count                  bigint NOT NULL CHECK (link_count >= 0)
);

CREATE INDEX file_metadata_last_write_idx ON fi.file_metadata_observation(last_write_time);

CREATE TABLE fi.content_hash_observation (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.file_observation(source_record_id),
    state                       text NOT NULL CHECK (state IN ('Error','NotApplicable','Present')),
    bytes_hashed                numeric(20,0) CHECK (bytes_hashed IS NULL OR bytes_hashed >= 0),
    md5                         bytea CHECK (md5 IS NULL OR octet_length(md5) = 16),
    sha1                        bytea CHECK (sha1 IS NULL OR octet_length(sha1) = 20),
    sha256                      bytea CHECK (sha256 IS NULL OR octet_length(sha256) = 32),
    reason_code                 text,
    detail                      text,
    CONSTRAINT content_hash_shape_ck CHECK (
        (state = 'Present' AND bytes_hashed IS NOT NULL AND md5 IS NOT NULL AND sha1 IS NOT NULL AND sha256 IS NOT NULL AND reason_code IS NULL AND detail IS NULL)
        OR (state = 'Error' AND bytes_hashed IS NULL AND md5 IS NULL AND sha1 IS NULL AND sha256 IS NULL AND reason_code IS NOT NULL)
        OR (state = 'NotApplicable' AND bytes_hashed IS NULL AND md5 IS NULL AND sha1 IS NULL AND sha256 IS NULL AND reason_code IS NULL AND detail IS NULL)
    )
);

CREATE INDEX content_hash_sha256_idx ON fi.content_hash_observation(sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX content_hash_md5_idx ON fi.content_hash_observation(md5) WHERE md5 IS NOT NULL;

CREATE TABLE fi.content_prefix_observation (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.file_observation(source_record_id),
    state                       text NOT NULL CHECK (state IN ('Error','NotApplicable','Present')),
    bytes_observed              smallint CHECK (bytes_observed IS NULL OR (bytes_observed >= 0 AND bytes_observed <= 16)),
    prefix_bytes                bytea CHECK (prefix_bytes IS NULL OR octet_length(prefix_bytes) <= 16),
    reason_code                 text,
    detail                      text,
    CONSTRAINT content_prefix_shape_ck CHECK (
        (state = 'Present' AND bytes_observed IS NOT NULL AND prefix_bytes IS NOT NULL AND octet_length(prefix_bytes) = bytes_observed AND reason_code IS NULL AND detail IS NULL)
        OR (state = 'Error' AND bytes_observed IS NULL AND prefix_bytes IS NULL AND reason_code IS NOT NULL)
        OR (state = 'NotApplicable' AND bytes_observed IS NULL AND prefix_bytes IS NULL AND reason_code IS NULL AND detail IS NULL)
    )
);

CREATE TABLE fi.reparse_observation (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.file_observation(source_record_id),
    state                       text NOT NULL,
    data_state                  text NOT NULL,
    data_format                 text NOT NULL,
    tag                         bigint,
    tag_name                    text,
    raw_buffer                  bytea,
    substitute_name_utf16le     bytea,
    print_name_utf16le          bytea,
    symbolic_link_flags         bigint,
    reason_code                 text
);

CREATE TABLE fi.stream_inventory (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.file_observation(source_record_id),
    state                       text NOT NULL,
    reason_code                 text
);

CREATE TABLE fi.stream_observation (
    source_record_id            bigint NOT NULL REFERENCES fi.stream_inventory(source_record_id),
    stream_ordinal              integer NOT NULL CHECK (stream_ordinal > 0),
    kind                        text NOT NULL,
    name_utf16le                bytea,
    stream_type                 text,
    raw_name_utf16le            bytea NOT NULL,
    logical_size                numeric(20,0) NOT NULL CHECK (logical_size >= 0),
    allocated_size              numeric(20,0) NOT NULL CHECK (allocated_size >= 0),
    PRIMARY KEY (source_record_id, stream_ordinal)
);

CREATE TABLE fi.security_observation (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.file_observation(source_record_id),
    state                       text NOT NULL,
    data_format                 text NOT NULL,
    raw_descriptor              bytea,
    revision                    smallint,
    control                     integer,
    owner_sid                   text,
    primary_group_sid           text,
    acl_state                   text,
    acl_revision                smallint,
    acl_size                    integer,
    reason_code                 text
);

CREATE INDEX security_owner_sid_idx ON fi.security_observation(owner_sid) WHERE owner_sid IS NOT NULL;
CREATE INDEX security_group_sid_idx ON fi.security_observation(primary_group_sid) WHERE primary_group_sid IS NOT NULL;

CREATE TABLE fi.security_ace (
    source_record_id            bigint NOT NULL REFERENCES fi.security_observation(source_record_id),
    ace_ordinal                 integer NOT NULL CHECK (ace_ordinal >= 0),
    ace_type                    integer NOT NULL,
    type_name                   text NOT NULL,
    flags                       integer NOT NULL,
    ace_size                    integer NOT NULL CHECK (ace_size > 0),
    raw_ace                     bytea NOT NULL,
    access_mask                 bigint,
    object_flags                bigint,
    object_type_guid            uuid,
    inherited_object_type_guid  uuid,
    sid                         text,
    PRIMARY KEY (source_record_id, ace_ordinal)
);

CREATE INDEX security_ace_sid_idx ON fi.security_ace(sid) WHERE sid IS NOT NULL;

CREATE TABLE fi.sacl_observation (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.file_observation(source_record_id),
    state                       text NOT NULL,
    data_format                 text NOT NULL,
    raw_descriptor              bytea,
    revision                    smallint,
    control                     integer,
    acl_state                   text,
    acl_revision                smallint,
    acl_size                    integer,
    reason_code                 text
);

CREATE TABLE fi.sacl_ace (
    source_record_id            bigint NOT NULL REFERENCES fi.sacl_observation(source_record_id),
    ace_ordinal                 integer NOT NULL CHECK (ace_ordinal >= 0),
    ace_type                    integer NOT NULL,
    type_name                   text NOT NULL,
    flags                       integer NOT NULL,
    ace_size                    integer NOT NULL CHECK (ace_size > 0),
    raw_ace                     bytea NOT NULL,
    access_mask                 bigint,
    object_flags                bigint,
    object_type_guid            uuid,
    inherited_object_type_guid  uuid,
    sid                         text,
    PRIMARY KEY (source_record_id, ace_ordinal)
);

CREATE INDEX sacl_ace_sid_idx ON fi.sacl_ace(sid) WHERE sid IS NOT NULL;

CREATE TABLE fi.observation_warning (
    source_record_id            bigint NOT NULL REFERENCES fi.file_observation(source_record_id),
    warning_ordinal             integer NOT NULL CHECK (warning_ordinal > 0),
    code                        text NOT NULL,
    detail                      text,
    PRIMARY KEY (source_record_id, warning_ordinal)
);

-- Runtime may append and read. It may not mutate authoritative history.
GRANT CONNECT ON DATABASE fi TO fi_ingest;
GRANT USAGE ON SCHEMA fi TO fi_ingest;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA fi TO fi_ingest;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA fi TO fi_ingest;

ALTER DEFAULT PRIVILEGES FOR ROLE fi_owner IN SCHEMA fi
    GRANT SELECT, INSERT ON TABLES TO fi_ingest;
ALTER DEFAULT PRIVILEGES FOR ROLE fi_owner IN SCHEMA fi
    GRANT USAGE, SELECT ON SEQUENCES TO fi_ingest;

COMMIT;
