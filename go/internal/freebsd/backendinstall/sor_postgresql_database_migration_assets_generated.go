// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Code generated from canonical FI PostgreSQL schema migrations. DO NOT EDIT.

package backendinstall

// Source: database/schema/0001_relational.sql
// SHA256: f83ffb7754e22eef6230300b38ff6d1cf039791fd08f356c77efa2e30b462ebf
const sorPostgreSQLDatabaseMigration0001Asset = `-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
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
`

// Source: database/schema/0002_source_families.sql
// SHA256: 82050818f1424b7870a1b992b182abeb5497fe52c5a6f84d08fdefc76c496439
const sorPostgreSQLDatabaseMigration0002Asset = `-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- FI Phase 3 relational source-family model v2.
--
-- This extends the relational foundation to every source-record kind currently
-- emitted by the collector code. Exact source JSONL remains in recorder custody;
-- PostgreSQL stores typed relational facts plus source-record lineage only.

BEGIN;

-- ---------------------------------------------------------------------------
-- CollectorIdentity
-- ---------------------------------------------------------------------------

CREATE TABLE fi.collector_identity (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL,
    computer_netbios_name       text NOT NULL,
    computer_dns_host_name      text,
    computer_dns_domain         text,
    computer_dns_fqdn           text,
    token_user_sid              text NOT NULL,
    token_user_account_name     text,
    token_user_domain_name      text,
    token_user_name_use_raw     bigint CHECK (token_user_name_use_raw IS NULL OR token_user_name_use_raw >= 0),
    token_user_name_use_name    text,
    token_type_raw              smallint NOT NULL CHECK (token_type_raw IN (1,2)),
    token_type_name             text NOT NULL CHECK (token_type_name IN ('Primary','Impersonation')),
    elevation_type_raw          smallint NOT NULL CHECK (elevation_type_raw IN (1,2,3)),
    elevation_type_name         text NOT NULL CHECK (elevation_type_name IN ('Default','Full','Limited')),
    elevated                    boolean NOT NULL
);

CREATE INDEX collector_identity_computer_idx ON fi.collector_identity(computer_netbios_name, observed_at);
CREATE INDEX collector_identity_user_sid_idx ON fi.collector_identity(token_user_sid, observed_at);

CREATE TABLE fi.collector_token_group (
    source_record_id            bigint NOT NULL REFERENCES fi.collector_identity(source_record_id),
    group_ordinal               integer NOT NULL CHECK (group_ordinal >= 0),
    principal_sid               text NOT NULL,
    account_name                text,
    domain_name                 text,
    name_use_raw                bigint CHECK (name_use_raw IS NULL OR name_use_raw >= 0),
    name_use_name               text,
    attributes_raw              bigint NOT NULL CHECK (attributes_raw >= 0),
    mandatory                   boolean NOT NULL,
    enabled_by_default          boolean NOT NULL,
    enabled                     boolean NOT NULL,
    owner                       boolean NOT NULL,
    deny_only                   boolean NOT NULL,
    integrity                   boolean NOT NULL,
    integrity_enabled           boolean NOT NULL,
    logon_id                    boolean NOT NULL,
    resource                    boolean NOT NULL,
    PRIMARY KEY (source_record_id, group_ordinal)
);

CREATE INDEX collector_token_group_sid_idx ON fi.collector_token_group(principal_sid);

CREATE TABLE fi.collector_token_privilege (
    source_record_id            bigint NOT NULL REFERENCES fi.collector_identity(source_record_id),
    privilege_ordinal           integer NOT NULL CHECK (privilege_ordinal >= 0),
    luid_low                    bigint NOT NULL CHECK (luid_low BETWEEN 0 AND 4294967295),
    luid_high                   integer NOT NULL,
    name                        text,
    attributes_raw              bigint NOT NULL CHECK (attributes_raw BETWEEN 0 AND 4294967295),
    enabled_by_default          boolean NOT NULL,
    enabled                     boolean NOT NULL,
    removed                     boolean NOT NULL,
    used_for_access             boolean NOT NULL,
    PRIMARY KEY (source_record_id, privilege_ordinal)
);

CREATE INDEX collector_token_privilege_name_idx ON fi.collector_token_privilege(name) WHERE name IS NOT NULL;

-- ---------------------------------------------------------------------------
-- SMBShareSnapshot
-- ---------------------------------------------------------------------------

CREATE TABLE fi.smb_share_snapshot (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL
);

CREATE TABLE fi.smb_share (
    source_record_id            bigint NOT NULL REFERENCES fi.smb_share_snapshot(source_record_id),
    share_ordinal               integer NOT NULL CHECK (share_ordinal > 0),
    name_display                text NOT NULL,
    name_utf16le                bytea NOT NULL,
    type_raw                    bigint NOT NULL CHECK (type_raw BETWEEN 0 AND 4294967295),
    type_name                   text NOT NULL,
    special                     boolean NOT NULL,
    temporary                   boolean NOT NULL,
    remark_display              text,
    remark_utf16le              bytea,
    local_path_display          text,
    local_path_utf16le          bytea,
    permissions_raw             bigint NOT NULL CHECK (permissions_raw BETWEEN 0 AND 4294967295),
    max_uses_raw                bigint NOT NULL CHECK (max_uses_raw BETWEEN 0 AND 4294967295),
    current_uses                bigint NOT NULL CHECK (current_uses BETWEEN 0 AND 4294967295),
    security_state              text NOT NULL,
    security_data_format        text NOT NULL,
    security_raw_descriptor     bytea,
    security_revision           smallint,
    security_control            integer,
    security_owner_sid          text,
    security_primary_group_sid  text,
    dacl_state                  text,
    dacl_revision               smallint,
    dacl_size                   integer,
    security_reason_code        text,
    PRIMARY KEY (source_record_id, share_ordinal),
    CONSTRAINT smb_share_name_uq UNIQUE (source_record_id, name_utf16le)
);

CREATE INDEX smb_share_name_display_idx ON fi.smb_share(name_display);
CREATE INDEX smb_share_local_path_idx ON fi.smb_share(local_path_display) WHERE local_path_display IS NOT NULL;
CREATE INDEX smb_share_owner_sid_idx ON fi.smb_share(security_owner_sid) WHERE security_owner_sid IS NOT NULL;

CREATE TABLE fi.smb_share_ace (
    source_record_id            bigint NOT NULL,
    share_ordinal               integer NOT NULL,
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
    PRIMARY KEY (source_record_id, share_ordinal, ace_ordinal),
    FOREIGN KEY (source_record_id, share_ordinal)
        REFERENCES fi.smb_share(source_record_id, share_ordinal)
);

CREATE INDEX smb_share_ace_sid_idx ON fi.smb_share_ace(sid) WHERE sid IS NOT NULL;

-- ---------------------------------------------------------------------------
-- LocalPrincipalSnapshot
-- ---------------------------------------------------------------------------

CREATE TABLE fi.local_principal_snapshot (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL,
    computer_name               text NOT NULL
);

CREATE TABLE fi.local_user (
    source_record_id            bigint NOT NULL REFERENCES fi.local_principal_snapshot(source_record_id),
    user_ordinal                integer NOT NULL CHECK (user_ordinal > 0),
    sid                         text NOT NULL,
    sid_raw                     bytea NOT NULL,
    name_display                text NOT NULL,
    name_utf16le                bytea NOT NULL,
    full_name_display           text,
    full_name_utf16le           bytea,
    comment_display             text,
    comment_utf16le             bytea,
    flags_raw                   bigint NOT NULL CHECK (flags_raw BETWEEN 0 AND 4294967295),
    account_disabled            boolean NOT NULL,
    account_locked              boolean NOT NULL,
    PRIMARY KEY (source_record_id, user_ordinal),
    CONSTRAINT local_user_sid_uq UNIQUE (source_record_id, sid)
);

CREATE INDEX local_user_sid_idx ON fi.local_user(sid);
CREATE INDEX local_user_name_idx ON fi.local_user(name_display);

CREATE TABLE fi.local_group (
    source_record_id            bigint NOT NULL REFERENCES fi.local_principal_snapshot(source_record_id),
    group_ordinal               integer NOT NULL CHECK (group_ordinal > 0),
    sid                         text NOT NULL,
    sid_raw                     bytea NOT NULL,
    account_domain              text,
    name_display                text NOT NULL,
    name_utf16le                bytea NOT NULL,
    comment_display             text,
    comment_utf16le             bytea,
    membership_state            text NOT NULL CHECK (membership_state IN ('Complete','Partial','Error')),
    membership_reason_code      text,
    membership_detail           text,
    PRIMARY KEY (source_record_id, group_ordinal),
    CONSTRAINT local_group_sid_uq UNIQUE (source_record_id, sid),
    CONSTRAINT local_group_membership_shape_ck CHECK (
        (membership_state = 'Complete' AND membership_reason_code IS NULL AND membership_detail IS NULL)
        OR (membership_state IN ('Partial','Error') AND membership_reason_code IS NOT NULL)
    )
);

CREATE INDEX local_group_sid_idx ON fi.local_group(sid);
CREATE INDEX local_group_name_idx ON fi.local_group(name_display);

CREATE TABLE fi.local_group_membership (
    source_record_id            bigint NOT NULL REFERENCES fi.local_principal_snapshot(source_record_id),
    membership_ordinal          integer NOT NULL CHECK (membership_ordinal > 0),
    group_sid                   text NOT NULL,
    member_sid                  text NOT NULL,
    member_sid_raw              bytea NOT NULL,
    member_domain_name_display  text,
    member_domain_name_utf16le  bytea,
    sid_name_use_raw            bigint NOT NULL CHECK (sid_name_use_raw BETWEEN 0 AND 4294967295),
    sid_name_use_name           text NOT NULL,
    PRIMARY KEY (source_record_id, membership_ordinal),
    FOREIGN KEY (source_record_id, group_sid)
        REFERENCES fi.local_group(source_record_id, sid)
);

CREATE INDEX local_group_membership_group_idx ON fi.local_group_membership(group_sid);
CREATE INDEX local_group_membership_member_idx ON fi.local_group_membership(member_sid);

-- ---------------------------------------------------------------------------
-- DirectoryPrincipalSnapshot
-- ---------------------------------------------------------------------------

CREATE TABLE fi.directory_principal_snapshot (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL,
    domain_dns_name             text NOT NULL,
    server_dns_name             text NOT NULL,
    naming_context              text NOT NULL
);

CREATE TABLE fi.directory_requested_sid (
    source_record_id            bigint NOT NULL REFERENCES fi.directory_principal_snapshot(source_record_id),
    sid_ordinal                 integer NOT NULL CHECK (sid_ordinal > 0),
    sid                         text NOT NULL,
    PRIMARY KEY (source_record_id, sid_ordinal),
    CONSTRAINT directory_requested_sid_uq UNIQUE (source_record_id, sid)
);

CREATE INDEX directory_requested_sid_idx ON fi.directory_requested_sid(sid);

CREATE TABLE fi.directory_principal (
    source_record_id            bigint NOT NULL REFERENCES fi.directory_principal_snapshot(source_record_id),
    principal_ordinal           integer NOT NULL CHECK (principal_ordinal > 0),
    sid                         text NOT NULL,
    sid_raw                     bytea NOT NULL,
    object_guid                 uuid NOT NULL,
    object_guid_raw             bytea NOT NULL CHECK (octet_length(object_guid_raw) = 16),
    distinguished_name          text NOT NULL,
    sam_account_name            text,
    user_principal_name         text,
    user_account_control_raw    bigint CHECK (user_account_control_raw IS NULL OR user_account_control_raw BETWEEN 0 AND 4294967295),
    account_disabled            boolean,
    primary_group_id_raw        bigint CHECK (primary_group_id_raw IS NULL OR primary_group_id_raw BETWEEN 0 AND 4294967295),
    PRIMARY KEY (source_record_id, principal_ordinal),
    CONSTRAINT directory_principal_sid_uq UNIQUE (source_record_id, sid),
    CONSTRAINT directory_principal_guid_uq UNIQUE (source_record_id, object_guid),
    CONSTRAINT directory_uac_shape_ck CHECK (
        (user_account_control_raw IS NULL AND account_disabled IS NULL)
        OR (user_account_control_raw IS NOT NULL AND account_disabled IS NOT NULL)
    )
);

CREATE INDEX directory_principal_sid_idx ON fi.directory_principal(sid);
CREATE INDEX directory_principal_guid_idx ON fi.directory_principal(object_guid);
CREATE INDEX directory_principal_sam_idx ON fi.directory_principal(sam_account_name) WHERE sam_account_name IS NOT NULL;

CREATE TABLE fi.directory_principal_class (
    source_record_id            bigint NOT NULL,
    principal_ordinal           integer NOT NULL,
    class_ordinal               integer NOT NULL CHECK (class_ordinal > 0),
    object_class                text NOT NULL,
    PRIMARY KEY (source_record_id, principal_ordinal, class_ordinal),
    FOREIGN KEY (source_record_id, principal_ordinal)
        REFERENCES fi.directory_principal(source_record_id, principal_ordinal)
);

CREATE INDEX directory_principal_class_idx ON fi.directory_principal_class(object_class);

CREATE TABLE fi.directory_membership (
    source_record_id            bigint NOT NULL REFERENCES fi.directory_principal_snapshot(source_record_id),
    membership_ordinal          integer NOT NULL CHECK (membership_ordinal > 0),
    member_sid                  text NOT NULL,
    group_sid                   text NOT NULL,
    source                      text NOT NULL,
    PRIMARY KEY (source_record_id, membership_ordinal),
    FOREIGN KEY (source_record_id, member_sid)
        REFERENCES fi.directory_principal(source_record_id, sid),
    FOREIGN KEY (source_record_id, group_sid)
        REFERENCES fi.directory_principal(source_record_id, sid)
);

CREATE INDEX directory_membership_member_idx ON fi.directory_membership(member_sid);
CREATE INDEX directory_membership_group_idx ON fi.directory_membership(group_sid);

CREATE TABLE fi.directory_not_found_sid (
    source_record_id            bigint NOT NULL REFERENCES fi.directory_principal_snapshot(source_record_id),
    sid_ordinal                 integer NOT NULL CHECK (sid_ordinal > 0),
    sid                         text NOT NULL,
    PRIMARY KEY (source_record_id, sid_ordinal),
    CONSTRAINT directory_not_found_sid_uq UNIQUE (source_record_id, sid)
);

CREATE INDEX directory_not_found_sid_idx ON fi.directory_not_found_sid(sid);

-- ---------------------------------------------------------------------------
-- WindowsSecurityCoverage
-- ---------------------------------------------------------------------------

CREATE TABLE fi.windows_security_coverage (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL,
    security_log_readable       boolean NOT NULL,
    status                      text NOT NULL CHECK (status IN ('Ready','Partial'))
);

CREATE TABLE fi.windows_security_audit_policy (
    source_record_id            bigint NOT NULL REFERENCES fi.windows_security_coverage(source_record_id),
    policy_kind                 text NOT NULL CHECK (policy_kind IN ('FileSystem','HandleManipulation','DetailedFileShare','AuditPolicyChange')),
    subcategory_guid            text NOT NULL,
    auditing_information        text NOT NULL,
    success_enabled             boolean NOT NULL,
    failure_enabled             boolean NOT NULL,
    reason_code                 text,
    PRIMARY KEY (source_record_id, policy_kind)
);

CREATE INDEX windows_security_policy_guid_idx ON fi.windows_security_audit_policy(subcategory_guid);

CREATE TABLE fi.windows_security_root_coverage (
    source_record_id            bigint NOT NULL REFERENCES fi.windows_security_coverage(source_record_id),
    root_ordinal                integer NOT NULL CHECK (root_ordinal > 0),
    scope_id                    text NOT NULL,
    governed_root               text NOT NULL,
    sacl_state                  text NOT NULL,
    recommended_change_audit_present boolean NOT NULL,
    recommended_read_audit_present   boolean NOT NULL,
    reason_code                 text,
    PRIMARY KEY (source_record_id, root_ordinal),
    CONSTRAINT windows_security_root_scope_uq UNIQUE (source_record_id, scope_id)
);

CREATE INDEX windows_security_root_scope_idx ON fi.windows_security_root_coverage(scope_id);

-- ---------------------------------------------------------------------------
-- WindowsSecurityEvent
-- ---------------------------------------------------------------------------

CREATE TABLE fi.windows_security_event (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL,
    channel                     text NOT NULL,
    provider                    text NOT NULL,
    event_id                    bigint NOT NULL CHECK (event_id >= 0),
    version                     text,
    event_record_id             numeric(20,0) NOT NULL CHECK (event_record_id >= 0),
    time_created                timestamptz NOT NULL,
    computer                    text NOT NULL,
    keywords                    text,
    audit_result                text NOT NULL CHECK (audit_result IN ('Success','Failure','NotApplicable','Unknown')),
    scope_basis                 text NOT NULL CHECK (scope_basis IN ('PathMatched','HardLinkPathMatched','SharePathMatched','UnresolvedFileDeleteIncluded','HostMonitoringChange')),
    subject_user_sid            text,
    subject_user_name           text,
    subject_domain_name         text,
    subject_logon_id            text,
    object_server               text,
    object_type                 text,
    object_name                 text,
    handle_id                   text,
    process_id                  text,
    process_name                text,
    access_mask                 text,
    access_list                 text,
    access_reason               text,
    transaction_id              text,
    file_name                   text,
    link_name                   text,
    source_ip                   text,
    source_port                 text,
    share_name                  text,
    share_local_path            text,
    relative_target_name        text,
    old_security_descriptor     text,
    new_security_descriptor     text,
    subcategory_guid            text,
    audit_policy_changes        text,
    raw_xml_bytes               integer NOT NULL CHECK (raw_xml_bytes > 0),
    raw_xml_sha256              bytea NOT NULL CHECK (octet_length(raw_xml_sha256) = 32)
);

CREATE INDEX windows_security_event_record_idx ON fi.windows_security_event(computer, event_record_id);
CREATE INDEX windows_security_event_time_idx ON fi.windows_security_event(time_created);
CREATE INDEX windows_security_event_id_idx ON fi.windows_security_event(event_id, time_created);
CREATE INDEX windows_security_event_subject_sid_idx ON fi.windows_security_event(subject_user_sid) WHERE subject_user_sid IS NOT NULL;
CREATE INDEX windows_security_event_process_idx ON fi.windows_security_event(process_name) WHERE process_name IS NOT NULL;
CREATE INDEX windows_security_event_source_ip_idx ON fi.windows_security_event(source_ip) WHERE source_ip IS NOT NULL;

CREATE TABLE fi.windows_security_event_scope (
    source_record_id            bigint NOT NULL REFERENCES fi.windows_security_event(source_record_id),
    scope_ordinal               integer NOT NULL CHECK (scope_ordinal > 0),
    scope_id                    text NOT NULL,
    governed_root               text NOT NULL,
    PRIMARY KEY (source_record_id, scope_ordinal),
    CONSTRAINT windows_security_event_scope_uq UNIQUE (source_record_id, scope_id)
);

CREATE INDEX windows_security_event_scope_idx ON fi.windows_security_event_scope(scope_id);

CREATE TABLE fi.windows_security_event_field (
    source_record_id            bigint NOT NULL REFERENCES fi.windows_security_event(source_record_id),
    field_ordinal               integer NOT NULL CHECK (field_ordinal > 0),
    name                        text NOT NULL,
    value                       text NOT NULL,
    PRIMARY KEY (source_record_id, field_ordinal)
);

CREATE INDEX windows_security_event_field_name_idx ON fi.windows_security_event_field(name);

-- ---------------------------------------------------------------------------
-- WindowsSecurityContinuityGap
-- ---------------------------------------------------------------------------

CREATE TABLE fi.windows_security_continuity_gap (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL,
    channel                     text NOT NULL CHECK (channel = 'Security'),
    scope_id                    text NOT NULL,
    reason_code                 text NOT NULL CHECK (reason_code IN ('SecurityLogResetOrCleared','SecurityLogRecordsOverwritten')),
    checkpoint_event_record_id  numeric(20,0) NOT NULL CHECK (checkpoint_event_record_id >= 0),
    current_oldest_event_record_id numeric(20,0) NOT NULL CHECK (current_oldest_event_record_id >= 0),
    current_newest_event_record_id numeric(20,0) NOT NULL CHECK (current_newest_event_record_id >= 0),
    coverage_state              text NOT NULL CHECK (coverage_state = 'Incomplete'),
    reconciliation_action       text NOT NULL CHECK (reconciliation_action = 'CurrentStateBaseline')
);

CREATE INDEX windows_security_gap_time_idx ON fi.windows_security_continuity_gap(observed_at);

-- ---------------------------------------------------------------------------
-- Explicit collector-source errors
-- ---------------------------------------------------------------------------

CREATE TABLE fi.ntfs_collection_error (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    path_display                text NOT NULL,
    path_utf16le                bytea NOT NULL,
    error_text                  text NOT NULL
);

CREATE TABLE fi.supporting_source_collection_error (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    source                      text NOT NULL,
    error_text                  text NOT NULL
);

-- ---------------------------------------------------------------------------
-- USNReadBoundary
-- ---------------------------------------------------------------------------

CREATE TABLE fi.usn_read_boundary (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL,
    ntfs_volume_id              bigint NOT NULL REFERENCES fi.ntfs_volume(ntfs_volume_id),
    journal_id                  numeric(20,0) NOT NULL CHECK (journal_id >= 0),
    start_usn                   numeric(20,0) NOT NULL CHECK (start_usn >= 0),
    next_usn                    numeric(20,0) NOT NULL CHECK (next_usn >= 0),
    source_record_count         integer NOT NULL CHECK (source_record_count >= 0),
    source_distinct_object_count integer NOT NULL CHECK (source_distinct_object_count >= 0),
    selected_record_count       integer NOT NULL CHECK (selected_record_count >= 0),
    selected_object_count       integer NOT NULL CHECK (selected_object_count >= 0),
    ignored_volume_record_count integer NOT NULL CHECK (ignored_volume_record_count >= 0),
    ignored_volume_object_count integer NOT NULL CHECK (ignored_volume_object_count >= 0),
    scope_unresolved_object_count integer NOT NULL CHECK (scope_unresolved_object_count >= 0),
    usn_read_operation_id       text NOT NULL,
    reobservation_operation_id  text NOT NULL
);

CREATE INDEX usn_read_boundary_journal_idx ON fi.usn_read_boundary(ntfs_volume_id, journal_id, start_usn, next_usn);

-- USNObjectObservation contains a bounded set of source USN records for one
-- object plus the re-observation outcome. When the payload also carries a fresh
-- NTFS observation, that observation is projected into the existing
-- file_observation subtree using the same source_record_id.
CREATE TABLE fi.usn_object_observation (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    identity_method_version     text NOT NULL,
    file_reference_number       numeric(20,0) NOT NULL CHECK (file_reference_number >= 0),
    sequence_number             numeric(20,0) NOT NULL CHECK (sequence_number >= 0),
    scope_basis                 text NOT NULL CHECK (scope_basis IN ('CurrentObjectContained','CurrentObjectContainedByHelper','RecordedAncestorContained','RecordedParentContained','ScopeUnresolvedIncluded')),
    scope_detail                text,
    status                      text NOT NULL CHECK (status IN ('Observed','OutsideGovernedRoot','Unavailable','Error')),
    reason_code                 text,
    error_text                  text,
    has_ntfs_observation        boolean NOT NULL,
    has_content_hashes          boolean NOT NULL
);

CREATE INDEX usn_object_identity_idx ON fi.usn_object_observation(file_reference_number, sequence_number);

CREATE TABLE fi.usn_object_change (
    source_record_id            bigint NOT NULL REFERENCES fi.usn_object_observation(source_record_id),
    change_ordinal              integer NOT NULL CHECK (change_ordinal > 0),
    major_version               smallint NOT NULL,
    minor_version               smallint NOT NULL,
    file_identity_method_version text NOT NULL,
    file_reference_number       numeric(20,0) NOT NULL CHECK (file_reference_number >= 0),
    file_sequence_number        numeric(20,0) NOT NULL CHECK (file_sequence_number >= 0),
    parent_identity_method_version text NOT NULL,
    parent_file_reference_number numeric(20,0) NOT NULL CHECK (parent_file_reference_number >= 0),
    parent_sequence_number      numeric(20,0) NOT NULL CHECK (parent_sequence_number >= 0),
    usn                         numeric(20,0) NOT NULL CHECK (usn >= 0),
    event_timestamp             timestamptz NOT NULL,
    reason_raw                  bigint NOT NULL CHECK (reason_raw BETWEEN 0 AND 4294967295),
    source_info_raw             bigint NOT NULL CHECK (source_info_raw BETWEEN 0 AND 4294967295),
    security_id                 bigint NOT NULL CHECK (security_id BETWEEN 0 AND 4294967295),
    file_attributes_raw         bigint NOT NULL CHECK (file_attributes_raw BETWEEN 0 AND 4294967295),
    file_name_utf16le           bytea NOT NULL,
    PRIMARY KEY (source_record_id, change_ordinal)
);

CREATE INDEX usn_object_change_usn_idx ON fi.usn_object_change(usn);
CREATE INDEX usn_object_change_file_idx ON fi.usn_object_change(file_reference_number, file_sequence_number, usn);
CREATE INDEX usn_object_change_parent_idx ON fi.usn_object_change(parent_file_reference_number, parent_sequence_number, usn);

CREATE TABLE fi.usn_object_change_reason (
    source_record_id            bigint NOT NULL,
    change_ordinal              integer NOT NULL,
    reason_ordinal              integer NOT NULL CHECK (reason_ordinal > 0),
    reason_name                 text NOT NULL,
    PRIMARY KEY (source_record_id, change_ordinal, reason_ordinal),
    FOREIGN KEY (source_record_id, change_ordinal)
        REFERENCES fi.usn_object_change(source_record_id, change_ordinal)
);

CREATE INDEX usn_object_change_reason_name_idx ON fi.usn_object_change_reason(reason_name);

-- ---------------------------------------------------------------------------
-- USNContinuityGap
-- ---------------------------------------------------------------------------

CREATE TABLE fi.usn_continuity_gap (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    observed_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL,
    scope_id                    text NOT NULL,
    governed_root               text NOT NULL,
    reason_code                 text NOT NULL,
    checkpoint_journal_id       numeric(20,0) NOT NULL CHECK (checkpoint_journal_id >= 0),
    checkpoint_next_usn         numeric(20,0) NOT NULL CHECK (checkpoint_next_usn >= 0),
    current_journal_id          numeric(20,0) NOT NULL CHECK (current_journal_id >= 0),
    current_first_usn           numeric(20,0) NOT NULL CHECK (current_first_usn >= 0),
    current_lowest_valid_usn    numeric(20,0) NOT NULL CHECK (current_lowest_valid_usn >= 0),
    current_next_usn            numeric(20,0) NOT NULL CHECK (current_next_usn >= 0),
    coverage_state              text NOT NULL CHECK (coverage_state = 'Incomplete'),
    reconciliation_action       text NOT NULL CHECK (reconciliation_action = 'CurrentStateBaselineAndUSNCatchUp')
);

CREATE INDEX usn_continuity_gap_scope_time_idx ON fi.usn_continuity_gap(scope_id, observed_at);

-- Runtime may append and read. It may not mutate relational history.
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA fi TO fi_ingest;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA fi TO fi_ingest;

COMMIT;
`

// Source: database/schema/0003_usn_relational_identity.sql
// SHA256: 906dccf64eaf13a0a008bc870801beefb2d372f71574d10fe40ae5f1ba5a174c
const sorPostgreSQLDatabaseMigration0003Asset = `-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- FI Phase 3 relational USN identity correction v2.1.
--
-- USN object identity is volume-scoped. FRN + sequence without the NTFS volume
-- is not a complete object identity. USNObjectObservation is therefore bound
-- explicitly to the preceding USNReadBoundary and to fi.ntfs_object. Individual
-- USN changes likewise reference volume-qualified fi.ntfs_object identities.
--
-- This migration intentionally requires the USN relational tables to be empty.
-- It is being applied before the relational ingester is enabled.

BEGIN;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fi.usn_object_observation LIMIT 1)
       OR EXISTS (SELECT 1 FROM fi.usn_object_change LIMIT 1) THEN
        RAISE EXCEPTION '0003_usn_relational_identity requires empty USN relational tables';
    END IF;
END
$$;

DROP INDEX IF EXISTS fi.usn_object_identity_idx;

ALTER TABLE fi.usn_object_observation
    ADD COLUMN usn_read_boundary_source_record_id bigint NOT NULL,
    ADD COLUMN ntfs_object_id bigint NOT NULL;

ALTER TABLE fi.usn_object_observation
    ADD CONSTRAINT usn_object_boundary_fk
        FOREIGN KEY (usn_read_boundary_source_record_id)
        REFERENCES fi.usn_read_boundary(source_record_id),
    ADD CONSTRAINT usn_object_ntfs_object_fk
        FOREIGN KEY (ntfs_object_id)
        REFERENCES fi.ntfs_object(ntfs_object_id);

ALTER TABLE fi.usn_object_observation
    DROP COLUMN identity_method_version,
    DROP COLUMN file_reference_number,
    DROP COLUMN sequence_number;

CREATE INDEX usn_object_boundary_idx
    ON fi.usn_object_observation(usn_read_boundary_source_record_id);

CREATE INDEX usn_object_ntfs_object_idx
    ON fi.usn_object_observation(ntfs_object_id);

DROP INDEX IF EXISTS fi.usn_object_change_file_idx;
DROP INDEX IF EXISTS fi.usn_object_change_parent_idx;

ALTER TABLE fi.usn_object_change
    ADD COLUMN file_ntfs_object_id bigint NOT NULL,
    ADD COLUMN parent_ntfs_object_id bigint NOT NULL;

ALTER TABLE fi.usn_object_change
    ADD CONSTRAINT usn_object_change_file_object_fk
        FOREIGN KEY (file_ntfs_object_id)
        REFERENCES fi.ntfs_object(ntfs_object_id),
    ADD CONSTRAINT usn_object_change_parent_object_fk
        FOREIGN KEY (parent_ntfs_object_id)
        REFERENCES fi.ntfs_object(ntfs_object_id);

ALTER TABLE fi.usn_object_change
    DROP COLUMN file_identity_method_version,
    DROP COLUMN file_reference_number,
    DROP COLUMN file_sequence_number,
    DROP COLUMN parent_identity_method_version,
    DROP COLUMN parent_file_reference_number,
    DROP COLUMN parent_sequence_number;

CREATE INDEX usn_object_change_file_idx
    ON fi.usn_object_change(file_ntfs_object_id, usn);

CREATE INDEX usn_object_change_parent_idx
    ON fi.usn_object_change(parent_ntfs_object_id, usn);

COMMIT;
`
