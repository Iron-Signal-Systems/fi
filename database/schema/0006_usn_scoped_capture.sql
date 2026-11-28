-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- Development-only, append-only source-first USN relational contract.
-- USN journal facts are NOT Windows file re-observations. These tables are
-- separate from USNObjectObservation and FileObservation.
-- Backend-usn branch only; no existing C220 schema is modified by this file.

BEGIN;

CREATE TABLE fi.usn_scoped_capture (
    source_record_id            bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    captured_at                 timestamptz NOT NULL,
    collection_method           text NOT NULL CHECK (collection_method = 'WindowsNTFSUSNJournalV0'),
    capture_scope_id            text NOT NULL CHECK (capture_scope_id LIKE 'volume-%'),
    governed_scope_id           text NOT NULL CHECK (governed_scope_id <> ''),
    ntfs_volume_id              bigint NOT NULL REFERENCES fi.ntfs_volume(ntfs_volume_id),
    root_ntfs_object_id         bigint NOT NULL REFERENCES fi.ntfs_object(ntfs_object_id),
    journal_id                  numeric(20,0) NOT NULL CHECK (journal_id >= 0),
    start_usn                   numeric(20,0) NOT NULL CHECK (start_usn >= 0),
    next_usn                    numeric(20,0) NOT NULL CHECK (next_usn > start_usn),
    source_batch_sha256         bytea NOT NULL CHECK (octet_length(source_batch_sha256) = 32),
    source_record_count         integer NOT NULL CHECK (source_record_count >= 0),
    included_record_count       integer NOT NULL CHECK (included_record_count >= 0),
    governed_record_count       integer NOT NULL CHECK (governed_record_count >= 0),
    unresolved_record_count     integer NOT NULL CHECK (unresolved_record_count >= 0),
    proven_outside_record_count integer NOT NULL DEFAULT 0 CHECK (proven_outside_record_count = 0),
    CONSTRAINT usn_scoped_capture_counts_ck CHECK (
        included_record_count = governed_record_count + unresolved_record_count
        AND source_record_count = included_record_count + proven_outside_record_count
    )
);

CREATE INDEX usn_scoped_capture_journal_idx
    ON fi.usn_scoped_capture(ntfs_volume_id, journal_id, start_usn, next_usn);
CREATE INDEX usn_scoped_capture_scope_idx
    ON fi.usn_scoped_capture(governed_scope_id, captured_at);

CREATE TABLE fi.usn_scoped_change (
    source_record_id      bigint NOT NULL REFERENCES fi.usn_scoped_capture(source_record_id),
    change_ordinal        integer NOT NULL CHECK (change_ordinal > 0),
    file_ntfs_object_id   bigint NOT NULL REFERENCES fi.ntfs_object(ntfs_object_id),
    parent_ntfs_object_id bigint NOT NULL REFERENCES fi.ntfs_object(ntfs_object_id),
    usn                   numeric(20,0) NOT NULL CHECK (usn >= 0),
    event_timestamp       timestamptz NOT NULL,
    major_version         smallint NOT NULL CHECK (major_version = 2),
    minor_version         smallint NOT NULL CHECK (minor_version >= 0),
    scope_class           text NOT NULL CHECK (scope_class IN ('Governed','Unresolved')),
    scope_reason          text NOT NULL DEFAULT '',
    reason_raw            bigint NOT NULL CHECK (reason_raw BETWEEN 0 AND 4294967295),
    source_info_raw       bigint NOT NULL CHECK (source_info_raw BETWEEN 0 AND 4294967295),
    security_id           bigint NOT NULL CHECK (security_id BETWEEN 0 AND 4294967295),
    file_attributes_raw   bigint NOT NULL CHECK (file_attributes_raw BETWEEN 0 AND 4294967295),
    file_name_utf16le     bytea NOT NULL,
    PRIMARY KEY (source_record_id, change_ordinal)
);

CREATE INDEX usn_scoped_change_file_idx
    ON fi.usn_scoped_change(file_ntfs_object_id, usn);
CREATE INDEX usn_scoped_change_parent_idx
    ON fi.usn_scoped_change(parent_ntfs_object_id, usn);

-- fi_ingest is intentionally limited to immutable relational inserts.
GRANT SELECT, INSERT ON fi.usn_scoped_capture, fi.usn_scoped_change TO fi_ingest;

COMMIT;
