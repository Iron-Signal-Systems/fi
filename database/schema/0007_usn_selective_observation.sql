-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- Development-only source-bound, independently observed NTFS outcomes.
-- Never infer historical file contents from the original USN journal.
-- Must be installed on an EMPTY/disposable SoR; no live C220 migration.

BEGIN;

CREATE TABLE fi.usn_selective_observation (
    source_record_id bigint PRIMARY KEY REFERENCES fi.source_record(source_record_id),
    original_capture_source_record_id bigint NOT NULL REFERENCES fi.usn_scoped_capture(source_record_id),
    capture_scope_id text NOT NULL CHECK (capture_scope_id LIKE 'volume-%'),
    governed_scope_id text NOT NULL CHECK (governed_scope_id <> ''),
    ntfs_volume_id bigint NOT NULL REFERENCES fi.ntfs_volume(ntfs_volume_id),
    root_ntfs_object_id bigint NOT NULL REFERENCES fi.ntfs_object(ntfs_object_id),
    file_ntfs_object_id bigint NOT NULL REFERENCES fi.ntfs_object(ntfs_object_id),
    journal_id numeric(20,0) NOT NULL CHECK (journal_id >= 0),
    start_usn numeric(20,0) NOT NULL CHECK (start_usn >= 0),
    next_usn numeric(20,0) NOT NULL CHECK (next_usn > start_usn),
    source_batch_sha256 bytea NOT NULL CHECK (octet_length(source_batch_sha256) = 32),
    observed_at timestamptz NOT NULL,
    observation_status text NOT NULL CHECK (
        observation_status IN ('Observed', 'Unavailable', 'OutsideGovernedRoot', 'Error')
    ),
    reason_code text NOT NULL,
    error_text text NOT NULL,
    has_ntfs_observation boolean NOT NULL,
    has_content_hashes boolean NOT NULL,
    trigger_count integer NOT NULL CHECK (trigger_count > 0 AND trigger_count <= 65536),
    CONSTRAINT selective_observation_state_ck CHECK (
        (observation_status = 'Observed'
          AND reason_code = '' AND error_text = ''
          AND has_ntfs_observation AND has_content_hashes)
        OR
        (observation_status <> 'Observed'
          AND reason_code <> ''
          AND NOT has_ntfs_observation AND NOT has_content_hashes)
    )
);

CREATE INDEX usn_selective_source_idx ON fi.usn_selective_observation (
    original_capture_source_record_id, file_ntfs_object_id
);
CREATE INDEX usn_selective_scope_idx ON fi.usn_selective_observation (
    governed_scope_id, observed_at
);

CREATE TABLE fi.usn_selective_observation_trigger (
    source_record_id bigint NOT NULL REFERENCES fi.usn_selective_observation(source_record_id),
    trigger_ordinal integer NOT NULL CHECK (trigger_ordinal > 0),
    usn numeric(20,0) NOT NULL CHECK (usn >= 0),
    PRIMARY KEY (source_record_id, trigger_ordinal)
);

GRANT SELECT, INSERT ON fi.usn_selective_observation,
    fi.usn_selective_observation_trigger TO fi_ingest;

COMMIT;
