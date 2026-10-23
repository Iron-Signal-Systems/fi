-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.
--
-- M6.1 additive relational capture binding. Preserve historic USN rows.
-- The metadata-only phase is committed BEFORE large-table validation.
-- The new constraints enforce writes immediately; existing rows are
-- validated afterward using PostgreSQL's less restrictive validation lock.
BEGIN;
SET LOCAL lock_timeout = '3s';

ALTER TABLE fi.usn_read_boundary
    ADD COLUMN source_batch_sha256 bytea,
    ADD COLUMN correlation_sha256 bytea,
    ADD COLUMN root_ntfs_object_id bigint,
    ALTER COLUMN usn_read_operation_id DROP NOT NULL;

ALTER TABLE fi.usn_read_boundary
    ADD CONSTRAINT usn_capture_root_fk
        FOREIGN KEY (root_ntfs_object_id)
        REFERENCES fi.ntfs_object(ntfs_object_id) NOT VALID,
    ADD CONSTRAINT usn_capture_contract_ck CHECK (
        (source_batch_sha256 IS NULL
         AND correlation_sha256 IS NULL
         AND root_ntfs_object_id IS NULL
         AND usn_read_operation_id IS NOT NULL
         AND usn_read_operation_id <> '')
        OR
        (source_batch_sha256 IS NOT NULL
         AND octet_length(source_batch_sha256) = 32
         AND correlation_sha256 IS NOT NULL
         AND octet_length(correlation_sha256) = 32
         AND root_ntfs_object_id IS NOT NULL
         AND usn_read_operation_id IS NULL)
    ) NOT VALID;

ALTER TABLE fi.usn_object_observation
    ADD COLUMN source_batch_sha256 bytea,
    ADD CONSTRAINT usn_object_capture_digest_ck CHECK (
        source_batch_sha256 IS NULL OR
        octet_length(source_batch_sha256) = 32
    ) NOT VALID;
COMMIT;

-- Each statement is its own transaction; validation scans may take time,
-- but do not hold the metadata phase's ACCESS EXCLUSIVE locks.
SET lock_timeout = '3s';
ALTER TABLE fi.usn_read_boundary
    VALIDATE CONSTRAINT usn_capture_root_fk;
ALTER TABLE fi.usn_read_boundary
    VALIDATE CONSTRAINT usn_capture_contract_ck;
ALTER TABLE fi.usn_object_observation
    VALIDATE CONSTRAINT usn_object_capture_digest_ck;
