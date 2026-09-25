-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
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
