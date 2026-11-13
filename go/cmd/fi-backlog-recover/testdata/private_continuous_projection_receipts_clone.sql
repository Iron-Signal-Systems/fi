-- FI development-only ALTERATION OF A VERIFIED DISPOSABLE CLONE.
-- Execute only after restoring the W0-W2 seed in a fresh PostgreSQL 18 clone.
-- Intentionally no IF NOT EXISTS: duplicate or wrong clone must fail closed.
BEGIN;
-- Continuous family projection proof. A row is written only in the SAME
-- transaction as the private source_record and ALL of its typed children.
-- Durable source staging and successful typed projection are distinct facts.
-- This is a development-only receipt, not Accepted ingest/publication.
CREATE TABLE fi_recovery.projected_source_record (
    receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
    window_index integer NOT NULL CHECK (window_index >= 0),
    batch_index integer NOT NULL CHECK (batch_index >= 0),
    record_ordinal bigint NOT NULL CHECK (record_ordinal > 0),
    record_sha256 bytea NOT NULL CHECK (octet_length(record_sha256)=32),
    shadow_source_record_id bigint NOT NULL CHECK (shadow_source_record_id > 0),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (receipt_sha256,batch_index,record_ordinal),
    FOREIGN KEY (receipt_sha256,batch_index,record_ordinal)
      REFERENCES fi_recovery.pending_source_record
                 (receipt_sha256,batch_index,record_ordinal),
    FOREIGN KEY (receipt_sha256,window_index)
      REFERENCES fi_recovery.source_window (receipt_sha256,window_index)
);
CREATE INDEX projected_source_record_window_idx
ON fi_recovery.projected_source_record (receipt_sha256,window_index);
REVOKE ALL ON fi_recovery.projected_source_record FROM PUBLIC;
GRANT SELECT, INSERT ON fi_recovery.projected_source_record TO fi_ingest;
COMMIT;
