-- Copyright (c) 2026 John Joseph Wood. All rights reserved.
-- Use of this source code is governed by the File Intelligence (FI)
-- Source Review License, Version 1.0, found in the repository root LICENSE file.

BEGIN;

ALTER TABLE fi.ingest_journal
    ADD COLUMN attempt_id text,
    ADD COLUMN event_sequence integer;

-- Preserve pre-0002 journal history. Each existing row becomes a complete
-- single-event legacy attempt; no prior event is rewritten or discarded.
UPDATE fi.ingest_journal
SET
    attempt_id = 'legacy-' || ingest_journal_id::text,
    event_sequence = 1
WHERE attempt_id IS NULL
   OR event_sequence IS NULL;

ALTER TABLE fi.ingest_journal
    ALTER COLUMN attempt_id SET NOT NULL,
    ALTER COLUMN event_sequence SET NOT NULL;

ALTER TABLE fi.ingest_journal
    ADD CONSTRAINT ingest_journal_attempt_id_nonempty_ck
        CHECK (btrim(attempt_id) <> ''),
    ADD CONSTRAINT ingest_journal_event_sequence_ck
        CHECK (event_sequence > 0);

CREATE UNIQUE INDEX ingest_journal_attempt_event_uq
    ON fi.ingest_journal (attempt_id, event_sequence);

CREATE INDEX ingest_journal_attempt_idx
    ON fi.ingest_journal (attempt_id, occurred_at);

COMMENT ON COLUMN fi.ingest_journal.attempt_id IS
    'Opaque identity shared by every immutable journal event from one ingest attempt.';

COMMENT ON COLUMN fi.ingest_journal.event_sequence IS
    'Monotonic event order within one ingest attempt. Phase 3 currently writes AttemptStarted as 1 and terminal outcome as 2.';

COMMIT;
