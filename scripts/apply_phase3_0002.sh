#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-/home/jwood/src/fi-phase3-work}"
MIGRATION="$ROOT/database/migrations/0002_phase3_ingest_attempt_journal.sql"

printf '%s\n' '===== APPLY PHASE 3 MIGRATION 0002 ====='

{
    printf '%s\n' 'SET ROLE fi_owner;'
    cat "$MIGRATION"
    printf '%s\n' 'RESET ROLE;'
} | sudo -iu postgres \
      psql \
        -X \
        -v ON_ERROR_STOP=1 \
        -d fi

printf '\n%s\n' '===== VERIFY ATTEMPT JOURNAL ====='

sudo -iu postgres \
  psql \
    -X \
    -d fi <<'SQL'
SELECT
    ingest_journal_id,
    attempt_id,
    event_sequence,
    outcome,
    stage
FROM fi.ingest_journal
ORDER BY ingest_journal_id;

SELECT
    indexname
FROM pg_indexes
WHERE schemaname = 'fi'
  AND tablename = 'ingest_journal'
ORDER BY indexname;
SQL
