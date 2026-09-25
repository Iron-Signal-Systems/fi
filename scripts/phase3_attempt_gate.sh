#!/usr/bin/env bash
set -euo pipefail

SOURCE_ID="${1:-iss-fs-01.iss.local}"
GENERATION_ID="${2:-20260919T184530.695418700Z-ed9f36afc547f5f3}"
MISSING_GENERATION_ID="phase3-intentional-missing-generation-test"

read_counts() {
    sudo -u fi-receiver \
      psql \
        -X \
        -h /run/postgresql \
        -U fi_ingest \
        -d fi \
        -At <<'SQL'
SELECT count(*) FROM fi.recorded_generation;
SELECT count(*) FROM fi.source_batch;
SELECT count(*) FROM fi.source_record;
SQL
}

mapfile -t BEFORE < <(read_counts)

printf '%s\n' '===== HARDENED REPLAY ====='

sudo -u fi-receiver \
  /tmp/fi-ingest \
    -source "$SOURCE_ID" \
    -generation-id "$GENERATION_ID"

printf '\n%s\n' '===== DURABLE FAILED ATTEMPT ====='

if sudo -u fi-receiver \
  /tmp/fi-ingest \
    -source "$SOURCE_ID" \
    -generation-id "$MISSING_GENERATION_ID"; then
    echo 'ERROR: missing generation unexpectedly succeeded' >&2
    false
fi

printf '\n%s\n' '===== FORCED CRASH / RETRY ====='

"$(dirname "$0")/phase3_attempt_crash_test.sh" \
  "$SOURCE_ID" \
  "$GENERATION_ID"

mapfile -t AFTER < <(read_counts)

if [ "${BEFORE[0]}" != "${AFTER[0]}" ] || \
   [ "${BEFORE[1]}" != "${AFTER[1]}" ] || \
   [ "${BEFORE[2]}" != "${AFTER[2]}" ]; then
    echo 'ERROR: Phase 3 attempt tests changed authoritative row counts' >&2
    printf 'before: generations=%s batches=%s records=%s\n' \
      "${BEFORE[0]}" "${BEFORE[1]}" "${BEFORE[2]}" >&2
    printf 'after:  generations=%s batches=%s records=%s\n' \
      "${AFTER[0]}" "${AFTER[1]}" "${AFTER[2]}" >&2
    false
fi

printf '\n%s\n' '===== ATTEMPT JOURNAL HISTORY ====='

sudo -u fi-receiver \
  psql \
    -X \
    -h /run/postgresql \
    -U fi_ingest \
    -d fi <<'SQL'
SELECT
    ingest_journal_id,
    attempt_id,
    event_sequence,
    source_id,
    generation_id,
    outcome,
    stage,
    reason_code,
    records_seen,
    records_committed
FROM fi.ingest_journal
ORDER BY ingest_journal_id;
SQL

printf '\n%s\n' \
  'PASS: attempt start, terminal journaling, forced-crash visibility, retry preservation, and authoritative row-count stability passed.'
