#!/usr/bin/env bash
set -euo pipefail

SOURCE_ID="${1:-iss-fs-01.iss.local}"
GENERATION_ID="${2:-20260919T184530.695418700Z-ed9f36afc547f5f3}"

LOCK_LOG="/tmp/fi-phase3-lock.$$.log"
INGEST_LOG="/tmp/fi-phase3-crash.$$.log"
INGEST_PID_FILE="/tmp/fi-phase3-crash.$$.pid"

rm -f "$LOCK_LOG" "$INGEST_LOG" "$INGEST_PID_FILE"

printf '%s\n' '===== HOLD AUTHORITATIVE TABLE ====='

sudo -iu postgres \
  psql \
    -X \
    -v ON_ERROR_STOP=1 \
    -d fi \
    -c "BEGIN; LOCK TABLE fi.recorded_generation IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(8); ROLLBACK;" \
    >"$LOCK_LOG" 2>&1 &
LOCK_WRAPPER_PID=$!

sleep 1

printf '%s\n' '===== START INGEST ATTEMPT ====='

sudo -u fi-receiver \
  sh -c 'printf "%s\n" "$$" > "$1"; exec /tmp/fi-ingest -source "$2" -generation-id "$3"' \
  sh "$INGEST_PID_FILE" "$SOURCE_ID" "$GENERATION_ID" \
  >"$INGEST_LOG" 2>&1 &
SUDO_WRAPPER_PID=$!

for _ in $(seq 1 100); do
    if grep -q '^AttemptID:' "$INGEST_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.05
done

ATTEMPT_ID="$(awk '/^AttemptID:/ {print $2; exit}' "$INGEST_LOG")"

if [ -z "$ATTEMPT_ID" ]; then
    cat "$INGEST_LOG"
    echo 'ERROR: ingest attempt did not publish AttemptID before timeout' >&2
    wait "$LOCK_WRAPPER_PID" || true
    wait "$SUDO_WRAPPER_PID" || true
    false
fi

printf 'attempt_id: %s\n' "$ATTEMPT_ID"

INGEST_PID="$(cat "$INGEST_PID_FILE")"
printf 'fi-ingest pid: %s\n' "$INGEST_PID"

printf '%s\n' '===== FORCE PROCESS CRASH ====='
sudo kill -KILL "$INGEST_PID"
wait "$SUDO_WRAPPER_PID" || true

wait "$LOCK_WRAPPER_PID" || true

printf '\n%s\n' '===== PROCESS OUTPUT ====='
cat "$INGEST_LOG"

printf '\n%s\n' '===== CRASH JOURNAL STATE ====='

sudo -u fi-receiver \
  psql \
    -X \
    -h /run/postgresql \
    -U fi_ingest \
    -d fi \
    -v attempt_id="$ATTEMPT_ID" <<'SQL'
SELECT
    ingest_journal_id,
    attempt_id,
    event_sequence,
    outcome,
    stage,
    reason_code,
    records_seen,
    records_committed
FROM fi.ingest_journal
WHERE attempt_id = :'attempt_id'
ORDER BY event_sequence;
SQL

EVENT_COUNT="$(
  sudo -u fi-receiver \
    psql \
      -X \
      -h /run/postgresql \
      -U fi_ingest \
      -d fi \
      -At \
      -v attempt_id="$ATTEMPT_ID" <<'SQL'
SELECT count(*)
FROM fi.ingest_journal
WHERE attempt_id = :'attempt_id';
SQL
)"

START_COUNT="$(
  sudo -u fi-receiver \
    psql \
      -X \
      -h /run/postgresql \
      -U fi_ingest \
      -d fi \
      -At \
      -v attempt_id="$ATTEMPT_ID" <<'SQL'
SELECT count(*)
FROM fi.ingest_journal
WHERE attempt_id = :'attempt_id'
  AND event_sequence = 1
  AND outcome = 'Incomplete'
  AND stage = 'AttemptStarted';
SQL
)"

if [ "$EVENT_COUNT" != '1' ] || [ "$START_COUNT" != '1' ]; then
    echo 'ERROR: forced crash did not leave exactly one durable unmatched AttemptStarted event' >&2
    false
fi

printf '\n%s\n' 'PASS: forced crash left one durable Incomplete/AttemptStarted event and no terminal event.'

printf '\n%s\n' '===== RETRY SAME GENERATION ====='

sudo -u fi-receiver \
  /tmp/fi-ingest \
    -source "$SOURCE_ID" \
    -generation-id "$GENERATION_ID"

printf '\n%s\n' '===== OLD CRASH ATTEMPT STILL PRESENT ====='

sudo -u fi-receiver \
  psql \
    -X \
    -h /run/postgresql \
    -U fi_ingest \
    -d fi \
    -v attempt_id="$ATTEMPT_ID" <<'SQL'
SELECT
    attempt_id,
    event_sequence,
    outcome,
    stage,
    reason_code
FROM fi.ingest_journal
WHERE attempt_id = :'attempt_id'
ORDER BY event_sequence;
SQL
