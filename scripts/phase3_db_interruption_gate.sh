#!/usr/bin/env bash
set -euo pipefail

SOURCE_ID="${1:-iss-fs-01.iss.local}"
GENERATION_ID="${2:-20260919T184530.695418700Z-ed9f36afc547f5f3}"

INGEST_APPLICATION_NAME="fi-phase3-db-interruption-probe"
LOCK_APPLICATION_NAME="fi-phase3-db-interruption-lock"

INGEST_LOG="/tmp/fi-phase3-db-interruption-ingest.$$.log"
LOCK_LOG="/tmp/fi-phase3-db-interruption-lock.$$.log"
RETRY_LOG="/tmp/fi-phase3-db-interruption-retry.$$.log"

LOCK_WRAPPER_PID=""
INGEST_WRAPPER_PID=""
ATTEMPT_ID=""

cleanup() {
    sudo -iu postgres \
      psql \
        -X \
        -At \
        -d fi \
        -v ingest_app="$INGEST_APPLICATION_NAME" \
        -v lock_app="$LOCK_APPLICATION_NAME" <<'SQL' >/dev/null 2>&1 || true
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND application_name IN (:'ingest_app', :'lock_app');
SQL

    if [ -n "$INGEST_WRAPPER_PID" ]; then
        wait "$INGEST_WRAPPER_PID" 2>/dev/null || true
    fi

    if [ -n "$LOCK_WRAPPER_PID" ]; then
        wait "$LOCK_WRAPPER_PID" 2>/dev/null || true
    fi

    rm -f "$INGEST_LOG" "$LOCK_LOG" "$RETRY_LOG"
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    false
}

read_authoritative_state() {
    sudo -u fi-receiver \
      psql \
        -X \
        -h /run/postgresql \
        -U fi_ingest \
        -d fi \
        -At \
        -v ON_ERROR_STOP=1 <<'SQL'
SELECT
    (SELECT count(*) FROM fi.recorded_generation)::text || '|' ||
    (SELECT count(*) FROM fi.source_batch)::text || '|' ||
    (SELECT count(*) FROM fi.source_record)::text || '|' ||
    (
        SELECT COALESCE(sum(record_bytes), 0)
        FROM fi.source_record
    )::text;
SQL
}

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

if pgrep -af 'fi-ingest-worker|fi-live-relational-ingest' >/dev/null 2>&1; then
    fail 'a live relational ingest worker appears to be running; use a controlled quiescent window for this failure gate'
fi

if [ ! -x /tmp/fi-ingest ]; then
    fail '/tmp/fi-ingest is missing or not executable'
fi

printf '\n%s\n' '===== VERIFY KNOWN ACCEPTED GENERATION ====='

ACCEPTED_COUNT="$(
    sudo -u fi-receiver \
      psql \
        -X \
        -h /run/postgresql \
        -U fi_ingest \
        -d fi \
        -At \
        -v ON_ERROR_STOP=1 \
        -v source_id="$SOURCE_ID" \
        -v generation_id="$GENERATION_ID" <<'SQL'
SELECT count(*)
FROM fi.recorded_generation
WHERE source_id = :'source_id'
  AND generation_id = :'generation_id';
SQL
)"

if [ "$ACCEPTED_COUNT" != '1' ]; then
    fail "expected exactly one accepted generation for source=$SOURCE_ID generation=$GENERATION_ID; found $ACCEPTED_COUNT"
fi

printf '\n%s\n' '===== RELATIONAL AUTHORITY BEFORE INTERRUPTION ====='

BEFORE="$(read_authoritative_state)"
printf 'recorded_generation|source_batch|source_record|record_bytes = %s\n' "$BEFORE"

printf '\n%s\n' '===== HOLD RECORDED GENERATION TABLE ====='

sudo -iu postgres \
  env PGAPPNAME="$LOCK_APPLICATION_NAME" \
  psql \
    -X \
    -v ON_ERROR_STOP=1 \
    -d fi \
    -c "BEGIN; LOCK TABLE fi.recorded_generation IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(60); ROLLBACK;" \
    >"$LOCK_LOG" 2>&1 &
LOCK_WRAPPER_PID=$!

LOCK_READY=''
for _ in $(seq 1 100); do
    LOCK_READY="$(
      sudo -iu postgres \
        psql \
          -X \
          -At \
          -d fi \
          -v app="$LOCK_APPLICATION_NAME" <<'SQL'
SELECT count(*)
FROM pg_stat_activity
WHERE application_name = :'app'
  AND state = 'active';
SQL
    )"

    if [ "$LOCK_READY" = '1' ]; then
        break
    fi

    sleep 0.05
done

if [ "$LOCK_READY" != '1' ]; then
    cat "$LOCK_LOG"
    fail 'recorded-generation lock session did not become active'
fi

printf '%s\n' '===== START RELATIONAL INGEST ATTEMPT ====='

INGEST_CONNECTION="host=/run/postgresql dbname=fi user=fi_ingest sslmode=disable application_name=$INGEST_APPLICATION_NAME"

sudo -u fi-receiver \
  /tmp/fi-ingest \
    -postgres "$INGEST_CONNECTION" \
    -source "$SOURCE_ID" \
    -generation-id "$GENERATION_ID" \
    >"$INGEST_LOG" 2>&1 &
INGEST_WRAPPER_PID=$!

for _ in $(seq 1 300); do
    if grep -q '^AttemptID:' "$INGEST_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.05
done

ATTEMPT_ID="$(awk '/^AttemptID:/ {print $2; exit}' "$INGEST_LOG")"

if [ -z "$ATTEMPT_ID" ]; then
    cat "$INGEST_LOG"
    fail 'ingest attempt did not publish AttemptID before timeout'
fi

printf 'attempt_id: %s\n' "$ATTEMPT_ID"

printf '%s\n' '===== WAIT FOR DATABASE LOCK BLOCK ====='

TARGET_PID=''
TARGET_WAIT=''

for _ in $(seq 1 400); do
    TARGET_STATE="$(
      sudo -iu postgres \
        psql \
          -X \
          -At \
          -F '|' \
          -d fi \
          -v app="$INGEST_APPLICATION_NAME" <<'SQL'
SELECT pid, COALESCE(wait_event_type, '')
FROM pg_stat_activity
WHERE application_name = :'app'
ORDER BY pid
LIMIT 1;
SQL
    )"

    if [ -n "$TARGET_STATE" ]; then
        IFS='|' read -r TARGET_PID TARGET_WAIT <<<"$TARGET_STATE"
        if [ "$TARGET_WAIT" = 'Lock' ]; then
            break
        fi
    fi

    sleep 0.05
done

if [ -z "$TARGET_PID" ] || [ "$TARGET_WAIT" != 'Lock' ]; then
    cat "$INGEST_LOG"
    fail 'fi-ingest PostgreSQL backend did not reach the expected blocked relational transaction'
fi

printf 'postgres backend pid: %s\n' "$TARGET_PID"
printf 'wait_event_type:     %s\n' "$TARGET_WAIT"

printf '%s\n' '===== TERMINATE FI-INGEST DATABASE BACKEND ====='

TERMINATED="$(
  sudo -iu postgres \
    psql \
      -X \
      -At \
      -d fi \
      -v app="$INGEST_APPLICATION_NAME" <<'SQL'
SELECT COALESCE(bool_and(pg_terminate_backend(pid)), false)
FROM pg_stat_activity
WHERE application_name = :'app';
SQL
)"

if [ "$TERMINATED" != 't' ]; then
    fail 'PostgreSQL did not confirm termination of the fi-ingest backend'
fi

printf '%s\n' '===== RELEASE TEST LOCK ====='

sudo -iu postgres \
  psql \
    -X \
    -At \
    -d fi \
    -v app="$LOCK_APPLICATION_NAME" <<'SQL' >/dev/null
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE application_name = :'app';
SQL

INGEST_STATUS=0
wait "$INGEST_WRAPPER_PID" || INGEST_STATUS=$?
INGEST_WRAPPER_PID=''

wait "$LOCK_WRAPPER_PID" 2>/dev/null || true
LOCK_WRAPPER_PID=''

printf '\n%s\n' '===== INTERRUPTED PROCESS OUTPUT ====='
cat "$INGEST_LOG"

if [ "$INGEST_STATUS" -eq 0 ]; then
    fail 'database-interrupted fi-ingest unexpectedly succeeded'
fi

printf '\n%s\n' '===== INTERRUPTED ATTEMPT JOURNAL ====='

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

EVENT_STATE="$(
  sudo -u fi-receiver \
    psql \
      -X \
      -h /run/postgresql \
      -U fi_ingest \
      -d fi \
      -At \
      -F '|' \
      -v attempt_id="$ATTEMPT_ID" <<'SQL'
SELECT
    count(*)::text || '|' ||
    count(*) FILTER (
        WHERE event_sequence = 1
          AND outcome = 'Incomplete'
          AND stage = 'AttemptStarted'
          AND reason_code = 'ATTEMPT_STARTED'
    )::text || '|' ||
    count(*) FILTER (WHERE event_sequence > 1)::text
FROM fi.ingest_journal
WHERE attempt_id = :'attempt_id';
SQL
)"

IFS='|' read -r EVENT_COUNT START_COUNT TERMINAL_COUNT <<<"$EVENT_STATE"

if [ "$EVENT_COUNT" != '1' ] || \
   [ "$START_COUNT" != '1' ] || \
   [ "$TERMINAL_COUNT" != '0' ]; then
    fail 'database interruption did not leave exactly one durable unmatched AttemptStarted event'
fi

printf '\n%s\n' '===== RELATIONAL AUTHORITY AFTER INTERRUPTION ====='

AFTER_INTERRUPTION="$(read_authoritative_state)"
printf 'recorded_generation|source_batch|source_record|record_bytes = %s\n' "$AFTER_INTERRUPTION"

if [ "$AFTER_INTERRUPTION" != "$BEFORE" ]; then
    fail 'interrupted relational transaction changed authoritative database state'
fi

printf '\n%s\n' '===== RETRY SAME ACCEPTED GENERATION ====='

sudo -u fi-receiver \
  /tmp/fi-ingest \
    -source "$SOURCE_ID" \
    -generation-id "$GENERATION_ID" \
    | tee "$RETRY_LOG"

if ! grep -q '^Outcome:[[:space:]]*AlreadyAccepted$' "$RETRY_LOG"; then
    fail 'retry after database interruption did not return AlreadyAccepted'
fi

printf '\n%s\n' '===== ORIGINAL INTERRUPTED ATTEMPT STILL PRESENT ====='

OLD_EVENT_COUNT="$(
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

if [ "$OLD_EVENT_COUNT" != '1' ]; then
    fail 'retry altered the interrupted attempt history'
fi

printf '\n%s\n' '===== RELATIONAL AUTHORITY AFTER RETRY ====='

AFTER_RETRY="$(read_authoritative_state)"
printf 'recorded_generation|source_batch|source_record|record_bytes = %s\n' "$AFTER_RETRY"

if [ "$AFTER_RETRY" != "$BEFORE" ]; then
    fail 'retry after database interruption changed known-good relational authority'
fi

printf '\n%s\n' \
  'PASS: database connection loss while the relational transaction was blocked left durable unmatched-attempt history, committed no partial relational authority, and retry remained duplicate-safe.'
