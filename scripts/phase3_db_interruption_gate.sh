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

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

if [ ! -x /tmp/fi-ingest ]; then
    echo 'ERROR: /tmp/fi-ingest is missing or not executable' >&2
    false
fi

printf '\n%s\n' '===== AUTHORITATIVE STATE BEFORE INTERRUPTION ====='

BEFORE="$({
  sudo -u fi-receiver \
    psql \
      -X \
      -h /run/postgresql \
      -U fi_ingest \
      -d fi \
      -At <<'SQL'
SELECT
    (SELECT count(*) FROM fi.recorded_generation)::text || '|' ||
    (SELECT count(*) FROM fi.source_batch)::text || '|' ||
    (SELECT count(*) FROM fi.source_record)::text || '|' ||
    (
        SELECT COALESCE(sum(octet_length(raw_record_bytes)), 0)
        FROM fi.source_record
    )::text;
SQL
} )"

printf 'recorded_generation|source_batch|source_record|raw_bytes = %s\n' "$BEFORE"

printf '\n%s\n' '===== HOLD AUTHORITATIVE TABLE ====='

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
    LOCK_READY="$({
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
    } )"

    if [ "$LOCK_READY" = '1' ]; then
        break
    fi

    sleep 0.05
done

if [ "$LOCK_READY" != '1' ]; then
    cat "$LOCK_LOG"
    echo 'ERROR: authoritative-table lock session did not become active' >&2
    false
fi

printf '%s\n' '===== START INGEST ATTEMPT ====='

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
    echo 'ERROR: ingest attempt did not publish AttemptID before timeout' >&2
    false
fi

printf 'attempt_id: %s\n' "$ATTEMPT_ID"

printf '%s\n' '===== WAIT FOR DATABASE LOCK BLOCK ====='

TARGET_PID=''
TARGET_WAIT=''

for _ in $(seq 1 400); do
    TARGET_STATE="$({
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
    } )"

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
    echo 'ERROR: fi-ingest PostgreSQL backend did not reach the expected blocked authoritative operation' >&2
    false
fi

printf 'postgres backend pid: %s\n' "$TARGET_PID"
printf 'wait_event_type:     %s\n' "$TARGET_WAIT"

printf '%s\n' '===== TERMINATE FI-INGEST DATABASE BACKEND ====='

TERMINATED="$({
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
} )"

if [ "$TERMINATED" != 't' ]; then
    echo 'ERROR: PostgreSQL did not confirm termination of the fi-ingest backend' >&2
    false
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
    echo 'ERROR: database-interrupted fi-ingest unexpectedly succeeded' >&2
    false
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

EVENT_STATE="$({
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
} )"

IFS='|' read -r EVENT_COUNT START_COUNT TERMINAL_COUNT <<<"$EVENT_STATE"

if [ "$EVENT_COUNT" != '1' ] || \
   [ "$START_COUNT" != '1' ] || \
   [ "$TERMINAL_COUNT" != '0' ]; then
    echo 'ERROR: database interruption did not leave exactly one durable unmatched AttemptStarted event' >&2
    false
fi

printf '\n%s\n' '===== AUTHORITATIVE STATE AFTER INTERRUPTION ====='

AFTER_INTERRUPTION="$({
  sudo -u fi-receiver \
    psql \
      -X \
      -h /run/postgresql \
      -U fi_ingest \
      -d fi \
      -At <<'SQL'
SELECT
    (SELECT count(*) FROM fi.recorded_generation)::text || '|' ||
    (SELECT count(*) FROM fi.source_batch)::text || '|' ||
    (SELECT count(*) FROM fi.source_record)::text || '|' ||
    (
        SELECT COALESCE(sum(octet_length(raw_record_bytes)), 0)
        FROM fi.source_record
    )::text;
SQL
} )"

printf 'recorded_generation|source_batch|source_record|raw_bytes = %s\n' "$AFTER_INTERRUPTION"

if [ "$AFTER_INTERRUPTION" != "$BEFORE" ]; then
    echo 'ERROR: interrupted authoritative transaction changed authoritative database state' >&2
    false
fi

printf '\n%s\n' '===== RETRY SAME GENERATION ====='

sudo -u fi-receiver \
  /tmp/fi-ingest \
    -source "$SOURCE_ID" \
    -generation-id "$GENERATION_ID" \
    | tee "$RETRY_LOG"

if ! grep -q '^Outcome:[[:space:]]*AlreadyAccepted$' "$RETRY_LOG"; then
    echo 'ERROR: retry after database interruption did not return AlreadyAccepted' >&2
    false
fi

printf '\n%s\n' '===== OLD INTERRUPTED ATTEMPT STILL PRESENT ====='

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

OLD_EVENT_COUNT="$({
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
} )"

if [ "$OLD_EVENT_COUNT" != '1' ]; then
    echo 'ERROR: retry altered the interrupted attempt history' >&2
    false
fi

printf '\n%s\n' '===== AUTHORITATIVE STATE AFTER RETRY ====='

AFTER_RETRY="$({
  sudo -u fi-receiver \
    psql \
      -X \
      -h /run/postgresql \
      -U fi_ingest \
      -d fi \
      -At <<'SQL'
SELECT
    (SELECT count(*) FROM fi.recorded_generation)::text || '|' ||
    (SELECT count(*) FROM fi.source_batch)::text || '|' ||
    (SELECT count(*) FROM fi.source_record)::text || '|' ||
    (
        SELECT COALESCE(sum(octet_length(raw_record_bytes)), 0)
        FROM fi.source_record
    )::text;
SQL
} )"

printf 'recorded_generation|source_batch|source_record|raw_bytes = %s\n' "$AFTER_RETRY"

if [ "$AFTER_RETRY" != "$BEFORE" ]; then
    echo 'ERROR: retry after database interruption changed the known-good authoritative state' >&2
    false
fi

printf '\n%s\n' 'PASS: database connection loss during the authoritative transaction left durable incomplete attempt history, committed no partial authoritative state, and retry was safe.'
