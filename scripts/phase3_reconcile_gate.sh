#!/usr/bin/env bash
set -euo pipefail

ROOT='/home/jwood/src/fi-phase3-work'
GO_ROOT="$ROOT/go"
BINARY='/tmp/fi-ingest-reconcile'
SOURCE_ID='iss-fs-01.iss.local'

cd "$GO_ROOT"

echo '===== TARGETED RECONCILE TESTS ====='
go test ./internal/recordingest
go vet ./internal/recordingest

echo
echo '===== BUILD RECONCILE WORKER ====='
rm -f "$BINARY"
go build -o "$BINARY" ./cmd/fi-ingest-reconcile
sha256sum "$BINARY"

echo
echo '===== FULL REGRESSION ====='
go test ./...
go vet ./...

echo
echo '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

read_state() {
    sudo -u fi-receiver \
      psql \
        -X \
        -h /run/postgresql \
        -U fi_ingest \
        -d fi \
        -At \
        -v ON_ERROR_STOP=1 <<'SQL'
SELECT count(*) FROM fi.recorded_generation;
SELECT count(*) FROM fi.source_batch;
SELECT count(*) FROM fi.source_record;
SELECT count(*) FROM fi.ingest_journal;
SQL
}

BEFORE_TEXT="$(read_state)"
mapfile -t BEFORE <<<"$BEFORE_TEXT"

if [[ ${#BEFORE[@]} -ne 4 ]]; then
    echo 'ERROR: failed to capture pre-plan authoritative state' >&2
    false
fi

echo
echo '===== READ-ONLY RECONCILE PLAN ====='
PLAN_OUTPUT="$(sudo -u fi-receiver "$BINARY" -plan -source "$SOURCE_ID")"
printf '%s\n' "$PLAN_OUTPUT"

AFTER_TEXT="$(read_state)"
mapfile -t AFTER <<<"$AFTER_TEXT"

if [[ ${#AFTER[@]} -ne 4 ]]; then
    echo 'ERROR: failed to capture post-plan authoritative state' >&2
    false
fi

if [[ "${BEFORE[*]}" != "${AFTER[*]}" ]]; then
    echo 'ERROR: read-only reconcile plan changed PostgreSQL state' >&2
    printf 'before: %s\n' "${BEFORE[*]}" >&2
    printf 'after:  %s\n' "${AFTER[*]}" >&2
    false
fi

DISCOVERED="$(printf '%s\n' "$PLAN_OUTPUT" | awk '/^ReceiptsDiscovered:/ {print $2}')"
ACCEPTED="$(printf '%s\n' "$PLAN_OUTPUT" | awk '/^AlreadyAccepted:/ {print $2}')"
PENDING="$(printf '%s\n' "$PLAN_OUTPUT" | awk '/^Pending:/ {print $2}')"
CONFLICT="$(printf '%s\n' "$PLAN_OUTPUT" | awk '/^Conflict:/ {print $2}')"

for value in "$DISCOVERED" "$ACCEPTED" "$PENDING" "$CONFLICT"; do
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo 'ERROR: reconcile plan did not return numeric summary values' >&2
        false
    fi
done

if (( DISCOVERED < 1 )); then
    echo 'ERROR: reconcile plan discovered no immutable recorder receipts' >&2
    false
fi

if (( ACCEPTED < 1 )); then
    echo 'ERROR: reconcile plan did not recognize the known-good authoritative generation' >&2
    false
fi

echo
echo "PASS: read-only reconciliation discovered $DISCOVERED receipt(s), skipped $ACCEPTED already-authoritative generation(s), found $PENDING pending and $CONFLICT conflict candidate(s), and wrote no database or journal rows."
