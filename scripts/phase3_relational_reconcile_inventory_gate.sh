#!/usr/bin/env bash
set -euo pipefail

ROOT='/home/jwood/src/fi-phase3-work'
GO_ROOT="$ROOT/go"
BINARY='/tmp/fi-ingest-reconcile-relational'
SOURCE_ID='iss-fs-01.iss.local'

cd "$GO_ROOT"

echo '===== TARGETED RELATIONAL RECONCILE / INVENTORY TESTS ====='
go test ./internal/recordingest
go vet ./internal/recordingest

echo
echo '===== BUILD READ-ONLY RELATIONAL RECONCILE / INVENTORY ====='
rm -f "$BINARY"
go build -o "$BINARY" ./cmd/fi-ingest-reconcile
sha256sum "$BINARY"

echo
echo '===== FULL GO TEST ====='
go test ./...

echo
echo '===== FULL GO VET ====='
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
SELECT pg_database_size('fi');
SQL
}

BEFORE_TEXT="$(read_state)"
mapfile -t BEFORE <<<"$BEFORE_TEXT"
if [[ ${#BEFORE[@]} -ne 5 ]]; then
    echo 'ERROR: failed to capture pre-gate authoritative state' >&2
    false
fi

echo
echo '===== READ-ONLY RELATIONAL RECONCILE PLAN ====='
PLAN_OUTPUT="$(sudo -u fi-receiver "$BINARY" -plan -source "$SOURCE_ID")"
printf '%s\n' "$PLAN_OUTPUT"

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
    echo 'ERROR: reconcile plan did not recognize the proven authoritative generation' >&2
    false
fi
if (( CONFLICT != 0 )); then
    echo 'ERROR: reconcile plan found recorder/database conflict candidates' >&2
    false
fi

if (( PENDING > 0 )); then
    echo
    echo '===== ONE-PENDING READ-ONLY CUSTODY INVENTORY ====='
    INVENTORY_OUTPUT="$(sudo -u fi-receiver "$BINARY" \
      -inventory \
      -source "$SOURCE_ID" \
      -max-inspect 1 \
      -stop-when-covered=false)"
    printf '%s\n' "$INVENTORY_OUTPUT"

    INSPECTED="$(printf '%s\n' "$INVENTORY_OUTPUT" | awk '/^InspectedPending:/ {print $2}')"
    WRITES="$(printf '%s\n' "$INVENTORY_OUTPUT" | awk '/^DatabaseWrites:/ {print $2}')"
    if [[ "$INSPECTED" != '1' || "$WRITES" != '0' ]]; then
        echo 'ERROR: bounded inventory did not inspect exactly one pending generation read-only' >&2
        false
    fi
else
    echo
    echo '===== ONE-PENDING READ-ONLY CUSTODY INVENTORY ====='
    echo 'SKIP: no pending recorder generations exist.'
fi

AFTER_TEXT="$(read_state)"
mapfile -t AFTER <<<"$AFTER_TEXT"
if [[ ${#AFTER[@]} -ne 5 ]]; then
    echo 'ERROR: failed to capture post-gate authoritative state' >&2
    false
fi

if [[ "${BEFORE[*]}" != "${AFTER[*]}" ]]; then
    echo 'ERROR: read-only relational reconcile/inventory gate changed PostgreSQL state' >&2
    printf 'before: %s\n' "${BEFORE[*]}" >&2
    printf 'after:  %s\n' "${AFTER[*]}" >&2
    false
fi

echo
echo "PASS: relational receipt plan and bounded custody inventory are read-only; discovered $DISCOVERED receipt(s), recognized $ACCEPTED authoritative generation(s), found $PENDING pending, $CONFLICT conflicts, and PostgreSQL/journal/database bytes remained unchanged."
