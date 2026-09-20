#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_ROOT="$ROOT/go"
BIN="/tmp/fi-ingest-relational"

echo '===== FORMAT CHECK ====='
cd "$GO_ROOT"

FORMAT_DIFF="$(
    gofmt -l \
      internal/recordingest/*.go \
      cmd/fi-ingest/main_linux.go \
      cmd/fi-ingest-reconcile/main_linux.go \
      cmd/fi-ingest-worker/main_linux.go \
      cmd/fi-ingest-worker/main_linux_test.go
)"

if [ -n "$FORMAT_DIFF" ]; then
    printf '%s\n' "$FORMAT_DIFF"
    echo 'ERROR: Phase 3 Go source requires gofmt' >&2
    false
fi

echo
echo '===== TARGETED TEST ====='
go test -count=1 \
  ./internal/recordingest \
  ./cmd/fi-ingest \
  ./cmd/fi-ingest-reconcile \
  ./cmd/fi-ingest-worker

echo
echo '===== TARGETED VET ====='
go vet \
  ./internal/recordingest \
  ./cmd/fi-ingest \
  ./cmd/fi-ingest-reconcile \
  ./cmd/fi-ingest-worker

echo
echo '===== FULL GO REGRESSION ====='
go test ./...

echo
echo '===== FULL GO VET ====='
go vet ./...

echo
echo '===== BUILD RELATIONAL COMMANDS ====='
rm -f \
  "$BIN" \
  /tmp/fi-ingest-reconcile-relational \
  /tmp/fi-ingest-worker-relational

go build -o "$BIN" ./cmd/fi-ingest
go build -o /tmp/fi-ingest-reconcile-relational ./cmd/fi-ingest-reconcile
go build -o /tmp/fi-ingest-worker-relational ./cmd/fi-ingest-worker

sha256sum \
  "$BIN" \
  /tmp/fi-ingest-reconcile-relational \
  /tmp/fi-ingest-worker-relational

echo
echo '===== DATABASE BOUNDARY ====='
sudo -v

BEFORE="$(
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
    (SELECT count(*) FROM fi.ingest_journal)::text;
SQL
)"

sudo -u fi-receiver "$BIN" -database-check

AFTER="$(
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
    (SELECT count(*) FROM fi.ingest_journal)::text;
SQL
)"

printf 'before: %s\n' "$BEFORE"
printf 'after:  %s\n' "$AFTER"

if [ "$BEFORE" != "$AFTER" ]; then
    echo 'ERROR: database-check changed relational or journal row counts' >&2
    false
fi

echo
echo 'PASS: current relational ingester, reconcile command, and live Go worker build/test/vet cleanly; database-check is read-only and validates the active 49-table append-only PostgreSQL boundary.'
