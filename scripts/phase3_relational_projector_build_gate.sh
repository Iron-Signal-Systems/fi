#!/usr/bin/env bash
set -euo pipefail

ROOT=/home/jwood/src/fi-phase3-work
GO_ROOT="$ROOT/go"
BIN=/tmp/fi-ingest-relational

echo '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

echo
echo '===== FORMAT CHECK ====='
cd "$GO_ROOT"
gofmt -w \
  internal/recordingest/*.go \
  cmd/fi-ingest/main_linux.go

echo
echo '===== TARGETED TEST ====='
go test -count=1 ./internal/recordingest ./cmd/fi-ingest

echo
echo '===== TARGETED VET ====='
go vet ./internal/recordingest ./cmd/fi-ingest

echo
echo '===== FULL GO REGRESSION ====='
go test ./...

echo
echo '===== FULL GO VET ====='
go vet ./...

echo
echo '===== BUILD RELATIONAL FI-INGEST ====='
go build -o "$BIN" ./cmd/fi-ingest
ls -lh "$BIN"
sha256sum "$BIN"

echo
echo '===== DATABASE BOUNDARY ====='
sudo -u fi-receiver "$BIN" -database-check

echo
echo '===== DATABASE MUST REMAIN EMPTY ====='
sudo -iu postgres psql -X -At -d fi <<'SQL'
SELECT 'recorded_generation|source_batch|source_record|ingest_journal';
SELECT
    (SELECT count(*) FROM fi.recorded_generation)::text || '|' ||
    (SELECT count(*) FROM fi.source_batch)::text || '|' ||
    (SELECT count(*) FROM fi.source_record)::text || '|' ||
    (SELECT count(*) FROM fi.ingest_journal)::text;
SQL

COUNTS="$(sudo -iu postgres psql -X -At -d fi -c "SELECT (SELECT count(*) FROM fi.recorded_generation)::text || '|' || (SELECT count(*) FROM fi.source_batch)::text || '|' || (SELECT count(*) FROM fi.source_record)::text || '|' || (SELECT count(*) FROM fi.ingest_journal)::text;")"
if [[ "$COUNTS" != '0|0|0|0' ]]; then
  echo "FAIL: relational projector build gate changed authoritative PostgreSQL state: $COUNTS" >&2
  false
fi

echo
echo 'PASS: typed relational projector builds, all Go tests/vet pass, generation ingest is enabled, and PostgreSQL remains empty.'
