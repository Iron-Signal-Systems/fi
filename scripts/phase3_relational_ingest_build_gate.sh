#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_ROOT="${ROOT}/go"

printf '%s\n' '===== REFRESH SUDO CREDENTIALS ====='
sudo -v

printf '\n%s\n' '===== RELATIONAL INGEST TARGETED TEST / VET ====='
cd "${GO_ROOT}"
go test -v ./internal/recordingest
go vet ./internal/recordingest

printf '\n%s\n' '===== RELATIONAL FI-INGEST BUILD ====='
go build -o /tmp/fi-ingest-relational ./cmd/fi-ingest
ls -lh /tmp/fi-ingest-relational
sha256sum /tmp/fi-ingest-relational

printf '\n%s\n' '===== FULL GO REGRESSION ====='
go test ./...
go vet ./...

printf '\n%s\n' '===== DATABASE BOUNDARY ====='
sudo -u fi-receiver /tmp/fi-ingest-relational -database-check

printf '\n%s\n' '===== DATABASE MUST REMAIN EMPTY ====='
COUNTS="$(
    sudo -u fi-receiver \
        psql \
            -X \
            -h /run/postgresql \
            -U fi_ingest \
            -d fi \
            -At \
            -F '|' \
            -c "
SELECT
    (SELECT count(*) FROM fi.recorded_generation),
    (SELECT count(*) FROM fi.source_batch),
    (SELECT count(*) FROM fi.source_record),
    (SELECT count(*) FROM fi.ingest_journal);
"
)"

printf 'recorded_generation|source_batch|source_record|ingest_journal\n'
printf '%s\n' "${COUNTS}"

if [[ "${COUNTS}" != '0|0|0|0' ]]; then
    printf '%s\n' 'FAIL: relational-ingest build gate changed or found non-empty Phase 3 authoritative state.' >&2
    false
fi

printf '\n%s\n' 'PASS: replacement relational fi-ingest builds, all Go tests/vet pass, the 49-table append-only PostgreSQL boundary is verified, and generation ingest remains intentionally disabled.'
