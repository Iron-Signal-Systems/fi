# FI C220 H16/W512 — two-worker ten-window baseline

DEVELOPMENT ONLY. Staged exclusively on
`experiment/fi-candidate-a-w512-2g-20261113`. No change to main.

## Required baseline

- Historical comparison: 997,434 records in 312.630 seconds =
  approximately 3,190 records/s (old fi-backend-b, two W512 windows).
- C220 target: **ten W512 windows**, 2 preparation workers, 4 in-flight
  credits, 1 PostgreSQL writer, K32=32768, P3/F3 buffers.
- W512 caps: 524,288 original records or 2 GiB signed source data,
  never splitting an authenticated batch.
- Authenticated source: iss-fs-22a.iss.local /
  20261030T000032.061323100Z-3e38b2210771462c,
  8,399 original batches / 15,140,785 source records.
- No live FI-ingest startup. No authoritative SoR connection or
  Accepted/publication writes. Do not restart live ingestion.

## Stage 1: authenticated private cache and window proof

The Go command in `go/cmd/fi-h16-private-cache` uses the original
`LoadRecordedGenerationSelectedWindowsCached` authenticated FIGT reader.
It verifies the whole transfer and immutable receipt before publishing a
receipt-bound cache marker, then checks the complete W512 descriptor plan,
including exact first-window digest and records.

**On fi-dev (ssh jwood@192.168.20.23):**

```sh
git clone --single-branch -b experiment/fi-candidate-a-w512-2g-20261113 \
  https://github.com/Iron-Signal-Systems/fi.git \
  /home/jwood/fi-w512-c220-stage
cd /home/jwood/fi-w512-c220-stage/go
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 test \
  ./internal/recordingest -run 'TestBacklogVerifiedCache|TestBacklogWindowsW512TwoGiB' -count=1
GOTOOLCHAIN=local GOFLAGS=-mod=readonly go127 build -trimpath \
  -o /home/jwood/fi-w512-c220-stage/fi-private-cache \
  ./cmd/fi-h16-private-cache
```

The restored `fi-deferred-experiment` worktree contains uncommitted
changes: do not pull/reset/clean/switch it.

**On root@c220:** Review and run the exact checked-out script:

```sh
runner=/fast/jails/roots/fi-dev/home/jwood/fi-w512-c220-stage/go/cmd/fi-backlog-recover/run_private_w512_c220_cache_host.sh
sh -n "$runner" &&
sh "$runner" preflight
```

After preflight passes, run `sh "$runner" prepare`.
The preparation script creates read-only nullfs mounts for historical
custody/receipts and configuration inside fi-dev, writes ONLY a new private
cache, and does not invoke PostgreSQL. It will stop on any existing target
rather than cover jail content.

The script does not persist nullfs mounts into jail.conf. A jail restart
removes these transient mounts; inspect before changing any persistent
jail configuration. Source files remain untouched.

## Stage 2 — NOT YET AUTHORIZED BY STAGE 1

After verified-cache and historical descriptor checks pass, build a
**fresh private W512 PostgreSQL 18.6 seed** with W0=493,478 records
and descriptor SHA-256
`ff58478b40ca35f1f6cc5e52aa0300de6371ed58243c41f34e4f20ad6d61a319`.
Then run a disposable 10-window **two-worker** (NOT sixteen-worker)
Candidate A variant using four in-flight credits and one SQL writer.

The original historical ten-window host runner is 16-worker-only,
requires absent old-VM private seed and evidence paths, and MUST NOT be
executed unchanged. The two-worker ten-window runner still needs
C220-safe adaptation and test gates. No readiness claim until completed.

## Security guards

- No live fi_ingest_worker; check both service and process table.
- No source trust override or CRL expiry bypass. If current CRL or
  signer admission fails, stop and inspect; do not forge a marker.
- No PostgreSQL in Stage 1; no FI SoR mounts or database credentials.
- Historical repo commit, manifests, signed bytes, counts, and descriptor
  digest must match before any timed comparison.
