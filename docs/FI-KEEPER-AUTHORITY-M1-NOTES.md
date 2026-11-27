# FI independent quarantine keeper — development increment (2026-10-15)

**Status: development code; namespace activation remains blocked.**

## Included

- Standalone **development** `fi-quarantine-keeper` entry point (`go/cmd/fi-quarantine-keeper/main_freebsd.go`) requiring explicit, distinct non-root worker and keeper identities. The socket is deliberately not unlinked automatically after shutdown; endpoint retirement is a separate protected operation.
- Keeper-owned durable marker storage (`go/internal/quarantinekeeper/store_freebsd.go`).
- Enrolled-source validation, strict complete-inventory checks, no marker replacement or release, authenticated handler hook for the existing Unix listener.
- Independent UID/GID and mode `0700` storage precondition; `openat`/`O_NOFOLLOW` directory-relative marker operations, mode `0400`, `linkat` no-clobber publication, file and directory fsync.
- Worker-side Unix client (`client_freebsd.go`) supporting **only** `read` and `publish`. The socket authority is verified against the separate keeper identity.
- FreeBSD tests for restart persistence, idempotence, concurrency, source enrollment, unsafe directory and object rejection, and denial of unrecognized reason codes.

## Not included — mandatory blockers before activation

1. An independently provisioned and supervised **operational service** (rc.d installer integration, UID, socket and storage mounts, protected endpoint retirement). A development keeper entry point is present but no production service is installed.
2. Routing the worker's runtime `Load` and `Persist` through this keeper and removing its access to marker storage; the prior worker-owned store remains only behind the currently closed namespace gate.
3. Operator-only release executable and authenticated authorization tied to independent keeper custody, audit history, and protected singleton-lock authority. No release operation is in the worker protocol.
4. Crash, restart, mount, permission, lock, and adversarial integration testing on FreeBSD. Particularly exercise interrupted temp publication; an unrecognized `.pending` object must fail closed until inspected and recovered by an independent administrator.
5. Explicit human approval and operational deployment/rollback; no automatic service changes or GitHub mutations.

## Validation

Run on `fi-dev` within the repository:

```sh
cd /home/jwood/src/fi/go
go test -count=1 -v ./internal/quarantinekeeper ./cmd/fi-quarantine-keeper
go vet ./internal/quarantinekeeper ./cmd/fi-quarantine-keeper
go build -trimpath -o ~/fi-quarantine-keeper-dev ./cmd/fi-quarantine-keeper
```

The namespace authority gate in `go/cmd/fi-ingest-worker/multisource_authority_gate_freebsd.go` is **unchanged** and must stay closed until all blockers are satisfied.
