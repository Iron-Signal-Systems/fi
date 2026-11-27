# FI quarantine keeper — administrative socket M6A

**Status:** Development-only, NOT activated, and DOES NOT authorize release.

New independent administrative Unix socket primitives reside in `go/internal/quarantinekeeper`. No running service, operational CLI, worker protocol, or activation gate is changed by this overlay.

* Admin endpoint directory: `/var/db/fi-keeper/admin` (must be independently pre-provisioned with `0700`, owner/group keeper); its immediate parent must also be private and keeper-owned.
* Socket path: `admin.sock` with exact keeper UID/GID, mode `0600`. Binding refuses occupied/stale objects. Shutdown never silently unlinks the endpoint.
* Every request is authenticated using FreeBSD `LOCAL_PEERCRED` and requires kernel-reported UID 0. The client cannot claim an operator UID in JSON; unknown and duplicate keys are rejected.
* Only the bounded `release` request shape is understood; exact source confirmation, change reference, and justification required.
* Existing worker socket still permits only `read` and `publish`. Release is not offered to the worker.
* This overlay **does not start an admin listener** and **does not call** `releaseTransaction`. The handler API must not be wired until keeper-side acquisition of the exact protected worker singleton inode is complete and cross-UID/privilege tests pass. Do not enable the namespaced gate.

## Native validation

From `fi-dev` `~/src/fi/go`:

```sh
go test -count=1 -v -run '^(TestAdmin|TestKeeperReleaseTransaction)' ./internal/quarantinekeeper
go test -count=1 ./internal/quarantinekeeper ./cmd/fi-quarantine-keeper ./cmd/fi-ingest-worker ./internal/workerlock
go vet ./internal/quarantinekeeper ./cmd/fi-quarantine-keeper ./cmd/fi-ingest-worker ./internal/workerlock
```

No provisioning, keeper restart, or live marker release is part of M6A. The original FS2019 synthetic marker should remain in place.
