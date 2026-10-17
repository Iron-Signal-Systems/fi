# FI Keeper M6C — Administrative Release Wiring (Development Only)

This update completes development-side wiring of the separately authenticated administrative Unix socket to the M6B keeper-protected release handler. It does not change the worker-facing read/publish protocol, the namespaced worker activation gate, or operational runtime services.

## Security contract

- Administrative release is disabled by default (`-admin-enable=false`). Enabling requires `-history-root` and independently preprovisioned keeper-owned, private storage. `VerifyReleaseHistory` checks directory metadata before any socket binds.
- The administrative socket is fixed at `/var/db/fi-keeper/admin/admin.sock`, and its containing directory is keeper-owned `0700`. The socket is keeper-owned `0600`. No worker account has directory access.
- `HandleAdminReleaseConnection` verifies the connecting peer's FreeBSD kernel UID is root **before** parsing a request. Request source confirmation, reference, and justification are strictly validated.
- Each release uses `ProtectedAdminReleaseHandler`, which first takes the same keeper-owned exclusive flock inode as namespaced ingest. The M5 transaction writes an immutable intent and fail-closed guard before retiring a marker, with a completion record before removing the guard.
- Administrative requests are serialized and time-bounded; the worker socket runs independently with its existing concurrency limit. An unexpected listener failure stops both.
- `fi-keeper-admin release` is explicitly invoked by root; the client validates the keeper-owned socket path and protocol response. It accepts no worker-originated release tokens.

## Native testing / acceptance sequence

1. On `fi-dev`, test `./internal/quarantinekeeper`, `./internal/workerlock`, `./cmd/fi-quarantine-keeper`, `./cmd/fi-keeper-admin`, and `./cmd/fi-ingest-worker`; run `go vet`, then build keeper and admin **development** binaries.
2. In a separately approved test-only restart, preserve the synthetic `m1-fixture-fs2019.local` marker; provision `/var/db/fi-keeper/history` and `/var/db/fi-keeper/admin` keeper:keeper `0700`; verify empty admin socket path. Retire the old keeper worker socket only after verifying it is stale and that the original process has exited.
3. Run the keeper with the existing test identities plus `-admin-enable -history-root /var/db/fi-keeper/history`. Verify root connection succeeds and unprivileged workers cannot reach the administrative socket.
4. Hold the protected lock as UID 61232; verify root release is rejected and marker and audit directory remain untouched.
5. Release the lock and authorize exactly the synthetic FS2019 release with exact source confirmation, change reference, and justification. Verify durable intent and completion records, retired source marker, clear FS2019, and unchanged FS22; verify worker cannot forge release.
6. Restart the keeper and verify the released state and history persist. Separately simulate interrupted audit to confirm a durable guard remains fail closed.

## Remaining release blockers

- Full cross-UID end-to-end authorized-release acceptance has **not** been run.
- The flat/mixed-mode worker locking boundary must be reconciled before operational activation; a flat worker using its legacy inode would not be serialized by the keeper's protected inode.
- No changes to GitHub or operational FI services are authorized by this archive.
