# FI Quarantine Keeper M6B — Protected Release Authority (Development Only)

Scope: keeper-side acquisition of the *same* singleton inode used by the namespaced ingest worker and a fail-closed wrapper for the existing M5 audit transaction.

- Worker path: `workerlock.AcquireProtected(policy)` checks worker UID/GID.
- Keeper path: `workerlock.AcquireProtectedAsKeeper(policy, keeperGID)` checks keeper UID/GID. Both open `/var/run/fi-keeper/fi-ingest-worker.lock`, require keeper-owned `0710` directory and keeper-owned `0640` lock, and take nonblocking exclusive `flock`.
- Admin handler: `quarantinekeeper.ProtectedAdminReleaseHandler` acquires keeper-side protected lock before M5 storage transaction; no marker or audit modification occurs when lock acquisition fails.
- This overlay does NOT start the administrative listener, create an operator client, alter the worker socket, replace running executables, or open the namespaced activation gate.

Acceptance still needed: Native FreeBSD unit tests; real separate-UID lock-contention test between UID 61231 and UID 61232; independently authenticated admin listener wiring and root client; authorized release with audit and restart persistence; mixed-mode startup and migration safety.

Preserve `/var/db/fi-keeper/quarantine/m1-fixture-fs2019.local.json` until authorized release acceptance. Do not change service binaries or restart the keeper during M6B source testing.
