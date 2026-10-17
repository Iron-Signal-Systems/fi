# M8A — Explicit dual-lock bridge for flat ingest

Development-only source change. **No production deployment or restart.**

Baseline on 2026-10-16:
- Operational fi-ingest (uid/gid 4100) holds `/var/run/fi/fi-ingest-worker.lock` in worker-writable directory `/var/run/fi` (0700). The legacy inode is worker-owned mode 0600.
- fi-dev test keeper (uid 61231) owns `/var/run/fi-keeper/fi-ingest-worker.lock` mode 0640, directory 0710, group fi-ingest (61232).
- These are separate jails, devices, paths, and locks; they are not interchangeable.

## M8A behavior

- Legacy flat ingest stays **unchanged by default** and uses its legacy lock only.
- Opt-in `-lock-migration-dual` is allowed **only** for flat ingest with the **exact installed legacy lock path**.
- A dual-mode worker obtains the legacy lock, then the existing keeper-owned protected lock, and holds **both** until the worker exits; acquisition failure releases any acquired lock and aborts before PostgreSQL ingestion.
- Namespaced ingest remains protected-only; dual flag with namespaces is rejected. The namespace activation gate stays unconditionally closed.
- The worker-side `quarantine-release` command remains disabled; M6C admin release is out of scope.

## Critical deployment restriction

The legacy lock path is in a worker-writable directory and does not protect against a malicious or faulty legacy worker replacing its pathname. **The keeper and production ingest run in separate jails**, so a protected file recreated under `/var/run/fi-keeper` in each jail would still be two independent locks. A production migration requires the keeper and worker to open the *same underlying filesystem inode* through a deliberately provisioned, protected shared mount, with verified device/inode identity across jails. A pathname match alone is insufficient. Dual locking coordinates *cooperating* binaries only; it does not prove old binary retirement. **Never expose M6C administrative release on a backend where an unmodified legacy-only worker can still be started.** Before a production cutover, atomically control service binary and rc script, stop and verify the old process, provision keeper accounts/runtime, confirm the new executable and both locks, and prove old executable rollback/launch cannot bypass protected authority.

The initial automated tests use two distinct cooperative file locks in temporary directories to confirm dual acquisition, contention, rollback, and shutdown. Native cross-UID acceptance with the pinned protected inode is still required. The patch must not be deployed to production merely because these tests pass.

Archive contains two unified patches against M4-era worker source and one new test file. Revalidate exact SHA-256 of both source files before applying. `patch -C` is not a compilation or security guarantee.
