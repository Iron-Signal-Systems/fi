# FI Keeper-Owned Singleton Lock: M3 Primitive

The worker-owned singleton pathname can be removed and replaced while the
original open inode retains its `flock` (confirmed on fi-dev on 2026-10-15).

This candidate provides a new FreeBSD-only `workerlock.AcquireProtected`
primitive. It does **not** yet wire startup/installation or open the namespace
activation gate.

Required operational filesystem contract before use:

- A trusted parent such as `/var/run`, neither group- nor other-writable.
- `/var/run/fi-keeper`, directory, keeper UID, worker primary GID, mode `0710`.
- `/var/run/fi-keeper/fi-ingest-worker.lock`, regular empty file, keeper UID,
  worker primary GID, mode `0640`, link count exactly one.
- Both service identities must be non-root, distinct and pinned.
- The worker gets group search on the directory and group read on the file.
  It does **not** get directory write or file write permissions.
- The directory and lock inode are **pre-provisioned by the installer or a
  privileged bootstrap**, not created by the ingest worker.
- The lock directory must be exposed inside the worker jail without becoming
  worker-owned/writable. Validate mounts and jail access before activation.

The function uses search-only directory descriptors, no-follow opens,
`fstat`/`fstatat` inode comparison, and nonblocking exclusive flock. No
fallback to worker-created lock on error.

## Remaining required work

1. Update the worker entry point and installed launchers so *every* ingest
   variant acquires the **same** keeper-owned lock, including flat mode after
   transition. If legacy and namespaced modes lock different paths, they can
   run concurrently and the security invariant is not met.
2. Provision and verify the ownership/modes during FreeBSD backend install.
3. Run a real two-account native FreeBSD integration test. Unit tests here
   only test policy validation; they cannot establish cross-UID enforcement.
4. Add independently authorized/audited keeper-controlled release and ensure
   worker-owned release cannot remove keeper markers.
5. Keep the namespace authority gate closed until all controls are proven.

No production jails, PostgreSQL databases, custody paths, services or GitHub
state should be modified by the M3 test overlay.
