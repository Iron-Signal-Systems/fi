# M8B: native cross-UID dual-lock acceptance probe

Development-only test source. No modifications to production FI backend services, lock paths, jail mounts, PostgreSQL, or GitHub.

The test is inert under ordinary go test runs unless FI_M8_LIVE_CASE is explicitly specified. The compiled Go test executable must run as the synthetic fi-ingest identity (UID/GID 61232) in fi-dev. The real fi-dev keeper-owned lock must already exist, and the separate legacy fixture lock directory must be provisioned as worker-owned 0700. The test invokes M8A's real m1AcquireWorkerSingleton() function for dual-lock acquisition, and the workerlock package for individual lock probes.

Cross-process acceptance matrix:
- Hold dual: a second legacy, protected, or dual request is denied.
- Hold legacy only: dual is denied at the legacy lock; protected remains available (demonstrates migration hazard).
- Hold protected only: dual is denied at protected lock; legacy is available afterward (demonstrates rollback).
- All released: both locks and dual mode can be acquired.

This is a cooperative-lock acceptance test, NOT proof of resistance to a legacy worker replacing its worker-owned pathname. A production migration still requires a shared underlying protected lock inode accessible to separate jails, retirement of all legacy-only worker launches, and exclusive ownership of administrative release.
