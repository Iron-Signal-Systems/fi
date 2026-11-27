# FI Keeper M7 — Interrupted Administrative Release (isolated test fixtures)

## Scope

Native FreeBSD test cases in `go/internal/quarantinekeeper/release_recovery_m7_freebsd_test.go`. They rely on the existing `keeperReleaseFixture` helper and use only temporary, keeper-owned fixture storage. They never access `/var/db/fi-keeper`, any running keeper socket, the live M6C history, or the operational FI backend.

## Tested interruption windows

1. **Intent audit published, guard not yet published:** original marker remains present; restart must still report quarantined. An intent-only audit is not authorization to treat the source as clear.
2. **Guard published and fsynced, marker removed:** worker read and publish fail closed, and keeper startup refuses the unexplained object. Original immutable intent and guard survive. No automatic guard deletion or marker reconstruction is attempted.
3. **Completion audit published, guard not retired:** even with a complete audit present, the stranded guard prevents keeper startup and both worker operations until independently reviewed.

These are **deterministic, on-disk crash-window simulations**, not SIGKILL/power-fault tests. They verify the existing inventory and audit semantics at representative points; they do not claim to prove atomicity under actual power loss or filesystem failure.

## Validation

From `fi-dev`, as the unprivileged repository owner:

```
cd /home/jwood/src/fi/go
go test -count=1 -v -run '^TestM7ReleaseCrash' ./internal/quarantinekeeper
go test -count=1 ./internal/quarantinekeeper ./internal/workerlock ./cmd/fi-quarantine-keeper ./cmd/fi-keeper-admin ./cmd/fi-ingest-worker ./internal/freebsd/backendinstall
go vet ./internal/quarantinekeeper ./internal/workerlock ./cmd/fi-quarantine-keeper ./cmd/fi-keeper-admin ./cmd/fi-ingest-worker ./internal/freebsd/backendinstall
```

Do not clear the namespace activation gate. Independent legacy/protected worker-lock modes still require a migration design and validation.
