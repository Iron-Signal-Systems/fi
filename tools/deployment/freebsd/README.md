# FI C220 FreeBSD backend

The **current observed C220 deployment**, not the historical experiments, is the FreeBSD backend development baseline.

See [C220 as-built inventory](../../../docs/deployment/C220-FREEBSD-AS-BUILT-20261127.md) for executable hashes, runtime layout, mounts and limitations.

## Active runtime

- `fi-receiver`: signed receiver custody, recorded receipts, READY scheduling and verified cache.
- `fi-sor`: PostgreSQL 18 plus the single-jail C1 P5/P6 consumer, with independent verifier B spawned from the same C1 binary.
- C220 host + `fi-sor`: the telemetry collector/recorder services.
- `fi-dev`: build environment, not a stage in data ingestion.

No production `fi-ingest` worker or old two-jail C1 SQL handoff participates in the observed live pipeline. The host may retain inactive old datasets and mounts; repository cleanup does not remove those.

## Current build targets

From the `go` directory, build the actual FreeBSD programs:

```sh
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o fi-receiver ./cmd/fi-receiver
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -tags fi_c1_sor_dev -o fi-c1-sor-live ./cmd/fi-c1-sor-local
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o fi-telemetry-backend ./cmd/fi-telemetry-backend
```

These build commands are **not** proof of byte-identical output to installed binaries; that requires C220 compiler/runtime and configuration comparison.

## Deployment safety

The original FI host bootstrap still includes historical generic jail assumptions. **Do not run legacy bootstrap against the live C220 until it has been reconciled with the as-built inventory and audited for exact active jail, PF, ZFS and role configuration.**

Only non-secret service templates belong in Git. No C220 service or PostgreSQL state is changed by this repository cleanup.
