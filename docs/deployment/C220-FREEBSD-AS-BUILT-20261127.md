# FI C220 FreeBSD backend — observed as-built

Observed on **2026-11-27** from a read-only inventory run by the C220 operator.
This is a description of what was observed running, **not** yet an exact source-to-binary, fresh-install, reboot, or sustained-load acceptance proof.

## Machine and scope
- Physical host: `c220`, FreeBSD `15.1-RELEASE-p5`.
- Active FI workload jails: `fi-receiver` and `fi-sor`.
- `fi-dev` remains an available FreeBSD source/build jail; it is not an ingest stage.
- The host also has an `fi-frontend` jail and persistent `fi-ingest` datasets, but the supplied process inventory did not show an FI application process in those locations. **Do not interpret mounted datasets as running components.**
- Independent verifier B is a child process spawned from the `fi-c1-sor-live` executable when needed (`--c1-b-child`), not a permanent standalone daemon.

## Observed running binaries (SHA-256)
| Location | Executable | SHA-256 |
|---|---|---|
| fi-receiver | `/usr/local/sbin/fi-receiver` | `c0006e7de05c38eb4da4869de5c9b8ecb56663b4ea35ed44b7a248ca23375f8c` |
| fi-sor | `/usr/local/sbin/fi-c1-sor-live` | `54ea5cce0538ba0f65cd1d6effc78b695ed44bd2f8257aa14781bf1e58e558b2` |
| fi-sor | `/usr/local/bin/postgres` | `6dcc4abce1723354636a7bce3819213b505a82fca5b4dfe47d94d446e42dfc1f` |
| c220 host | `/usr/local/sbin/fi-telemetry-backend` | `dab1deb8cc39ded4c9b293e74bc8c39f30a61393828dc73899a8db560ccf3a11` |
| fi-sor (two processes) | `/usr/local/sbin/fi-telemetry-backend` | `dab1deb8cc39ded4c9b293e74bc8c39f30a61393828dc73899a8db560ccf3a11` |

Processes in the operator inventory: `fi-receiver`, `fi-c1-sor-live`, PostgreSQL, one host telemetry backend and two fi-sor telemetry backends. The inventory alone does not prove ongoing database telemetry delivery.

## Active custody and filesystem boundaries
- `/work/fi-c220-20261114/custody/generation`, `transport`, `ready`, `recorded`: mounted read/write into `fi-receiver` where applicable.
- `generation` and `recorded`: mounted **read-only** into `fi-sor`.
- `ready`: mounted read/write into `fi-sor` for scheduling and retirement.
- `verified-cache`: **read/write** in `fi-receiver`, **read-only** in `fi-sor`.
- `/fast/data/fi/sor/pgdata`: ZFS-backed PostgreSQL data, mounted read/write at `fi-sor:/var/db/fi/sor/postgres`.
- `/fast/data/fi/telemetry/spool`: shared telemetry spool mounted read/write in `fi-sor`.
- A legacy `/var/run/fi-c1-handoff` tmpfs/nullfs mount was observed; the currently running single-jail C1 binary is documented in source as not using an inter-jail RAM handoff. Do not remove the host mount solely on this observation.

## Source/build and service mapping
- Receiver: `go/cmd/fi-receiver`, `go/internal/transportreceiver`, `go/internal/generationrecorder`, `go/internal/receivertrust`.
- C1 SoR: `go/cmd/fi-c1-sor-local` with build tag `fi_c1_sor_dev`, plus `go/internal/recordingest` and `go/internal/c1handoff`. Installed executable name is `fi-c1-sor-live`.
- B verifier: `go/internal/recordingest/c1_sor_native_b_process.go`, launched by the C1 executable itself.
- Telemetry: `go/cmd/fi-telemetry-backend`, `go/internal/telemetrybackend`.
- Runtime definitions: `tools/deployment/freebsd/runtime.d/fi-c1-sor-live-*`, `fi-receiver-*`, `fi-telemetry-*`.
- Existing C220 operational installation helper: `go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_operational_install.sh`.

## Observed acceptance and limitations
- Operator had previously verified end-to-end sender ingest into canonical `fi` SoR: **53 accepted generations and 631 committed records** from `iss-fs-22b.iss.local`.
- Neither the source commit that compiled each installed binary nor byte-for-byte reproducibility was confirmed by this inventory.
- This cleanup deliberately does **not** change C220 files, services, ZFS, signed custody, or PostgreSQL content.
- Old H16/W512 benchmark runners and retired fi-ingest workers do not belong to the accepted live FreeBSD execution path.
- Replacing the remaining legacy host bootstrap with a complete reproducible C220 installer still requires capture and verification of current jail, PF, ZFS and non-secret rc configuration. Never commit private keys, certificates with keys, passwords, or live credentials.

**Development branch:** `dev-backend`. **Accepted prior baseline:** `main` remains unchanged until a separate acceptance/promotion decision.
