# FI C220 — service identity boundaries

> **Observed 27 Nov 2026:** This describes the currently running C220 FreeBSD 15.1 backend, not a future three-jail design or a verified fresh-install recipe. [Current architecture and diagrams](../../../docs/architecture/FI-C220-CURRENT-BACKEND.md).

Installed binary locations and services are observed; these names follow the current checked-in rc scripts. Numeric UID/GID mappings and secrets were not provided in the latest inventory.

## Services

| Location | Program / service | Intended identity |
|---|---|---|
| `fi-receiver` | `fi-receiver` / `fi_receiver` | `fi-receiver` |
| `fi-sor` | `fi-c1-sor-live` / `fi_c1_sor_live` | `fi-sor` |
| `fi-sor` | `postgres` | `postgres` |
| C220 host and `fi-sor` | `fi-telemetry-backend` collector | `fi-telemetry` (scope-specific config) |
| `fi-sor` | `fi-telemetry-backend` uploader | `fi-telemetry-recorder` |

C1 publisher and SQL worker PostgreSQL roles remain distinct. Independent verifier B is a separate unprivileged child using **read-only** local PostgreSQL access. Telemetry monitor reads PostgreSQL statistics; telemetry recorder writes only the `fi_telemetry` database/schema, not canonical `fi`.

The operator-observed `/etc/rc.conf.d/fi_receiver` and `fi_c1_sor` files were mode 0640; telemetry configs were mode 0600. Never commit secret DSNs, private keys, passwords or production certificate/key material.

Historical `fi-ingest` service identities and separate `fi-sor-db` identities in old templates are not part of the current C220 runtime.
