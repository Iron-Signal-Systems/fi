# FI C220 — current ZFS and filesystem authority

> **Observed 27 Nov 2026:** This describes the currently running C220 FreeBSD 15.1 backend, not a future three-jail design or a verified fresh-install recipe. [Current architecture and diagrams](../../../docs/architecture/FI-C220-CURRENT-BACKEND.md).

The FreeBSD physical host manages ZFS and mounts; receiver writes original signed custody; SoR consumes protected read-only views and owns its separate PostgreSQL state.

## Observed access controls

| Material | fi-receiver | fi-sor |
|---|---|---|
| Original signed FIGT generation | RW | **RO** |
| Durable recorded receipts | RW | **RO** |
| Receiver verified cache | **RW** | **RO** |
| READY state | RW | RW (controlled scheduling and retirement) |
| PostgreSQL `fi` PGDATA | No mount | RW (local PostgreSQL process) |
| Receiver trust and source registrations | Controlled RO | Controlled RO as configured |
| Telemetry spool | Separate host spool access | RW, dedicated telemetry identity |

Exact hosts and nullfs paths: [C220 inventory](../../../docs/deployment/C220-FREEBSD-AS-BUILT-20261127.md).

Custody and receipts must not be reset, overwritten or deleted as an installation side effect. An independently verified C1 B process must check original signed custody rather than trusting cache output alone. A committed SQL transaction by itself does not authorize an `Accepted` journal event. PostgreSQL-consistent backup/restore is required for SQL recovery; a ZFS snapshot alone is not proof of logical database consistency.

Some unused old dataset mounts survive the migration. They are **not** runtime components and are not deleted by repository cleanup.
