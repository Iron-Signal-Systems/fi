# FI C220 — evidence-based acceptance

> **Observed 27 Nov 2026:** This describes the currently running C220 FreeBSD 15.1 backend, not a future three-jail design or a verified fresh-install recipe. [Current architecture and diagrams](../../../docs/architecture/FI-C220-CURRENT-BACKEND.md).

This page distinguishes what the current two-jail C220 has demonstrated from what is still unverified. It replaces the historical old-host fi-backend-b / vtnet / fi-ingest / fi-sor-db acceptance guide.

## Verified observations

- Host: `c220`, FreeBSD `15.1-RELEASE-p5`.
- Active processes: `fi-receiver`, `fi-c1-sor-live`, PostgreSQL in `fi-sor`, one host and two `fi-sor` telemetry backend processes.
- Signed custody/receipts/verified cache: writable in receiver, read-only in SoR; READY shared RW.
- PostgreSQL SoR was observed accepting real input: **53 accepted generations and 631 committed records** from queued historical signed generations.
- GitHub FreeBSD runtime cross-build and native disposable FreeBSD PostgreSQL 18 integration workflows completed successfully prior to this documentation pass.

## Not yet proven by this evidence

- Byte-for-byte identity between running binaries and a build from the current source revision.
- Successful cold install of a replacement C220 host from GitHub alone.
- Full runtime jail/VNET/PF configuration from as-built evidence; not captured in the process/mount inventory.
- Fresh sender run, sustained representative-load campaign, restart proof, and fully audited telemetry delivery.

## Read-only checks

See [C220 operator reference](../../../docs/deployment/C220-OPERATOR-REFERENCE.md) for read-only service/mount/hash inventory commands, and [as-built exact hashes](../../../docs/deployment/C220-FREEBSD-AS-BUILT-20261127.md).

No instruction here authorizes DB reset, source-custody mutation, jail reinstall, reboot or automatic promotion.
