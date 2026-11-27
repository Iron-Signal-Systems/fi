# FI C220 — current deployment/change contract

> **Observed 27 Nov 2026:** This describes the currently running C220 FreeBSD 15.1 backend, not a future three-jail design or a verified fresh-install recipe. [Current architecture and diagrams](../../../docs/architecture/FI-C220-CURRENT-BACKEND.md).

This is a safety and ownership contract for the existing C220 runtime. The original generic three-jail fi-bootstrap scripts are **legacy** and are not an as-built deployment tool for C220.

## Deployment requirements

1. Identify the exact physical FreeBSD host, current commit, running binary hashes, jail status and ZFS/nullfs custody mounts **before** any change.
2. Use the current two-jail architecture: `fi-receiver` for signed custody and verified cache; `fi-sor` for C1 P5/P6, B verification and PostgreSQL 18.
3. Never change or reset canonical PostgreSQL state, original signed custody/receipts, READY or ZFS assets as a side effect of a source update.
4. Keep receiver cache writable only to receiver, and read-only from SoR. B must verify the original signed material.
5. Fail closed on an uncertain Pending generation, verification mismatch, custody issue or PostgreSQL failure. No unreviewed replay/Accepted transition.
6. Protect runtime credentials and private keys from Git; site-specific configuration is input, not code.
7. Run current FreeBSD CI and explicit read-only host verification before considering deployment.

## Current checked-in paths

- Main programs: `go/cmd/fi-receiver`, `go/cmd/fi-c1-sor-local`, `go/cmd/fi-telemetry-backend`.
- Runtime services: `tools/deployment/freebsd/runtime.d/`.
- C220-specific operational scripts: `tools/deployment/freebsd/operations/`.
- Current visual architecture: [FI C220 current](../../../docs/architecture/FI-C220-CURRENT-BACKEND.md).

**Do not run the old `fi-bootstrap.sh` or `fi-host-*-apply.sh` layers against C220** based on their historical three-jail assumptions. Current source passes build tests, but exact installed ELF equivalence and full fresh-server provisioning have not been proven.
