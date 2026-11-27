# FI C220 — source-specific ingest fault isolation

> **Observed 27 Nov 2026:** This describes the currently running C220 FreeBSD 15.1 backend, not a future three-jail design or a verified fresh-install recipe. [Current architecture and diagrams](../../../docs/architecture/FI-C220-CURRENT-BACKEND.md).

Current multi-source intake is managed by the single-jail C1 engine in fi-sor, not the removed fi-ingest-worker or staging backlog CLI.

## Fail-closed behavior

- Each signed sender source is identified and governed independently through registered sources and exact receipts.
- The receiver owns original signed FIGT custody, recorded receipts and its derived verified cache.
- READY indicates work for SoR; READY deletion/retirement is not an alternative to canonical `Accepted` proof.
- Source-specific trust, custody, conflict or verification errors must not be generalized into acceptance for a different sender or silently overwrite another source's history.
- C1 A processes P5/P6 and writes local PostgreSQL; independent child verifier B reads original FIGT and restricted SQL. Any disagreement blocks acceptance.
- Uncertain commit/replay state requires explicit source-scoped reconciliation; no automatic mass replay or SoR reset.
- The maximum 32 SQL workers in the service runner controls SQL execution concurrency, not the number of source identities.

This document is an authority contract, not proof that every failure-injection scenario has been accepted under the live C220 workload.
