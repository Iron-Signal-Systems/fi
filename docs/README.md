# File Intelligence documentation

FI's root [README](../README.md) states the product's mission and purpose. Engineering designs, implementation records, operational references, and historical evidence belong in this documentation tree.

## Purpose, scope, and product design

- [Product definition](PRODUCT-DEFINITION.md) — the purpose of FI, file-centered intelligence, evidence, uncertainty, and the non-remediating boundary.
- [Development roadmap](../fi-roadmap/roadmap.md) — phases, implementation status, and future acceptance gates.
- [Published projection contract](PUBLISHED-FI-PROJECTION-CONTRACT.md) — the intended separation of historical authority, query projections, and user access.

## Windows collection and installation

- [Windows collector contract](COLLECTOR-CONTRACT.md) — what the collector observes, continuity handling, and the boundary between facts and derived conclusions.
- [Windows installer](WINDOWS-INSTALLER.md) and [operator guide](WINDOWS-INSTALLER-OPERATOR-GUIDE.md) — the configuration-driven native Windows installation model.
- [Windows Server validation](WINDOWS-SERVER-VALIDATION.md) — supported build characteristics and dated acceptance evidence.
- [USN privilege boundary](security/usn-privilege-boundary.md) — privilege separation and collection limitations.
- [Windows and source engineering notes (2026-11-27 snapshot)](WINDOWS-SOURCE-ENGINEERING-NOTES-20261127.md) — the detailed Windows runtime, audit, continuity, spool, and source-reference material formerly in the root README.

## Current FreeBSD backend

- [Current C220 architecture](architecture/FI-C220-CURRENT-BACKEND.md) — the actual receiver / SoR runtime and independent acceptance boundary.
- [C220 as-built evidence](deployment/C220-FREEBSD-AS-BUILT-20261127.md), [operator reference](deployment/C220-OPERATOR-REFERENCE.md), and [live source lock](deployment/C220-LIVE-RUNTIME-LOCK-20261127.md).
- [FreeBSD backend deployment materials](../tools/deployment/freebsd/README.md) — current operational files and status.
- [Transport, ingest, and engineering history notes (2026-11-27 snapshot)](BACKEND-ENGINEERING-NOTES-20261127.md) — custody, former Gate 3, historical implementation, and engineering principles originally in the root README.

## Acceptance, security, and governance

- [Verification record](VERIFICATION-RECORD.md) and [Gate 1 result record](GATE-1-RESULT-RECORD.md) — recorded evidence with its original scope.
- [Performance reports](performance/README.md) — historical measurement and acceptance results.
- [Security reporting](../SECURITY.md), [source license](../LICENSE), and [adopted engineering-standard reference](../ENGINEERING-STANDARD).

### Reading historical notes

The two dated engineering-note documents preserve technical material moved out of the former long README. They are **snapshots**, not newly accepted implementations. In particular, the current C220 architecture replaces historical Linux ingest, three-jail development, and obsolete backlog worker paths. For actual deployment decisions, use current source, dated acceptance evidence, and current operating contracts.
