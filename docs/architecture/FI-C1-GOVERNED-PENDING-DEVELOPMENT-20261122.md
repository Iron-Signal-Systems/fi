# FI C1 — Governed pending relational state (unreleased development)

**Date:** 2026-11-22
**Branch:** `dev/c1-two-process-20261120`
**Status:** code-only schema plan; not installed; live ingestion prohibited.

## Verified integration blocker

The live two-jail C1 service still assumes the discarded
`fi_recovery_projection` / `fi_recovery` development staging schemas,
and the independent offline canonical remapper is not part of its Drain
path. Installing those schemas back onto the populated physical C220 is
prohibited. Multiple independently committed SourceParent/family SQL
transactions must remain invisible to canonical `fi` readers until verifier
B and a single atomic Accepted transaction complete.

## Governed pending representation (code-only first slice)

`C1GovernedPendingPlan` builds a SHA-checked schema migration plan for
`fi_c1_pending` in the **existing fi-sor PostgreSQL server**. It mirrors
the exact audited canonical relational structure, FKs and identity rules,
and adds a constrained `generation_control` table linking all original
signed generation fields. A transaction-scoped DDL helper is exercised only by disposable PostgreSQL 18 CI; no production installer or service invokes it.

The native SoR five-family writer/COPY boundary is now capable of targeting the governed pending namespace while the original isolated benchmark path still targets its original schema. Startup metadata, verifier B, recovery and publication are not yet migrated.

Control state is `Pending`, `SQLSealed`, `BVerified`,
`PublicationUncertain`, or `Retired`. None means canonically Accepted.
The unique index admits only one unresolved generation; an uncertain
commit fails closed rather than making a new generation eligible.
The SoR SQL worker role may INSERT only the six signed-identity columns of
a Pending generation control record in the same transaction as the original
signed source metadata. It cannot specify B proof fields or the lifecycle
state, and cannot UPDATE those fields or write a pending `ingest_journal`.
The new `StageC1SignedPendingMetadata` primitive enforces original
immutable signed receipt and exact batch roster before this atomic SQL
admission; it does not enable service startup or claim final acceptance. The canonical journal remains the sole acceptance
authority.

This is a **design candidate**, not approval to install a second
authoritative database or revive the deleted private development schemas.

## Remaining mandatory engineering work

1. Complete the admin-only installation and SoR-owned lifecycle API. The
   existing transaction-scoped DDL helper and disposable PostgreSQL 18 tests
   cover rollback, mirrored FKs, writer ACLs and unresolved-generation fence;
   production preflight and a safe state-transition owner are still missing.
2. Replace the active C1 Bootstrap/private-stage preflight with the new
   guarded pending metadata transaction, then move signed SQL-ID readback,
   SourceParent, the existing five-family pool, independent B and crash-prefix
   recovery to the same pending namespace. The pending metadata primitive
   and SQL writer target exist, but are not yet invoked as a complete service.
   Do not introduce a second SQL ingestion algorithm or PostgreSQL access in
   fi-ingest.
3. Rework the existing canonical promotion SQL for exact generation-scoped
   pending tables, **not** global copied staging tables. Lock and independently
   re-verify original immutable custody, hashes, relational completeness,
   USN dependencies and FK maps under publication locks.
4. In a single PostgreSQL transaction map all typed rows into existing
   populated canonical `fi` tables and insert **one** matching
   `fi.ingest_journal` Accepted event. An error or uncertain commit
   must never become an accepted Drain ACK.
5. Re-read canonical generation and journal after publication before sending
   `FinalAccepted`. Preserve original custody and READY marker on all
   errors; reconcile exact prior Accepted on restart before attempting replay.
6. Run FreeBSD / disposable PostgreSQL 18 acceptance for complete signed
   generation, duplicate receipt, forged ACK, corruption, SQL rollback,
   SIGKILL/power loss, interrupted transfer, ambiguous commit and restart.
   Compare relational contents/families and previous C1 throughput; no
   Windows backend tests.

## Physical C220 hold

Do not start C1, install pending DDL, change canonical PostgreSQL or restart
C220 on the strength of this schema-plan commit. Only tested and reviewed
application integration can lift that hold.
