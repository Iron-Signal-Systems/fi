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
signed generation fields. No installer or service currently executes it.

Control state is `Pending`, `SQLSealed`, `BVerified`,
`PublicationUncertain`, or `Retired`. None means canonically Accepted.
The unique index admits only one unresolved generation; an uncertain
commit fails closed rather than making a new generation eligible.
The SQL worker role cannot modify verifier state or write a pending
`ingest_journal`. The canonical journal remains the sole acceptance
authority.

This is a **design candidate**, not approval to install a second
authoritative database or revive the deleted private development schemas.

## Remaining mandatory engineering work

1. Implement an audited, transaction-owned installation and lifecycle API.
   Test only on disposable PostgreSQL 18; add a distinct writable role for
   the SoR-owned lifecycle if needed. Verify exact permissions, no mixed
   generation leakage and no unresolved-generation bypass.
2. Move the existing C1 signed metadata, SourceParent, five-family pool,
   independent B verification and crash-prefix readback from discarded
   development schemas to this pending state. No second SQL ingestion
   algorithm; keep fi-ingest without PostgreSQL access.
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
