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

The native SoR five-family writer/COPY boundary is now capable of targeting the governed pending namespace while the original isolated benchmark path still targets its original schema.
Independent verifier B now has an explicitly whitelisted SQL schema in its
signed group plan. Its original receiver custody, committed group, typed-root
and whole-generation relational readbacks can use exactly the same pending
schema chosen by the SoR writer pool. The isolated benchmark preserves the
original private schema by default; schema selection never comes from
fi-ingest network input. The active `C1SoRService.Bootstrap` now uses a read-only governed pending
schema/ACL gate, the original signed-custody metadata admission transaction,
exact pending SQL-ID readback, and the existing C1 SourceParent/five-family
pool. Verifier B can follow the same schema. This is **application code**,
not an authorized installation on physical C220.

The existing 49-table canonical remapper has now been parameterized to
consume precisely the single governed pending generation. Its natural NTFS
identity reconciliation, generated-ID mapping, FK audit, and all-or-nothing
Accepted journal transaction remain the SAME SQL implementation as the
previous isolated benchmark. It holds pending table and control locks,
rechecks original signed custody and relational proof under those locks,
and refuses foreign or uncertain control state.

The development `FinalProof` continuation now invokes pending publication
only after independent process B fully completes, then checks the *actual*
canonical recorded_generation + Accepted journal in a fresh read-only
PostgreSQL transaction before returning `FinalAccepted`. An uncertain SQL
outcome leaves fi-ingest READY intact and requires read-only reconciliation.

This automatic implementation is **not yet accepted for live deployment**:
pending retention/cleanup, interrupted-generation recovery, power-loss and
full two-jail signed-generation acceptance remain incomplete. The optional
`BVerified` lifecycle transition is not yet made durable: publication
instead requires independent B completion and repeats the full proof under
locks before committing Accepted. Existing incomplete generations fail closed.

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
2. Finish governed pending interrupted-generation read-only recovery,
   committed-prefix reconciliation and safe replay. The active clean START
   and A/B SQL readback have been routed to the same pending schema; a
   previous dirty generation is intentionally rejected until replay proof is
   accepted. No second SQL ingestion algorithm and no PostgreSQL access in
   fi-ingest.
3. Validate the reused canonical promotion SQL against a fully populated
   disposable PostgreSQL 18 database and a genuine original signed C1
   generation, including NTFS natural-key remaps and each five-family table.
   The current one-unresolved-generation admission model intentionally
   prohibits unrelated pending source rows; future concurrency requires a
   separate accepted isolation design.
4. Prove the wired final Drain publisher in full disposable acceptance:
   all typed rows and the one canonical `fi.ingest_journal` Accepted event
   must commit in the same SQL transaction. An error or uncertain commit
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
