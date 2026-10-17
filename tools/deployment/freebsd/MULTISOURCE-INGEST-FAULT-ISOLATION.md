# FreeBSD Multi-Source Ingest Fault Isolation

## Scope

This contract applies to the FreeBSD FI relational ingest worker.

It supplements the historical Linux Phase 3 operating contract.
It does not change Windows sender or installer behavior.

## Operational authority

Immutable recorder receipts, generation custody, the ingest journal,
and PostgreSQL constraints remain authoritative.

Quarantine is an operational scheduling decision. It cannot:
- accept conflicting relational data;
- rewrite or delete recorder receipts;
- retire READY state for an unresolved conflict;
- bypass PostgreSQL validation; or
- alter another source's identity or records.

## Source-specific relational conflict

When an authoritative reconciliation plan identifies a relational
conflict belonging to the currently scheduled source:

1. Stop ingest scheduling for that source.
2. Retain its durable custody and reconciliation state.
3. Emit a source-identified quarantine diagnostic.
4. Reset its non-authoritative repair cadence.
5. Continue processing other enabled sources.

Quarantine is held in memory for the current PostgreSQL session.

There is no automatic in-session release or administrative unquarantine
command in this implementation.

Restart or PostgreSQL reconnection reconstructs source session state
and performs startup reconciliation again. If the conflict remains,
the source is quarantined again.

## Global failures

PostgreSQL availability errors retain the established reconnect and
bounded backoff handling.

Authentication, PostgreSQL identity or privilege failures, global
storage failures, and unclassified errors are not source-quarantined.

Cross-source conflict identity mismatch remains fatal.

## Deployment boundaries

Development: fi-dev

Current operational reference: fi-backend-b

FreeBSD installer implementation validation: fi-receiver-c

No Windows code or installer changes belong to this milestone.

## Shared recorded-receipt discovery boundary

The current authoritative startup and repair discovery paths enumerate
the shared recorded-receipt directory.

Receipt structure and deterministic identity are validated before the
source ID filter is applied. A malformed or unreadable receipt may
therefore prevent discovery for otherwise healthy sources.

This is intentionally fail-closed. The worker must not ignore an
unattributable integrity failure or assume that a receipt belongs to
a particular source based on an untrusted filename.

The recorded receipt filename is a hash-derived identifier, not a
plain-text source identifier.

Source-local handling of malformed receipts requires an independently
trustworthy source-to-receipt attribution mechanism.

Current regression coverage verifies that:
- valid receipts from other sources are correctly filtered; and
- malformed receipts are not silently ignored.

This boundary is not yet accepted as complete source-level fault
isolation. Source-specific discovery and its failure handling remain
open multi-source engineering work.

## Acceptance status

Development regression coverage includes:
- source-specific scheduler quarantine;
- healthy source continuation;
- startup conflict handling;
- global failure propagation;
- cross-source identity mismatch;
- race detection and Go static analysis.

Passing unit tests does not establish complete PostgreSQL integration
or real-host multi-source failure acceptance.

Required subsequent acceptance:
- real PostgreSQL-backed startup conflict isolation;
- running worker conflict isolation;
- durable custody and READY preservation;
- healthy source ingest continuity;
- reconnect and restart behavior.

Do not induce an artificial relational conflict in the known-good
backend database without a separately reviewed test and recovery plan.

## October 12, 2026 — fi-backend-b integration

### Deployment

Host: fi-backend-b
FreeBSD: 15.1-RELEASE-p3
Branch: freebsd-backend-multisource-20261011
Base commit: d7516d8
Candidate SHA-256:
18b38b2e2240c1df1b2e43ef9d1be4973081a348a1507f9e2738a9898584beae

Only fi-ingest-worker was replaced.
The receiver and PostgreSQL services remained running.
The original worker binary was preserved for rollback.

### Startup reconciliation

At 2026-10-12 12:24:54 UTC:

- iss-fs-2019.iss.local: 87 accepted, 0 pending, 0 conflicts
- iss-fs-22.iss.local: 118 accepted, 0 pending, 0 conflicts

PostgreSQL connected using fi_ingest against database fi.

### Post-deployment ingest

Observed between 12:30:21 and 13:03:37 UTC:

- iss-fs-2019.iss.local: 4 accepted generations, 50 committed records
- iss-fs-22.iss.local: 4 accepted generations, 47 committed records

Total: 8 accepted generations, 97 committed records.

Observed generation processing duration: 56–109 ms.

Both READY queues were empty at the final observation.
The receiver and ingest services remained running.

### Accepted result

PASS: Normal two-source startup reconciliation.
PASS: Two-source ongoing generation ingest.
PASS: PostgreSQL acceptance from both sources.
PASS: Worker replacement without receiver restart.
PASS: READY queue drainage during normal operation.

### Outstanding acceptance

NOT YET PROVEN: Real PostgreSQL-backed source-conflict isolation.
NOT YET PROVEN: Recovery following a quarantined source conflict.
NOT YET PROVEN: Source-specific malformed-receipt containment.

The conflicting-source scheduler behavior is covered by unit tests,
but an isolated database-backed fault test is still required.

This checkpoint does not constitute complete multi-source acceptance.
