# Phase 2 — Secure Record Transport

## Purpose

Move FI records from Windows source custody to durable backend custody securely,
reliably, and without ambiguous loss.

Transport sender and receiver mechanics belong to the same product boundary.

Phase 1 creates and verifies the durable local source queue. Phase 2 begins at
that accepted queue boundary and owns transport custody, acknowledgement,
retry/resume, and retirement only after backend custody is established.

## Responsibilities

Phase 2 owns:

- transport custody of the accepted Phase 1 durable source queue;
- record/package construction and identity;
- source identity;
- signing;
- encryption;
- authenticated transport;
- backend reception;
- durable backend staging;
- durable acknowledgement/receipt;
- retry and resume;
- duplicate handling;
- replay protection;
- conflicting duplicate detection;
- sequencing;
- identity/certificate revocation handling;
- bounded storage and retry behavior;
- restart and recovery behavior.

## Custody Rule

The source does not retire its durable copy until backend custody has been
established according to the transport contract.

If acknowledgement is lost after durable receipt, retransmission must be safe.

The same package identity with the same bytes is recognized as a duplicate. The
same identity with conflicting bytes is rejected and recorded as a conflict.

## Content Boundary

Customer source-file content never travels through Secure Record Transport.

Only FI records and transport/journal material use this path.

## Journal Requirements

Material transport actions produce immutable journal state, including queueing,
send attempts, receipt, acknowledgement, retry, replay detection, duplicate
handling, conflict, failure, and recovery.

## Gate 2 — Secure Durable Record Transfer

Gate 2 proves:

> An FI record either reaches durable backend custody or remains safely under
> source custody.

Representative testing includes:

- network interruption;
- source restart;
- backend restart;
- lost acknowledgement;
- retransmission;
- duplicate delivery;
- replay;
- conflicting duplicate;
- sequence conflict;
- revoked identity;
- resource exhaustion/bounds.

No ambiguous record loss is accepted.
