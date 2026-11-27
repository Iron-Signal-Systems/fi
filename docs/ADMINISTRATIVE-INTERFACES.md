# FI Administrative Interfaces

## Purpose

FI's administrative and diagnostic interfaces exist for professionals who deploy,
operate, validate, troubleshoot, and verify FI itself.

They are not governed by the same abstraction boundary as the product/query user
experience.

The product UX answers questions about the customer's environment.
Administrative interfaces answer questions about FI's operation.

Both represent the same underlying FI truth.

---

## Core Rule

> **Administrative interfaces favor precision over abstraction.**

A professional running FI locally on a governed Windows system or diagnosing an
FI service is operating at the engineering boundary. FI should therefore expose
the actual technical information required to understand what the system did,
what source it used, where its durable boundary is, and why an operation failed
or became incomplete.

Administrative output must not replace technically meaningful information with a
generic friendly status when the underlying information is available.

---

## Information That Should Remain Explicit

Where applicable to the operation, administrative and diagnostic interfaces may
and should expose technical information such as:

- `FICollector` and `FIUSNReader` service identity;
- Windows service SID and gMSA identity;
- relevant enabled or unavailable privileges;
- governed root and associated volume;
- volume identity and filesystem information;
- USN Journal ID;
- `FirstUSN`, `LowestValidUSN`, `NextUSN`, and accepted USN checkpoint;
- Windows Security Event Record ID and accepted Security checkpoint;
- source/feed status;
- operation identifier and operation lifecycle status;
- spool batch and manifest identity;
- effective configured-collection, independent-USN, independent-Windows-Security,
  and supporting-refresh intervals;
- service-runtime record kind and outcome, including `ServiceStarted`,
  `ConfiguredCollection`, `USNCatchUp`, `WindowsSecurityCatchUp`,
  `SupportingSourceRefresh`, and `ServiceStopped`;
- independent-USN cycle root accounting where recorded, including configured,
  completed, skipped, and failed governed-root counts;
- Windows Security worker facts where recorded, including read-window count,
  source-match/selected/ignored counts, verified-batch count, checkpoint
  advancement/reinitialization, continuity-gap state, and whether more source
  history was immediately available;
- generation identity, canonical/encoded byte counts and hashes, FIGT transfer
  byte count/hash, recorder disposition, and acknowledgement outcome;
- recorder receipt SHA-256 and exact transfer SHA-256 used by Phase 3 relational
  identity checks;
- relational ingest attempt ID, stage, terminal outcome, record counts, and
  recorded-generation identity where available;
- relational reconcile counts for discovered, accepted, pending, and conflicting
  recorder receipts;
- relational inventory record-kind coverage and missing-kind set;
- PostgreSQL runtime user/database and expected relational-table count;
- relational ingest version;
- record count, byte count, and integrity verification status;
- continuity and reconciliation status;
- Windows error code and the operation that produced it;
- source-unavailable, access-denied, interrupted, or resource-related status;
- exact supported build/version behavior where FI intentionally branches on a
  characterized platform; and
- other bounded source or runtime facts required to understand FI's behavior.

Friendly explanatory text may accompany those facts. It must not replace them.

---

## Failure Presentation

An administrative failure should identify, where FI knows the information:

1. **what operation failed**;
2. **which governed scope or source was involved**;
3. **the last accepted durable boundary**;
4. **the newly observed boundary or state, when applicable**;
5. **the operating-system or FI error/status**;
6. **what FI did in response**; and
7. **whether coverage or history is now incomplete**.

For example, a USN continuity failure should expose the relevant Journal ID and
USN boundaries rather than only reporting that collection encountered a problem.

A Security source failure should expose the applicable event/checkpoint boundary
and Windows status rather than only reporting that activity collection failed.

For the independent service worker, diagnostics should also make it possible to
distinguish steady-state waiting from active backlog drain. A
`security_more_available=true` cycle followed immediately by another bounded
cycle is expected catch-up behavior, not scheduler overlap.

A spool failure should identify the affected batch or finalization boundary and
must not imply that a checkpoint advanced when the applicable durable boundary
was not satisfied.

A Phase 3 relational failure should identify the immutable recorder source and
generation identity, attempt ID, stage, terminal journal outcome, and whether the
failure occurred before authoritative commit. A source-record rejection must not
be presented as a partially accepted generation when the transaction was rolled
back.

A relational conflict should expose the conflicting source/generation identity
and bounded reason, such as receipt/transfer identity disagreement, generation
total disagreement, incomplete child rows, or missing typed projections.

---

## Phase 3 relational administrative surfaces

The accepted Phase 3 administrative commands are engineering and operational
surfaces. They remain technical administrative interfaces rather than the
finished product/query user experience.

### `fi-ingest`

`fi-ingest` can verify the PostgreSQL relational boundary and ingest one exact
recorded generation.

The database check should expose:

```text
PostgreSQLUser
PostgreSQLDatabase
RelationalTables
SupportedRecordKinds
IngestVersion
RelationalFoundation
GenerationIngest
```

A generation ingest should expose bounded identity and outcome facts such as:

```text
AttemptID
Source
GenerationID
TransferSHA256
ReceiptSHA256
Batches
DataBytes
RecordsSeen
RecordsCommitted
RecordedGenerationID
Outcome
```

### `fi-ingest-reconcile`

`-plan` is read-only and reports recorder/database state:

```text
ReceiptsDiscovered
AlreadyAccepted
Pending
Conflict
```

`-inventory` is also read-only. It may reopen pending exact recorded generations
through the FI custody loader to report record-kind coverage, but it must report:

```text
DatabaseWrites: 0
```

The reconcile tool deliberately does not expose a write/reconcile mode.

### `fi-ingest-worker`

The accepted worker is the permanent sequential live Phase 3 consumer. Useful
administrative output includes:

- polling time;
- discovered / accepted / pending / conflict counts;
- deferred rejection count;
- generation start/finish identity;
- records seen/committed;
- elapsed ingest time; and
- terminal outcome.

The accepted runtime properties that administrative documentation must expose
include:

- durable PostgreSQL-backed `SOURCE_RECORD_REJECTED` retry state across worker
  restart;
- bounded READY-marker discovery for normal operational ingest rather than
  full-receipt-root scanning on every polling pass;
- deterministic journal-driven rejected-generation retry ordering;
- reconcile conflict that fails the worker closed;
- host-local singleton `flock()` protection acquired before PostgreSQL access;
- PostgreSQL availability reconnect/backoff with runtime-boundary revalidation
  before ingest resumes;
- adaptive authoritative operational repair reconciliation; and
- permanent systemd service packaging with bounded restart behavior and
  fail-closed permanent configuration/database-boundary errors.

The accepted Phase 3 topology still has deliberate deployment boundaries that
administrative documentation must not hide:

- one active backend ingest-worker host per deployment;
- the accepted worker remains source-scoped through `-source`;
- cross-backend HA/failover requires a future authoritative distributed lock or
  lease before multiple backend hosts may contend for ingest ownership; and
- the administrative commands remain technical operating surfaces rather than
  the final product/query UX.

These boundaries are not permission to bypass the recorder authority path or to
introduce ad-hoc filesystem discovery.

---

## No False Simplicity

Administrative interfaces must not hide:

- continuity gaps;
- checkpoint state;
- partial or incomplete collection;
- degraded source coverage;
- privilege-boundary failures;
- source-specific ambiguity;
- relational pending/conflict/rejection state;
- missing typed projections;
- operating-system or database errors that materially explain a failure; or
- FI's own recovery or reconciliation actions.

A simplified summary may be shown first, but the underlying technical state must
remain directly available to the administrator.

---

## Stable Truth Across Interfaces

The product UX and administrative interfaces may use different language and
different levels of detail, but they do not maintain separate truths.

```text
                 FI Historical Truth
                        |
           +------------+------------+
           |                         |
           v                         v
      Product / Query UX       Administrative CLI
           |                         |
  Environment questions        FI operation questions
           |                         |
  What happened?               What source was used?
  Why?                         What checkpoint advanced?
  Who has access?              What Windows operation failed?
  What changed?                What generation was materialized?
           |                   What receipt/transfer identity bound it?
           +------------+------------+
                        |
                  SAME FI TRUTH
```

An authorized user may drill from a product answer into deeper FI source facts.
An administrator may start directly at those source and runtime facts. Neither
interface is allowed to contradict the authoritative history or hide known
uncertainty.

---

## Engineering Guidance

New administrative commands, diagnostic modes, validation tools, and local
runtime status output should be reviewed against this contract.

If an engineering choice makes an administrative interface easier to read but
removes information required to diagnose or verify FI, the information should be
restored or made directly accessible.

If an engineering choice exposes internal implementation detail that is not
needed to operate or verify FI, that detail does not become mandatory merely
because it exists.

The goal is precise operational transparency, not uncontrolled debug output.
