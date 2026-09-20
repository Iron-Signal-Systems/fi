# Phase 3 — Ingest & Recorder

## Current Development Status

**ACTIVE — Phase 3 / Gate 3**

Phase 2 / Gate 2 completed on 2026-09-20.

The relational architecture and principal ingest path are implemented and under
acceptance. Gate 3 is **not closed**.

Current status:

| Area | Status |
|---|---|
| 49-table relational PostgreSQL foundation | PASS |
| No JSON/JSONB/XML relational storage shortcut | PASS |
| 13 collector record kinds accepted | PASS |
| Typed projector coverage for all 13 kinds | PASS |
| Exact recorder receipt / FIGT transfer identity binding | PASS |
| Generation-atomic relational ingest | PASS |
| Batch / byte / record reconciliation | PASS |
| Typed-projection completeness check | PASS |
| Duplicate-safe `AlreadyAccepted` path | PASS |
| Rejected-generation rollback and journal outcome | PASS |
| Volume-qualified NTFS/USN identity | PASS |
| Read-only recorder-aware reconcile/inventory | PASS |
| Live sequential Go ingest worker | PASS for validation |
| Fresh 250K relational acceptance campaign | IN PROGRESS |
| Authoritative receiver/database record-kind proof | 13/13 PASS |
| `USNContinuityGap` receiver/database proof | PASS |
| Permanent worker hardening / service deployment | OUTSTANDING |
| Gate 3 closure | NOT YET |

## Purpose

Turn transported FI material into immutable, reconstructable FI historical
records while preserving the exact authority and custody chain established by
Phase 2.

Verification, acceptance/rejection decisions, relational materialization, and
journal outcomes are one Phase 3 product boundary.

## Authority boundary

The Phase 2 `generationrecorder` semantically validates an exact canonical
generation and durably publishes an immutable receipt used by the
`recorded` / `already_recorded` acknowledgement contract.

That receipt remains the authority transition for the transported generation.
It is intentionally narrower than the full relational FI historical model.
Phase 3 does **not** replace that receipt with an ad-hoc filesystem scan or a
second transport authority.

The implemented Phase 3 path is:

```text
source spool / generation builder
        |
        v
sealed transport generation
        |
        v
FIGO offer -> FIGD decision -> exact FIGT transfer
        |
        v
receiver durable FIGT custody
/var/lib/fi/custody/generation
        |
        v
generation recorder reopens exact durable object
        |
        v
revalidate custody + trust + transfer + collector semantics
        |
        v
immutable recorder receipt
/var/lib/fi/custody/recorded
        |
        v
Phase 3 relational materialization
        |
        v
PostgreSQL typed historical records + append-only ingest journal
```

The recorded root contains immutable recorder receipts. It is not a source-JSONL
store. Relational ingest starts from the receipt, reopens the exact durable FIGT
object through FI's generation loader, and binds PostgreSQL state back to the
same receipt and transfer identities.

## Relational foundation

The current implementation uses PostgreSQL through runtime identity `fi_ingest`.
The runtime database check requires:

- exactly 49 FI relational tables;
- zero JSON, JSONB, or XML storage columns;
- required core tables including `recorded_generation`, `source_batch`,
  `source_record`, `ingest_journal`, and the typed source families; and
- no normal `UPDATE`, `DELETE`, or `TRUNCATE` authority over
  `fi.source_record`.

Current ingest version:

```text
fi-postgresql-relational-ingest/0.2
```

The relational schema is typed. JSON is decoded at the source-record boundary;
it is not retained as a database storage shortcut.

## Supported source-record kinds

The relational ingester accepts the complete current collector-emitted set:

```text
CollectorIdentity
DirectoryPrincipalSnapshot
FileObservation
LocalPrincipalSnapshot
NTFSCollectionError
SMBShareSnapshot
SupportingSourceCollectionError
USNContinuityGap
USNObjectObservation
USNReadBoundary
WindowsSecurityContinuityGap
WindowsSecurityCoverage
WindowsSecurityEvent
```

Each accepted `source_record` must have its corresponding typed relational
projection. A generation cannot become authoritative with missing typed
projections.

## Generation ingest semantics

A generation is ingested as one PostgreSQL transaction.

Phase 3 verifies or records:

- source and generation identity;
- immutable recorder receipt SHA-256;
- durable FIGT transfer SHA-256;
- declared generation batch/data-byte/record totals;
- actual inserted batch/data-byte/record totals;
- exact LF-terminated source-record bytes and SHA-256 lineage;
- source record version and supported record kind;
- typed record validation and projection; and
- zero missing typed projections before acceptance.

The accepted terminal ingest-journal record is written in the same transaction
as the authoritative generation materialization.

Exact re-delivery of an already-authoritative generation is idempotent and
returns `AlreadyAccepted`. Reuse of a generation identity with different receipt
or transfer identity fails closed as a conflict.

A source-record rejection rolls the generation transaction back. The terminal
journal outcome records `Rejected` with zero committed records rather than
leaving a partial authoritative generation.

## NTFS and USN identity

The Phase 3 relational model does not treat a file-reference number alone as a
global NTFS object identity.

USN object observations are tied to:

- the exact volume-qualified NTFS object identity; and
- the durable `USNReadBoundary` source record that established the read context.

This preserves the relationship between changed-object identity, volume,
read-boundary state, and the typed NTFS object used by later queries.

## Reconciliation and inventory

`fi-ingest-reconcile` is deliberately read-only. It has no reconciliation write
mode.

`-plan`:

- discovers only immutable deterministic `generation-*.record.json` receipts;
- compares receipt/transfer identity and declared totals to PostgreSQL;
- checks actual batch/data-byte/record totals;
- checks typed-projection completeness; and
- reports `Accepted`, `Pending`, or `Conflict`.

`-inventory` revalidates only pending generations through
`LoadRecordedGeneration`, then runs exact source-record preparation and reports
record-kind coverage without writing to PostgreSQL.

This is the supported reconciliation surface. FI does not infer canonical source
records by guessing filenames or extensions inside custody storage.

## Every material ingest outcome is recorded

The ingest journal preserves material outcomes such as:

- `Incomplete` / attempt started;
- `Accepted`;
- `AlreadyAccepted`;
- `Rejected`;
- `Failed`; and
- `Conflict`.

The journal records the attempt, source, generation, transfer identity, stage,
reason where applicable, and record counts where known.

Rejected or failed input does not become authoritative merely because some rows
were inserted before the failure; the transaction is rolled back.

## Write-once rule

If an authoritative FI record is written to the FI System of Record:

> **that is it — it is write-once.**

Normal runtime operation does not update, overwrite, or delete historical source
records.

Later observations, corrections, analysis, classification, or changed
conclusions are represented by new related records.

## Current live worker

`go/cmd/fi-ingest-worker` is the current live sequential Phase 3 consumer used
for acceptance work.

Implemented behavior includes:

- receipt/database reconcile planning;
- fail-closed handling of reconcile conflicts;
- sequential pending-generation ingest;
- bounded `-once` / `-max-attempts` validation modes;
- configurable polling interval;
- source-record rejection deferral; and
- continued processing of later pending generations after a deferred source
  rejection.

It is **not yet the permanent production service**.

Current hardening work still required:

- persist rejection retry suppression across worker restarts;
- replace full receipt-root rescans on every polling cycle with bounded or
  incremental discovery;
- formalize the long-term ordering policy when a rejected generation is
  bypassed;
- add singleton/advisory-lock behavior; and
- define production database-failure/backoff and supervisor behavior.

Parallel relational ingest is not part of the current accepted design.

## Current acceptance record

The fresh relational database campaign intentionally started from an empty
49-table schema and is re-materializing the active 250K source campaign through
the new relational path.

Current acceptance has proven, among other items:

- real generation ingest and idempotence;
- real rollback on a source-record rejection;
- the valid `Present` / zero-byte `ContentPrefix` case after correction;
- relationship reconstruction from a `FileObservation` into path, NTFS object,
  metadata, hashes, content prefix, streams, security, SACL/reparse state, and
  warnings;
- real `SupportingSourceCollectionError` relational materialization;
- real `WindowsSecurityEvent` relational materialization; and
- all 13 supported record kinds through authoritative receiver/database proof.

`USNContinuityGap` completed controlled source-side detection,
gap/baseline/catch-up reconciliation, normal Phase 2 transport, immutable
receiver custody, recorder receipt creation, and exact Phase 3 relational
materialization on 2026-09-20. The closing generation was
`20260920T224721.460692300Z-9b2a72230f46185b`, with `JournalIDChanged`, explicit
`Incomplete` coverage, and `CurrentStateBaselineAndUSNCatchUp` reconciliation.

This closes the record-family proof requirement at 13/13. Gate 3 remains active
for completion of the fresh 250K acceptance campaign, worker hardening,
failure/recovery acceptance, and permanent service deployment.

The running acceptance record is:

`docs/performance/PHASE-3-250K-RELATIONAL-INGEST-ACCEPTANCE.md`

## Gate 3 — Authoritative Record & Journal Integrity

Gate 3 closes only when FI demonstrates that:

- valid input is recorded correctly;
- rejected input creates durable history without partial authority;
- failed/incomplete ingest is visible;
- duplicate delivery is safe;
- conflicting material is visible and fails closed;
- authoritative records are write-once;
- normal runtime authority cannot overwrite/delete history;
- relationships remain reconstructable;
- crash/retry behavior does not create ambiguous history;
- backup/restore preserves the authoritative record and journal;
- all supported record kinds have authoritative end-to-end proof; and
- the permanent ingest runtime is hardened and accepted operationally.

Gate 3 remains active until those remaining acceptance items are complete.
