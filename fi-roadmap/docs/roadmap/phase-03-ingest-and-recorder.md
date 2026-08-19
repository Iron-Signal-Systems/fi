# Phase 3 — Ingest & Recorder

## Purpose

Turn transported FI material into immutable FI System of Record history.

Verification, acceptance/rejection decisions, recording, and journal outcomes are
one product boundary.

## Ingest Responsibilities

Phase 3 owns:

- decryption;
- source/signature verification;
- canonical decoding;
- schema/contract/version validation;
- governed-scope validation;
- relationship validation;
- duplicate/replay/conflict determination;
- outcome determination;
- authoritative record creation;
- immutable journal creation.

## Every Outcome Is Recorded

Accepted input produces the applicable authoritative FI record and journal
history.

Rejected input still produces immutable rejection/journal history.

Failed or interrupted processing produces an immutable failed/incomplete journal
state.

Nothing material disappears because it failed validation.

A rejection record should preserve bounded identifying information sufficient to
explain what was received, from which source, when, what validation failed, why,
and which package/record/digest/version was involved where determinable.

FI does not blindly persist arbitrary hostile or oversized rejected input in full.

## Write-Once Rule

If an authoritative FI record is written to the FI System of Record:

> **that is it — it is write-once.**

Normal runtime operation does not update, overwrite, or delete the record.

Later observations, corrections, analysis, classification, or changed conclusions
are new related records.

## Representative Record Families

The final schema may evolve, but the model is expected to include relationships
among records such as:

```text
FileObject
FileObservation
StreamObservation
StorageObservation
PathObservation
SecurityObservation
ShareObservation

DirectoryIdentityRecord
AccessAnalysisRecord

ActivityRecord
JournalRecord
ContinuityRecord

ClassificationResult
```

Current-state projections are derived from these records and are not authoritative
history.

## Journal Requirements

The FI operation journal must allow an auditor or investigator to determine what
FI did at material ingest boundaries: received, verified, accepted, rejected,
failed, retried, conflicted, or completed.

## Gate 3 — Authoritative Record & Journal Integrity

Gate 3 proves:

- valid input is recorded correctly;
- rejected input creates durable history;
- failed/incomplete ingest is visible;
- duplicate delivery is safe;
- conflicting material is visible;
- authoritative records are write-once;
- normal runtime authority cannot overwrite/delete history;
- relationships remain reconstructable;
- crash/retry behavior does not create ambiguous history;
- backup/restore preserves the authoritative record and journal.
