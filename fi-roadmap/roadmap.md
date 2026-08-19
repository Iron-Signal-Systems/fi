# FI Roadmap

## Purpose

File Intelligence (FI) is a historical file-intelligence system that records the
state, security, access, activity, and meaning of governed files as immutable
history.

The same FI history supports help desk, application support, administrators,
security, disaster recovery, management/compliance, audit, and forensic
investigation.

## Roadmap Rules

- FI operates only on explicitly configured governed roots.
- Authoritative FI records are write-once.
- Every material FI action and outcome has an immutable journal record.
- FI distinguishes `Observed`, `Derived`, `Classified`, `Unknown`, and `Incomplete`.
- Customer source-file content never travels through normal FI record transport.
- AD identity collection is performed via gMSA, producing versioned directory identity records.
- Current-state views are rebuildable projections of immutable history.

---

## Phase 1 — Windows File & Identity Intelligence

Establish the complete source-side intelligence model for governed Windows/NTFS
roots. Baseline files, deep NTFS state, ADS/streams, security, shares, local and
directory identity, Windows activity, continuity, and ongoing change-driven
re-observation.

**Gate 1 — Source Intelligence & Continuity:** prove FI can establish and
continuously maintain trustworthy governed-source history without silently losing
coverage.

[Phase 1 details](docs/roadmap/phase-01-windows-file-and-identity-intelligence.md)

---

## Phase 2 — Secure Record Transport

Move FI records from Windows source custody to durable backend custody with
authenticated, encrypted, retry-safe, duplicate-safe transport. A record is either
durably received or remains safely queued at its source.

**Gate 2 — Secure Durable Record Transfer:** prove transport cannot ambiguously
lose FI history across failures, retries, restarts, or network interruption.

[Phase 2 details](docs/roadmap/phase-02-secure-record-transport.md)

---

## Phase 3 — Ingest & Recorder

Verify transported FI material and write the resulting history to the FI System
of Record. Accepted, rejected, failed, interrupted, and conflicting ingest actions
all leave immutable journal history.

**Gate 3 — Authoritative Record & Journal Integrity:** prove authoritative FI
history is write-once, reconstructable, and every material ingest outcome is
preserved.

[Phase 3 details](docs/roadmap/phase-03-ingest-and-recorder.md)

---

## Phase 4 — Classification & Enrichment

Add meaning to already-recorded file and stream observations through the
**Separate Protected Classification Stream**. Source content is inspected
transiently and is not persisted on the Linux FI system.

**Gate 4 — Protected Classification & Enrichment:** prove bounded source-content
inspection, exact observation correlation, safe failure, and immutable
classification history.

[Phase 4 details](docs/roadmap/phase-04-classification-and-enrichment.md)

---

## Phase 5 — Projection, Query & Protected User Experience

Turn the same immutable FI history into useful intelligence for help desk,
developers, administrators, security teams, DR, management/compliance, auditors,
and forensic investigators.

**Gate 5 — Operational, Security, DR & Forensic Intelligence:** prove FI can solve
representative real-world questions at different levels of depth from the same
underlying historical truth.

[Phase 5 details](docs/roadmap/phase-05-projection-query-and-user-experience.md)

---

## Phase 6 — Integrated Deployment & Release

Combine the accepted Windows, transport, recorder, classification, query, user
experience, operational, backup, recovery, upgrade, and release capabilities into
a reproducible supported product.

**Gate 6 — Integrated Release Acceptance:** prove FI survives representative
installation, failure, recovery, upgrade, rollback, DR, and investigation
scenarios without losing the integrity or explainability of its history.

[Phase 6 details](docs/roadmap/phase-06-integrated-deployment-and-release.md)

---

## Dependency Structure

```text
Phase 1
Windows File & Identity Intelligence
        |
      Gate 1
        |
        v

Phase 2
Secure Record Transport
        |
      Gate 2
        |
        v

Phase 3
Ingest & Recorder
        |
      Gate 3
        |
        v

FI SYSTEM OF RECORD
       / \
      /   \
     v     v

Phase 4                 Phase 5
Classification          Projection, Query &
& Enrichment            Protected User Experience
     |                         |
   Gate 4                    Gate 5
     |                         |
     +------------+------------+
                  |
                  v

              Phase 6
     Integrated Deployment & Release
                  |
                Gate 6
```

## Roadmap Control Rule

A new phase is created only when work introduces a genuinely separate product,
runtime, trust, durability, or release boundary that cannot cleanly remain inside
an existing phase.

Implementation mechanics, components, test campaigns, and work packages stay
inside the phase that owns their outcome.
