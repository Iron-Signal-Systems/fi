# FI Roadmap

## Purpose

File Intelligence (FI) is a historical file-intelligence system that records the
state, security, access, governed-file activity, relationships, and later meaning
of governed files as immutable history.

The same FI history supports help desk, application support, administrators,
security, disaster recovery, management/compliance, audit, and forensic
investigation.

## Roadmap Rules

- FI operates only on explicitly configured governed roots.
- Authoritative FI records are write-once.
- Every material FI action and outcome has immutable journal history.
- FI distinguishes `Observed`, `Derived`, `Classified`, `Unknown`, and
  `Incomplete`.
- Customer source-file content never travels through normal FI record transport.
- AD identity collection is performed through the Windows collector's deployed
  service identity, intended to be a gMSA.
- Current-state views are rebuildable projections of immutable history.
- FI collects Windows activity because it concerns governed objects, not to act
  as a general Windows event collector or SIEM.
- Source collectors preserve source facts and may perform deterministic decoding
  of documented values from the same source. Cross-source correlation,
  effective-access conclusions, intent, causality, and reconstruction of missing
  history belong outside the source collector.

---

## Current Development Focus

FI is currently focused on **Phase 1 / Gate 1**.

The major Phase 1 architecture is now established:

- governed NTFS baseline collection;
- NTFS identity, metadata, streams, reparse, security, hashing, and bounded
  content-prefix observation;
- durable local spool creation and verification;
- persistent USN and Windows Security checkpoints;
- normal checkpoint continuation;
- explicit USN and Windows Security continuity-gap history and reconciliation;
- historical containment based on bounded NTFS object identity rather than
  stale-path trust;
- major operation lifecycle journaling;
- bounded SMB/local/AD supporting-source refresh;
- a persistent Windows service runtime;
- service scheduling for configured collection and supporting-source refresh;
- a non-administrative `FICollector` service identity;
- a separate privileged `FIUSNReader` helper exposing only bounded
  `QueryJournal`, `ReadJournal`, `CheckContainment`, and `ReadSACL` operations;
  and
- local named-pipe authentication using the enabled
  `NT SERVICE\FICollector` service SID.

Windows Server 2016 build `14393` has completed exact Candidate #4 Gate 1
acceptance, including the current four-operation broker and live `ReadSACL`
path.

The underlying split-privilege Windows behavior is also characterized on Server
2019 `17763`, Server 2022 `20348`, and Server 2025 `26100`, but those earlier
findings do not substitute for exact Candidate #4 acceptance.

Current Candidate #4 status:

```text
Server 2016 / 14393    COMPLETE
Server 2019 / 17763    PENDING
Server 2022 / 20348    PENDING
Server 2025 / 26100    PENDING
```

Remaining Gate 1 work is primarily **cross-version acceptance and production
characterization**, not new source architecture:

- exact Candidate #4 acceptance on Server 2019, 2022, and 2025;
- repeated representative performance/source-impact measurement where needed;
- production interval/cadence characterization from accumulated measurements;
  and
- final Gate 1 result-record review across the intended exact release/build set.

Gate 1 remains open overall until those boundaries are proved.

---

## Phase 1 — Windows File & Identity Intelligence

Establish and continuously maintain source-side history for explicitly governed
Windows/NTFS roots.

Phase 1 owns:

- baseline file and directory observation;
- NTFS identity and state;
- ADS/streams;
- security descriptors and ACLs;
- share exposure and share security;
- local and directory identity source facts;
- bounded refresh of slower-changing SMB/local/AD supporting source facts;
- USN-driven change detection and re-observation;
- governed-file access/activity source facts;
- source checkpoints and continuity assessment;
- local durable spool creation and verification;
- explicit gap/reconciliation state;
- source-side operation accountability; and
- the local Windows runtime required to perform those source-side functions.

Phase 1 does **not** own general Windows telemetry, backend correlation,
downstream transport acknowledgement, or protected classification content
streaming.

**Gate 1 — Source Intelligence & Continuity:** prove FI can establish and
continuously maintain trustworthy governed-source history without silently losing
coverage.

[Phase 1 details](docs/roadmap/phase-01-windows-file-and-identity-intelligence.md)

---

## Phase 2 — Secure Record Transport

Move FI records from Windows source custody to durable backend custody with
authenticated, encrypted, retry-safe, duplicate-safe transport.

A record is either durably received or remains safely queued at its source.

Only after durable downstream acknowledgement may the source transport remove the
acknowledged local spool batch.

**Gate 2 — Secure Durable Record Transfer:** prove transport cannot ambiguously
lose FI history across failures, retries, restarts, or network interruption.

[Phase 2 details](docs/roadmap/phase-02-secure-record-transport.md)

---

## Phase 3 — Ingest & Recorder

Verify transported FI material and write the resulting history to the FI System
of Record.

Accepted, rejected, failed, interrupted, and conflicting ingest actions leave
immutable journal history.

**Gate 3 — Authoritative Record & Journal Integrity:** prove authoritative FI
history is write-once, reconstructable, and every material ingest outcome is
preserved.

[Phase 3 details](docs/roadmap/phase-03-ingest-and-recorder.md)

---

## Phase 4 — Classification & Enrichment

Add meaning to already-recorded file and stream observations through the
**Separate Protected Classification Stream**.

Phase 4 owns the protected streaming/read-broker path used to obtain bounded
transient source content for classification. Source content is not carried by the
normal FI record transport and is not persisted on the Linux FI system.

**Gate 4 — Protected Classification & Enrichment:** prove bounded source-content
inspection, exact observation correlation, safe failure, and immutable
classification history.

[Phase 4 details](docs/roadmap/phase-04-classification-and-enrichment.md)

---

## Phase 5 — Projection, Query & Protected User Experience

Turn immutable FI history into useful intelligence for help desk, developers,
administrators, security teams, DR, management/compliance, auditors, and forensic
investigators.

**Gate 5 — Operational, Security, DR & Forensic Intelligence:** prove FI can solve
representative real-world questions at different levels of depth from the same
underlying historical source facts.

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
