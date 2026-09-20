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

FI is currently focused on **Phase 3 / Gate 3 — Ingest & Recorder**.

**Phase 1 / Gate 1: COMPLETE — PASS**

**Phase 2 / Gate 2: COMPLETE — PASS**

**Phase 3 / Gate 3: ACTIVE — ACCEPTANCE IN PROGRESS**

Phase 3 has moved beyond initial design. The relational PostgreSQL foundation,
typed materialization path, recorder-aware reconciliation/inventory, and live
sequential Go ingest worker are implemented and have passed the current
correctness gates. Gate 3 is not yet closed.

Current Phase 3 checkpoint:

```text
49-table relational foundation          PASS
No JSON/JSONB/XML storage shortcut      PASS
13 typed record-kind projectors         PASS
Generation-atomic ingest                PASS
Receipt/transfer identity binding       PASS
Typed-projection completeness           PASS
Duplicate-safe AlreadyAccepted          PASS
Rejected-generation rollback            PASS
Volume-qualified NTFS/USN identity      PASS
Read-only reconcile/inventory           PASS
Live Go ingest worker                   PASS for validation
Fresh 250K relational acceptance        IN PROGRESS
Authoritative record-kind proof         12/13
USNContinuityGap receiver/DB proof      OUTSTANDING
Permanent worker hardening              OUTSTANDING
Gate 3                                  NOT YET CLOSED
```

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
- a governed-root/current-state lane with sequential supporting-source refresh;
- an independent USN catch-up lane for established continuous checkpoints,
  defaulting to 10 minutes and configurable through `FI_SERVICE_USN_EVERY`;
- an independent Windows Security lane, defaulting to one minute and configurable
  through `FI_SERVICE_WINDOWS_SECURITY_EVERY`, with bounded EventRecordID
  windows, immediate backlog drain, durable verification before checkpoint
  advancement, and Security-specific continuity-gap recovery;
- a non-administrative `FICollector` service identity;
- a separate privileged `FIUSNReader` helper exposing only bounded
  `QueryJournal`, `ReadJournal`, `CheckContainment`, and `ReadSACL` operations;
  and
- local named-pipe authentication using the enabled
  `NT SERVICE\FICollector` service SID.

Windows Server 2016 build `14393` and Windows Server 2019 build `17763` have
completed exact Gate 1 acceptance, including the current
four-operation broker and live `ReadSACL` path.

The underlying split-privilege Windows behavior is also characterized on Server
2022 `20348` and Server 2025 `26100`, but those earlier findings do not substitute
for exact Gate 1 acceptance.

Current Gate 1 status:

```text
Server 2016 / 14393    COMPLETE
Server 2019 / 17763    COMPLETE
Server 2022 / 20348    COMPLETE
Server 2025 / 26100    COMPLETE
```

Gate 1 closure completed the remaining **cross-version acceptance and source-impact characterization** work:

- exact Gate 1 acceptance on Server 2022 and 2025;
- repeated representative performance/source-impact measurement where needed;
- production interval/cadence characterization from accumulated measurements;
  and
- final Gate 1 result-record review across the intended exact release/build set.

Gate 1 is complete. Phase 2 begins at the finalized, verified, published local-spool boundary.

---

### Phase 1 closeout

Final source-impact acceptance included a `100,000`-file / `122.344-GiB`
onboarding campaign with configured collection outcome `Complete`.

The source-side operating rule is that host availability and durable FI state
take priority over maintaining nominal cadence.

**Phase 1 / Gate 1: COMPLETE — PASS**

**Phase 2 / Gate 2: COMPLETE — PASS**

Phase 2 closeout includes generation freezing, `fi-generation-canonical/0.1`,
zstd encoding, signed generation descriptors, FIGT transport, durable receiver
generation custody, semantic generation recorder receipts, exact `recorded` /
`already_recorded` acknowledgement binding, sender retirement only after exact
acknowledgement, startup recovery, and acknowledged-generation reclamation.

Integrated coverage established lost-acknowledgement, retry, duplicate,
conflicting-identity, revocation, bounds, startup, retirement, and reclaim
behavior. Live Server 2016 campaigns established receiver-outage backlog
retention/recovery, sender interruption recovery, measured source impact during
backlog drain, and cross-root independent-USN behavior after remediation in
`41906af`.

The post-Gate-1 250K randomized nested campaign is retained as
engineering/resilience characterization. Its strict clean onboarding acceptance
was intentionally interrupted during fault injection and is not rewritten as a
clean scale PASS.

That campaign also exposed two source-runtime scheduling defects that were
remediated without changing FI's source-truth rules. Cross-root USN work was
separated with governed-root-scoped synchronization, and Windows Security was
moved to its own sequential service worker so a multi-hour root operation cannot
strand the Security checkpoint. On 2026-09-20 the Security worker remained inside
the retained Server 2016 Security-log window with the lab log returned to 20 MiB
and durably selected a controlled pair of Event ID 4719 records before advancing
its checkpoint. The same real controlled source record family was subsequently
accepted by the Phase 3 receiver/relational path. This remains post-Gate-1
resilience characterization, not a revision of the original Gate 1 acceptance
result and not a universal Security-log sizing claim.

Replay at the Phase 2 boundary is defined as exact generation re-delivery:
identical durable state is idempotent / `already_recorded`, while conflicting
bytes for the same generation identity fail closed. The final generation
protocol does not use a separate monotonic security sequence; earlier
`sequence conflict` wording is retired.

See `docs/performance/PHASE-2-GATE-2-CLOSEOUT.md`.


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

Verify transported FI material and write the resulting typed historical records
to the FI relational System-of-Record materialization while preserving the
immutable Phase 2 recorder authority that authorized the generation.

The implemented Phase 3 path now includes:

- a 49-table typed PostgreSQL foundation;
- zero JSON/JSONB/XML database-storage shortcuts;
- the append-only `fi_ingest` runtime boundary;
- typed projectors for all 13 current collector record kinds;
- generation-atomic ingest;
- receipt/transfer/batch/record reconciliation;
- typed-projection completeness checks;
- append-only ingest-journal outcomes;
- duplicate-safe `AlreadyAccepted` handling;
- conflict detection and source-record rejection rollback;
- volume-qualified NTFS/USN identity;
- recorder-aware read-only reconciliation/inventory; and
- a sequential Go live-ingest worker used for the current acceptance campaign.

Accepted, rejected, failed, incomplete, duplicate, and conflicting ingest
actions leave journal history appropriate to their outcome.

The remaining Gate 3 work is acceptance/hardening, not a relational redesign:
finish the fresh 250K relational campaign, close authoritative
`USNContinuityGap` receiver/database proof, harden the permanent ingest worker,
and run the final controlled service/database interruption and recovery cases.

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
