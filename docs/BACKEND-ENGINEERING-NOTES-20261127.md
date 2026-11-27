# FI Transport, Ingest, and Engineering History Notes

> **Reference status — historical snapshot (November 27, 2026).**
> Relocated from the original root README at commit [`1d16760bd137`](https://github.com/Iron-Signal-Systems/fi/commit/1d16760bd1375b9cd37f7f98472d944593e414aa).
> This preserves historical technical explanations and milestone records; older phase descriptions and diagrams must not be treated as instructions for deploying the current C220 service.
>
> **Current authorities:** [C220 backend architecture](architecture/FI-C220-CURRENT-BACKEND.md) · [C220 live runtime lock](deployment/C220-LIVE-RUNTIME-LOCK-20261127.md) · [C220 operator reference](deployment/C220-OPERATOR-REFERENCE.md) · [FI roadmap](../fi-roadmap/roadmap.md) · [Published projection contract](PUBLISHED-FI-PROJECTION-CONTRACT.md).

The historical Gate 3 worker and other retired development paths in these notes are **not** the current receiver/C1/SoR runtime. C1 is an internal backlog and recovery-processing facility, not an end-user feature or product selling point.

## Generation transport and custody — November 2026 snapshot

Phase 2 now includes generation-based transport for published Phase 1 spool
material.

A generation is built from an exact frozen set of published batches, represented
canonically as `fi-generation-canonical/0.1`, compressed with zstd, and bound
to a signed generation descriptor. The wire object is a FIGT transfer whose
descriptor binds source identity, generation identity, canonical byte count and
SHA-256, encoded byte count and SHA-256, and artifact count.

The receiver first establishes durable FIGT custody, then semantically validates
the decoded canonical generation and durably publishes an immutable recorder
receipt. The acknowledgement returned to the sender is only valid when it binds
the exact durable transfer identity and has outcome `recorded` or
`already_recorded`.

The sender retires local generation custody only after that exact acknowledgement
matches the generation descriptor, metadata identity, transfer byte count, and
transfer SHA-256. Lost acknowledgement, receiver restart, sender retry, duplicate
delivery of the same bytes, startup recovery, and post-acknowledgement
reclamation are covered by the generation transport tests integrated in Phase 2.

Live Phase 2 fault campaigns also retained source custody through approximately
10-minute and 60-minute receiver outages and through a sender interruption. The
one-hour receiver outage retained seven generations / 51,538 records; backlog
reached receiver custody within approximately 8m53s after receiver service
returned, without manual sender repair.

Replay protection at this boundary is generation-identity based: exact
re-delivery is duplicate-safe and may return `already_recorded`; the same
generation identity with conflicting bytes fails closed. Phase 2 does not use a
separate monotonic security sequence.

The durable generation receipt used at this boundary is a Phase 2 custody and
acknowledgement fact. It is not by itself the complete Phase 3 FI System of
Record. Phase 3 now consumes that immutable receipt and reopens the exact durable
FIGT object to produce typed relational materialization bound back to the same
receipt and transfer identity.

---

---

## Historical Gate 3 relational ingest and recorder materialization (September 2026)

**Historical record only:** the sequential Linux `fi-ingest-worker` described below was replaced as the active C220 backend by FreeBSD `fi-c1-sor-live`. The present C220 operation is documented above. The old implementation's acceptance history must not be used as today's startup or deployment procedure.

Phase 3 / Gate 3 is complete. The accepted relational implementation is
`fi-postgresql-relational-ingest/0.2` and establishes the authoritative typed
PostgreSQL FI System of Record from the immutable Phase 2 recorder authority.
Recorder custody remains the accepted source representation and authorization
basis for each generation.

The implemented path is:

```text
immutable generation recorder receipt
        |
        v
exact durable FIGT custody
        |
        v
revalidate custody + trust + transfer + collector semantics
        |
        v
single-generation PostgreSQL transaction
        |
        +-- recorded_generation
        +-- source_batch
        +-- source_record
        +-- typed relational projections
        +-- append-only ingest_journal terminal outcome
```

The current database boundary verifies:

- exactly 49 FI relational tables;
- no JSON, JSONB, or XML relational storage columns;
- the `fi_ingest` runtime identity;
- no normal `UPDATE`, `DELETE`, or `TRUNCATE` authority over
  `fi.source_record`;
- exact receipt and FIGT transfer SHA-256 binding;
- declared and actual batch/data-byte/record totals;
- typed-projection completeness; and
- duplicate-safe `AlreadyAccepted` behavior for an exact authoritative
  generation.

The relational ingester accepts the complete current collector-emitted set of 13
record kinds:

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

`fi-ingest-reconcile` is deliberately read-only. Its plan mode compares immutable
recorder receipts to PostgreSQL state; inventory mode reopens only pending exact
recorded generations through FI's custody loader and reports validated record-kind
coverage without database writes.

The permanent sequential Go ingest worker performs live receipt discovery and
relational ingest for the accepted Phase 3 runtime. The worker uses bounded
READY-marker discovery for normal work, durable ingest-journal retry state for
rejected generations, a host-local singleton lock, and adaptive authoritative
repair reconciliation.

The Phase 3 singleton lock is intentionally host-local. The accepted operating
contract supports one active backend ingest-worker host per deployment.
Distributed ownership is independent of Windows source count; the accepted
Phase 3 worker is source-scoped through `-source`. Final multi-source backend
topology is a separate deployment concern. Multi-backend HA/failover requires a
future authoritative distributed coordination mechanism such as a PostgreSQL
advisory lock or database-backed lease before multiple backend hosts may contend
for ingest ownership.

The adaptive repair path starts conservatively after worker startup: six clean
hourly full operational reconciliations, one clean 12-hour reconciliation, then
24-hour steady-state repair. A repair anomaly returns the worker to hourly
validation. READY-notified pending work and generations already governed by
durable `SOURCE_RECORD_REJECTED` retry state do not count as repair anomalies.

PostgreSQL reconnect/backoff and permanent Linux ingest-worker service
packaging completed controlled runtime acceptance. Final unfiltered
authoritative reconciliation on 2026-09-24 reported 1,342 recorder receipts,
1,342 accepted generations, zero pending, zero conflict, and zero READY
markers. Phase 3 / Gate 3 is complete.

Authoritative receiver/database proof is complete for all 13 current relational
record kinds, including `USNContinuityGap`. See
the historical Gate 3 acceptance record (retired from the current branch) and
the historical Linux ingest-worker operating contract (retired from the current branch).

---

---

## Historical Phase 1–3 closeout and Phase 4 planning

Phase 1 / Gate 1 is complete for the accepted source-intelligence boundary.

Windows Server 2016 build `14393` has completed the exact Gate 1 acceptance
campaign. That campaign includes:

- reproducible two-service/two-gMSA deployment and exact deployment acceptance;
- service, executable, configuration, state, spool, and service-token boundary
  validation;
- local and true remote-SMB governed-file activity coverage;
- collector restart, spool-write-denial, governed-root-unavailable, and bounded
  dependency-observation exercises;
- bounded performance, churn, spool-pressure, and operation/resource
  characterization;
- historical containment without stale-path trust;
- content-prefix / magic-byte durable custody; and
- the four-operation `FIUSNReader` broker, including live exact-object
  `ReadSACL`, while `FICollector` remains non-administrative.

Windows Server 2019 build `17763` has also completed exact Gate 1
acceptance. Its build-sensitive acceptance campaign covered deployment and ACL
boundaries, the actual collector service-token boundary, local and true remote
SMB activity/Security custody, live `ReadSACL`, collector and helper outage
catch-up, bounded AD-LDAPS dependency observation, and bounded baseline/resource
observation. The detailed record is
[`docs/GATE-1-SERVER-2019.md`](../docs/GATE-1-SERVER-2019.md).

The underlying Windows split-privilege behavior is characterized and green for
the split-privilege acceptance baseline on:
```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
Windows Server 2025    10.0.26100
```

Exact Gate 1 acceptance is:

```text
Windows Server 2016    10.0.14393    COMPLETE
Windows Server 2019    10.0.17763    COMPLETE
Windows Server 2022    10.0.20348    COMPLETE
Windows Server 2025    10.0.26100    COMPLETE
```

Gate 1 closure subsequently completed:

- exact Gate 1 acceptance on Server 2022 and 2025;
- repeated representative performance/source-impact measurement across the
  intended supported deployment set where needed;
- production collection/supporting-refresh cadence selection from accumulated
  measurements; and
- final review of the Gate 1 result record across the intended release/build set.

The Gate 1 test deployment uses `1m` collection and `30m` supporting-source
refresh only as an acceptance configuration. Gate 1 does not declare one universal production cadence; pilot and production intervals remain deployment-specific and measurement-driven.

Gate 1, Gate 2, and Gate 3 are complete.

**Phase 2 / Gate 2 — Secure Record Transport: COMPLETE — PASS**

**Phase 3 / Gate 3 — Ingest & Recorder: COMPLETE — PASS**

FI's next planned development boundary is **Phase 4 — Classification &
Enrichment**.

Phase 2 closeout includes durable FIGT custody, semantic recorder receipts,
exact acknowledgement-before-retirement, retry/duplicate/conflict safety,
receiver and sender interruption recovery, and the root-isolation remediation
validated during the 250K resilience campaign.

Phase 3 established the relational ingest foundation, typed projectors,
recorder-aware reconciliation/inventory, volume-qualified NTFS/USN identity,
all 13 current authoritative record-kind proofs, bounded READY-driven ingest,
durable rejected-generation retry state, host-local singleton protection,
controlled crash/restart recovery, adaptive operational repair reconciliation,
PostgreSQL reconnect/backoff, and the permanent Linux ingest-worker service.
The fresh 250K relational closeout, permanent service acceptance, and final
authoritative reconciliation completed Gate 3 on 2026-09-24.

See:

- `docs/performance/PHASE-2-250K-RANDOM-NESTED-ONBOARDING-REPORT.md`
- `docs/performance/PHASE-2-GATE-2-CLOSEOUT.md`
- the historical Gate 3 acceptance record (retired from the current branch)

No additional Phase 1 or Phase 2 subsystem should be added unless a concrete
accepted requirement demonstrates that the corresponding boundary is incomplete.

---

### Phase 1 / Gate 1 final closeout

Final source-impact acceptance used FICollector SHA-256:

```text
5C2A8FA07D9AF6F9762F7ED62975E6E6247CCF50325CF3B24211229596E90DB0
```

The final onboarding acceptance covered `100,000` files totaling
`131,365,642,498` bytes (`122.344 GiB`) with `ConfiguredCollection: Complete`.

```text
Collection elapsed:          10,048.082 sec
Peak whole-host CPU:         36.91 %
Peak combined FI CPU:        11.14 % of host
Peak combined FI RAM:        36.21 MiB
Minimum host available RAM:  7,069.99 MiB
Peak host memory load:       21.00 %
Peak Y: logical read:        34.842 MiB/s
Peak Y: logical write:       0.723 MiB/s
Peak observed Y: queue:       3
Spool files:                 6,320
Spool bytes:                 870,946,901
Manifest record count:       202,012
```

Y: values are Windows logical-disk measurements, not per-process physical-disk
byte counters.

The accepted source-side rule is that host availability and durable FI collection
state take priority over maintaining nominal FI cadence.

Phase 2 begins at the finalized, verified, published local spool boundary.

---

## Historical architecture overview

```text
             Windows File & Identity Collection
                         |
                         v
                 Durable Local Spool
                         |
                         v
                  Secure Transport
                         |
                         v
              Durable FIGT Custody
                         |
                         v
           Immutable Recorder Receipt
                         |
                         v
             Phase 3 Relational Ingest
                         |
                         v
          PostgreSQL FI System of Record
                     AUTHORITATIVE
                         |
                         | read only
                         v
                 Correlation / Projector
                         |
                         v
                Candidate FI Projection
                         |
                     validation
                         |
                         v
                Published FI Projection
                   REBUILDABLE / QUERY
                         |
                         v
                    Query / API
                         |
                         v
                         UX
```

The collector observes.

The authoritative backend preserves accepted FI history.

Published FI Projections present validated, rebuildable, query-optimized
representations of that history without becoming a second source of truth.

See [`docs/PUBLISHED-FI-PROJECTION-CONTRACT.md`](../docs/PUBLISHED-FI-PROJECTION-CONTRACT.md)
for the publication, freshness, rebuild, and authority contract.

FI remains non-remediating toward the systems it observes.

---

---

## Core design principles

- The file is the primary subject of FI.
- File identity must not depend solely on pathname.
- FI operates only on explicitly governed roots.
- FI does not intentionally change governed customer state during normal
  collection.
- Preserve historical state instead of keeping only current state.
- Preserve native source information needed for later verification or
  reinterpretation.
- Keep observed, derived, classified, unknown, and incomplete information
  distinct.
- Never hide collection gaps or uncertainty.
- Never interpret a missing Windows activity record as proof that no activity
  occurred.
- Maintain relationships between files, storage, paths, shares, permissions,
  identities, governed-file activity, and time.
- Make historical records append-only.
- Keep normal customer source-file content outside the FI record path.
- Add classification only after the underlying file/stream observation exists.
- Prefer simple collectors that report source facts over collectors that make
  organizational decisions.
- Keep privileged Windows code narrow and obvious.
- Present the same FI truth at the appropriate depth: user-facing experiences
  answer environmental questions without requiring knowledge of FI internals,
  while administrative interfaces expose the technical detail required to
  operate and verify FI.

---
