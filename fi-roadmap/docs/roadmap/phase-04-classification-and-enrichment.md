# Phase 4 — Classification & Enrichment

## Purpose

Add meaning and deeper interpretation to FI observations that are already present
in the System of Record.

Classification does not block or replace the underlying file or stream
observation.

Phase 4 begins with a bounded **Operational Telemetry Foundation** so FI can
measure source and backend behavior before the new protected content/classification
workload is introduced. Telemetry is an enabling work package; it does not change
Phase 4's product outcome or become file-history authority.

---

## Phase 4 Work Packages

```text
4A  Operational Telemetry Foundation
        |
        v
4B  Protected Classification Contracts
        |
        v
4C  Protected Classification Streaming Service
        |
        v
4D  Windows Bounded Content Reader
        |
        v
4E  Classification Engine
        |
        v
4F  Deep Inspection
        |
        v
4G  Classification Result Ingest
        |
        v
Gate 4 — Protected Classification & Enrichment
```

The work-package labels are implementation organization inside Phase 4. They are
not separate product phases or gates.

---

## 4A — Operational Telemetry Foundation

Telemetry answers:

> **What was FI and the infrastructure supporting FI doing while FI collected,
> transported, recorded, ingested, classified, or queried information?**

It does not answer FI's primary file-history question and does not become a
second System of Record.

The permanent telemetry design covers both Windows/source hosts and FI backend
hosts. It includes bounded host, storage, network, process, executable,
configuration, receiver/custody/ingest, PostgreSQL, repair/reconciliation, and
later classification operational measurements.

Telemetry uses a dedicated custody/receiver/recorder path and a separate
PostgreSQL telemetry database with separate authority from the FI System of
Record.

The controlling failure invariant is:

```text
TELEMETRY FAILURE
        MUST NOT BECOME
FI HISTORY FAILURE
```

The existing Windows operation `resourcejournal` remains useful for
operation-correlated resource history and is integrated conceptually with the
central telemetry plane rather than discarded.

Backend telemetry is retained for operational review rather than as infinite
historical authority. The design objective supports 30-day minimum, 60-day normal,
and 90-day preferred operational-review horizons; exact production retention and
rollup defaults remain subject to characterization.

Configuration and executable physical SHA-256 observations are first-class
telemetry facts. Exact configuration bytes and the canonical effective parsed
configuration identity remain separate observations.

See:

- [`../../../docs/PHASE-4-TELEMETRY-CONTRACT.md`](../../../docs/PHASE-4-TELEMETRY-CONTRACT.md)
- [`../../../docs/TELEMETRY-DATA-MODEL.md`](../../../docs/TELEMETRY-DATA-MODEL.md)
- [`../../../docs/TELEMETRY-TRUST-BOUNDARY.md`](../../../docs/TELEMETRY-TRUST-BOUNDARY.md)
- [`../../../docs/FI-CONFIG-2.0-CONTRACT.md`](../../../docs/FI-CONFIG-2.0-CONTRACT.md)

No telemetry service, database schema, configuration 2.0 parser, or privileged
telemetry reader is claimed implemented merely because these contracts exist.

---

## Separate Protected Classification Stream

Phase 4 owns the **Separate Protected Classification Stream**, including the
protected streaming/read-broker service required to obtain bounded source
content.

This path is intentionally separate from normal FI record transport.

Conceptually:

```text
recorded FileObservation / StreamObservation
        |
classification request
        |
        v
Classification Engine
        |
        v
Protected Classification Streaming Service
        |
        v
Windows bounded read/broker path
        |
        v
bounded transient source content
        |
        v
Classification Engine
        |
        v
ClassificationResult
        |
        v
Ingest & Recorder
        |
        v
FI System of Record
```

The normal Phase 1 Windows record collector does not own this content-streaming
boundary.

---

## Classification Scope

Classification may use:

- file signatures;
- extension/signature relationships;
- structured format interpretation;
- metadata;
- bounded content inspection;
- hash lists;
- policy rules;
- executable/script recognition;
- archive/container inspection;
- ADS/stream inspection; and
- recursive inspection of nested structured content to a bounded policy-defined
  depth.

This may identify executables, DLLs, scripts, PowerShell, batch, JavaScript,
documents, archives, databases, configuration, encrypted/opaque material,
unknown binary content, or other governed categories.

Deep inspection limits belong to explicit configuration/policy. They are not
inferred from file type or silently expanded during runtime.

---

## Content Persistence Rule

The FI backend may transiently process bounded source-content buffers.

It does not persist source content as:

- a copied source file;
- a complete temporary file;
- database BLOB;
- object-store copy;
- backend spool; or
- persistent classification cache.

Normal FI record transport never becomes a source-file copy mechanism.

---

## Classification History

Every result references the exact FileObservation or StreamObservation examined.

Results retain applicable classifier version, policy version, time, result,
completeness, and error state.

Reclassification creates a new result. Earlier classifications remain immutable
history.

Every classification attempt also produces journal state.

Operational classification telemetry such as queue depth, CPU/RAM/I/O,
throughput, throttling, content-read byte totals, and classifier failures belongs
to the telemetry database rather than the authoritative classification result.

---

## Classification and Projection Freshness

Classification may advance independently from base file/history ingest.

A slower classifier must not invalidate or unnecessarily block publication of
newer base historical state.

Published FI Projections must not silently represent older classification as if
it were current. Where classification or another enrichment pipeline trails the
base FI System of Record, the query surface must preserve the applicable
freshness/completeness distinction.

Conceptually:

```text
base FI history represented through:  source cut A
classification represented through:   source cut B
```

The exact source-cut representation is owned by Phase 5 and the
`docs/PUBLISHED-FI-PROJECTION-CONTRACT.md` contract.

---

## Gate 4 — Protected Classification & Enrichment

Gate 4 proves:

- exact observation/stream correlation;
- bounded protected content access;
- safe cancellation and failure;
- bounded recursive/container inspection;
- no persistent backend copy of customer source content;
- classifier/policy versioning;
- immutable classification results;
- classification journaling;
- classification freshness can be represented without overstating completeness;
  and
- classification failure does not invalidate the base FI observation.

Operational telemetry supports Gate 4 validation by showing the source and
backend cost/behavior of classification, but telemetry health is not substituted
for classification correctness or file-history integrity.
