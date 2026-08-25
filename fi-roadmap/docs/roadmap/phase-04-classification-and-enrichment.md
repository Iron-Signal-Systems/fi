# Phase 4 — Classification & Enrichment

## Purpose

Add meaning and deeper interpretation to FI observations that are already present
in the System of Record.

Classification does not block or replace the underlying file or stream
observation.

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

---

## Content Persistence Rule

The Linux FI system may transiently process bounded source-content buffers.

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

---

## Gate 4 — Protected Classification & Enrichment

Gate 4 proves:

- exact observation/stream correlation;
- bounded protected content access;
- safe cancellation and failure;
- bounded recursive/container inspection;
- no persistent Linux copy of customer source content;
- classifier/policy versioning;
- immutable classification results;
- classification journaling; and
- classification failure does not invalidate the base FI observation.
