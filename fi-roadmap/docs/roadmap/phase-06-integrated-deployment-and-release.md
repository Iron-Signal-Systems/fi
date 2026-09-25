# Phase 6 — Integrated Deployment & Release

## Purpose

Turn the accepted FI capabilities into a reproducible, supportable, recoverable
product.

Phase 6 freezes and proves the supported integrated backend deployment profile.
The currently proposed backend direction is documented in
`docs/architecture/ADR-0001-FREEBSD-BACKEND.md`.

The accepted Linux Phase 3 service remains part of FI's engineering history
regardless of the final Phase 6 deployment platform.

## Integrated Scope

The release combines:

- Windows File & Identity Intelligence;
- governed-root configuration;
- gMSA identity requirements;
- accepted Windows NTFS/ADS collection;
- Secure Record Transport;
- Ingest & Recorder;
- PostgreSQL FI System of Record;
- Protected Read Broker;
- Separate Protected Classification Stream;
- Classification & Enrichment;
- projection builder;
- Published FI Projection database;
- query/API services;
- FI user experience/client;
- journal and integrity functions;
- backend service isolation/network policy;
- backend storage/backup/recovery layout; and
- operational tooling.

If the FreeBSD ADR is accepted, the integrated scope also includes:

- FreeBSD backend/appliance lifecycle;
- VNET jail lifecycle;
- PF service-boundary policy; and
- ZFS dataset, backup, restore, and replication behavior.

## Release Responsibilities

Phase 6 owns:

- installation;
- configuration;
- PKI/certificate requirements;
- supported deployment topology;
- backend service identities;
- service/jail startup and restart ordering;
- service-to-service network policy;
- System-of-Record/query-plane separation;
- capacity/resource limits;
- operational health;
- projection freshness/health;
- continuity reporting;
- backup;
- restore;
- disaster recovery;
- recovery validation;
- projection rebuild;
- upgrade;
- rollback;
- SBOM;
- provenance;
- dependency state;
- known limitations;
- release packaging; and
- release documentation.

## Integrated Authority Boundary

The release must preserve:

```text
FI System of Record
    authoritative
    authoritative ingest/reconcile workload

Published FI Projection
    rebuildable
    query optimized
    normal Query/API/UX workload
```

Loss or corruption of the query/projection plane must not silently become loss
of FI historical authority.

The query plane must not gain authoritative write authority merely because it is
co-located on the same backend appliance.

## Integrated Failure and Recovery

The release must remain understandable and recoverable across representative:

- Windows source restart;
- backend host restart;
- individual backend service/jail restart;
- authoritative database restart;
- query database restart;
- network outage;
- queue backlog;
- USN continuity loss;
- Windows-event continuity loss;
- classification failure;
- projection build failure;
- projection validation failure;
- projection database loss;
- projection rebuild;
- Query/API outage;
- UX outage;
- backup/restore;
- DR;
- upgrade; and
- rollback.

FI's immutable journal/history should still explain what happened, what FI did,
what succeeded, what failed, what was rejected, what became incomplete, what
recovered, and what changed.

Projection-specific failures must additionally expose:

- last successfully published projection;
- authoritative source cut represented by that projection;
- current projection lag;
- candidate build/validation failure state; and
- whether query service is using a still-valid older projection.

## Backup and Recovery Separation

Backup/restore planning must distinguish:

```text
authoritative state
    FI System of Record
    durable custody / required recorder state
    configuration / trust material

rebuildable state
    Published FI Projection database
    query-specific indexes/materializations
```

A product backup may protect both for recovery speed, but Gate 6 must still prove
that the query projection can be recreated from authoritative history.

Filesystem/ZFS snapshots, where used, are storage/recovery mechanisms and do not
replace PostgreSQL-consistent backup/recovery semantics or the Published FI
Projection publication contract.

## Gate 6 — Integrated Release Acceptance

Gate 6 proves a complete candidate can be freshly installed, baselined, operated,
failed, recovered, upgraded, rolled back, backed up, restored, used for DR, and
used for representative operational and forensic investigations without losing
historical integrity or explainability.

Gate 6 additionally proves:

- the supported backend topology is reproducibly installed;
- service/network authority boundaries match the documented deployment;
- authoritative PostgreSQL can be restored without relying on the query database;
- the query database can be destroyed and rebuilt from authoritative FI history;
- failed projection publication cannot replace the last valid projection;
- backend/individual-service restart preserves authority separation;
- Query/API/UX compromise boundaries do not imply System-of-Record write
  authority;
- upgrade/rollback preserves both authoritative history and projection
  compatibility; and
- operational health clearly distinguishes source continuity, authoritative
  ingest health, projection freshness, and query availability.

A candidate passing Gate 6 is eligible for formal release acceptance.
