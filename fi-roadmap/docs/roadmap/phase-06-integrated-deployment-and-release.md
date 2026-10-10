# Phase 6 — Integrated Deployment & Release

## Purpose

Turn the accepted FI capabilities into a reproducible, supportable, recoverable
product.

Phase 6 freezes and proves the supported integrated backend deployment profile.
The currently proposed backend direction is documented in
`docs/architecture/ADR-0001-FREEBSD-BACKEND.md`.

The accepted Linux Phase 3 service remains part of FI's engineering history
regardless of the final Phase 6 deployment platform.

## Current Windows source installer status

The native Go Windows source installer is now a substantial implemented Phase 6
component rather than only a future release responsibility.

Current implemented Windows installer capabilities include:

- authoritative host/AD/PKI/configuration/service/package discovery;
- explicit environment and deployment-input prerequisite evaluation;
- exact Windows Server build profiles;
- desired-state planning with `BLOCKED`, `QUESTION`, `NO CHANGE`, `CREATE`, and
  `RECONCILE` outcomes;
- apply-by-default and explicit `-plan-only` behavior;
- interactive or validated configuration-file deployment input;
- exact configuration approval;
- shared Enterprise CA template-publication approval;
- Approval 1 for AD/PKI mutations;
- post-Approval-1 rediscovery and sealed Approval 2;
- Approval 2 for local FI mutation;
- per-host gMSA derivation and local installation;
- source certificate enrollment;
- transport trust and CRL installation;
- FI release-trust policy validation/installation;
- manifest, detached-signature, payload-hash, Authenticode, and signer-policy
  validation;
- five-service SCM reconciliation;
- local rights, group, ACL, and CNG-key ACL reconciliation;
- receiver mTLS activation;
- Receiver Pending behavior with FISender Manual/Stopped;
- executable-name migration from legacy runtime names to canonical names;
- actual running-process-image verification;
- transaction rollback ownership;
- service/broker/collector readiness verification;
- durable installer records; and
- converged-state idempotency.

The authoritative operating description is:

```text
docs/WINDOWS-INSTALLER.md
```

The current live migration/recovery acceptance record is:

```text
docs/WINDOWS-INSTALLER-ACCEPTANCE-2026-10-09.md
```

### Current build boundary

The installer contains discovery profiles for:

```text
Windows Server 2016  build 14393
Windows Server 2019  build 17763
Windows Server 2022  build 20348
Windows Server 2025  build 26100
```

The current integrated installer mutation prerequisite is enabled only on Server
2016 and Server 2019 because FIObjReader rights mutation acceptance remains
fail-closed on Server 2022 and Server 2025.

This is narrower than the broader Gate 1 Windows runtime characterization and
acceptance set. Phase 6 must not conflate those two boundaries.

## Integrated Scope

The release combines:

- Windows File & Identity Intelligence;
- governed-root configuration;
- Windows source installation and upgrade/reconciliation;
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

The current Windows source installer closes part of this responsibility set, but
does not by itself close Gate 6.

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
- Windows source installation interruption;
- Windows source upgrade/reconciliation interruption;
- receiver-unavailable installation / Receiver Pending;
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

Installer-specific failures must additionally expose:

- exact approved plan/boundary digests;
- release/package identity;
- applied mutation authorities;
- rollback attempt/error state;
- post-mutation convergence state; and
- final convergence state.

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

## Remaining Windows installer release work

Before the Windows source installer is treated as a completed product release
boundary, Phase 6 still needs at least:

- current installer mutation acceptance for Server 2022 and Server 2025 or an
  explicit release support decision excluding them;
- clean fresh-install acceptance from a release package;
- update acceptance from a supported prior installed release;
- rollback acceptance across representative interruption points;
- receiver-available activation acceptance in addition to Receiver Pending;
- repeatable signed release-package build/provenance;
- final operator install/update/recovery instructions;
- supported upgrade/rollback compatibility policy; and
- release-level CI/acceptance automation appropriate to the supported Windows
  and backend platforms.

## Gate 6 — Integrated Release Acceptance

Gate 6 proves a complete candidate can be freshly installed, baselined, operated,
failed, recovered, upgraded, rolled back, backed up, restored, used for DR, and
used for representative operational and forensic investigations without losing
historical integrity or explainability.

Gate 6 additionally proves:

- the supported backend topology is reproducibly installed;
- the supported Windows source topology is reproducibly installed and
  reconciled;
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
