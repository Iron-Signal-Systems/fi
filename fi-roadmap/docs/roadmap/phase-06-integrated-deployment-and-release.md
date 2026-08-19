# Phase 6 — Integrated Deployment & Release

## Purpose

Turn the accepted FI capabilities into a reproducible, supportable, recoverable
product.

## Integrated Scope

The release combines:

- Windows File & Identity Intelligence;
- governed-root configuration;
- gMSA identity requirements;
- deep NTFS/ADS inspection;
- Secure Record Transport;
- Ingest & Recorder;
- PostgreSQL FI System of Record;
- Protected Read Broker;
- Separate Protected Classification Stream;
- Classification & Enrichment;
- projection/query services;
- DNP-protected human access;
- FI user experience/client;
- journal and integrity functions;
- operational tooling.

## Release Responsibilities

Phase 6 owns:

- installation;
- configuration;
- PKI/certificate requirements;
- supported deployment topology;
- capacity/resource limits;
- operational health;
- continuity reporting;
- backup;
- restore;
- disaster recovery;
- recovery validation;
- upgrade;
- rollback;
- SBOM;
- provenance;
- dependency state;
- known limitations;
- release packaging;
- release documentation.

## Integrated Failure and Recovery

The release must remain understandable and recoverable across representative:

- Windows source restart;
- backend restart;
- database restart;
- network outage;
- queue backlog;
- USN continuity loss;
- Windows-event continuity loss;
- classification failure;
- projection rebuild;
- backup/restore;
- DR;
- upgrade;
- rollback.

FI's immutable journal/history should still explain what happened, what FI did,
what succeeded, what failed, what was rejected, what became incomplete, what
recovered, and what changed.

## Gate 6 — Integrated Release Acceptance

Gate 6 proves a complete candidate can be freshly installed, baselined, operated,
failed, recovered, upgraded, rolled back, backed up, restored, used for DR, and
used for representative operational and forensic investigations without losing
historical integrity or explainability.

A candidate passing Gate 6 is eligible for formal release acceptance.
