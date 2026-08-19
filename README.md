# File Intelligence (FI)

File Intelligence (FI) is a pre-release project developed by **John J. Wood** under the **Iron Signal Systems** project and brand name.

# FI Roadmap
[FI Roadmap details](fi-roadmap/roadmap.md)


**Iron Signal Systems is currently a project/brand name and GitHub/domain identity used by John Joseph Wood. It is not represented by this repository as a separate corporation, LLC, or other legal entity.**

Copyright ownership and licensing for FI are held and granted by **John Joseph Wood** unless a future written agreement expressly states otherwise.

## Purpose

FI is being developed as a historical forensic model of governed files.

FI is intended to continuously record what is known or deterministically discoverable about a governed file's:

- identity;
- storage;
- location;
- metadata;
- Windows security;
- exact Windows rights;
- share exposure;
- local and directory identity relationships;
- effective access;
- activity;
- history; and
- classification.

FI is not intended to be only a file-inventory product.

Its purpose is to support defensible reconstruction of what FI knew about a governed file, identity, governed root, or incident interval at a recorded point in time.

## Initial platform scope

Initial development targets Windows Server and NTFS file services.

Monitoring is explicitly scope-driven. FI operates only against configured governed roots such as approved drives or directories. Installing FI on a Windows server does not imply that the entire server is governed.

## Core design principles

- Perform an initial baseline of each governed root and then maintain the model continuously.
- Use the NTFS USN journal as a change detector, followed by fresh applicable observation of affected objects.
- Capture relevant Windows filesystem, security, SMB, identity, and activity events before normal Windows log retention removes them.
- Convert relevant source activity into durable FI records.
- Perform **AD identity collection via gMSA, producing versioned directory identity records**.
- Retain local and directory identity relationships needed to explain historical access.
- Preserve exact Windows security information, including native security descriptors, ACLs, ACE ordering, access masks, inheritance, and applicable share security.
- Preserve authoritative FI history as append-only records. Changes, corrections, re-analysis, and reclassification create new related records rather than rewriting prior history.
- Keep observed, derived, classified, unknown, and incomplete information explicitly distinct.
- Record continuity loss and degraded forensic coverage rather than silently claiming completeness.
- Store FI metadata, security, identity, activity, access-analysis, and classification records normally while keeping customer source-file content out of the Linux FI repository.
- When classification requires file content, obtain it through a separate protected, bounded source stream and consume it transiently.
- Treat current-state and query-oriented views as rebuildable projections of authoritative historical records.

## High-level architecture

```text
Windows File & Identity Intelligence
        |
        v
Secure Shipper
        |
        v
Receiver
        |
        v
Ingest
        |
        v
Recorder & FI System of Record
       / \
      /   \
     v     v
Classification   Projection / Query / Protected UX
& Enrichment
      \   /
       \ /
Integrated Deployment & Release
```

The normal FI record path does not transport customer source-file content.

Classification operates after the underlying file observation has been recorded and produces separate append-only enrichment records linked to the exact observation that was classified.

## Forensic model

FI is being designed to answer questions such as:

- What governed files could a specific identity access during a defined time interval?
- What exact Windows rights existed, and why?
- What files were actually accessed where source auditing allows that conclusion?
- What files were created, modified, renamed, moved, deleted, or had security changed?
- What was the file's state before and after the activity?
- Where was the file located by server, volume, storage relationship, path, and share?
- What identity, membership, security, and access-analysis records applied at that time?
- What classification applied to the relevant file observation?
- Which conclusions are directly observed, which are derived, and where does incomplete coverage prevent a definitive answer?

A known gap in source coverage must never be presented as proof that activity did not occur.

## Project status

FI is currently pre-release and under active architectural and implementation development.

No compatibility promise should be inferred from current pre-release contracts, schemas, APIs, command names, or internal package layout unless explicitly declared otherwise by an accepted release.

## Source review and licensing

**FI is proprietary source-available software. It is not open-source software.**

The source is published so prospective customers and their authorized technical reviewers can independently inspect how FI works before deciding whether to deploy or license it.

Subject to the repository `LICENSE`, evaluators may clone, download, build, execute, and test FI in a non-production environment for purposes such as:

- technical evaluation;
- security review;
- architecture review;
- interoperability assessment;
- audit preparation;
- proof-of-concept testing; and
- procurement due diligence.

This evaluation permission is intended to include prospective customers and their authorized IT, security, engineering, audit, and technical personnel.

The source-review permission does **not** by itself authorize production deployment, resale, redistribution outside the evaluating organization, modification, derivative works, incorporation into another product or service, or other use not expressly allowed by the `LICENSE`.

The repository `LICENSE` file is the controlling license text.

Copyright (c) 2026 John Joseph Wood. All rights reserved except as expressly licensed.

## Security

Security issues should not be disclosed through public issues when doing so would expose an active vulnerability or sensitive implementation detail.

A dedicated security policy and reporting process will be maintained in `SECURITY.md`.
