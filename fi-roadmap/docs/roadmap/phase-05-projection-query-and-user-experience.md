# Phase 5 — Projection, Query & Protected User Experience

## Purpose

Turn one immutable FI historical record into useful intelligence for users with
different roles, permissions, workflows, and required depth.

There is one authoritative FI history. User experiences are authorized
projections of that history.

## UX Abstraction Boundary

FI user-facing experiences present the environment at the level appropriate to
the person asking the question. Ordinary product use should begin with files,
identities, access, changes, impact, history, and time rather than FI's internal
record types or source mechanics.

A help-desk or operational user should not need to understand Windows event IDs,
USN journal mechanics, FI collection stages, database tables, or correlation
implementation to answer a supported environmental question.

Abstraction does not permit FI to simplify uncertainty into certainty. Every
presentation depth must preserve the distinction between:

```text
Observed
Derived
Classified
Unknown
Incomplete
```

Appropriately authorized users must be able to drill from a higher-level answer
into the relationships and source facts that support it. Different roles may stop
at different depths, but FI does not maintain separate versions of the truth for
different users.

Administrative and local diagnostic interfaces are outside this UX abstraction
boundary. They expose the technical detail required to operate and verify FI as
defined in `docs/ADMINISTRATIVE-INTERFACES.md`.

### Gate 5 UX acceptance

Representative help-desk, administrative, security, disaster-recovery, and
forensic questions must be answerable at an appropriate level of abstraction
from the same underlying FI history without requiring ordinary users to
understand FI implementation details.

The same representative answers must remain traceable to their applicable source
facts, relationships, coverage state, and uncertainty when a user with sufficient
authorization drills deeper.

## Help Desk / User Support

FI should answer questions such as:

- Does this user have access to this file now?
- What exact rights do they have?
- If access changed, when?
- What ACL, share, identity, or membership change explains the result?
- Who made the relevant change where observable?

The goal is to solve ordinary access problems without manually correlating
multiple Windows tools and short-retention logs.

## Application / Development Support

FI should help identify changes to application files, DLLs, configurations, and
related governed objects.

It should correlate retained history with observable deployment, Windows
update/KB, administrator, file, and surrounding activity without overstating
causation.

## System / Network Administration

FI should surface coordinated or abnormal patterns such as:

- mass modification;
- rapid file rewrites;
- rename bursts;
- deletion;
- unexpected permission changes;
- unexpected share exposure;
- unexpected ADS creation/modification;
- large change bursts across governed roots.

This can help identify ransomware-like behavior, bad deployments, administrative
mistakes, or other significant changes.

## Security Operations

FI should support investigation of suspicious file/security changes, unusual
identity exposure, executable/script material in unexpected locations, suspicious
streams, coordinated changes, and known audit/continuity gaps.

FI complements rather than replaces EDR, SIEM, or other security tools.

## Disaster Recovery

FI should help teams:

- identify affected governed files;
- determine likely last-known-good observations;
- identify historical hashes, paths, permissions, and shares;
- identify suspicious change windows;
- support restore-point selection;
- observe restored objects;
- compare restored state to historical expectations;
- identify unexpected differences;
- journal recovery and validation outcomes.

FI is not required to be the backup platform. It provides the historical context
needed to make recovery more accurate and verifiable.

## Management / Policy / Compliance / Audit

FI should present higher-level historical intelligence about access, exposure,
classification, permission changes, exceptions, continuity/coverage, recovery,
and audit-relevant relationships.

## Forensic Investigation

FI should allow low-level reconstruction using combinations of:

```text
identity
file
stream
server
folder
share
time interval
hash
classification
incident
```

Investigators should be able to reconstruct applicable file, stream, path,
storage, security, access, identity, activity, classification, session/source,
continuity, and FI journal history.

Where the retained record supports it, FI should help work backward and forward
toward the earliest known affected object or patient-zero candidate.

## Truth Presentation

Material conclusions are explicitly represented as:

```text
Observed
Derived
Classified
Unknown
Incomplete
```

Known uncertainty and coverage gaps remain visible.

## Protected Human Access

User-facing and query components do not receive authoritative database write authority. Their access to FI data is read-only.

## Gate 5 — Operational, Security, DR & Forensic Intelligence

Gate 5 proves the same FI history can support representative:

- help-desk access troubleshooting;
- application/development change investigation;
- operational/security abnormal-change analysis;
- DR last-known-good and recovery comparison;
- management/compliance/audit questions;
- deep forensic incident reconstruction; and
- role-appropriate UX abstraction with drill-down to the same underlying truth.

Gate 5 is the primary customer-value gate for FI.
