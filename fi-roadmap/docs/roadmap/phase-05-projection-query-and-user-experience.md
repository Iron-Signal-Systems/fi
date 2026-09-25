# Phase 5 — Projection, Query & Protected User Experience

## Purpose

Turn one immutable FI historical record into useful intelligence for users with
different roles, permissions, workflows, and required depth.

There is one authoritative FI history.

User experiences operate through **Published FI Projections**: validated,
rebuildable, query-optimized representations of authoritative FI history through
an explicit publication boundary.

The FI System of Record remains authoritative.

See `docs/PUBLISHED-FI-PROJECTION-CONTRACT.md`.

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

## Published FI Projection Boundary

Ordinary query workloads do not run directly against the authoritative
PostgreSQL ingest workload.

The logical boundary is:

```text
                    FI System of Record
                       AUTHORITATIVE
                            |
                            | read only
                            v
                     Projection Builder
                            |
                            v
                    Candidate Projection
                            |
                        validation
                            |
                            v
                    Published Projection
                       REBUILDABLE
                            |
                            v
                        Query API
                            |
                            v
                            UX
```

The projection is allowed to use structures designed specifically for fast user
questions, including additional indexes, current-state tables, denormalized query
shapes, precomputed relationships, time-oriented search structures, and other
derived accelerators.

Those structures never become historical authority.

Query convenience must not broaden `fi_ingest` authority or create another
System-of-Record write path.

## Projection Publication

Publication is state-driven.

FI normally waits until authoritative ingest has reached a completed boundary and
a configurable quiet/debounce interval has elapsed.

A permanently busy source must not block projection advancement forever.
Therefore a separate configurable maximum-projection-lag policy may cause FI to
publish a transactionally complete source cut even while later authoritative
ingest continues.

The projection builder obtains a coherent read of the authoritative database,
binds the candidate to its exact authoritative source cut, builds/updates the
candidate, validates it, and only then atomically makes it the active query
target.

The implementation must not infer "settled" from low CPU, low I/O, or an
apparently idle PostgreSQL process.

It uses FI authoritative state.

## Projection Lifecycle

The minimum lifecycle is:

```text
BUILDING
   |
   v
VALIDATING
   |
   +---- failure ----> REJECTED
   |
   v
PUBLISHED
   |
   v
SUPERSEDED
```

A candidate is not visible to ordinary queries.

If build or validation fails, the existing Published FI Projection remains
active.

Every published projection declares enough identity/freshness information to
establish the authoritative source cut it represents.

## Human-Readable Query Contract

Ordinary FI investigation begins with values an operator actually knows. Supported
lookup pivots include, as applicable, file name, full Windows path, SHA-256, NTFS
object identity, FI source-record identity, time interval, and source/server
context.

Users must not be required to convert file names or paths into UTF-16LE bytes,
hexadecimal, PostgreSQL `bytea`, internal table names, or hand-written relational
joins.

The query layer owns those mechanics. Human-readable input is normalized and
encoded as required, applied against the Published FI Projection, and returned
as file history with applicable metadata, hashes, NTFS identity, security/SACL
information, streams, warnings, coverage, and source/batch/generation lineage.

The authoritative PostgreSQL representation does not change merely for query
convenience. Exact Windows path bytes may remain stored as UTF-16LE `bytea`; the
projection/query layer converts human-readable input into the representation
required for comparison.

Base file-detail projections should preserve one logical file observation rather
than creating misleading row multiplication. One-to-many relationships such as
DACL ACEs, SACL ACEs, streams, warnings, and other relationships remain
independently addressable and may be assembled by a higher-level query surface.

Authorized technical users must be able to drill from returned values through
FI lineage to the applicable source record, batch, generation, receipt, and
authoritative relational relationships without requiring the UX/API itself to
hold System-of-Record write authority.

### Gate 5 UX acceptance

Representative help-desk, administrative, security, disaster-recovery, and
forensic questions must be answerable at an appropriate level of abstraction
from the same underlying FI history without requiring ordinary users to
understand FI implementation details.

The same representative answers must remain traceable to their applicable source
facts, relationships, coverage state, uncertainty, and projection freshness when
a user with sufficient authorization drills deeper.

## Projection Freshness and Truth Presentation

A Published FI Projection never claims to represent authoritative state newer
than its declared source cut.

Where asynchronous work advances at different rates, FI must preserve that
distinction rather than collapse all components into one false "current" state.

For example:

```text
base FI history:      current through source cut A
classification:       current through source cut B
identity derivation:  current through source cut C
```

Known lag is operational state, not missing historical authority.

Known source-collection gaps remain separate from projection lag.

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

Projection lag/freshness must also remain visible where it affects an answer.

## Protected Human Access

User-facing and query components do not receive authoritative database write
authority.

The intended minimum logical authority is:

```text
Projection Builder
    read:  FI System of Record
    write: projection database

Query Service
    read:  Published FI Projection

UX
    use:   Query/API service
```

The UX and normal query service do not require direct System-of-Record write
authority.

## Projection Rebuild Requirement

Published FI Projections are rebuildable.

Gate 5 must include a destructive query-plane test:

```text
destroy projection/query database
        |
        v
create empty projection database
        |
        v
rebuild from FI System of Record
        |
        v
validate
        |
        v
publish
        |
        v
same supported answers for the same authoritative source cut
```

Incremental refresh is expected in normal operation.

A full rebuild remains the proof that incremental projection state has not become
an undocumented second source of truth.

## Gate 5 — Operational, Security, DR & Forensic Intelligence

Gate 5 proves the same FI history can support representative:

- help-desk access troubleshooting;
- application/development change investigation;
- operational/security abnormal-change analysis;
- DR last-known-good and recovery comparison;
- management/compliance/audit questions;
- deep forensic incident reconstruction; and
- role-appropriate UX abstraction with drill-down to the same underlying truth.

Gate 5 also proves the Published FI Projection contract:

- candidate state is not query-visible before validation;
- failed publication leaves the active projection intact;
- published state declares its authoritative source cut;
- projection freshness/coverage is represented truthfully;
- continuous ingest does not indefinitely prevent publication;
- ordinary query workload does not compete directly with authoritative ingest;
- query/API/UX identities cannot write authoritative FI history;
- loss of the projection database does not damage historical authority; and
- the projection can be rebuilt from an empty query database using the System of
  Record.

Gate 5 is the primary customer-value gate for FI.
