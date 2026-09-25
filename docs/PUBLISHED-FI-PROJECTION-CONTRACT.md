# Published FI Projection Contract

**Project:** File Intelligence (FI)<br>
**Status:** Design contract — Phase 5 implementation and Gate 5 acceptance pending<br>
**Authority:** FI architectural contract<br>
**Applies to:** projection building, query databases, query/API services, UX, and projection freshness reporting

## 1. Purpose

FI preserves one authoritative historical record and may derive multiple useful
representations from that record.

The **FI System of Record** establishes authoritative FI history.

A **Published FI Projection** is a validated, rebuildable, query-optimized
representation of committed authoritative FI history through an explicitly
declared source cut.

A Published FI Projection is not a second source of truth and is not a
filesystem/database snapshot.

The projection exists so query, correlation, reporting, API, and UX workloads
do not compete directly with authoritative ingest and so FI can optimize user
questions without distorting the authoritative relational model.

## 2. Normative terminology

### FI System of Record

The PostgreSQL FI System of Record is the authoritative relational
representation of accepted FI history.

It is populated only through the accepted authoritative ingest path.

Normal runtime historical authority remains append-oriented/write-once as
defined by the Phase 3 contracts.

The System of Record is designed first for:

- historical correctness;
- source lineage;
- immutable relationships;
- explicit uncertainty and gaps;
- deterministic reconstruction; and
- authoritative ingest and reconciliation.

It is not redesigned merely to make a user query convenient.

### Published FI Projection

A Published FI Projection is:

- derived from committed FI System-of-Record state;
- bound to an explicit authoritative source cut;
- validated before it becomes query-visible;
- rebuildable from authoritative FI history;
- optimized for query/correlation/UX workloads;
- non-authoritative;
- disposable without loss of FI historical authority; and
- isolated from the authoritative ingest write path.

### Candidate FI Projection

A Candidate FI Projection is a projection being built or validated.

A candidate is never the normal query target.

### Authoritative source cut

The **authoritative source cut** defines exactly how far authoritative FI history
is represented by a candidate or published projection.

The implementation may represent the cut using per-source accepted frontiers,
included generation identities, an authoritative manifest, a transactionally
consistent database boundary, or another deterministic representation.

The representation is an implementation detail. The required semantics are:

> Every value exposed by a Published FI Projection must derive only from
> authoritative FI records visible within its declared source cut.

A single global generation number must not be assumed because generation
identity is source-scoped.

### Projection freshness

Projection freshness describes the distance between the currently published
projection and the newest committed authoritative FI history.

Freshness is not the same as source collection continuity.

FI must not describe a projection as current beyond its declared source cut.

## 3. Core invariants

The following invariants are mandatory.

1. There is one authoritative FI history.
2. The FI System of Record is authoritative; Published FI Projections are not.
3. Query convenience must not create an alternate authoritative write path.
4. Candidate projection state is not visible to ordinary query clients.
5. Publication is atomic from the query client's perspective.
6. A failed candidate does not alter the current published projection.
7. Loss of the projection/query plane does not destroy FI historical authority.
8. A Published FI Projection must be reproducibly rebuildable from authoritative
   FI history.
9. Query/API/UX identities do not receive System-of-Record write authority.
10. The normal UX does not require direct network/database access to the FI
    System of Record.
11. Projection freshness and applicable coverage/uncertainty remain explicit.
12. `Observed`, `Derived`, `Classified`, `Unknown`, and `Incomplete` remain
    distinguishable through the query surface.

## 4. Authority and workload separation

The intended logical boundary is:

```text
                 AUTHORITATIVE PLANE

Windows Sources
      |
      v
Receiver -> Durable Custody -> Recorder / Ingest
                                  |
                                  v
                    PostgreSQL FI System of Record
                         AUTHORITATIVE
                                  |
                                  | read only
                                  v


                    PROJECTION / QUERY PLANE

                         Projection Builder
                                  |
                                  v
                       Candidate Projection
                                  |
                              validation
                                  |
                                  v
                       Published FI Projection
                          REBUILDABLE
                                  |
                                  v
                             Query API
                                  |
                                  v
                                 UX
```

Ordinary query load must be directed to the Published FI Projection rather than
the authoritative PostgreSQL ingest workload.

The projection database may use query-specific structures that would be
inappropriate or unnecessarily expensive in the System of Record, including:

- additional indexes;
- current-state tables;
- denormalized query shapes;
- precomputed relationships;
- search-specific structures;
- materialized access relationships;
- time-oriented lookup structures; and
- other rebuildable query accelerators.

Those structures remain derived state.

## 5. Publication eligibility

Publication is **state-driven**, not merely timer-driven.

A timer may enforce a maximum allowed projection lag, but the ordinary
publication trigger should wait for a meaningful completed authoritative
boundary.

FI must determine publication eligibility from FI authoritative state, not from
incidental host symptoms such as:

- low CPU utilization;
- low disk activity;
- PostgreSQL appearing idle; or
- an arbitrary periodic wall-clock tick.

A normal publication opportunity occurs after authoritative ingest has reached a
completed boundary and a configurable quiet/debounce interval has elapsed
without newer committed work resetting that interval.

Conceptually:

```text
authoritative ingest commits
        |
        v
projection publication becomes eligible
        |
        v
quiet/debounce interval
        |
        +---- newer authoritative commit ----+
        |                                     |
        +<------------------------------------+
        |
        v
establish transactionally consistent source cut
        |
        v
build candidate
        |
        v
validate
        |
        v
publish atomically
```

## 6. Continuous-ingest safeguard

A permanently busy source must not prevent projection advancement forever.

The implementation therefore supports two independent policy concepts:

```text
settle_quiet_period
maximum_projection_lag
```

Normal behavior:

> Publish after authoritative ingest settles for the configured quiet period.

Continuous-ingest behavior:

> If authoritative ingest does not settle before maximum projection lag is
> reached, publish a transactionally complete authoritative source cut without
> waiting for global inactivity.

The actual values are deployment/configuration parameters and must be informed by
measurement. They are not fixed architectural constants.

## 7. Transactionally consistent source read

Projection creation must read a coherent authoritative state.

The projection builder must not observe half of an authoritative generation or
assemble one projection from mutually inconsistent database moments.

The intended PostgreSQL model is a read-only transactionally consistent view,
for example a suitable `REPEATABLE READ` transaction or another mechanism that
provides equivalent semantics.

Authoritative ingest does not need to stop while a projection is built.

The important rule is:

> The candidate is built from one coherent authoritative source cut while later
> authoritative transactions may continue independently.

## 8. Projection lifecycle

The minimum projection lifecycle is:

```text
BUILDING
   |
   v
VALIDATING
   |
   +---- validation/build failure ----> REJECTED
   |
   v
PUBLISHED
   |
   v
SUPERSEDED
```

### BUILDING

A candidate is being created or incrementally advanced.

It is not available to normal query clients.

### VALIDATING

FI verifies that the candidate satisfies the projection contract and is complete
for its declared source cut.

### REJECTED

The candidate failed build or validation.

The currently published projection remains active and unchanged.

### PUBLISHED

The candidate has passed validation and becomes the active normal query target.

Publication must be atomic from the perspective of query clients.

### SUPERSEDED

A later valid projection has been published.

Superseded projections may be retained temporarily for rollback/diagnostic
purposes according to product policy, but they do not become historical
authority.

## 9. Required projection identity and metadata

Every Published FI Projection must carry enough metadata to answer at least:

- which projection is active;
- which projection schema/version produced it;
- when build began;
- when build completed;
- when publication occurred;
- which authoritative source cut it represents;
- its validation result; and
- applicable component freshness where asynchronous enrichment is involved.

Conceptually:

```text
projection_id
projection_schema_version
authoritative_source_cut
build_started_at
build_completed_at
published_at
validation_status
```

These names are conceptual until the Phase 5 schema is designed.

## 10. Classification and enrichment freshness

Classification and other enrichment may advance at a different rate from base FI
historical ingest.

A slower classifier must not:

- cause FI to present stale classification as current;
- force FI to suppress newer base historical state unnecessarily; or
- cause the query surface to collapse `Unknown`, `Incomplete`, and not-yet-
  classified into one state.

A projection may therefore carry separate freshness boundaries where required,
for example:

```text
base FI history represented through:      source cut A
classification represented through:       source cut B
identity/access derivation through:        source cut C
```

The exact representation is a later schema decision.

## 11. Query and UX authority

Normal query and UX components receive no authoritative database write
authority.

The intended minimum separation is:

```text
Projection Builder
    read:  FI System of Record
    write: candidate/projection database

Query Service
    read:  Published FI Projection
    write: no FI historical authority

UX
    use:   Query/API service
    direct System-of-Record database authority: none
```

The product may expose lineage, source-record identity, generation, receipt, and
other technical detail through the API without granting the user-facing service
direct authoritative database write authority.

## 12. Rebuild requirement

A projection must be independently rebuildable.

A required Gate 5/6 recovery test is conceptually:

```text
destroy query/projection database
        |
        v
create empty projection database
        |
        v
rebuild from authoritative FI history
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

A projection that cannot be deterministically recreated is carrying hidden
authority and violates this contract.

Incremental projection refresh is permitted and expected for normal operation.

Periodic or release-validation full rebuilds must prove that incremental state
has not become an undocumented source of truth.

## 13. Failure behavior

### Projection builder failure

- authoritative ingest continues;
- the System of Record remains unchanged;
- the active projection remains queryable;
- candidate state is rejected or recoverable according to its durable build
  protocol; and
- failure is visible to FI operational health.

### Projection database loss

- FI historical authority remains intact;
- query capability may be degraded/unavailable;
- the projection is rebuilt from authoritative history; and
- no authoritative source modification is required.

### Query/API failure

- authoritative ingest continues;
- the published projection remains derived state; and
- no source or authoritative database write is authorized merely to restore the
  query service.

### System-of-Record unavailability

- a previously published projection may remain available according to product
  policy;
- FI must expose that the projection is no longer advancing; and
- the projection must not claim freshness beyond its published source cut.

## 14. Performance model

The authoritative database is optimized for trustworthy historical ingest and
relationships.

The projection database is optimized for interactive questions.

Performance work should therefore avoid adding query-only write cost to the
System of Record when equivalent derived structures can be built safely in the
projection.

Representative Phase 5 performance classes should include:

- exact file/path/object/hash lookup;
- file timeline reconstruction;
- security/access explanation;
- historical hash/path searches;
- surrounding-activity windows;
- relationship pivots; and
- broad forensic searches.

Specific latency thresholds are measurement-driven Gate 5 acceptance criteria,
not part of this architecture contract.

## 15. ZFS/PostgreSQL snapshot distinction

A **Published FI Projection** is not a ZFS snapshot and is not a copied live
PostgreSQL data directory.

These mechanisms serve different purposes.

```text
ZFS / PostgreSQL backup or snapshot
-----------------------------------
storage and recovery mechanism
point-in-time storage state
backup / replication / rollback / DR

Published FI Projection
-----------------------
application-level derived representation
bound to committed authoritative FI history
query optimized
validated before publication
rebuildable
```

Storage snapshots may protect the System of Record or projection datasets, but
they do not replace the projection publication contract.

## 16. Gate 5 acceptance requirements

Gate 5 must prove at least:

- a projection can be built from authoritative FI history;
- the candidate is invisible until validation succeeds;
- a failed candidate does not replace the active projection;
- a published projection declares its authoritative source cut;
- human-readable queries execute against the projection/query plane;
- answers preserve lineage, coverage, and uncertainty;
- query/API/UX identities cannot write authoritative FI history;
- loss of the projection database does not damage FI historical authority;
- an empty projection database can be rebuilt from the System of Record;
- rebuild produces equivalent supported answers for the same source cut;
- continuous authoritative ingest cannot indefinitely prevent publication; and
- ordinary query workloads do not compete directly with authoritative ingest.

## 17. Gate 6 implications

The integrated product must additionally prove:

- backend restart preserves authority/projection separation;
- projection publication resumes after restart;
- projection loss/rebuild is operationally supported;
- backup/restore preserves the FI System of Record;
- disaster recovery can rebuild or restore the query plane independently;
- upgrade/rollback does not create a second historical authority; and
- deployment network/service boundaries prevent query-plane compromise from
  becoming System-of-Record write authority.

## 18. Governing statement

> **The FI System of Record establishes historical authority. Published FI
> Projections provide validated, rebuildable, query-optimized views of that
> authority through an explicit publication boundary.**
