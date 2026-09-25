# ADR-0001 — FreeBSD Backend and Jail-Isolated FI Services

**Status:** Proposed<br>
**Date:** 2026-09-25<br>
**Decision scope:** FI backend deployment platform and service-isolation model<br>
**Related contract:** `docs/PUBLISHED-FI-PROJECTION-CONTRACT.md`

## Context

Phase 3 / Gate 3 established the FI relational System of Record and permanent
ingest-worker behavior on Linux with `systemd`.

That acceptance is historical fact and remains valid.

FI now needs an integrated backend architecture for later classification,
projection/query, API/UX, backup/recovery, upgrade, and release work.

The desired deployment model separates:

- network-facing receiver work;
- durable custody;
- authoritative recorder/ingest work;
- the PostgreSQL FI System of Record;
- projection building;
- the query-optimized PostgreSQL projection;
- query/API services; and
- the user experience.

The System of Record should not compete with ordinary user-query workload.

The backend should also provide strong local service isolation, explicit network
paths, and first-class storage/recovery primitives suitable for a controlled FI
appliance.

## Proposed decision

Adopt **FreeBSD** as the target FI backend/appliance operating system and use
**VNET jails**, **PF**, and **ZFS** as the primary local isolation, network-policy,
and storage foundations.

This proposal does not rewrite Phase 3 acceptance.

If accepted, Phase 6 will validate the FreeBSD deployment as the supported
integrated release platform.

## Decision drivers

The proposal is driven by:

- strong service separation through jails;
- independent VNET network stacks;
- explicit PF-enforced service communication;
- ZFS datasets for clear storage boundaries;
- ZFS snapshot/replication capability for backup and recovery workflows;
- ability to isolate authoritative and query workloads;
- a small controlled appliance-oriented operating environment;
- explicit ownership of backend service topology; and
- compatibility with FI's existing least-authority design.

The decision is not based on an assumption that FreeBSD automatically makes FI
secure. Security remains dependent on the actual jail, PF, service identity,
PostgreSQL, filesystem, upgrade, and operational configuration.

## Logical trust boundaries

The target logical backend is:

```text
Windows Sources
      |
      v
+------------------+
| fi-receiver      |
| VNET jail        |
+------------------+
      |
      v
durable custody
      |
      v
+------------------+
| fi-recorder      |
| / ingest         |
| VNET jail        |
+------------------+
      |
      v
+--------------------------+
| fi-sor-db                |
| PostgreSQL               |
| FI System of Record      |
| AUTHORITATIVE            |
+--------------------------+
      |
      | read only
      v
+--------------------------+
| fi-projector             |
| projection builder       |
+--------------------------+
      |
      v
+--------------------------+
| fi-query-db              |
| PostgreSQL               |
| Published FI Projection  |
| REBUILDABLE              |
+--------------------------+
      |
      v
+--------------------------+
| fi-query                 |
| API / query service      |
+--------------------------+
      |
      v
+--------------------------+
| fi-ux                    |
| user-facing service      |
+--------------------------+
```

These are logical trust boundaries.

Early implementations may combine compatible roles where justified, but any
combination must preserve the same authority restrictions and must not create a
hidden path from UX/query compromise to authoritative database write authority.

## Network policy intent

The intended communication model is narrow and explicit.

Conceptually:

```text
Windows sources  -> fi-receiver        required transport port only

fi-receiver      -> custody boundary   only required local/backend path

fi-recorder      -> fi-sor-db          PostgreSQL ingest/reconcile path

fi-projector     -> fi-sor-db          read only
fi-projector     -> fi-query-db        projection write

fi-query         -> fi-query-db        read only

fi-ux            -> fi-query           API only
```

Normal prohibited relationships include:

```text
fi-ux       -X-> fi-sor-db
fi-query    -X-> authoritative writes
fi-query-db -X-> authoritative writes
external    -X-> PostgreSQL directly
```

PF rules should default to deny between jail service networks except for
documented required paths.

Where operationally practical, management access and workload/service traffic
should use separate VNET interfaces/networks so administrative SSH/package
traffic is not conflated with FI data-plane traffic.

## Jail identity and privilege model

Each jail should run the minimum service identity/privilege required for its
function.

A jail boundary does not replace application-level authorization.

PostgreSQL role separation remains required.

A likely role model is:

```text
fi_owner
    NOLOGIN
    owns authoritative schema

fi_ingest
    accepted authoritative runtime rights only

fi_projector
    SELECT authoritative System of Record

fi_projection_writer
    write projection database only

fi_query
    SELECT published projection only

fi_migrator
    explicit controlled schema migration authority
```

Final privileges are established by implementation and acceptance tests rather
than this ADR alone.

## Storage layout intent

Use separate ZFS datasets for independently managed FI state.

Conceptually:

```text
zroot/fi/custody
zroot/fi/sor/postgres
zroot/fi/query/postgres
zroot/fi/recorder-state
zroot/fi/config
zroot/fi/backups

zroot/jails/fi-receiver
zroot/jails/fi-recorder
zroot/jails/fi-sor-db
zroot/jails/fi-projector
zroot/jails/fi-query-db
zroot/jails/fi-query
zroot/jails/fi-ux
```

Exact pool/dataset names are deployment details.

The important property is that authoritative state, rebuildable query state,
custody, configuration, and jail roots can be governed independently.

## ZFS snapshot role

ZFS snapshots are for storage protection, recovery, rollback/replication support,
and operational recovery testing.

They are not the FI query publication mechanism.

The query publication mechanism is the **Published FI Projection** contract.

A PostgreSQL data-directory ZFS snapshot must not be mounted and treated as the
live normal query database merely because it is point-in-time storage.

PostgreSQL-aware backup/recovery semantics remain required.

## System of Record vs query database

The authoritative PostgreSQL instance is reserved for:

- authoritative ingest;
- authoritative reconciliation;
- durable relational history;
- lineage; and
- controlled projection reads.

The query PostgreSQL instance is rebuildable and may be optimized independently
for:

- file/path/hash lookup;
- timelines;
- effective-access relationships;
- correlation;
- reporting;
- API response assembly; and
- forensic searches.

Loss of the query database must not imply loss of FI historical authority.

## Projection publication

The projector follows `docs/PUBLISHED-FI-PROJECTION-CONTRACT.md`.

In particular:

- publication is state-driven;
- FI normally waits for a completed authoritative boundary and quiet/debounce
  interval;
- continuous ingest cannot prevent publication indefinitely;
- candidate projections are validated before activation;
- publication is atomic for query clients;
- every projection declares its authoritative source cut; and
- the query plane never becomes a second authority.

## Migration from accepted Linux Phase 3 runtime

The accepted Linux `fi-ingest-worker.service` remains the Gate 3 proof.

Migration to FreeBSD is a later deployment/platform change.

Required migration work includes at least:

- FreeBSD service supervision/rc integration;
- FreeBSD build/test support for backend Go components;
- PostgreSQL service/bootstrap automation;
- jail creation/configuration;
- VNET/PF policy;
- ZFS dataset creation and permissions;
- service identities;
- logging/health integration;
- backup/restore;
- upgrade/rollback;
- projection rebuild;
- host/jail restart behavior; and
- release packaging.

Phase 3 does not need to be rewritten as though it originally ran on FreeBSD.

## Consequences

### Positive

- query load is isolated from authoritative ingest;
- compromise boundaries become easier to reason about;
- ZFS provides strong storage-management primitives;
- PF/VNET make service communication explicit;
- query state can be discarded/rebuilt independently;
- appliance deployment can be reproducible and tightly controlled.

### Costs / risks

- additional service topology increases operational complexity;
- jail/PF/ZFS/PostgreSQL lifecycle must be productized, not handcrafted;
- FreeBSD becomes a supported platform requiring CI/build/release coverage;
- monitoring and upgrades must understand multiple isolated services;
- cross-jail dependencies can fail independently and require clear health state;
- performance/resource isolation still requires measurement;
- PostgreSQL backup/recovery rules still apply despite ZFS availability.

## Non-goals

This ADR does not:

- define HA topology;
- define cross-appliance failover;
- define final jail count;
- define final network addressing;
- define final ZFS pool geometry;
- claim that every service requires a separate jail forever;
- replace PostgreSQL transaction/backup semantics with filesystem snapshots; or
- alter Windows source-side architecture.

## Acceptance criteria for changing status to Accepted

Before this ADR is marked `Accepted`, FI should prove or explicitly commit to:

- required backend Go components build and run on target FreeBSD release;
- PostgreSQL System-of-Record behavior is equivalent to accepted semantics;
- jail service startup/restart ordering is defined;
- PF paths are explicit and default-deny;
- authoritative and query database roles are separated;
- projection builder can read SoR and publish query state without widening
  authority;
- query/UX cannot directly write or administer the System of Record;
- ZFS dataset ownership/backup/restore behavior is defined;
- host reboot and individual jail restart are recoverable;
- projection database loss/rebuild is demonstrated; and
- Phase 6 documentation owns the final supported deployment profile.

## Decision record

Until this ADR becomes `Accepted`, existing Linux Gate 3 implementation remains
the only completed backend runtime acceptance record.

Adopting this ADR changes the target integrated deployment architecture; it does
not invalidate or rewrite the engineering history that established the FI System
of Record.
