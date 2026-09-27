# FI FreeBSD Backend Deployment

This subtree owns the supported FI FreeBSD backend deployment model.

The FreeBSD backend uses:

- native FreeBSD jails with VNET;
- ZFS datasets owned and managed by the host;
- PF for explicit inter-jail and external network policy;
- rc.d for service lifecycle;
- separate service identities for FI runtime components;
- PostgreSQL in a dedicated VNET jail;
- explicit configuration rather than host-local service discovery.

The historical Linux Phase 3 deployment under `tools/deployment/linux/`
remains as acceptance history. It is not the target integrated backend
deployment.

## Initial jail layout

```text
fi-receiver
    network-facing FI receiver
    generation recorder
    durable custody publication

fi-ingest
    relational ingest worker
    authoritative reconciliation
    PostgreSQL client only

fi-sor-db
    authoritative FI PostgreSQL System of Record

fi-dev
    development/build environment only
```

## Authority boundaries

```text
                         fi-receiver     fi-ingest
generation custody          RW              RO
recorded receipts           RW              RO
READY markers               RW              RW
receiver PKI/config         RO              --
PostgreSQL network          --            CLIENT
```

The host owns:

- jail lifecycle;
- ZFS dataset lifecycle;
- ZFS snapshots and replication;
- PF;
- backup/restore operations;
- controlled deployment actions.

FI service jails do not receive ZFS administrative authority.

## FreeBSD filesystem conventions

Runtime configuration:

```text
/usr/local/etc/fi
```

Persistent FI data:

```text
/var/db/fi
```

Runtime state:

```text
/var/run/fi
```

FI executables:

```text
/usr/local/sbin
```

## PostgreSQL

The authoritative PostgreSQL instance is a separate VNET jail.

FI ingest processes must receive an explicit PostgreSQL connection string.
They must not fall back to a host-local Unix socket.

Direct external PostgreSQL access is prohibited.

## Deployment principle

Deployment automation must be:

- deterministic;
- idempotent;
- fail-closed;
- safe against unexpected pre-existing state;
- explicit about site-specific variables;
- free of embedded private keys, passwords, or other secrets;
- verifiable after installation.

Manual deployment and acceptance testing establish the reference implementation
before bootstrap automation is finalized.

## Bootstrap implementation state

The FreeBSD bootstrap currently implements:

- `plan` — non-mutating deterministic deployment rendering;
- `preflight` — non-mutating initial-deployment host validation;
- `apply-zfs` — narrowly scoped mutation of the FI production ZFS data hierarchy.

Configuration files are strict data files using:

    FI_VARIABLE="literal-value"

They are not sourced or executed by the shell.

Shell expansion, command substitution, duplicate keys, unknown keys, and
unsupported characters are rejected.

Every host-inspecting or host-mutating operation is bound to the exact
configured `FI_HOSTNAME`.

A deployment plan is generated with:

    ./fi-bootstrap.sh plan /path/to/fi-bootstrap.conf /path/to/new-plan-directory

Initial-deployment host state is inspected with:

    ./fi-bootstrap.sh preflight /path/to/fi-bootstrap.conf

The FI production ZFS hierarchy is created or verified with:

    ./fi-bootstrap.sh apply-zfs /path/to/fi-bootstrap.conf

`preflight` and `apply-zfs` must run as root on the intended FreeBSD host.

The fixture under `verify/fixtures/` exists for deterministic rendering and
negative acceptance tests. It is deliberately bound to a non-production
hostname and is not a production deployment configuration.

A real host configuration must identify the exact hostname, template snapshot,
networks, addresses, identities, paths, VNET interface names, and other
deployment inputs intended for that host.

### Plan phase

The plan phase:

- validates required configuration;
- validates the configured deployment hostname syntax;
- validates numeric identities;
- validates management/workload IPv4 CIDR relationships;
- validates deterministic VNET interface names;
- validates jail-root and ZFS naming relationships;
- verifies all template tokens have values;
- renders jail configuration and per-jail fstab files;
- rejects unresolved template tokens;
- writes SHA-256 hashes of rendered artifacts.

The plan phase does not inspect or modify host state.

### Preflight phase

The preflight phase validates the initial deployment target before any
production resources are created.

It currently verifies:

- execution as root on FreeBSD;
- configured deployment hostname matches the current host;
- required host commands;
- the configured ZFS pool;
- the jail dataset root and its configured mountpoint;
- the exact configured jail-template snapshot;
- read-only state of the jail-template dataset;
- FreeBSD release agreement between the host and template dataset;
- the FI dataset root at `/var/db/fi`;
- persistent and runtime PF state;
- persistent and runtime IPv4 forwarding;
- persistent management and workload bridges;
- management and workload bridge addresses within their configured networks;
- the `/etc/jail.conf.d/*.conf` include;
- current `jail_enable` state as informational lifecycle state only;
- availability of the configured FI runtime UID and GID;
- availability of the configured production devfs ruleset number;
- absence of conflicting production jail names;
- absence of conflicting production jail roots;
- absence of conflicting production jail datasets;
- absence of conflicting jail configuration and fstab paths;
- absence of conflicting FI production storage paths and datasets;
- absence of conflicting deterministic VNET interface names.

Preflight fails closed on a configuration mismatch or unexpected collision.

The current preflight is specifically an **initial-deployment preflight**.
Existing production resources are treated as collisions rather than silently
accepted or reconciled.

### ZFS apply phase

`apply-zfs` implements only the FI production data-storage layer.

It creates or verifies:

    <FI_ZPOOL>/fi/custody
    <FI_ZPOOL>/fi/custody/generation
    <FI_ZPOOL>/fi/recorded
    <FI_ZPOOL>/fi/ready
    <FI_ZPOOL>/fi/config
    <FI_ZPOOL>/fi/config/receiver
    <FI_ZPOOL>/fi/config/ingest
    <FI_ZPOOL>/fi/sor
    <FI_ZPOOL>/fi/sor/postgres
    <FI_ZPOOL>/fi/backups

The pre-existing `<FI_ZPOOL>/fi` dataset is a validated prerequisite and is not
adopted or modified by `apply-zfs`.

The ZFS apply layer:

- requires root on FreeBSD;
- requires an exact deployment-hostname match;
- classifies the entire ZFS layer before the first mutation;
- rejects `OWNED_DRIFT`, `FOREIGN_COLLISION`, and `UNKNOWN`;
- validates destination-path absence for datasets that will mount;
- reclassifies every resource immediately before mutation;
- creates absent datasets with explicit FI ownership properties;
- accepts only exact locally-set FI and native ZFS properties;
- verifies each newly created dataset immediately;
- treats an exact second apply as a no-op.

Initial `apply-zfs` does not repair drift.

The only production mutation primitive currently implemented by this phase is
`zfs create`.

### ZFS verification phase

`verify-zfs` is the read-only acceptance path for an already-created FI
production ZFS hierarchy.

It:

- requires root on FreeBSD;
- requires an exact deployment-hostname match;
- validates the configured ZFS pool and `/var/db/fi` root;
- classifies every required production dataset;
- requires every dataset to be `OWNED_MATCH`;
- fails on `ABSENT`, `OWNED_DRIFT`, `FOREIGN_COLLISION`, or `UNKNOWN`;
- validates exact FI ownership metadata, native ZFS properties, and runtime
  mount state;
- performs no ZFS mutation.

Real-host acceptance has demonstrated that the selected ZFS state is
byte-identical before and after `verify-zfs`.

### Current mutation boundary

`apply-zfs` does **not**:

- clone or destroy jail roots;
- create users or groups;
- create or modify devfs rulesets;
- install or modify jail configuration under `/etc`;
- install or modify per-jail fstab files;
- create or destroy VNET interfaces;
- modify bridges;
- modify PF;
- change IP forwarding;
- change jail boot policy;
- start, stop, or modify jails;
- install or start FI services.

Those operations remain future reviewed apply layers.

### Non-mutation contract

`plan`, `preflight`, and `verify-zfs` may not:

- create or destroy ZFS datasets or snapshots;
- clone jail roots;
- create or destroy VNET interfaces;
- modify bridges;
- create users or groups;
- create or modify devfs rulesets;
- install or modify files under `/etc`;
- mount or unmount production filesystems;
- start, stop, or modify jails;
- modify PF;
- change IP forwarding;
- change jail boot policy;
- start or stop FI services.

### Production jail-root phase

Production jail roots are created from the explicitly configured
`FI_JAIL_TEMPLATE_SNAPSHOT`.

The jail-root deployment commands are:

    preflight-jail-roots
    apply-jail-roots
    verify-jail-roots

`preflight-jail-roots` is read-only. It accepts only `ABSENT` or exact
`OWNED_MATCH` resources and fails closed on drift, foreign collisions, or
unknown inspection state.

`apply-jail-roots` performs the controlled production mutation. Its only
mutation primitive is `zfs clone`. All three production jail roots are
classified before the first clone, and an `ABSENT` resource is reclassified
immediately before creation.

`verify-jail-roots` is read-only post-apply acceptance. Every production jail
root must classify as exact `OWNED_MATCH`.

The initial production roots are:

    fi-receiver
    fi-ingest
    fi-sor-db

This layer does not create runtime identities, devfs rules, host configuration
files, VNET interfaces, jail lifecycle configuration, or services.
