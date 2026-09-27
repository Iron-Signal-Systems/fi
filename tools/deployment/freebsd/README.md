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

The FreeBSD bootstrap currently implements two non-mutating phases:

- `plan`
- `preflight`

Configuration files are strict data files using:

    FI_VARIABLE="literal-value"

They are not sourced or executed by the shell.

Shell expansion, command substitution, duplicate keys, unknown keys, and
unsupported characters are rejected.

A deployment plan is generated with:

    ./fi-bootstrap.sh plan /path/to/fi-bootstrap.conf /path/to/new-plan-directory

Host state is inspected with:

    ./fi-bootstrap.sh preflight /path/to/fi-bootstrap.conf

`preflight` must run as root on the intended FreeBSD host.

The fixture under `verify/fixtures/` exists for deterministic render and
negative-parser tests. It is not a production host configuration. A real host
configuration must identify the exact template snapshot, networks, addresses,
identities, paths, VNET interface names, and other deployment inputs intended
for that host.

### Plan phase

The plan phase:

- validates required configuration;
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
accepted or reconciled. Idempotent ownership validation and reconciliation of
already-created FI resources belong to the later apply/reapply contract.

### Non-mutation contract

Neither `plan` nor `preflight` may:

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

No `apply` operation is implemented by this checkpoint.
