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

The FreeBSD bootstrap currently implements a non-mutating deployment-plan
phase.

Configuration files are strict data files using:

    FI_VARIABLE="literal-value"

They are not sourced or executed by the shell.

Shell expansion, command substitution, duplicate keys, unknown keys, and
unsupported characters are rejected.

A plan is generated with:

    ./fi-bootstrap.sh plan /path/to/fi-bootstrap.conf /path/to/new-plan-directory

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

The plan phase does not:

- create ZFS datasets;
- clone jail roots;
- create VNET interfaces;
- modify bridges;
- install files under `/etc`;
- start jails;
- modify PF;
- start FI services.

Host-state preflight and apply behavior are separate implementation
checkpoints.
