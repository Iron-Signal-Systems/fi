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
