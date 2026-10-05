# FI FreeBSD Storage Authority

This document defines the initial ZFS dataset and jail mount authority for the
FI FreeBSD backend.

The host owns ZFS administration.

FI service jails receive only the filesystem paths required by their role and
do not receive ZFS administrative authority.

## Authority classes

FI backend storage is divided into three classes.

### Authoritative

Authoritative state must be preserved and protected.

```text
generation custody
transport custody (batch/recovery)
recorded generation receipts
FI System of Record PostgreSQL data
receiver trust/configuration material
```

### Operational and reconstructable

Operational state is required for normal runtime behavior but is not the
authoritative source of FI facts.

```text
READY markers
runtime lock files
temporary processing state
```

READY state can be reconstructed by authoritative reconciliation.

### Development

Development source and build output are not production FI backend state.

```text
fi-dev source
fi-dev build output
```

## ZFS hierarchy

The initial production hierarchy is:

```text
zroot/fi
├── custody
│   ├── generation
│   └── transport
├── recorded
├── ready
├── sor
│   └── postgres
├── config
│   ├── receiver
│   └── ingest
└── backups
```

`zroot` is an example pool name. The actual pool is supplied by site
configuration.

The existing development datasets are separate from this production hierarchy:

```text
zroot/fi/dev
zroot/fi/dev/src
zroot/fi/dev/build
```

## Host mountpoints

The intended host-visible mountpoints are:

```text
zroot/fi/custody/generation  /var/db/fi/custody/generation
zroot/fi/custody/transport   /var/db/fi/custody/transport
zroot/fi/recorded            /var/db/fi/custody/recorded
zroot/fi/ready               /var/db/fi/custody/ready
zroot/fi/sor/postgres        /var/db/fi/sor/postgres
zroot/fi/config/receiver     /var/db/fi/config/receiver
zroot/fi/config/ingest       /var/db/fi/config/ingest
zroot/fi/backups             /var/db/fi/backups
```

Hierarchy-only parent datasets may use `canmount=off` where appropriate.

## Jail mount matrix

```text
Host source                       fi-receiver                  fi-ingest                    fi-sor-db
--------------------------------  ---------------------------  ---------------------------  --------------------------
custody/generation                /var/db/fi/custody/generation RW  /var/db/fi/custody/generation RO  --
custody/transport                 /var/db/fi/custody/transport  RW  --                           --
recorded                          /var/db/fi/custody/recorded   RW  /var/db/fi/custody/recorded   RO  --
ready                             /var/db/fi/custody/ready      RW  /var/db/fi/custody/ready      RW  --
config/receiver                   /usr/local/etc/fi             RO  --                           --
config/ingest                     --                           /usr/local/etc/fi             RO  --
sor/postgres                      --                           --                           PostgreSQL data RW
```

No production FI dataset is mounted into `fi-dev`.

## Generation custody

Generation custody is authoritative durable input.

`fi-receiver` requires read/write access because it publishes accepted durable
generation custody.

`fi-ingest` requires read-only access.

The ingest jail must not be capable of modifying or deleting generation
custody through its mounted filesystem view.

## Transport custody

Transport custody is authoritative durable input for ordinary batch and
recovery transport.

`fi-receiver` requires read/write access because receiver transport publishes
accepted custody there.

`fi-ingest` receives no filesystem view of transport custody. Adding such
access requires a separately reviewed authority contract.

## Recorded receipts

Recorded receipts are authoritative recorder state.

`fi-receiver` requires read/write access because the generation recorder
publishes receipts.

`fi-ingest` requires read-only access for ingest/reconciliation decisions.

The ingest jail must not be capable of modifying recorder receipts.

## READY markers

READY markers are operational notification state, not authoritative FI state.

Both `fi-receiver` and `fi-ingest` require read/write access:

- receiver-side recording publishes READY state;
- ingest consumes/removes READY state.

Loss of READY state must not destroy authoritative FI information.
Authoritative reconciliation must be capable of reconstructing missed work.

READY therefore does not receive the same backup/retention requirements as
generation custody, recorded receipts, or the System of Record.

## Receiver configuration and trust

Receiver configuration is host-managed and mounted read-only into
`fi-receiver` at:

```text
/usr/local/etc/fi
```

This includes the receiver trust hierarchy, source registry, certificate
material, and receiver private-key material required by the runtime.

Private keys and secrets are never stored in the repository.

The receiver jail can read only the material required by its service identity.
It does not receive write authority to the host-managed configuration dataset.

## Ingest configuration

Ingest configuration is host-managed and mounted read-only into `fi-ingest`
at:

```text
/usr/local/etc/fi
```

PostgreSQL connectivity must be explicitly configured.

There is no host-local PostgreSQL Unix-socket fallback in the supported
FreeBSD deployment.

## PostgreSQL System of Record

The authoritative PostgreSQL data directory resides on:

```text
zroot/fi/sor/postgres
```

Only the `fi-sor-db` jail receives filesystem access to that dataset.

`fi-ingest` accesses PostgreSQL only through the explicitly authorized VNET
network path.

Neither `fi-receiver` nor `fi-ingest` receives filesystem access to PostgreSQL
data files.

The PostgreSQL data directory presented inside `fi-sor-db` will use an
explicit deployment-controlled `PGDATA` path rather than relying on a
package-version-specific default.

## Runtime state

`/var/run/fi` is jail-local runtime state.

It is not a ZFS-backed FI authoritative dataset.

Examples include:

```text
fi-ingest-worker.lock
process IDs
ephemeral service runtime files
```

Runtime directories are created with explicit ownership and mode during service
startup/deployment.

A stale pathname is not treated as singleton ownership authority; the worker
uses the operating-system file lock.

## Dataset hardening

Production data datasets should default to conservative properties appropriate
to their content.

Candidate baseline properties include:

```text
atime=off
exec=off
setuid=off
devices=off
```

Compression and workload-specific properties are established by measured
acceptance testing rather than assumed globally.

PostgreSQL-specific ZFS tuning is validated separately before becoming part of
the production deployment contract.

## Mount enforcement

Read-only versus read/write jail access is enforced by the jail mount
configuration in addition to Unix ownership and mode.

A dataset that must be RW in one jail and RO in another is not made globally
read-only at the ZFS dataset property level.

The host remains able to snapshot, replicate, inspect, and recover the
underlying dataset.

## Identity implications

Shared host datasets make numeric UID/GID ownership part of the deployment
contract.

Production service identities therefore require deterministic UID/GID
assignment across the relevant jails.

The service-identity contract will define those IDs and shared groups before
the production datasets are populated.

## Snapshot and recovery policy

At minimum, snapshot/recovery policy must distinguish:

```text
generation custody      authoritative
transport custody       authoritative
recorded receipts       authoritative
System of Record        authoritative
receiver configuration  authoritative configuration
ingest configuration    authoritative configuration
READY                    reconstructable operational state
runtime state            ephemeral
fi-dev                    development only
```

Snapshot, retention, replication, and restore procedures are defined separately
and tested before pilot acceptance.

No jail receives permission to create, destroy, rollback, or replicate ZFS
snapshots.
