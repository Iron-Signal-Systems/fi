# FI FreeBSD Host Layout

This document defines the production host-side jail-root and mount layout for
the FI FreeBSD backend.

It implements the authority contracts defined by:

    STORAGE-AUTHORITY.md
    SERVICE-IDENTITY.md
    JAIL-CAPABILITIES.md

No FI application service runs directly on the host.

## Jail root hierarchy

Production jail root filesystems live beneath the host jail-container
hierarchy.

Logical dataset layout:

    <FI_JAIL_DATASET_ROOT>/fi-receiver
    <FI_JAIL_DATASET_ROOT>/fi-ingest
    <FI_JAIL_DATASET_ROOT>/fi-sor-db

Logical host mountpoints:

    <FI_JAIL_ROOT_BASE>/fi-receiver
    <FI_JAIL_ROOT_BASE>/fi-ingest
    <FI_JAIL_ROOT_BASE>/fi-sor-db

For the initial FI appliance layout the expected defaults are:

    FI_JAIL_DATASET_ROOT=<FI_ZPOOL>/jails/containers
    FI_JAIL_ROOT_BASE=/usr/local/jails/containers

The production jail roots are separate from the FI authoritative data
hierarchy under `/var/db/fi`.

Destroying or rebuilding a jail root must not imply destruction of FI
authoritative datasets.

## Jail root provenance

Production jail roots are created from an explicitly configured and verified
FreeBSD base template snapshot.

The deployment configuration supplies:

    FI_JAIL_TEMPLATE_SNAPSHOT

The bootstrap must not guess the template snapshot.

Before cloning, deployment must verify that:

- the configured template snapshot exists;
- it is a ZFS snapshot;
- the destination jail-root dataset does not conflict with unexpected state;
- the FreeBSD release represented by the template matches the accepted
  deployment release.

A pre-existing matching jail root may be accepted only after explicit
validation.

Deployment must not destroy or overwrite an unexpected existing jail root.

## Production jail roots

The initial production roots are:

    fi-receiver
        /usr/local/jails/containers/fi-receiver

    fi-ingest
        /usr/local/jails/containers/fi-ingest

    fi-sor-db
        /usr/local/jails/containers/fi-sor-db

The exact host root prefix remains a site configuration value.

## FI data hierarchy

Persistent production FI data remains outside the jail root datasets.

Host-visible paths:

    /var/db/fi/custody/generation
    /var/db/fi/custody/recorded
    /var/db/fi/custody/ready
    /var/db/fi/sor/postgres
    /var/db/fi/config/receiver
    /var/db/fi/config/ingest
    /var/db/fi/backups

These paths are backed by the datasets defined in `STORAGE-AUTHORITY.md`.

## Jail-visible paths

The receiver jail receives:

    /var/db/fi/custody/generation    RW
    /var/db/fi/custody/recorded      RW
    /var/db/fi/custody/ready         RW
    /usr/local/etc/fi                RO

The ingest jail receives:

    /var/db/fi/custody/generation    RO
    /var/db/fi/custody/recorded      RO
    /var/db/fi/custody/ready         RW
    /usr/local/etc/fi                RO

The System of Record jail receives:

    /var/db/fi/sor/postgres          RW

No production FI data dataset is mounted into `fi-dev`.

## Mount mechanism

Shared production data is presented through host-controlled nullfs mounts.

Per-jail fstab files are maintained by the host and referenced by the jail
configuration through `mount.fstab`.

The application jail is not granted:

    allow.mount
    allow.mount.nullfs
    allow.mount.zfs

The host creates the mount before the jail starts.

The host removes the mount when the jail is removed.

## Mountpoint preparation

Destination directories inside a jail root must exist before jail creation.

Deployment tooling creates only the expected empty mountpoint directories.

A destination that unexpectedly contains files or directories must cause
preflight failure unless the contents are explicitly recognized as deployment
state.

This prevents an absent production mount from being silently masked by local
jail-root data.

## Configuration mount

Receiver and ingest configuration are different host datasets even though both
are presented inside their respective jails as:

    /usr/local/etc/fi

This prevents one jail from seeing the other jail's configuration material.

Both configuration mounts are read-only in the application jail.

## PostgreSQL data mount

The System of Record PostgreSQL dataset is mounted only into `fi-sor-db`.

The jail-visible path is:

    /var/db/fi/sor/postgres

This path becomes the explicit FI PostgreSQL `PGDATA` authority during the
PostgreSQL service implementation checkpoint.

The package default data directory is not implicitly authoritative.

## Runtime state

Each jail owns its local:

    /var/run/fi

This is created during service startup or deployment with explicit ownership
and mode.

It is not a host-shared production dataset.

## Jail destruction and rebuild

Removing a production jail must not remove or destroy:

    generation custody
    recorded receipts
    READY state
    System of Record data
    production FI configuration
    backups

Those are separately managed host datasets.

A jail root can therefore be rebuilt from the accepted FreeBSD template while
persistent FI state remains under host storage authority.

## Verification requirements

Deployment verification must prove:

1. each production jail root is a distinct ZFS dataset;
2. each root is beneath the configured jail-container dataset;
3. no authoritative FI dataset is a child of a production jail-root dataset;
4. required destination mountpoints exist before jail creation;
5. destination mountpoints are empty before their host mount is attached;
6. receiver receives the expected three RW data mounts and one RO config mount;
7. ingest receives two RO data mounts, READY RW, and config RO;
8. `fi-sor-db` alone receives the PostgreSQL data mount;
9. no production FI dataset is mounted into `fi-dev`;
10. removal of a jail leaves authoritative host datasets intact.
