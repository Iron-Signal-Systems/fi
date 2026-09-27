# FI FreeBSD Service Identity

This document defines the initial service-identity model for the FI FreeBSD
backend.

Service identities are jail-local operating-system accounts.

The host does not run FI application services.

## Shared storage identity requirement

FI generation custody and recorded receipt objects are immutable runtime objects
whose application contract requires owner-only file modes.

Generation custody objects are published as:

```text
0400
```

Recorded receipt objects are also validated as:

```text
0400
```

READY markers are published as:

```text
0600
```

The ingest runtime must read generation custody and recorded receipts, and both
receiver and ingest runtimes must operate on READY state.

Changing these object modes merely to accommodate separate numeric Unix users
would alter an established FI runtime contract.

The FreeBSD deployment therefore uses a shared numeric FI runtime UID/GID across
the receiver and ingest jails.

## Jail-local account names

The accounts remain semantically distinct inside their respective jails.

```text
jail           account name
-------------  ------------
fi-receiver    fi-receiver
fi-ingest      fi-ingest
```

The accounts use the same configured numeric UID and primary GID.

Conceptually:

```text
fi-receiver jail:
    fi-receiver:<FI_RUNTIME_UID>:<FI_RUNTIME_GID>

fi-ingest jail:
    fi-ingest:<FI_RUNTIME_UID>:<FI_RUNTIME_GID>
```

FreeBSD jail-local account databases allow the same numeric filesystem identity
to have a different local account name in each jail.

The shared numeric identity exists specifically to preserve FI's immutable
owner-only object mode contract across host-mounted shared datasets.

## Why this does not grant ingest write authority

Numeric filesystem ownership alone is not the complete authority boundary.

The host controls how each dataset is mounted into each jail.

```text
                         fi-receiver     fi-ingest
generation custody          RW              RO
recorded receipts           RW              RO
READY                       RW              RW
```

The ingest jail therefore receives owner-level read access to `0400` custody and
receipt objects while the read-only mount prevents filesystem mutation.

The ingest jail must not receive authority to mount, remount, or alter mount
flags.

In particular, the production jail configuration must not grant filesystem or
ZFS administrative privileges that would allow the ingest jail to convert an
RO authoritative mount into an RW mount.

## Receiver identity

`fi-receiver` runs the receiver and generation-recorder runtime in the
`fi-receiver` jail.

The account:

- has no interactive login requirement;
- receives no host administrative authority;
- receives no ZFS administrative authority;
- receives no PF administrative authority;
- owns FI receiver-created custody and receipt objects;
- can modify READY state;
- can read only the receiver configuration and key material required by the
  runtime.

The receiver runtime's existing trust inspection expects the service identity
to be named:

```text
fi-receiver
```

That name remains authoritative inside the receiver jail.

## Ingest identity

`fi-ingest` runs the relational ingest worker and reconciliation runtime in the
`fi-ingest` jail.

The account:

- has no interactive login requirement;
- receives no host administrative authority;
- receives no ZFS administrative authority;
- receives no PF administrative authority;
- can read generation custody through an RO mount;
- can read recorded receipts through an RO mount;
- can create, inspect, and remove READY markers through an RW mount;
- connects to PostgreSQL only across the explicitly authorized VNET path.

The ingest identity receives no filesystem access to PostgreSQL data files.

## PostgreSQL identity

The PostgreSQL service identity exists only inside `fi-sor-db`.

Its numeric UID/GID does not need to match the FI runtime UID/GID because the
PostgreSQL data dataset is not shared with receiver or ingest jails.

The PostgreSQL account is established and validated as part of the selected
FreeBSD PostgreSQL package/runtime deployment.

FI deployment must not assume a PostgreSQL UID/GID until the selected package
has been installed and inspected.

## Host identity

The FreeBSD host does not run `fi-receiver`, `fi-ingest-worker`, or other FI
application processes.

The host does not require an interactive FI runtime account merely to make ZFS
ownership readable by name.

Host-side deployment and verification tooling may operate on the configured
numeric FI runtime UID/GID directly.

## Numeric identity configuration

The FI runtime UID and GID are explicit site configuration values:

```text
FI_RUNTIME_UID
FI_RUNTIME_GID
```

They must be numeric, non-zero, and explicitly configured before production
datasets are populated.

Deployment preflight must fail closed if either configured number is already
associated with an unexpected identity in a target jail.

Existing matching FI service identities may be accepted only when their:

- numeric UID matches;
- numeric primary GID matches;
- account name matches the jail role;
- home-directory policy matches;
- login-shell policy matches.

Deployment automation must not silently renumber an existing account.

## Login policy

Production FI runtime accounts are service accounts.

They are not administrator login identities.

Their shell must prohibit normal interactive login using the FreeBSD-supported
nologin mechanism selected by deployment.

No SSH authorized keys are installed for FI service identities.

Administrative access uses separately authorized administrator identities.

## Home directories

FI runtime accounts do not store authoritative application data in home
directories.

Authoritative and operational FI state belongs only in the explicitly defined
mounted paths under:

```text
/var/db/fi
/usr/local/etc/fi
/var/run/fi
```

A service-account home, if required by the operating system account mechanism,
is non-authoritative and must not become an undocumented application state
location.

## Jail boundary

The shared numeric FI runtime UID/GID does not imply that receiver and ingest
are the same process security boundary.

They remain separated by:

- distinct FreeBSD jails;
- distinct VNET stacks;
- distinct local account names;
- separate root filesystems;
- host-controlled dataset mounts;
- read-only versus read/write mount authority;
- PF policy;
- separate runtime configuration;
- absence of jail mount/ZFS administration authority.

The shared numeric identity exists only where required for owner-only shared
filesystem objects.

## Verification requirements

Deployment verification must prove at minimum:

1. `fi-receiver` exists only with the configured FI runtime UID/GID in the
   receiver jail.
2. `fi-ingest` exists only with the configured FI runtime UID/GID in the ingest
   jail.
3. neither account has an interactive login shell;
4. custody objects remain mode `0400`;
5. recorded receipts remain mode `0400`;
6. READY markers remain mode `0600`;
7. receiver can create and read custody/receipt state;
8. ingest can read custody/receipt state;
9. ingest cannot modify custody or recorded state;
10. both receiver and ingest can operate READY state;
11. neither jail can remount authoritative datasets RW;
12. neither jail has ZFS administrative authority.
