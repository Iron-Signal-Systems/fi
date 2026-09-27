# FI FreeBSD Apply Contract

This document defines the authority, ownership, reconciliation, and failure
rules for mutating FI FreeBSD deployment automation.

The `apply` implementation must follow this contract before it is permitted to
create or alter production resources.

## Deployment host binding

Every production deployment configuration must identify the exact FreeBSD host
that it is authorized to target through:

    FI_HOSTNAME="<exact-hostname>"

Host-mutating operations must compare the configured value with the current
host's exact `hostname` value before mutation.

A mismatch is a configuration failure.

A configuration created for another production host, a test fixture, or an
offline render environment must never be accepted merely because ZFS pool,
network, path, or numeric identity values happen to match.

## Scope

`apply` is responsible for creating FI-owned FreeBSD backend infrastructure
that has already passed:

1. strict configuration parsing;
2. deterministic deployment planning;
3. read-only host preflight.

`apply` is not a general-purpose host remediation mechanism.

It must not silently adopt unrelated resources, repair ambiguous state, or
destroy resources merely because they differ from the requested FI
configuration.

## Resource state model

Every resource managed by `apply` must be classified into exactly one of these
states before an action is taken:

### ABSENT

The resource does not exist.

Action:

    CREATE

The resource may be created only with the exact configured identity,
ownership, permissions, properties, and role.

### OWNED_MATCH

The resource already exists, is authoritatively identifiable as FI-managed,
and exactly matches the requested deployment state.

Action:

    KEEP

No destructive or corrective action is permitted.

Re-running `apply` against an unchanged successful deployment must therefore
be a no-op for an `OWNED_MATCH` resource.

### OWNED_DRIFT

The resource is authoritatively identifiable as FI-managed but differs from
the requested deployment state.

Examples include:

- wrong ZFS property;
- wrong clone origin;
- wrong mountpoint;
- wrong UID or GID;
- wrong file content;
- wrong file ownership or mode;
- wrong jail configuration;
- wrong VNET interface assignment;
- wrong devfs rules.

Action:

    FAIL

Initial `apply` does not silently reconcile drift.

Changing an existing FI deployment belongs to a separately reviewed
reconciliation/upgrade contract.

### FOREIGN_COLLISION

The requested name, path, numeric identity, dataset, jail, interface, ruleset,
or other resource already exists but cannot be authoritatively identified as
the FI resource requested by the deployment.

Action:

    FAIL

FI must not adopt, overwrite, rename, renumber, destroy, or repurpose the
resource.

### UNKNOWN

The resource cannot be classified safely because inspection failed or state is
ambiguous.

Action:

    FAIL

Unknown state is never interpreted as absence.

## Global mutation rule

For every resource:

    ABSENT             -> CREATE
    OWNED_MATCH        -> KEEP
    OWNED_DRIFT        -> FAIL
    FOREIGN_COLLISION  -> FAIL
    UNKNOWN            -> FAIL

No other transition is permitted by initial `apply`.

## Destructive operations

Initial `apply` must not perform destructive remediation.

It must not:

- run `zfs destroy`;
- destroy an existing jail root;
- overwrite a foreign file;
- recursively remove a production directory;
- renumber an existing UID or GID;
- replace an existing user or group identity;
- destroy an unrelated VNET interface;
- replace an unrelated devfs ruleset;
- remove an existing PF rule;
- stop an unrelated jail or service;
- rewrite an ambiguous host configuration.

A failed apply may leave resources that were successfully created earlier in
the same invocation.

Automatic rollback is not permitted when rollback could destroy data or hide
the actual failure boundary.

The acceptance verifier must make the resulting state explicit.

## FI ownership markers

Where FreeBSD provides a durable resource metadata mechanism, FI must mark
resources it creates.

### ZFS datasets and jail-root clones

FI-created ZFS datasets and jail-root clones must carry local user properties:

    org.ironsignal.fi:managed=1
    org.ironsignal.fi:schema=1
    org.ironsignal.fi:role=<resource-role>

These properties establish FI management authority but do not by themselves
prove that a resource is acceptable.

An existing dataset is `OWNED_MATCH` only when:

- the FI ownership properties are local and exact;
- its configured role is exact;
- all required native ZFS properties are exact;
- its mountpoint is exact;
- its clone origin is exact when an origin is required.

An FI ownership property inherited from another dataset is not sufficient to
establish ownership of a production child resource.

### Generated host files

Files installed by FI under `/etc` must contain an FI-managed header and must
match the exact deterministic rendered content expected for the deployment.

Existing files are `OWNED_MATCH` only when:

- the FI-managed marker is present;
- file content is exact;
- owner is exact;
- group is exact;
- mode is exact;
- file type is regular;
- the path is not a symbolic link.

Initial `apply` must not update an FI-managed file whose expected content has
changed. That condition is `OWNED_DRIFT` and fails closed.

### Resources without durable metadata

Some FreeBSD resources do not provide an independent ownership-marker
mechanism.

Examples include runtime interface names and numeric devfs ruleset numbers.

For these resources, ownership must be established through the authoritative
FI host configuration plus an exact runtime match.

If ownership cannot be proven unambiguously, the resource is a
`FOREIGN_COLLISION` or `UNKNOWN`, not `OWNED_MATCH`.

## ZFS authority

The host owns all production FI ZFS datasets.

The initial production hierarchy is:

    zroot/fi
    ├── custody
    │   └── generation
    ├── recorded
    ├── ready
    ├── config
    │   ├── receiver
    │   └── ingest
    ├── sor
    │   └── postgres
    └── backups

`zroot/fi` already exists before initial production apply and is validated by
preflight.

Hierarchy-only parent datasets may use `canmount=off`.

Production data datasets must use the mountpoints defined by
`STORAGE-AUTHORITY.md`.

Dataset hardening properties must be explicitly created and verified rather
than assumed from inherited host defaults.

No FI jail receives ZFS delegation or jail-side mount authority.

## Initial production ZFS desired state

The initial ZFS apply layer manages the production children beneath the
pre-existing `<FI_ZPOOL>/fi` dataset.

The `<FI_ZPOOL>/fi` dataset itself is a validated prerequisite. Initial apply
does not adopt it, add FI ownership markers to it, or alter its properties.

Every dataset created by this layer must set these local FI properties:

    org.ironsignal.fi:managed=1
    org.ironsignal.fi:schema=1
    org.ironsignal.fi:role=<role>

Every managed production dataset must also explicitly set these local native
properties:

    atime=off
    exec=off
    setuid=off
    devices=off

No production dataset uses ZFS `readonly=on` to implement receiver/ingest
access separation. Read-only and read-write jail views are enforced later by
host-controlled nullfs mounts.

The initial desired state is:

| Dataset relative to `<FI_ZPOOL>/fi` | FI role | mountpoint | canmount | expected mounted state |
| --- | --- | --- | --- | --- |
| `custody` | `custody-parent` | `none` | `off` | `no` |
| `custody/generation` | `custody-generation` | `/var/db/fi/custody/generation` | `on` | `yes` |
| `recorded` | `recorded` | `/var/db/fi/custody/recorded` | `on` | `yes` |
| `ready` | `ready` | `/var/db/fi/custody/ready` | `on` | `yes` |
| `config` | `config-parent` | `none` | `off` | `no` |
| `config/receiver` | `config-receiver` | `/var/db/fi/config/receiver` | `on` | `yes` |
| `config/ingest` | `config-ingest` | `/var/db/fi/config/ingest` | `on` | `yes` |
| `sor` | `sor-parent` | `none` | `off` | `no` |
| `sor/postgres` | `sor-postgres` | `/var/db/fi/sor/postgres` | `on` | `yes` |
| `backups` | `backups` | `/var/db/fi/backups` | `on` | `yes` |

No workload-specific ZFS tuning such as `recordsize`, compression policy,
quota, reservation, or PostgreSQL-specific tuning is selected by this
checkpoint. Those settings require separate measurement and review.

For an absent dataset with a real mountpoint, the mountpoint path must also be
absent before creation. Existing filesystem content must never be hidden by
creating a ZFS mount over it.

For an existing FI-managed dataset, all FI properties and every native
property controlled above must have the exact expected value and must be
locally set. Required local state must not be accepted merely because an
inherited value happens to match.

The runtime `mounted` value must also match the expected state shown above.

## Jail-root clone authority

Production jail roots are cloned from the exact configured template snapshot.

An existing jail-root dataset is acceptable only when:

- FI ZFS ownership properties are exact;
- its FI role is exact;
- its ZFS origin is the exact configured template snapshot;
- its configured mountpoint is exact;
- no unexpected mounted production data is hidden beneath the root.

A root cloned from another template is `OWNED_DRIFT` or
`FOREIGN_COLLISION` and must fail.

## Numeric identity authority

The configured FI runtime UID and GID are deployment contracts.

Initial values must be explicit and nonzero.

The deployment must never silently select a replacement numeric identity.

The receiver and ingest jails use distinct local account names but the same
configured numeric runtime UID/GID so owner-only permissions remain meaningful
across host-controlled shared datasets.

An existing numeric identity with an unexpected name or role is a collision.

Host FI applications are not created or run merely to satisfy ownership
lookups.

## Host-file authority

Production host files include:

    /etc/jail.conf.d/fi-receiver.conf
    /etc/jail.conf.d/fi-ingest.conf
    /etc/jail.conf.d/fi-sor-db.conf
    /etc/fstab.fi-receiver
    /etc/fstab.fi-ingest
    /etc/fstab.fi-sor-db

Initial apply may create an absent path.

It may keep an existing exact FI-owned file.

It must fail on:

- a symbolic link;
- a directory at the expected file path;
- unexpected contents;
- unexpected ownership;
- unexpected mode;
- an existing non-FI file.

Atomic temporary-file-plus-rename installation must be used when these files
are eventually written.

## VNET lifecycle authority

Production VNET lifecycle follows the pattern already proven by `fi-dev`:

    host exec.prestart
        create epair
        configure host peer
        attach host peer to configured bridge

    vnet.interface
        transfer jail peer

    jail exec.start
        configure jail peer address
        start /etc/rc

    host exec.poststop
        remove host peer from bridge
        destroy epair

`apply` installs this lifecycle configuration.

It does not create long-lived runtime epairs merely to prove configuration.

A pre-existing interface using a configured production name remains a
collision unless FI runtime ownership is unambiguous.

## devfs authority

Production FI jails use a dedicated FI devfs ruleset.

The existing `fi-dev` ruleset is not reused because development exposure is
broader than production requirements.

Initial apply must create only the exact production rules required by the FI
jails.

An existing configured ruleset number with different or ambiguous rules is a
collision.

## Jail boot policy

`preflight` reports the current jail boot policy but does not change it.

`apply` must not silently choose a production boot policy.

Automatic production jail startup and jail ordering must be explicitly defined
and accepted before `apply` is permitted to modify `jail_enable`, `jail_list`,
or equivalent lifecycle settings.

### Layer preclassification

Before the first mutation in an apply layer, FI must classify every resource
that the layer intends to manage.

If any resource is `OWNED_DRIFT`, `FOREIGN_COLLISION`, or `UNKNOWN`, the layer
must fail before creating any resource in that layer.

Resources classified as `ABSENT` must also have any required destination path
validated for absence before the first mutation.

After layer-wide preclassification succeeds, each resource must still be
reclassified immediately before mutation. The initial classification is not an
authorization to ignore state changes that occur between inspection and
creation.

This two-pass rule prevents known late-layer conflicts from producing avoidable
partial deployments while retaining fail-closed behavior against races.

## Ordering

Mutations must occur in dependency order.

The intended apply sequence is:

1. validate the complete apply contract and desired state;
2. create/verify production ZFS hierarchy;
3. create/verify jail-root clones;
4. create/verify jail-local runtime identities;
5. create/verify required jail-local directories;
6. create/verify dedicated production devfs rules;
7. install/verify deterministic host jail/fstab files;
8. establish/verify production lifecycle policy;
9. run post-apply acceptance.

Later steps must not begin when an earlier dependency fails.

## Acceptance

A successful `apply` is not accepted merely because every creation command
returned success.

Post-apply verification must independently prove the resulting state.

At minimum it must eventually verify:

- exact ZFS datasets and properties;
- exact jail-root origins;
- exact numeric identities;
- exact directory ownership and modes;
- exact host-file contents, ownership, and modes;
- exact devfs rules;
- exact jail definitions;
- exact VNET lifecycle configuration;
- expected mount authority;
- absence of unauthorized PostgreSQL paths;
- expected PF boundaries;
- expected restart behavior.


## Current implementation boundary

The first mutating apply layer is now implemented as:

    fi-bootstrap.sh apply-zfs <config-file>

This command is limited to the production FI ZFS data hierarchy defined by
this contract.

The ZFS layer implements:

- exact host binding;
- layer-wide preclassification before mutation;
- immediate reclassification before each create;
- FI ZFS ownership markers;
- explicit locally-set native properties;
- mountpoint-path collision checks;
- exact post-create verification;
- exact idempotent reapply behavior;
- fail-closed handling of drift, foreign collisions, and unknown state.

The only production mutation primitive in this layer is:

    zfs create

No jail-root, identity, devfs, host-file, VNET, PF, service, or boot-policy
mutation is implemented by this checkpoint.

Real-host production mutation remains subject to explicit pre-mutation review
and post-apply acceptance.

## Read-only ZFS acceptance

The production ZFS layer also exposes:

    fi-bootstrap.sh verify-zfs <config-file>

`verify-zfs` is not a reconciliation path.

It:

- requires the exact configured deployment host;
- inspects the configured FI ZFS root;
- classifies every required production FI dataset;
- accepts only `OWNED_MATCH`;
- fails on absence, owned drift, foreign collision, or unknown state;
- performs no production mutation.

Real-host acceptance must prove that selected ZFS state is unchanged across the
verification run.
