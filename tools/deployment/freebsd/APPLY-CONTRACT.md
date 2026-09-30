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

The deterministic host-file layer owns exactly these eight production files:

    /etc/jail.conf.d/fi-receiver.conf
    /etc/jail.conf.d/fi-ingest.conf
    /etc/jail.conf.d/fi-sor-db.conf
    /etc/fstab.fi-receiver
    /etc/fstab.fi-ingest
    /etc/fstab.fi-sor-db
    /etc/devfs.rules.fi
    /usr/local/libexec/fi-vnet-pair

The three `FI_*_FSTAB` configuration values are required to resolve to the
three exact fstab paths above. Initial apply does not accept arbitrary host
destinations.

Every managed host artifact contains the exact ownership marker:

    # FI-MANAGED: ironsignal-fi-freebsd-host-file-v1

Each artifact also contains an exact `FI-ROLE` comment.

The required metadata is:

| Host file | Owner | Group | Mode |
| --- | ---: | ---: | ---: |
| `/etc/jail.conf.d/fi-receiver.conf` | `0` | `0` | `0644` |
| `/etc/jail.conf.d/fi-ingest.conf` | `0` | `0` | `0644` |
| `/etc/jail.conf.d/fi-sor-db.conf` | `0` | `0` | `0644` |
| `/etc/fstab.fi-receiver` | `0` | `0` | `0600` |
| `/etc/fstab.fi-ingest` | `0` | `0` | `0600` |
| `/etc/fstab.fi-sor-db` | `0` | `0` | `0600` |
| `/etc/devfs.rules.fi` | `0` | `0` | `0644` |
| `/usr/local/libexec/fi-vnet-pair` | `0` | `0` | `0555` |

Owner `0` and group `0` are the FreeBSD `root:wheel` identity.

An existing file is `OWNED_MATCH` only when:

- it is a regular file and not a symbolic link;
- it contains the exact FI management marker;
- its complete content is byte-identical to the deterministic expected file;
- its numeric owner and group are exact;
- its mode is exact;
- its hard-link count is exactly one.

An FI-marked file with content, metadata, or hard-link drift is `OWNED_DRIFT`.

An existing unmarked regular file, symbolic link, directory, or other file
type at a managed destination is `FOREIGN_COLLISION`.

Inspection failure is `UNKNOWN`.

The layer preclassifies all eight resources before its first production
mutation. Every `ABSENT` resource is classified again immediately before
creation.

Creation uses a same-directory temporary regular file. FI writes the complete
expected content, applies final ownership and mode, and verifies the temporary
file before publication.

Publication uses an atomic no-clobber hard-link creation. If the destination
appears before publication, creation fails rather than replacing it. The
temporary link is then removed and the final destination is independently
verified.

Initial apply never uses an overwriting rename for a production host-file
destination.

A runtime failure after one or more files have been created may therefore
leave an incomplete but accurately classifiable FI host-file set. Initial
apply does not delete successfully created files to hide that failure boundary.

### Persistent devfs file

`/etc/devfs.rules.fi` contains one named ruleset:

    [fi_production=<FI_DEVFS_RULESET>]

followed by the exact five production rules already accepted by the in-kernel
devfs layer.

The host-file layer only installs this persistent definition.

It does not modify `rc.conf`, `devfs_rulesets`, `devfs_system_ruleset`, or the
host `/dev` ruleset.

Loading `/etc/devfs.rules.fi` through `devfs_rulesets` belongs to the later
lifecycle/boot-policy layer.

### VNET helper installation

`/usr/local/libexec/fi-vnet-pair` is a byte-identical installation of the
reviewed repository helper.

Installing the helper does not execute it and does not create, destroy, rename,
or attach any network interface.

The jail lifecycle configuration invokes the helper later through
`exec.prestart` and `exec.poststop`.

## VNET lifecycle authority

Production VNET lifecycle uses deterministic interface names supplied by the
site configuration.

Management and workload network attachments use epair pairs:

    host exec.prestart
        validate configured host and jail endpoint names are absent
        create epair
        rename both endpoints deterministically
        configure host endpoint
        attach host endpoint to the configured bridge

    vnet.interface
        transfer the configured jail endpoint into the jail VNET

    jail exec.start
        configure the jail interface address
        establish the jail default route
        start /etc/rc

    jail exec.stop
        run /etc/rc.shutdown jail

    host exec.poststop
        detach/destroy the managed epair pair

The receiver has an additional dedicated external physical interface.

Before receiver epair creation, the host helper must verify that the configured
`FI_RECEIVER_EXTERNAL_IF`:

- exists;
- has no host IPv4 or IPv6 address;
- is not a member of the FI management bridge;
- is not a member of the FI workload bridge.

The receiver jail receives that physical interface directly through
`vnet.interface` in addition to its management and workload epairs.

Inside the receiver VNET:

    FI_RECEIVER_EXTERNAL_IF
        receives FI_RECEIVER_EXTERNAL_ADDRESS

    FI_RECEIVER_MGMT_JAIL_IF
        receives FI_RECEIVER_MGMT_ADDRESS

    FI_RECEIVER_WORK_JAIL_IF
        receives FI_RECEIVER_WORK_ADDRESS

    default route
        FI_RECEIVER_EXTERNAL_GATEWAY

The ingest and System of Record jails receive management and workload epairs
only. Their default route is `FI_MGMT_GATEWAY`.

The dedicated receiver interface is not created or destroyed by FI. It is
temporarily assigned to the receiver VNET by jail lifecycle authority and must
return to the host when the jail is removed.

Real-host restart acceptance must prove that after receiver shutdown the
dedicated external interface:

- is visible on the host again;
- has no IPv4 address;
- has no IPv6 address;
- is not attached to either FI bridge.

A pre-existing epair interface using a configured production name remains a
collision unless FI runtime ownership is unambiguous.

This checkpoint defines and renders the lifecycle configuration. It does not
start production jails or mutate live host networking.

## devfs authority

Production FI jails use one dedicated FI devfs ruleset identified by the site-configured `FI_DEVFS_RULESET` number. FI requires this custom ruleset number to be 100 or greater.

FI defines the production rules explicitly and does not include `devfsrules_jail` or `devfsrules_jail_vnet`.

The exact production rule actions are:

```text
add hide
add path null unhide
add path zero unhide
add path random unhide
add path urandom unhide
```

No other device is authorized. In particular, production FI jails must not expose `zfs`, `pf`, `bpf`, `fuse`, `mem`, PTY/PTS devices, `ptmx`, or the login-oriented `fd`, `stdin`, `stdout`, and `stderr` aliases.

`random` is retained because FreeBSD 15.1 `rc.d/tmp` uses it when the default `tmpmfs=AUTO` path is evaluated. `urandom` remains the standard alias to `random`. The FI Go runtime itself uses `getrandom(2)` for `crypto/rand` on FreeBSD.

An absent configured ruleset is eligible for creation. An existing configured ruleset is accepted only when its ordered rules exactly match this contract. Different, additional, missing, or ambiguous rules are `FOREIGN_COLLISION` and must not be silently repaired or replaced.

The devfs apply layer creates and verifies the in-kernel ruleset. The
deterministic host-file layer installs the matching `/etc/devfs.rules.fi`
definition. Loading that file remains part of the later lifecycle policy.
Any additional device requires an explicit contract revision and acceptance before exposure.

## Jail boot policy

FI production lifecycle authority is isolated from the host's global jail
service policy.

FI does not set or own:

    jail_enable
    jail_parallel_start
    jail_list
    jail_reverse_stop

The FI production jail controller is:

    /usr/local/etc/rc.d/fi_jails

Its dedicated service enable configuration is:

    /etc/rc.conf.d/fi_jails

The controller is ordered after the base FreeBSD `jail` rc service and
participates in shutdown ordering.

It starts FI production jails one at a time in this exact order:

    fi-sor-db
    fi-ingest
    fi-receiver

It stops FI production jails one at a time in this exact reverse order:

    fi-receiver
    fi-ingest
    fi-sor-db

Each start or stop uses the base jail rc service for exactly one named jail.
The controller independently checks the resulting state with `jls` rather
than accepting the wrapper command return alone as runtime acceptance.

The jail definitions additionally enforce:

    fi-ingest
        depend = "fi-sor-db"

    fi-receiver
        depend = "fi-ingest"

The System of Record is the FI dependency root.

The resulting application dependency chain is:

    fi-sor-db
        -> fi-ingest
        -> fi-receiver

FI therefore owns its own production application lifecycle without selecting,
reordering, or enabling unrelated site jails.

The persistent FI devfs lifecycle fragment is:

    /etc/rc.conf.d/devfs/90-fi

It requires:

    devfs_load_rulesets="YES"

and appends:

    /etc/devfs.rules.fi

to the existing site `devfs_rulesets` value only when that path is not already
present.

FI does not set `devfs_system_ruleset` and therefore does not choose a host
`/dev` ruleset.

Rendering the lifecycle policy does not mutate rc configuration, reload devfs,
or start/stop jails.

Installation and verification remain the mutating portion of this layer and
must satisfy FI's fail-closed preclassification and no-clobber requirements.

Before lifecycle installation is accepted, FI must also reject any existing
site lifecycle configuration that already claims direct automatic authority
over the FI production jail names. That collision check belongs to the
mutating lifecycle helper and real-host preflight, not this render checkpoint.

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

Jail-root, jail-local identity, filesystem-directory, dedicated devfs, and
deterministic host-file mutation are also implemented by the later layers in
this contract. Live VNET lifecycle, PF, service, and boot-policy mutation
remain unimplemented by this checkpoint.

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

## Production jail-root clone layer

The production jail-root layer creates exactly three ZFS clones:

    <FI_JAIL_DATASET_ROOT>/fi-receiver
    <FI_JAIL_DATASET_ROOT>/fi-ingest
    <FI_JAIL_DATASET_ROOT>/fi-sor-db

Each clone must originate from exactly:

    <FI_JAIL_TEMPLATE_SNAPSHOT>

The configured snapshot is authoritative. The apply layer must never select,
substitute, create, or advance a template snapshot on its own.

### Jail-root ownership

Every FI-managed production jail-root dataset must carry locally-set:

    org.ironsignal.fi:managed=1
    org.ironsignal.fi:schema=1

The required roles are:

    fi-receiver  -> jail-root-receiver
    fi-ingest    -> jail-root-ingest
    fi-sor-db    -> jail-root-sor-db

Inherited FI ownership metadata does not establish FI authority.

### Jail-root controlled state

Every production jail-root clone must have:

    origin      = exact FI_JAIL_TEMPLATE_SNAPSHOT
    mountpoint  = exact configured jail root
    canmount    = on
    readonly    = off
    atime       = off
    exec        = on
    setuid      = on
    devices     = on
    mounted     = yes

Controlled writable ZFS properties must be locally set by FI. `origin` and
`mounted` are inspected runtime/read-only state and are validated by exact
value.

This clone layer does not introduce additional jail hardening. Jail capability,
devfs, filesystem visibility, service privilege, and network restrictions are
separate reviewed deployment layers.

### Jail-root classification

Each requested production jail root is classified before mutation as exactly
one of:

    ABSENT
    OWNED_MATCH
    OWNED_DRIFT
    FOREIGN_COLLISION
    UNKNOWN

`ABSENT` requires both the destination ZFS dataset and destination filesystem
path to be absent.

`OWNED_MATCH` requires exact FI ownership metadata, exact role, exact origin,
exact controlled ZFS state, exact mountpoint, and mounted runtime state.

`OWNED_DRIFT` means the resource is authoritatively FI-owned but differs from
requested state.

`FOREIGN_COLLISION` includes an existing destination dataset without exact
local FI ownership metadata or an existing destination path when the
destination dataset is absent.

`UNKNOWN` means inspection could not establish a safe classification.

Only `ABSENT` may be cloned. `OWNED_MATCH` is a no-op. All other states fail
closed.

### Layer-wide preclassification

All three jail-root resources must be classified before the first clone is
created.

If any resource is `OWNED_DRIFT`, `FOREIGN_COLLISION`, or `UNKNOWN`, the layer
must fail before creating any jail-root clone.

Immediately before cloning an `ABSENT` resource, the implementation must
reclassify it to detect races or newly-created collisions.

### Mutation boundary

The only production mutation primitive permitted in the initial jail-root
layer is:

    zfs clone

The layer must not:

- destroy, rename, promote, rollback, or rewrite an existing jail-root dataset;
- create or modify users or groups;
- create or modify devfs rules;
- install jail or fstab files;
- create or destroy VNET interfaces;
- modify bridges or PF;
- start or stop jails;
- install or start FI services;
- select jail boot policy;
- automatically remove partially-created resources after a runtime failure.

A partial clone set after an unexpected runtime failure is preserved for
inspection. A later invocation must classify the existing FI-managed resources
rather than destroy or silently replace them.

### Jail-root readiness and verification

The read-only pre-apply command accepts:

    ABSENT
    OWNED_MATCH

and fails closed on:

    OWNED_DRIFT
    FOREIGN_COLLISION
    UNKNOWN

The read-only post-apply verification command accepts only:

    OWNED_MATCH

Neither read-only path may invoke the `zfs clone` mutation primitive.

## Production jail-local runtime identity layer

FI application identities are created inside their production jail roots.
The FreeBSD host must not receive FI application accounts merely to support
filesystem ownership.

The initial runtime identities are:

    fi-receiver:
        user  = fi-receiver
        group = fi-receiver
        uid   = FI_RUNTIME_UID
        gid   = FI_RUNTIME_GID

    fi-ingest:
        user  = fi-ingest
        group = fi-ingest
        uid   = FI_RUNTIME_UID
        gid   = FI_RUNTIME_GID

The same numeric UID/GID is deliberate across the separate receiver and ingest
jails. Their local names remain distinct.

`fi-sor-db` is not modified by this layer. PostgreSQL package installation is
responsible for establishing the database service identity expected by the
FreeBSD package.

Each FI runtime account must have:

    home    = /nonexistent
    shell   = /usr/sbin/nologin
    login   = disabled

The identity layer uses the jail root as an alternate password-database root.
It must not create FI application users or groups on the FreeBSD host.

### Identity classification

Each receiver or ingest identity is classified as:

    ABSENT
    OWNED_MATCH
    OWNED_DRIFT
    FOREIGN_COLLISION
    UNKNOWN

`ABSENT` requires the requested user name, group name, UID, and GID all to be
unused within that jail root.

`OWNED_MATCH` requires the configured name, UID, GID, primary group, home,
shell, and disabled-login state to match exactly.

A configured FI name with mismatched controlled attributes is
`OWNED_DRIFT`.

Use of the configured UID or GID by another local identity is
`FOREIGN_COLLISION`.

Inspection failure is `UNKNOWN`.

Only `ABSENT` may be created. `OWNED_MATCH` is a no-op. All other states fail
closed.

### Identity mutation boundary

The only initial production identity mutations are:

    pw -R <jail-root> groupadd
    pw -R <jail-root> useradd

The layer must not:

- create host FI application identities;
- modify or delete an existing user or group;
- renumber an existing UID or GID;
- modify the PostgreSQL jail;
- create application directories;
- modify jail, VNET, devfs, PF, or service configuration.

## Production filesystem directory layer

The filesystem directory layer is the next deployment mutation boundary after
jail-local runtime identities.

It establishes only the FI-controlled directory ownership and mode required
before host-controlled mounts and FI services can be installed.

It does not:

- install or modify jail or fstab files;
- mount or unmount filesystems;
- create or modify devfs rules;
- create or destroy VNET interfaces;
- modify bridges or PF;
- start or stop jails;
- install or start FI services;
- select or modify jail boot policy.

### Directory initialization marker

Directory initialization uses the locally-set ZFS user property:

    org.ironsignal.fi:directory-schema=1

This property is not an ownership marker by itself.

The underlying production dataset or jail-root clone must already classify as
exact `OWNED_MATCH` under its authoritative ZFS or jail-root contract before
the directory layer may act on it.

A missing directory-schema property means that directory initialization has
not yet been completed for that FI-owned resource.

Once the property is locally set to `1`, directory ownership or mode mismatch
is `OWNED_DRIFT` and must fail closed.

An inherited directory-schema property is not accepted as local initialization
authority.

### Host source-directory permissions

The following FI-owned ZFS dataset roots receive exact Unix ownership and mode:

| Configuration path | Owner | Group | Mode |
| --- | ---: | ---: | ---: |
| `FI_CUSTODY_GENERATION_HOST` | `FI_RUNTIME_UID` | `FI_RUNTIME_GID` | `0700` |
| `FI_RECORDED_HOST` | `FI_RUNTIME_UID` | `FI_RUNTIME_GID` | `0700` |
| `FI_READY_HOST` | `FI_RUNTIME_UID` | `FI_RUNTIME_GID` | `0700` |
| `FI_RECEIVER_CONFIG_HOST` | `0` | `FI_RUNTIME_GID` | `0750` |
| `FI_INGEST_CONFIG_HOST` | `0` | `FI_RUNTIME_GID` | `0750` |

The custody, recorded, and READY roots use the shared FI numeric identity so
the existing owner-only FI object modes remain valid across the receiver and
ingest jail views.

The configuration roots remain host-root-owned. Their FI runtime group permits
the applicable jail-local service identity to traverse and read explicitly
permitted configuration material after the host mounts that dataset read-only
into the jail.

`FI_SOR_POSTGRES_HOST` is not modified by this layer. PostgreSQL ownership and
mode remain deferred until the selected FreeBSD PostgreSQL package has been
installed and its service UID/GID has been inspected and accepted.

### Receiver jail directories

Before the receiver directory-schema marker is set, the following FI-specific
paths are created inside `FI_RECEIVER_ROOT`:

| Jail path | Owner | Group | Mode | Purpose |
| --- | ---: | ---: | ---: | --- |
| `/var/db/fi` | `0` | `0` | `0755` | FI data namespace |
| `/var/db/fi/custody` | `0` | `0` | `0755` | custody mount parent |
| `/var/db/fi/custody/generation` | `0` | `0` | `0755` | nullfs mountpoint |
| `/var/db/fi/custody/recorded` | `0` | `0` | `0755` | nullfs mountpoint |
| `/var/db/fi/custody/ready` | `0` | `0` | `0755` | nullfs mountpoint |
| `/usr/local/etc/fi` | `0` | `0` | `0755` | read-only config mountpoint |
| `/var/run/fi` | `FI_RUNTIME_UID` | `FI_RUNTIME_GID` | `0700` | jail-local runtime state |

### Ingest jail directories

Before the ingest directory-schema marker is set, the following FI-specific
paths are created inside `FI_INGEST_ROOT`:

| Jail path | Owner | Group | Mode | Purpose |
| --- | ---: | ---: | ---: | --- |
| `/var/db/fi` | `0` | `0` | `0755` | FI data namespace |
| `/var/db/fi/custody` | `0` | `0` | `0755` | custody mount parent |
| `/var/db/fi/custody/generation` | `0` | `0` | `0755` | nullfs mountpoint |
| `/var/db/fi/custody/recorded` | `0` | `0` | `0755` | nullfs mountpoint |
| `/var/db/fi/custody/ready` | `0` | `0` | `0755` | nullfs mountpoint |
| `/usr/local/etc/fi` | `0` | `0` | `0755` | read-only config mountpoint |
| `/var/run/fi` | `FI_RUNTIME_UID` | `FI_RUNTIME_GID` | `0700` | jail-local runtime state |

### System-of-Record jail directories

Before the System-of-Record jail directory-schema marker is set, the following
mount hierarchy is created inside `FI_SOR_DB_ROOT`:

| Jail path | Owner | Group | Mode | Purpose |
| --- | ---: | ---: | ---: | --- |
| `/var/db/fi` | `0` | `0` | `0755` | FI data namespace |
| `/var/db/fi/sor` | `0` | `0` | `0755` | SOR mount parent |
| `/var/db/fi/sor/postgres` | `0` | `0` | `0755` | PostgreSQL nullfs mountpoint |

The PostgreSQL service does not use these root-owned mountpoint permissions as
its data-directory authority. After the host-controlled nullfs mount is active,
the mounted source dataset's separately accepted PostgreSQL ownership and mode
are authoritative.

### Directory preclassification and mutation

The entire directory layer is preclassified before its first mutation.

For host source directories, the corresponding dataset must already be an
exact FI-owned dataset. A missing directory-schema marker permits the layer to
establish the contracted owner and mode and then verify them before setting the
marker locally.

For jail-local directories, a jail root without a local directory-schema
marker may be initialized only when every FI-specific managed destination path
for that jail is absent. An unexpected pre-existing managed path is a
`FOREIGN_COLLISION` and fails closed.

When a jail root has a local directory-schema marker, every managed directory
must:

- exist;
- be a directory;
- not be a symbolic link;
- have the exact numeric owner;
- have the exact numeric group;
- have the exact mode.

Any mismatch is `OWNED_DRIFT`.

The directory-schema marker is written only after all directories for that
resource have been independently verified.

A partial runtime failure is preserved for inspection. The deployment must not
recursively remove, replace, rename, or silently repair an ambiguous
pre-existing directory.

The only initial directory mutation primitives are:

    mkdir
    chown
    chmod
    zfs set org.ironsignal.fi:directory-schema=1

`/var/run/fi` is operational state. The later rc.d service layer must recreate
it with the same exact owner and mode after boot when required.
