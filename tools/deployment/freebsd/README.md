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

The ZFS apply layer's production mutation primitive is `zfs create`.
Later reviewed layers separately implement jail-root, identity, filesystem
directory, and dedicated devfs mutation.

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
Later sections define the reviewed jail-root, identity, directory, and devfs layers. Remaining operations stay behind future reviewed apply boundaries.
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

### Jail-local runtime identities

FI runtime application accounts are local to their production jail roots.

The initial identities are:

    fi-receiver  uid/gid FI_RUNTIME_UID/FI_RUNTIME_GID
    fi-ingest    uid/gid FI_RUNTIME_UID/FI_RUNTIME_GID

The shared numeric UID/GID is deliberate. The receiver and ingest jail-local
user and group names remain distinct.

The FreeBSD host does not receive FI application accounts for filesystem
ownership.

The `fi-sor-db` jail is not modified by this layer. PostgreSQL package
installation establishes the database service identity expected by FreeBSD.

`apply-identities` classifies both identities before the first mutation. Exact
matches are retained, absent identities are created, and drift, collisions,
or unknown state fail closed.

The only identity mutation primitives are:

    pw -R <jail-root> groupadd
    pw -R <jail-root> useradd

The created accounts use `/nonexistent`, `/usr/sbin/nologin`, and disabled
password login.

### Production filesystem directories

`apply-directories` initializes and verifies the FI-controlled production
directory layer after ZFS, jail-root, and jail-local identity acceptance.

The layer manages:

- ownership and mode of the custody, recorded, READY, receiver-config, and
  ingest-config host dataset roots;
- required receiver and ingest jail mountpoint directories;
- `/var/run/fi` for receiver and ingest with the configured FI runtime UID/GID;
- the System-of-Record jail mountpoint hierarchy.

Initialization is recorded with the locally-set ZFS property:

    org.ironsignal.fi:directory-schema=1

The marker is accepted only on an already-authoritative FI dataset or jail-root
clone. Inherited markers are not accepted.

The layer preclassifies every managed resource before its first mutation,
fails closed on drift or collisions, independently verifies newly initialized
resources, and treats an exact second apply as a no-op.

PostgreSQL data-directory ownership is intentionally not selected by this
layer. It remains deferred until the selected FreeBSD PostgreSQL package has
established and exposed the service UID/GID.

Production invocation is:

    ./fi-bootstrap.sh apply-directories /path/to/fi-bootstrap.conf

### Production devfs ruleset

`apply-devfs` creates or verifies one dedicated production devfs ruleset after
the filesystem-directory layer has been accepted.

The ruleset number comes from `FI_DEVFS_RULESET` and must be 100 or greater. The deployment never selects
+a production number automatically. The value `100` in the verification fixture
is test data only.

The production ruleset is intentionally independent of the stock
`devfsrules_jail` and `devfsrules_jail_vnet` rulesets. Its exact effective
ordered rules are:

    hide
    path null unhide
    path zero unhide
    path random unhide
    path urandom unhide

The layer does not expose ZFS, PF, BPF, FUSE, memory devices, PTYs, PTS,
`ptmx`, or login-oriented fd/stdin/stdout/stderr aliases.

Classification is fail closed:

- an absent configured ruleset is `ABSENT` and may be created;
- an exact effective ordered ruleset is `OWNED_MATCH`;
- any existing different, additional, missing, or reordered rule is
  `FOREIGN_COLLISION`;
- inability to inspect devfs state is `UNKNOWN`.

The apply path never deletes, clears, replaces, or silently repairs an existing
ruleset. An exact second apply performs no mutation.

`verify-devfs` is the read-only production acceptance path and requires exact
`OWNED_MATCH`.

The commands are:

    ./fi-bootstrap.sh apply-devfs /path/to/fi-bootstrap.conf
    ./fi-bootstrap.sh verify-devfs /path/to/fi-bootstrap.conf

This layer establishes only the in-kernel ruleset. The deterministic host-file
layer installs the matching `/etc/devfs.rules.fi` definition and rendered jail
configuration. Loading the persistent rules file and enabling production jail
lifecycle remain responsibilities of the later lifecycle/boot-policy layer.

### Production host-file layer

`apply-host-files` creates or verifies the deterministic host artifacts required
before production jail lifecycle can be enabled.

The managed set is:

    /etc/jail.conf.d/fi-receiver.conf
    /etc/jail.conf.d/fi-ingest.conf
    /etc/jail.conf.d/fi-sor-db.conf
    /etc/fstab.fi-receiver
    /etc/fstab.fi-ingest
    /etc/fstab.fi-sor-db
    /etc/devfs.rules.fi
    /usr/local/libexec/fi-vnet-pair

All eight artifacts carry the FI host-file ownership marker and exact role
metadata in their content.

The jail configuration files are installed `root:wheel` mode `0644`.

The per-jail fstab files are installed `root:wheel` mode `0600`.

The persistent FI devfs rules file is installed `root:wheel` mode `0644`.

The VNET helper is installed `root:wheel` mode `0555`.

Initial apply preclassifies the complete layer and fails closed on owned drift,
foreign collisions, or unknown state.

Absent files are published through same-directory temporary files and atomic
no-clobber hard links. Existing destinations are never overwritten.

`verify-host-files` is the read-only acceptance path and requires all eight
files to classify as exact `OWNED_MATCH`.

The host-file layer does not start jails, run the VNET helper, reload devfs,
change `rc.conf`, modify PF, or select jail boot policy.

`/etc/devfs.rules.fi` is intentionally inert until the later lifecycle layer
adds it to the configured FreeBSD `devfs_rulesets` list.

### Production lifecycle policy

FI does not take ownership of the host's global FreeBSD jail-service policy.

In particular, FI does not set:

    jail_enable
    jail_parallel_start
    jail_list
    jail_reverse_stop

Production FI jail startup is instead controlled by a dedicated local rc.d
service:

    /usr/local/etc/rc.d/fi_jails

with its dedicated enable configuration:

    /etc/rc.conf.d/fi_jails

The FI controller starts production jails one at a time in this order:

    fi-sor-db
    fi-ingest
    fi-receiver

It stops them one at a time in the reverse order:

    fi-receiver
    fi-ingest
    fi-sor-db

Each operation invokes the base FreeBSD jail service with `onestart` or
`onestop` for exactly one named jail and then independently verifies runtime
state with `jls`.

The jail configuration additionally carries explicit dependencies:

    fi-receiver -> fi-ingest -> fi-sor-db

The controller therefore owns FI application ordering without changing the
site's global jail ordering or selection policy.

The FI controller requires the base `jail` rc service. This places it after
the base jail service during startup and before it during reverse shutdown
ordering.

Persistent FI devfs loading uses:

    /etc/rc.conf.d/devfs/90-fi

The devfs fragment enables ruleset loading and adds `/etc/devfs.rules.fi` to
the site's existing `devfs_rulesets` list only when it is not already present.

FI does not set `devfs_system_ruleset`.

Rendering this policy does not install rc files, reload devfs, or start/stop
any jail.
