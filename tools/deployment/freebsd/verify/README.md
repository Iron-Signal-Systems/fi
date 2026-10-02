# FreeBSD Deployment Verification

This directory contains acceptance checks for the FI FreeBSD backend.

Verification scripts must never silently remediate failed state.

## Implemented checks

### Deterministic render

Run:

    ./Validate-FI-FreeBSD-Render.sh

This check runs without root privileges and verifies:

- strict configuration grammar;
- template rendering;
- absence of unresolved template tokens;
- deterministic output manifests;
- byte-identical plans from identical input;
- rejection of unknown configuration keys;
- rejection of duplicate configuration keys;
- rejection of shell expressions;
- rejection of address/network mismatches.

### Host preflight

Run on the intended FreeBSD host:

    ./Validate-FI-FreeBSD-Preflight.sh /path/to/fi-bootstrap.conf

When executed as a non-root user, the verifier proves that the bootstrap
preflight refuses host inspection through the root guard.

When executed as root, the verifier:

- captures selected host control-plane state;
- runs the bootstrap preflight;
- captures the same state again;
- requires the bootstrap preflight to succeed;
- requires the before and after host-state captures to be identical.

The host-state comparison covers ZFS datasets, mounts, interfaces, running
jails, devfs ruleset identifiers, users/groups, selected rc.conf state, PF
rules/NAT state, forwarding state, and deployment-parent filesystem metadata.

The verifier does not remediate failed state.

### ZFS apply state machine

Run:

    ./Validate-FI-FreeBSD-ZFS-Apply.sh

This verifier is an offline mock-backed acceptance test for the ZFS apply
state machine.

It verifies:

- `ABSENT` classification;
- `OWNED_MATCH` classification;
- `OWNED_DRIFT` classification;
- `FOREIGN_COLLISION` classification;
- `UNKNOWN` classification;
- inspection failure is never interpreted as absence;
- inherited FI ownership metadata does not establish ownership;
- inherited controlled ZFS properties are not accepted as local desired state;
- an existing destination mountpoint path fails closed;
- wrong-host apply fails before mutation;
- layer-wide preclassification prevents an avoidable partial deployment;
- a newly created resource is independently reclassified and verified;
- an exact second apply is a no-op;
- collision and unknown states fail closed.

The verifier uses mock ZFS functions and does not modify the production pool.

The fixture under `fixtures/` is an offline deterministic fixture. It is bound
to `fi-test.invalid` so it cannot be accepted as a production configuration on
the real FI backend host.

## Current production ZFS commands

The implemented production ZFS commands are:

    ../fi-bootstrap.sh apply-zfs /path/to/fi-bootstrap.conf
    ../fi-bootstrap.sh verify-zfs /path/to/fi-bootstrap.conf

`apply-zfs` is the controlled mutating path. It may create absent FI-owned
production datasets and otherwise requires exact owned state.

`verify-zfs` is the read-only acceptance path. It requires all ten production
datasets to classify as `OWNED_MATCH` and fails closed on absence, drift,
foreign ownership, or unknown state.

Real-host acceptance on the intended FreeBSD backend demonstrated:

- all ten production datasets classify as `OWNED_MATCH`;
- `verify-zfs` exits successfully;
- selected ZFS state captured before and after verification is byte-identical.

The ZFS commands themselves do not create jail roots, runtime identities,
directories, devfs rules, jail/fstab files, VNET interfaces, PF policy,
FI services, or boot policy. Jail-root, identity, and directory mutation are
separate reviewed deployment layers.

## Future runtime acceptance

Verification must eventually also cover:

- expected production jail identities and VNET interfaces;
- FI service users and groups after deployment;
- configuration and runtime directory ownership/modes;
- rc.d service state;
- PF network-policy boundaries;
- receiver trust readiness;
- ingest-worker singleton behavior;
- PostgreSQL reachability only across the authorized path;
- denial of unauthorized PostgreSQL access;
- custody/receipt/READY permissions;
- service restart behavior;
- jail restart recovery;
- host restart recovery.

## Production jail-root verification

The jail-root acceptance path proves:

- `ABSENT`, `OWNED_MATCH`, `OWNED_DRIFT`, `FOREIGN_COLLISION`, and `UNKNOWN`
  classification behavior;
- destination-path collision rejection;
- local FI ownership requirements;
- exact template snapshot origin;
- exact controlled ZFS properties;
- layer-wide preclassification before mutation;
- exact second-apply no-op behavior;
- wrong-host rejection;
- exact `zfs clone` argument construction;
- read-only preflight acceptance of only `ABSENT` and `OWNED_MATCH`;
- read-only post-apply verification requiring `OWNED_MATCH`;
- no clone mutation from either read-only path.

Production acceptance uses:

    preflight-jail-roots
    apply-jail-roots
    verify-jail-roots

## Jail-local identity verification

The identity verifier proves:

- absent identity classification;
- foreign UID and GID collision rejection;
- partial FI identity drift detection;
- exact matching identity acceptance;
- password-enabled identity rejection;
- locked-password acceptance;
- exact `pw groupadd` and `pw useradd` argument construction;
- layer-wide preclassification before mutation;
- exact second-apply no-op behavior;
- wrong-host rejection before mutation.

Production acceptance additionally verifies the resulting receiver and ingest
`master.passwd` and group records and confirms that the FreeBSD host remains
clear of FI runtime identities.

## Filesystem directory verification

Run:

    ./Validate-FI-FreeBSD-Directory-Apply.sh

This offline acceptance path verifies:

- uninitialized FI-owned host-directory classification;
- exact `OWNED_MATCH` classification;
- ownership/mode drift detection;
- symbolic-link collision rejection;
- wrong local directory-schema version rejection;
- marker inspection failure as `UNKNOWN`;
- empty uninitialized jail-directory classification;
- rejection of pre-existing managed jail paths;
- exact directory-schema `zfs set` mutation arguments;
- initialization of exactly five host resources and three jail resources;
- exact second-apply no-op behavior;
- layer-wide preclassification before mutation;
- wrong-host rejection before mutation.

The verifier does not modify the production pool or production jail roots.

## Devfs verification

Run:

    ./Validate-FI-FreeBSD-Devfs-Apply.sh
    ./Validate-FI-FreeBSD-Bootstrap-Dispatch.sh

The devfs verifier proves:

- absent ruleset classification;
- inspection failure as `UNKNOWN`;
- exact ordered rules as `OWNED_MATCH`;
- missing rule rejection;
- additional rule rejection;
- rule-order drift rejection;
- exact ordered `devfs rule -s ... add` mutation arguments;
- exact second-apply no-op behavior;
- read-only verification without mutation;
- absent-state verification failure;
- wrong-host rejection before mutation;
- unknown-state rejection before mutation.

The bootstrap-dispatch verifier proves that each reviewed deployment command has
exactly one helper-loading arm before configuration parsing and exactly one
execution arm after configuration parsing. This specifically prevents a
command from being accepted and prepared by bootstrap without ever executing
its implementation.

## Jail network render verification

Run:

    ./Validate-FI-FreeBSD-Jail-Network-Render.sh

This offline verifier renders the production jail configuration using the
accepted fixture and proves:

- host retention of the dedicated receiver physical interface;
- exact receiver external bridge/epair lifecycle;
- exact receiver management and workload epair lifecycle;
- receiver external, management, and workload addresses;
- receiver default routing through the external gateway;
- exact ingest dual-epair lifecycle;
- ingest default routing through the management gateway;
- preservation of the System of Record dual-epair lifecycle;
- absence of the receiver dedicated interface from ingest and SOR;
- absence of the host administrative address from the receiver jail template;
- exact VNET interface counts;
- network configuration before `/etc/rc`;
- controlled `/etc/rc.shutdown jail` on stop.

This verifier performs no live VNET, bridge, route, jail, or interface mutation.

Real-host acceptance remains required to prove physical receiver-interface
return and address cleanup after jail shutdown.

## Host-file apply verification

Run:

    ./Validate-FI-FreeBSD-Host-File-Apply.sh

The offline host-file verifier proves:

- absent host-file classification;
- exact `OWNED_MATCH` classification;
- FI-owned content drift detection;
- FI-owned mode drift detection;
- unmarked file collision rejection;
- symbolic-link collision rejection;
- directory collision rejection;
- unexpected hard-link detection;
- metadata inspection failure as `UNKNOWN`;
- atomic no-clobber publication when a destination appears during creation;
- exact first creation;
- exact second-apply no-op behavior;
- read-only verification of exact state;
- layer-wide preclassification before mutation;
- unknown-state rejection before mutation;
- wrong-host rejection before mutation;
- absent-state verification failure without mutation.

The verifier uses temporary files only. It does not install anything beneath
`/etc` or `/usr/local/libexec` and does not operate live jails, VNET, PF, or
devfs.

## Lifecycle render verification

Run:

    ./Validate-FI-FreeBSD-Lifecycle-Render.sh

This offline verifier proves:

- dedicated FI lifecycle enable authority;
- absence of FI ownership over global `jail_*` policy;
- explicit FI startup order;
- explicit reverse FI shutdown order;
- one-jail-at-a-time base jail-service invocation;
- independent `jls` runtime verification;
- FI rc ordering after the base jail service;
- explicit ingest dependency on System of Record;
- explicit receiver dependency on ingest;
- System of Record as the dependency root;
- persistent loading of `/etc/devfs.rules.fi`;
- preservation of existing site `devfs_rulesets`;
- duplicate-safe FI rules-file append behavior;
- absence of FI control over `devfs_system_ruleset`.

The verifier performs no live rc, jail, devfs, VNET, or service mutation.

## Lifecycle apply verification

Run:

    ./Validate-FI-FreeBSD-Lifecycle-Apply.sh

The offline lifecycle-apply verifier proves:

- exact lifecycle parent-directory classification;
- parent symbolic-link and metadata collision rejection;
- disabled global jail-policy compatibility;
- compatibility with enabled global policy that selects only unrelated jails;
- rejection of enabled `_ALL` global jail authority;
- rejection of explicit global FI jail ownership;
- exact first lifecycle-file creation;
- exact second-apply no-op behavior;
- read-only lifecycle verification;
- layer-wide preclassification before mutation;
- global jail-policy rejection before mutation;
- wrong-host rejection before mutation;
- absence of live jail or devfs activation from the installer.

The lifecycle installer writes configuration only. It does not start or stop
jails and does not reload or mutate the running devfs ruleset.

## PF render verification

Run:

    ./Validate-FI-FreeBSD-PF-Render.sh

The offline PF render verifier proves the deterministic host PF policy,
including the ingest-to-System-of-Record PostgreSQL authorization, denial of
other PostgreSQL initiation paths, workload-network external-path denial, and
absence of unresolved FI tokens.

## PF persistence verification

Run:

    ./Validate-FI-FreeBSD-PF-Apply.sh

The offline PF persistence verifier proves create, verify, explicit legacy
adoption, controlled FI-owned update, metadata/collision rejection,
preclassification, syntax validation before mutation, and absence of runtime
PF activation from the persistence helper.

## PF lifecycle render verification

Run:

    ./Validate-FI-FreeBSD-PF-Lifecycle-Render.sh

The offline PF lifecycle verifier proves exact PF runtime configuration,
`pf -> fi_pf -> fi_jails` ordering, FI-jail startup dependence on verified PF
readiness, policy-hash binding, bridge-filtering configuration, and
System-of-Record state invalidation.

## PF runtime behavior verification

Run:

    ./Validate-FI-FreeBSD-PF-Runtime.sh

The mock runtime verifier proves fail-closed policy and metadata validation,
snapshot-path safety, PF-load and state-invalidation failure boundaries,
bridge-member filtering enabled last, exact runtime snapshot behavior,
filter/NAT drift detection, idempotent second start, and intentional
continued PF enforcement during FI jail shutdown.

## Real-host state capture

Run the read-only state capture before and after important real-host
acceptance transitions.

For the current receiver host:

    ./Capture-FI-FreeBSD-Host-State.sh \
        vtnet0 \
        vtnet1 \
        bridge30 \
        epre0a \
        epre0b \
        bridge10 \
        bridge20 \
        baseline

The capture reports host, physical/external/internal interface state, routes,
jails, rc policy, devfs, persistent PF policy, active PF filter/NAT rules,
bridge-filtering sysctls, PF runtime snapshot, and FI production files. It
performs no mutation.

## Dedicated receiver interface return verification

After `fi-receiver` has been stopped through the reviewed lifecycle path, run:

    ./Validate-FI-FreeBSD-Dedicated-Interface-Return.sh \
        vtnet0 \
        192.168.1.218 \
        vtnet1 \
        bridge30 \
        epre0a \
        epre0b \
        bridge10 \
        bridge20

Acceptance requires:

- the administrative interface and expected administrative IPv4 remain;
- `vtnet1` remains present on the host;
- `vtnet1` has no IPv4 or IPv6 address;
- the IPv4 and IPv6 route tables do not reference `vtnet1`;
- `vtnet1` is not a member of either internal FI bridge;
- `bridge30` is absent;
- `epre0a` is absent;
- `epre0b` is absent;
- `fi-receiver` is stopped.

The verifier is read-only.
