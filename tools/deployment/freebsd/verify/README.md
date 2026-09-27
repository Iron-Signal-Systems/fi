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

## Current production apply boundary

The only implemented production apply command is:

    ../fi-bootstrap.sh apply-zfs /path/to/fi-bootstrap.conf

It is limited to creation or exact verification of the FI production ZFS data
hierarchy.

Jail roots, runtime identities, devfs rules, `/etc` files, VNET lifecycle, PF
changes, service installation, and boot policy remain outside the current apply
boundary.

## Future runtime acceptance

Verification must eventually also cover:

- expected production jail identities and VNET interfaces;
- ZFS dataset ownership and mount authority after real-host apply;
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
