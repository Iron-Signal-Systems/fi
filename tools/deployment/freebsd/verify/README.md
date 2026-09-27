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

Neither command currently creates jail roots, runtime identities, devfs rules,
jail/fstab files, VNET interfaces, PF policy, FI services, or boot policy.

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
