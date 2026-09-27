# FreeBSD Deployment Verification

This directory contains read-only acceptance checks for the FI FreeBSD backend.

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

The fixture under `fixtures/` is an offline deterministic-render fixture. It is
not a substitute for a host-specific production deployment configuration.

## Future runtime acceptance

Verification must eventually also cover:

- expected production jail identities and VNET interfaces;
- ZFS dataset ownership and mount authority;
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

Verification scripts must never silently remediate failed state.
