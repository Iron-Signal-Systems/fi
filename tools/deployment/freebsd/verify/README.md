# FreeBSD Deployment Verification

This directory contains read-only acceptance checks for the FI FreeBSD backend.

Verification must eventually cover:

- expected jail identities and VNET interfaces;
- ZFS dataset ownership and mount authority;
- FI service users and groups;
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

Verification scripts must not silently remediate failed state.
