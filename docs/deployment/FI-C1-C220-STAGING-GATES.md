# FI C1 — C220 deployment staging and acceptance gates

**Status:** Unreleased development, not authorized for live ingestion merely
because CI passes. This procedure preserves the existing populated FI SoR,
its PostgreSQL 18 PGDATA, original receiver-signed custody and READY markers.

## Fixed two-jail processing path

- **fi-receiver** continues to own durable signed generation custody and
  original recorded receipts. Its trust files and source registry remain the
  original authority.
- **fi-ingest** runs the tested C1 source reader, P5 preparation, and
  SourceParent/five-family buffers. It owns the write view of host tmpfs
  `/var/run/fi-c1-handoff`. It has **no PostgreSQL connection**.
- **fi-sor** runs the tested C1 ordered SQL workers on the **existing**
  PostgreSQL 18 database and consumes the read-only nullfs view of the
  same tmpfs. Its separate B OS child verifies original signed custody and
  committed SQL in parallel. A distinct local canonical publisher makes
  verified rows visible and inserts exactly one Accepted journal entry.
- **No old fi_ingest_worker process may compete** for the same receiver
  READY work during controlled C1 activation.

Reporting windows do not force buffer flushing. tmpfs objects are
transient; post-crash recovery trusts original signed custody plus
committed PostgreSQL identities, not the contents of lost RAM.

## Stage exact binaries on the development FreeBSD checkout

From a clean checkout on the existing
`dev/c1-two-process-20261120` branch, with FreeBSD amd64 and Go 1.27.x:

```sh
commit=$(git rev-parse --short=12 HEAD)
sh tools/deployment/freebsd/build-fi-c1-dev.sh "/var/tmp/fi-c1-dev-$commit"
```

The script refuses a dirty/detached/wrong branch and refuses to overwrite an
existing staging directory. It builds **only** these four binaries:

`fi-c1-ingest-worker`, `fi-c1-sor-worker`,
`fi-c1-private-schema`, and `fi-c1-host-preflight`.

It includes the exact Git SHA and SHA-256 hashes in
`BUILD-MANIFEST.txt`. This is a local staging directory, **not a ZIP or
source patch**. It does not install, enable, publish or run C1 on C220.

The existing `fi-backend-install apply-c1-binaries` installer expects
precisely those four files. Move the reviewed staging directory into a
root-controlled location on the C220 host before invoking the existing
installer with its correct host configuration. Its follow-up
`verify-c1-binaries` must match the same staging files. Both C1 jail
rc services are created **disabled** by
`fi-backend-install apply-c1-runtime`, then inspected with
`verify-c1-runtime`.

## Read-only C220 verification

The physical host must have the existing **fi-receiver**, **fi-ingest**
and **fi-sor** jails, correct ZFS/nullfs mounts, a bounded host tmpfs,
original receiver trust/custody available read-only, and the current
populated authoritative `fi` PostgreSQL 18.

Before any offline installation, run the repository's
`go/cmd/fi-backlog-recover/diagnostics/fi_c1_c220_governed_deploy_gate.sh`
with `--audit` from the actual C220 root shell. This operation is
read-only.

Only after a separately authorized offline governed Pending / SQL role
installation and complete disabled service staging, run the **same**
script with `--ready`. It requires:

1. A unique real `fi-sor` jail and exact fi-ingest / fi-sor service
   identities, host tmpfs producer/consumer isolation, and original
   read-only custody.
2. Existing canonical FI data and schema preserved, PostgreSQL 18 durable
   settings, governed Pending relations, and the least-privileged
   `fi_ingest` / `fi_c1_publisher` roles.
3. The original `fi_ingest_worker` **disabled and stopped**, with neither
   C1 worker enabled.
4. Actual installed jailed C1 binaries executing read-only `--verify`
   through their exact rc runners, under the **unprivileged** service
   identities. The binary `-preflight` validates TLS, original custody,
   tmpfs, and the SoR local SQL role permission boundary. It opens no
   ingest listener, runs no B worker, writes no SQL and removes no READY
   marker.

A PASS on this gate is **pre-activation evidence only**.

## Controlled acceptance still required

Do not enable C1 as a live reader until these gates have passed:

- Run the two **real jailed C1 processes**, connected by host tmpfs for
  record data and authenticated mTLS for control/commit acknowledgments.
- Prove a complete genuine receiver-signed generation through all actual
  SourceParent/five-family SQL, separate B child, canonical single
  transaction, one Accepted journal, and receiver READY marker retirement.
- Interrupt/restart the jail services with original signed custody intact,
  and prove exact read-only recovery without duplicate canonical records
  or an unverified acceptance.
- Measure actual C220 W512 throughput/CPU and compare to the retained
  tested C1 baseline, without claiming a performance improvement from CI
  microfixtures.

On failure, **do not clear Pending tables, touch canonical FI, delete
original custody or remove READY markers**. Keep the C1 services disabled
or stopped and retain the PostgreSQL evidence for reconciliation.
