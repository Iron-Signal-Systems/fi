# C220 FI C1: automatic sender-to-canonical SoR cutover

Status: DEVELOPMENT; SOURCE COMMITTED, NOT ACTIVATED on C220.

## Reuse the existing proven single-jail engine
The original \`go/cmd/fi-c1-sor-local\` FreeBSD \`fi_c1_sor_dev\` binary
already implements \`-sources\`, \`-ready-root\`, \`-continuous\`, bounded
READY passes, authenticated receiver cache, original P5/P6 SQL, independent
B verification, canonical Accepted and READY retirement. The original
sender custody and recorded receipts remain immutable and read only.
No obsolete fi-ingest jail or old generic ingest worker is required.

The files in tools/deployment/freebsd/runtime.d define a fail-stop
supervised service in fi-sor. It loads the existing rc.conf.d/fi_c1_sor
worker/publisher Unix socket identities and custody config, combined with
the explicit live source roster and READY/cache/staging paths in
fi_c1_sor_live.rc.conf. Maximum SQL workers 32; polling 5s;
automatic Pending replay forbidden.

IMPORTANT: daemon never uses -r. If source/SQL/B/Accepted has
uncertainty, service exits and stays stopped; original READY/custody
are preserved for operator reconciliation. Do not restart blindly.

## Before enabling
1. Build and FreeBSD-test from an exact GitHub branch commit.
2. Verify real fi-sor PG system identifier, 8GiB max_wal_size,
   worker/publisher authority and existing 15,140,785 Accepted records.
3. Confirm receiver signed custody and recorded mounts RO; verified
   batch cache RO into fi-sor; only READY scheduling RW.
4. Confirm no obsolete C1 or generic ingest process competing.
5. Confirm source roster matches registered receiver senders,
   scratch is on fast ZFS, and fi-sor service user is unprivileged.
6. Run executable -preflight; no SQL writes or marker retirement.
7. Restore separate 15s/5min telemetry and prove fresh samples.
8. Activate the service only under an explicit operator cutover.
9. Observe one NEW signed sender generation end-to-end, B PASS,
   canonical Accepted and only that scheduling marker retired.
10. Test power/restart, halt-on-error, and recovery before claiming
    boot-persistent acceptance.
