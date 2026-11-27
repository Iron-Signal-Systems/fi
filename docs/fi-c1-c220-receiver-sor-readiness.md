# FI C1 receiver → SoR: C220 readiness and acceptance

Status: **development, not released**. The old fi-ingest jail is not an input
processor and must not be reintroduced. The only runtime path is
**fi-receiver → receiver-authenticated batch cache → fi-sor C1 → canonical fi**.

## Protocol and integrity

- The receiver keeps the original immutable signed FIGT transfer, recorded
  receipt and READY marker. It can publish a receiver-owned verified batch
  cache **during its existing cryptographic/semantic receipt validation**.
  The cache marker is published only after the original receipt is durable.
- fi-sor mounts this verified cache **read-only**, loads the full manifest plan
  without first extracting the entire FIGT again, and executes the existing
  header-first P5, five-family P6 and adaptive SQL processing directly into
  canonical `fi`.
- Independent verifier B still reads **original signed FIGT**, not the cache,
  before a single canonical Accepted journal event. READY retirement follows
  that Accepted readback. No Pending-to-canonical relational copy.

## One-time historical backlog

The original C220 signed generation predates receiver-side cached publication.
It therefore needs **one exact-generation** receiver-cache backfill, not a new
SoR reset or a receiver restart of every historical transfer.

The dedicated `fi-receiver` mode takes the same receiver trust and generation
configuration arguments as normal operation, plus
`-generation-cache-backfill-source iss-fs-22a.iss.local`
and
`-generation-cache-backfill-generation 20261030T000032.061323100Z-3e38b2210771462c`.

The backfill does not start a network listener or touch SQL/READY. It refuses
non-enrolled sources, missing/changed recorded receipts and unsafe custody;
it revalidates the original signed transfer before cache publication.
Use only the newly compiled `fi-receiver`, with the existing receiver trust
configuration and correct mounted cache root. Never run a second receiver
listener with these flags. The output must include
`FI RECEIVER VERIFIED CACHE BACKFILL PASS`.

## Filesystem/security prerequisites

The receiver-owned host ZFS source should be placed under the existing
`/work/fi-c220-20261114/custody` area, separate from generation and
recorded-receipt roots. The recommended path is
`/work/fi-c220-20261114/custody/verified-cache`.

Provide that root as **rw nullfs** at
`/fast/jails/roots/fi-receiver/var/db/fi/verified-cache`, and **ro nullfs**
at `/fast/jails/roots/fi-sor/var/db/fi/verified-cache`. Receiver startup
uses `-generation-verified-cache-root /var/db/fi/verified-cache`.
The SoR uses `-receiver-verified-cache-root /var/db/fi/verified-cache`
(the normal service runner already supplies this from its config).
Use a shared *restricted* group with root directory mode `2750` (setgid,
group readable) and only authorized receiver writer / fi-sor reader members.
Files are `0640`; the receiver explicitly sets this despite restrictive
service umasks. Do **not** make custody, cache or the SoR mount world-readable
or write-enable fi-sor. The configuration must be persisted in each jail's
existing fstab, with original mounts and PostgreSQL preserved.

First execute `fi_c1_c220_receiver_sor_readiness_audit.sh --audit` on
physical C220 as root. It is read-only and reports mount/security blockers.

## Acceptance gates (all required before unattended READY)

1. Exact source revision passes Go tests and FreeBSD native PostgreSQL 18
   tests, including receiver's verified cache + B original-custody coverage.
2. Original receiver custody/receipt/trust remain immutable and accessible;
   verified-cache root is physically mounted read-only into fi-sor and readable
   by the service identity; no fi-ingest worker is running.
3. One-time exact-generation backfill verifies all 8,399 batch manifests and
   15,140,785 records against the original signed receipt, with no SoR SQL.
4. Real fi-sor read-only preflight sees original signed custody, cache, correct
   local PG18, SQL roles, and an empty canonical/pending baseline. A rollback
   ZFS snapshot is present. **Do not reset an already-empty SoR**.
5. Direct canonical execution exercises the same native C1 service used by
   routine READY. Verify complete independent B, one Accepted entry, row count,
   generation identity, and no additional Pending publication.
6. Power-loss/restart, concurrent reader-visibility, idempotent READY
   reconciliation and multi-generation acceptance are validated before enabling
   `fi_c1_sor_local_enable="YES"`.

Do not run any real-SoR writer or turn on unattended service merely because
compile and disposable CI passed. In particular, the presence of a verified
batch cache is not itself an Accepted generation or a substitute for B.
