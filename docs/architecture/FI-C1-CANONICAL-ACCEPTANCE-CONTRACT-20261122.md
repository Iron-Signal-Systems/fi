# FI C1 — Canonical acceptance contract (unreleased development, 2026-11-22)

## Actual installed substrate versus application state

- Physical C220: `fi-receiver`, `fi-ingest`, `fi-sor` remain the
  only FI receiver/ingest/SoR jails. There is **no** `fi-sor-db` jail.
- Original signed generation and recorded receipt custody remain on
  `work`, writable by `fi-receiver` and **read-only** to `fi-sor`.
  The original source registry and signing trust are also RO to SoR.
- `fi-ingest` has a writable view of the 4 GiB host tmpfs; `fi-sor`
  has a read-only view of the same RAM. Cross-jail test passed.
- PostgreSQL 18 is **one existing populated canonical server** in
  `fi-sor`. Its PGDATA is on SSD `fast`, and its working data must
  not be replaced, reset, or cloned as the live database.
- The 18 original+new FI nullfs boot mounts and three jail-managed devfs
  mounts are configured persistently, but a controlled restart acceptance
  has **not** occurred.
- The physical SoR had 6,249 canonical accepted generations at the
  last read-only check. `fi_recovery_projection` and `fi_recovery`
  were absent and must stay absent on C220.

## Current implemented application boundaries

1. READY processing: `fi-ingest` reads source-scoped operational
   zero-byte markers. It reads the ORIGINAL recorder receipt to
   determine source/generation and receipt SHA; the READY filename is
   a hash, not an encoded generation ID.
2. Before staging, it performs an authenticated read-only `Status`
   query against `fi-sor` over TLS 1.3. On exact already-Accepted
   canonical generation and journal, it retires only that READY marker
   without replay. Unknown or unavailable status fails closed.
3. For a pending generation, the existing trust-validated loader opens
   original immutable receipt and signed generation custody. It
   prepares the C1 SourceParent/five-family work and places bounded
   buffers on the shared RAM. The `fi-ingest` process opens **no**
   PostgreSQL connection.
4. `fi-sor` owns all SQL connections. The six C1 handoff families
   preserve source and dependency ordering; individual SQL ACKs mean
   *only that buffer's SQL commit*, not final generation acceptance.
5. Verifier B runs in its own unprivileged SoR process with its own
   read-only PostgreSQL connection. Its original signed custody and
   relational proof runs in parallel to A, without family flushes.
6. Final mTLS `Drain` ACK is versioned and identifies three separate
   states: `FinalNone` (SQL-only), `FinalVerified` (B passed),
   `FinalAccepted` (actual canonical Accepted transaction).
7. `fi-ingest` will not retire a READY marker or claim an accepted
   generation unless the exact authenticated final state is
   `FinalAccepted`, the original receipt SHA and record/batch counts
   agree, and cleanup succeeds.

## Critical missing canonical SQL integration

The already-ported C1 SQL work in `c1_sor_service.go` and the adaptive
SourceParent/five-family pool **still uses the discarded DEVELOPMENT
`fi_recovery_projection` / `fi_recovery` SQL stage**. The old
offline `PublishC1VerifiedPrivateGeneration` function is not part
of the live two-jail service. It is prohibited to install those
discarded schemas into the physical populated C220 merely to make
the worker start. The default FI SQL ingestion service remains
blocked by `C1ServiceAdmission()`; it must not fall back silently.

There is an unavoidable transaction-isolation constraint:

- The C1 SQL pool executes independently committed SQL transactions
  from more than one local PostgreSQL connection.
- Independent verifier B can read only **committed** relational rows.
- Canonical `fi` readers must not observe *partial* generation rows,
  nor should an `Accepted` event exist before all relational rows and
  original signed proof pass.
- Consequently the concurrently committed C1 rows **cannot simply be
  written straight into the currently visible `fi` tables** while
  retaining all three requirements. A single shared SQL transaction
  would eliminate visibility issues but serialize the shared writer and
  would prevent B's separate transaction from reading A's uncommitted
  rows. PostgreSQL prepared transactions alone do not make several
  independent commits atomically visible to every reader.

The replacement needs a **governed, durable pending/unpublished
relational state inside the existing `fi-sor` PostgreSQL server**
(or a carefully proven equivalent), not the abandoned experimental
private SQL schema and never another SoR jail. Its identity, lifecycle,
isolation, permissions, recovery and capacity must be accepted as
real database design, not disguised as a temporary experiment.

## Required implementation and acceptance gates (not yet passed)

- Define the exact *new* durable pending representation and enforce
  that normal `fi` queries cannot see unfinished SourceParent/family
  rows. No old `fi_recovery_projection` or `fi_recovery` DDL.
- Preserve C1's bounded SQL workers, Security/File/Coverage/USN/Other
  buffer ordering and no cross-generation flushing.
- Bind every pending source row/typed child to original immutable
  source+generation+batch+record ordinal and SHA. B must independently
  prove the original receipt, trust, source authorization, record hashes,
  relational coverage and all USN dependencies.
- After B passes, execute exactly **one PostgreSQL canonical publication
  transaction**: remap source/typed identity and FK references into the
  populated existing `fi` tables, reconcile natural NTFS identities,
  insert exactly one matching `fi.ingest_journal` Accepted event, and
  commit all or roll back all. Do not rerun the old canonical ingester as
  a second SQL algorithm.
- Recheck original signed custody and pending relational content under
  publication locks, not only before locking.
- On connection loss or crash before acceptance, retain original
  receipt/custody and READY marker. Reconcile exact canonical
  Accepted, pending SQL committed prefix, and original signed source
  **read-only** before replay; prohibit blind duplicate insertion.
- Test normal, duplicate, corrupted original receipt, forged ACK,
  missing/duplicate journal, wrong source, failed FK remap, SIGKILL,
  power loss, and restart against a **disposable PostgreSQL 18 clone**
  with original signed data; keep physical C220 unchanged until
  acceptance and review.
- Full C220 controlled restart acceptance then deployment and
  observed canonical record counts/journal equality. No Windows CI
  for this FreeBSD backend-only change.

## Admission status

**C1 is development; not ready for live ingestion.**

The physical RAM handoff and persistent startup configuration are
verified without restart, and the source READY/status/independent B
acknowledgment contracts are committed and CI-tested. The new governed
canonical writer and true end-to-end two-jail accepted-generation
transaction have **not** yet passed implementation or acceptance.
