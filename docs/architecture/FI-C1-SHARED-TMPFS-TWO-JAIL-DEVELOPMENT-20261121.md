# FI C1 — Shared-tmpfs two-jail processing (development only)

**Approved target, November 21, 2026.** Preserve the original benchmarked
C1 P5/P6 and five-family SQL processing model, while retaining the FreeBSD
fi-ingest and fi-sor-db jail responsibility boundary. This document does
**not** authorize deployment against live receiver backlog, populated
PostgreSQL or authoritative fi tables.

## Data and control paths

1. **fi-receiver:** unchanged original immutable receiver-verified signed
   batches, manifests and recorded receipts in durable custody.
2. **fi-ingest jail:** continuous original signed batch reader, exact C1
   P5 preparation workers and five independent P6 family buffers; no
   PostgreSQL connection. Each flushed prepared handoff becomes an immutable
   bounded object in **host tmpfs** through an ingest-writable nullfs mount.
   Batch/reporting-window boundaries do not flush unrelated family buffers.
3. **Shared volatile transport:** each object has a random opaque name, an
   exact byte size and SHA-256, a 128 MiB limit, and a fixed sixteen-object
   outstanding credit cap (at most 2 GiB of completed objects). Producer
   writes a temporary object and atomically publishes its final name.
   **Never fsync, journal, ZFS-store, or back up these handoff objects.**
4. **mTLS control channel:** signed-generation START, validated original
   source-batch index/SQL-ID map, prepared RAM object references, sealed
   reporting-group notifications, and per-object SQL COMMIT acknowledgments
   remain mutually authenticated and sequence-checked. The original row
   payloads are not sent over the network in shared-RAM mode.
5. **fi-sor-db jail (FI SoR processing owner):** tmpfs is mounted read-only
   through nullfs. Validate SHA-256, signed original source-batch identity,
   exact ordinals, original raw record digests and native C1 SQL family.
   Consume original prepared P5 envelopes and Security single-pass values.
   Use ordered SourceParent writer and the frozen adaptive shared SQL pool
   with up to 32 workers; only this jail talks to local PostgreSQL.
6. **Private PostgreSQL staging:** signed source/typed SQL commits and
   recovery progress belong in PostgreSQL, not RAM. Independent verifier B
   is a separate read-only OS process and runs alongside commits.
7. **Canonical populated SoR:** never change until full signed-generation,
   source, artifact and typed acceptance passes and atomic promotion is safe.

Once an exact SQL COMMIT ACK arrives, **fi-ingest** deletes the associated
RAM object. On uncertain outcome, do not delete or infer a commit; stop and
reconcile the PostgreSQL state against original signed custody first.

## Host-owned mount layout — configuration example, NOT an installation script

Actual C220 jail roots, service UIDs and GIDs must be read from the current
host and FI installer configuration; do not guess them from documentation.

- Host tmpfs: `/var/run/fi-c1-handoff`, **4 GiB size ceiling**.
- fi-ingest jail: `/var/run/fi-c1-handoff` — **read/write nullfs**.
- fi-sor-db jail: `/var/run/fi-c1-handoff` — **read-only nullfs**.
- tmpfs root: dedicated host producer UID and shared host GID, `2770`
  setgid directory; published files are `0640`. The fi-sor service identity
  must have the matching numeric shared GID but no write privileges.
- The **host**, not either jailed service, creates and mounts the filesystems.
  Persist host mount configuration in the two jail fstab files using the
  actual installed jail-root paths; do not grant the jails `allow.mount`.
- Mount tmpfs with `nosuid,noexec` where supported. Verify the underlying
  host filesystem is actually **tmpfs** (not a normal ZFS path), then verify
  `mount -p` shows an ingest-writable and an SoR-read-only nullfs mount.
- Start the SoR listener only after mounts and group access are verified.
  Start fi-ingest only after SoR has independently validated its private SQL
  signed-generation plan.
- `--shared-ram-dir=/var/run/fi-c1-handoff` is required by both new
  FreeBSD C1 worker executables.

The tmpfs memory objects are **not durable**. FreeBSD tmpfs may use swap,
so they should not be described as guaranteed unswappable physical RAM;
protect or disable swap as appropriate for local custody confidentiality.
This option is not equivalent to a durable recovery journal.

### Host read-only validation command

Compile `go/cmd/fi-c1-host-preflight` with
`GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -tags fi_c1_sor_dev`.
On the FreeBSD host, supply the **actual** installed C220 jail-root paths
to the command. For example:

```sh
fi-c1-host-preflight \\
  --host-tmpfs /var/run/fi-c1-handoff \\
  --ingest-root /ACTUAL/fi-ingest-jail-root \\
  --sor-root /ACTUAL/fi-sor-db-jail-root \\
  --jail-ram-path /var/run/fi-c1-handoff \\
  --host-custody-root /ACTUAL/receiver/signed/custody \\
  --host-recorded-root /ACTUAL/receiver/recorded/receipts \\
  --sor-custody-path /ACTUAL/readonly/custody/in/sor \\
  --sor-recorded-path /ACTUAL/readonly/receipts/in/sor
```

This is a **read-only check**, not an installer. It proves the actual host
mount is `tmpfs`, both jail RAM paths are distinct exact `nullfs`
mountpoints with the same source, fi-ingest is RW and fi-sor is RO.
It also proves that fi-sor's original signed receiver custody and
recorded-receipt paths are two separate **read-only exact nullfs mounts**
with their own explicitly supplied original host sources. Do not substitute
example jail-root placeholders or skip the real host check. A separate
mount-installation and runtime wiring acceptance gate remains.

## Read-only committed-prefix recovery audit (development)

`AuditC1SoRPrivateRecovery` runs after a rejected dirty START preflight
using a separate **read-only, repeatable-read** PostgreSQL transaction.
It scans all signed source-batch manifests and committed SourceParent
rows, enforces contiguous 1-based ordinals and exact signed byte totals,
then uses the existing 13-kind typed-root projection coverage checker
to locate the first batch lacking a fully committed relational root.

It logs the **last parent-complete batch prefix** and **last typed-complete
relational batch prefix**; these may differ because the five SQL families
commit independently. No RAM buffer is needed or recovered for this scan.

The audit is **not an authorization to resume**. It has no signed raw-record
readback, no reconciliation of a partially committed batch's five family
state, and no authority to delete SQL rows or publish the canonical SoR.
Until a complete idempotent per-record replay and original-custody
comparison pass acceptance, the current START deliberately stops on a
dirty stage. This preserves all committed PostgreSQL work for diagnosis.

### Per-record signed replay reconciliation evidence (read-only)

`c1AuditCommittedRowStates` looks up each exact original
`(source_batch_id, record_ordinal)` in one SQL batch read, verifies its
persisted envelope identity and SHA-256 against the prepared original signed
record, and reports whether the matching typed root has committed. This
distinguishes fully committed records from durable SourceParent rows still
awaiting a typed family. The routine does **not** admit new SQL, skip records,
change a checkpoint, or authorize a replay yet. The next step is to bind this
evidence to the normal C1 SQL dispatch and prove that every skipped record is
identical to custody before accepting partial-batch resumption.

A prefix of fully committed batches followed by empty batches is **not**
itself a dirty tail; only a partial SourceParent batch or an incomplete typed
root inside the committed source prefix is reported as dirty.

## Independent B original custody readback

Verifier B now has a separate signed custody verification path. The
fi-sor jail needs **read-only** nullfs access to the existing immutable
receiver custody and recorded receipt roots, plus the installed trusted
root, batch issuer, CRL and source registry. The host installs these
read-only views; neither fi-sor nor fi-ingest may modify the originals.

B streams the original signed transport, verifies cryptographic receiver
authorization and recorded receipt, checks each signed manifest/data
SHA-256 and rechecks each original record's exact SourceParent digest
and typed root with a distinct read-only SQL session. Unlike the old
disposable recovery pipeline, this path does **not** duplicate the entire
generation on disk. C1 cannot report independent full proof if these
read-only custody mounts are unavailable.

The fi-sor worker now requires `--custody-root` and `--recorded-root`
and refuses a writable custody filesystem. Correct host mount roots,
certificate trust availability and real source permissions still require
FreeBSD acceptance testing.

## Interruption semantics

On power loss, both jails discard incomplete prepared work and reconstruct
it from original signed custody. The source of the **last committed position**
is PostgreSQL, not a RAM filename, file existence, or mTLS admission. An
incomplete batch may have individually committed source/typed families:
restart must reconcile those partial transactions before replay, avoiding
duplicate SourceParent rows, typed projections, and USN dependencies.

**Current stop gate:** full verified PostgreSQL checkpoint reconciliation
and partial-batch replay are not yet implemented/accepted for this C1
split. The current SoR bootstrap deliberately refuses prior partial SQL
projection. Restart must fail closed rather than blindly replaying. A
temporary RAM object from an uncertain session may be removed only after
the SQL session is quiescent and the replay plan is reconciled.

## FreeBSD C1 service-binary staging (NOT activation)

The existing host installer accepts explicitly selected
`apply-c1-binaries` and `verify-c1-binaries` operations. The release
directory must contain **both** distinct FreeBSD executables,
`fi-c1-ingest-worker` and `fi-c1-sor-worker`. Installation is root-owned
mode `0555` inside the preconfigured fi-ingest and fi-sor-db jail roots.
No existing `fi-ingest-worker` binary is replaced, no rc script is started,
and no PostgreSQL connection or file is modified.

This is only the binary-staging part of the development installer; it
does **not** mount tmpfs, activate C1, or imply deployment acceptance.
Subsequent mount wiring, rc service installation, restart replay and
isolated true two-jail acceptance remain required.

## FreeBSD C1 service account and disabled rc scripts

The FreeBSD host installer now has four explicit *development staging* commands:
`apply-c1-sor-identity`, `verify-c1-sor-identity`,
`apply-c1-runtime` and `verify-c1-runtime`. The dedicated `fi-sor`
identity is a non-root jail-local user; no SQL credentials or host user are
created. Each separate jail receives its own root-owned runner,
root-owned rc service, and group-readable runtime config. Both
`fi_c1_ingest_enable` and `fi_c1_sor_enable` default to `NO` and
missing source/custody/TLS/PostgreSQL settings fail closed. The existing
`fi_ingest_worker` service is unchanged.

These steps **do not mount tmpfs, add custody RO nullfs mappings, change
PostgreSQL authentication or start any service**. They are not a substitute
for a real FreeBSD isolated two-jail acceptance run.

## Explicit offline C1 atomic publication candidate (NOT LIVE ACCEPTED)

The development fi-sor executable contains a separate,
explicitly authorized **offline** publication mode. It does not run
during fi-ingest P5/P6 processing or over the bounded mTLS handoff.
The publisher reconstructs the complete original signed batch plan
from immutable recorded receipt plus read-only local PostgreSQL
source_batch metadata, then reuses the existing populated-SoR
foreign-key remap, table lock, Accepted journal and atomic transaction.
Inside those locks a **fresh** independent original receiver-signed
custody/typed row/USN verification is mandatory; the earlier B process
alone is not sufficient.

This candidate requires `--publish-verified-private`, an explicitly
selected source, generation and unique attempt ID, both read-only
custody roots, and an approval environment guard set to
`FI_C1_CANONICAL_PUBLISH_APPROVED=I_HAVE_VERIFIED_ISOLATED_CLONE`.
There is **no default rc publication switch**. Its actual full signed
generation remap and late-failure rollback are **not yet accepted on
the C220 isolated populated SoR clone**. Do NOT run this against
the live populated canonical fi database yet.

## Validation before any live C220 activation

- Go race, C1 handoff, prepared-family tests and cross-built FreeBSD
  executables pass on the exact commit.
- On an **isolated private PostgreSQL clone**, run real signed backlog
  through both actual FreeBSD jails and host tmpfs. Confirm original C1
  per-family buffers, SourceParent ordering, Security COPY and NTFS/USN
  relational identity.
- Prove per-object ACK after actual SQL COMMIT; tamper, truncated data,
  wrong GID/mount, ENOSPC/backpressure, no listener and process interruption
  all fail closed. Test restart/power-loss at SourceParent and each family
  commit boundary, with no duplicate rows and no source loss.
- Independently prove full generation using B and source/artifact/typed
  marker chains. Only then permit an explicitly gated atomic promotion into
  an isolated populated-SoR **clone**; confirm rollback and recovery.
- Benchmark throughput against the **frozen actual C1 full-backlog run**.
  No performance claim is warranted until this two-jail path is measured.
- Install and validate real FreeBSD rc services and mounts **before**
  considering live deployment. Windows agent CI is not a backend gate.

## Code inventory

- `go/internal/c1handoff/shared_ram.go` — opaque bounded RAM objects,
  checksums, atomic publish/read, and producer-only removal.
- `go/internal/c1handoff/frame.go` — small mTLS shared-object reference.
- `go/internal/recordingest/c1_shared_ram_codec.go` — original P5
  prepared-envelope/Security single-pass transfer, no fi-sor re-preparation.
- `go/internal/recordingest/c1_remote_sor_sink.go` — five-family producer,
  in-flight bound and COMMIT ACK-based reclamation.
- `go/internal/recordingest/c1_sor_commit_handler.go` — read-only tmpfs
  consumer feeding unchanged ordered SourceParent/SQL projectors.
- `go/cmd/fi-c1-ingest-worker`, `go/cmd/fi-c1-sor-worker` — FreeBSD
  service candidates; neither is authorized for live ingestion yet.
