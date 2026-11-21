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
