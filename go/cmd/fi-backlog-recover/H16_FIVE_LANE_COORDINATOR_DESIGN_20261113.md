# FI original-H16 private five-lane coordinator experiment — 2026-11-13

**Status:** experimental development branch only. Historical-source cross-build and
unit gates run in GitHub Actions; actual signed W3-W4 relational replay and
performance are **not yet accepted**. Do not promote to main, install on FI
Windows, update the receiver or modify the canonical SoR.

## Why this experiment exists

The original 2026-11-12 H16+SHA-once+Security-JSON-once signed W3-W4
completed in **89.931 s**. The original exact same code rerun on 2026-11-13
completed in **92.554 s**, showing environmental variation. The prior
combined-buffer candidate completed in **92.090 s** on 2026-11-13, with
Security event/source COPY calls reduced from **106** to **60** and worker
CPU reduced from **47.24 s** to **44.51 s**. However, its File source COPY
also drained the File projection queue on every source drain, even when
the projection queue was not independently full.

This new experiment tests *separate collection and bounded processing lanes*,
not more goroutines, a separate SQL writer, a shared mixed-record array or
another transaction.

## Five independently managed logical processing lanes

| Lane | Existing state/ownership | Drain triggers |
|---|---|---|
| Security event/source | pendingSecurity and pendingSecurityBytes; P3 | own 4,096-row/16 MiB limit, audited hard ordering barrier, final W128 |
| File source | pendingFiles and pendingFileBytes; F3 | own 8,192-row/32 MiB limit, dependency prerequisite, hard barrier, final W128 |
| File relational projection | fileObservationBulkState; F3 | own 8,192-row/32 MiB limit enforced by original add(), prerequisite to ordered USN projector, hard barrier, final W128 |
| Security coverage | existing securityCoverageBulkState | existing internal bounds, final W128 |
| Ordered USN dependency | pendingDependencies and pendingDependencyBytes | own 512-record/8 MiB limit, original source-order fence, final W128 |

The pre-existing **joined signed-source custody ledger** is not counted as
one of the five typed-processing lanes and is **unchanged**. The File source
and File projection lanes were already separate structures in H16: the
change is making their **drain decisions independent**. No second copy
of File observation payloads is introduced.

### Coordinator and dependency rules

1. Signed batch bytes are authenticated and decoded exactly as in original
   H16. Record SHA-256, original batch/ordinal identity, strict decoder,
   per-source identity checks, original joined-source COPY and SQL readback
   remain unchanged.
2. Security collection and File source collection remain independent. A
   Security, File or coverage transition does not force the other family
   to flush. Security/coverage keep the proven combined-buffer behavior.
3. A full **File source** lane uses the existing COPY of fi.source_record
   and maps the returned database identities by exact original
   `(source_batch_id,record_ordinal)` keys. It validates and adds records to
   `fileObservationBulkState` as before, but **does not force a partial
   File projection drain** just because source COPY completed.
4. The existing `fileObservationBulkState.add` itself enforces F3 projection
   limits and flushes when those bounds are reached; it is not replaced or
   resized.
5. **Before queued USN read boundaries and object dependencies execute**,
   the coordinator first drains required File source rows and then all
   pending File projection parent/metadata/children; then the original
   dependency projector runs in signed custody order.
6. An unaudited record kind conservatively drains Security, File source,
   queued dependencies and File projection before that record projects.
   No speculative reordering of unknown kinds.
7. K32 stays a processing/telemetry unit only, not a partial typed-buffer
   drain. At the last signed batch in the same W128 transaction all lanes
   must be empty before the existing typed checkpoint marker. Failure
   rolls back the entire W128. No cross-W128 carry.

## Changes staged (source, not release)

- `go/cmd/fi-backlog-recover/testdata/h16-five-lane/private_h16_five_lane.go`:
  explicit private context, fail-closed gating, five logical lane contract,
  ordering rules and per-W128 telemetry.
- `.../private_h16_five_lane_test.go`: rejects ordinary/non-P3 mode,
  changed row/byte caps, lost Security isolation, missing USN dependency
  and premature K32 drains. Tests zero-copy ownership of the existing
  File and Security buffers.
- `go/cmd/fi-backlog-recover/patchers/h16_five_lane/main.go`:
  10 exact source edits to 3 files applied **after** the earlier pinned
  mixed/dependency/combined historical overlays. Exact anchors must match
  once or patching stops before any changes to the disposable source.
- `run_private_h16_five_lane_w34_host.sh`: reconstructs immutable source
  blobs in a freshly initialized private FreeBSD/PostgreSQL fixture, runs
  Go/real-signed preflights and requires source and SQL integrity proofs.
- `.github/workflows/fi-h16-five-lane-source.yml`: reconstructs historical
  H16 and the private overlays, runs regression tests and a FreeBSD build.

The ordinary FI backend path is unmodified. This is a distinct opt-in
`-private-h16-five-lane` flag available **only** inside the disposable
overlay; it additionally requires the existing mixed/dependency, signed
verified-cache, private W128/K32/P3/F3 context.

## Evidence required before considering any improvement

**Hard correctness gates, first:** real signed W3/W4; 111 authenticated
COW batches; 116,357 and 116,522 Security events via strict JSON-once;
259,178 new records; 5|649565|4 typed checkpoint; verified projection
and SQL source identity; all 111 batch data files/manifests byte-identical;
zero Accepted/canonical writes; exact W128 rollback on failure; new
`FI PRIVATE FIVE LANE PROOF` counters for both windows with nonzero
File source and deferred File projection events.

**Performance evaluation, second:** compare to the same-day original H16
92.554 s and combined-buffer H16 92.090 s. Measure actual Security/File
COPY calls, File source-versus-projection drain counters, worker and
PostgreSQL CPU, peak RSS, `vmstat`, `iostat`, `pg_stat_io`, WAL bytes,
WAL buffer-full events, checkpoints and autovacuum. A single faster
result is not enough to demonstrate a repeatable speedup.

**Known risks:** File source and projection F3 capacity limits are similar
and may cause both queues to fill at nearly the same time, reducing
measurable benefit; retaining projected File objects longer can increase
peak RSS; sparse keyed source identity lookup remains mandatory; WAL
pressure may remain or increase; USN ordering can force necessary early
File projection drains. The experiment makes no claim to eliminate all
identity lookup work, duplicate required SQL writes, or disk latency.

Do not execute a ten-window trial until W3/W4 validity, resource
measurements and a meaningful advantage over both controls are proven.
