# FI ingest: source-first continuous type-directed buffering

**Engineering status (2026-11-12):** development-branch-only source-first continuous router, PostgreSQL family sink, signed-window replay driver, append-only per-record SQL completion receipts, and strictly isolated W3-W4 CLI gate are implemented. The disposable PostgreSQL 18 CI fixture validates two-window family commits, exact replay, and late-child rollback. This is **NOT a signed W3-W4 acceptance**, and is **NOT ready for the 10-window benchmark**. The private W3-W4 database clone runner and real USN, File and Security cross-window correctness/throughput proof remain mandatory. H16 (89.931 s reference) is untouched.

## Required behavior

1. Verify signed custody and its exact batch/record identity (source ID, generation, receipt SHA, signed batch index, record ordinal, SHA-256 of exact LF-terminated bytes).
2. Commit immutable source checkpoints independently of projection. The private `StageVerifiedBacklogSourceWindow` + `fi_recovery.pending_source_record` + `fi_recovery.source_window` implementation **already exists** and is a suitable durability foundation.
3. Only **after** the source-window checkpoint is verified durable, stream typed records through the router into an independent bounded lane:
   - Security events: P3, 4,096 records or 16 MiB.
   - File observations: F3, 8,192 records or 32 MiB.
   - WindowsSecurityCoverage: existing 512 records or 8 MiB.
   - USNReadBoundary and USNObjectObservation: ordered dependency lane, 512 records or 8 MiB.
   - Other currently supported record types: a conservative bounded lane; **per-type relational dependency audit is mandatory before enabling writes**.
4. When a lane hits its own cap, the durable PostgreSQL sink commits that lane's `source_record` rows, all typed parents and all children, and its replay-identifiable completion evidence **in the same database transaction**. USN parent/capture resolution is ordered by **original signed batch index and record ordinal**, never by PostgreSQL-generated numeric IDs.
5. **Do not empty partially filled lanes at K32 or W128.** K32 remains an observation/work-unit checkpoint, not a typed flush. W128 remains an immutable signed **source** checkpoint, while typed completion may lag it. Only an actual full lane, a real dependency of that lane, or EndOfInput may drain.
6. A window becomes typed complete only when all its source identities are projected and verified in PostgreSQL. `typed_window` markers are inserted contiguously, cannot skip missing predecessors, and cannot be inferred from signed source presence alone.
7. Crash/restart: recover from the last committed **source** and typed markers. Reconstruct in-memory lanes by rereading authenticated signed cache; skip only the exact source identities whose entire typed family transaction committed, using SQL-recorded identity and digest. A failed SQL transaction must not lose pending lane records. Do not introduce a second unverifiable manifest or duplicate source digest.
8. No authoritative SoR writes or `Accepted` outcome in development. No new external service, remote queue, plaintext credential store, or ELK dependency.

## Why the existing H16 routine cannot simply stop flushing

`StageBacklogTypedWindow` currently inserts a fully projected `typed_window` marker in the **same W128 SQL transaction** after verifying every source and relational projection. Flushing incomplete buffers after the commit would leave missing children behind a falsely complete marker; keeping an in-memory buffer only would lose unprojected source on crash. Therefore the continuous design MUST split:
- **Source committed**: signed data and `source_window` marker are durable, but some typed buffers may remain pending.
- **Typed complete**: every parent/child is committed and verified, then the `typed_window` marker is durable.

The current source-only staging path already performs receipt/digest/chain checks and writes `pending_source_record` and `source_window` atomically. We must reuse it instead of inventing a second durability boundary.

Typed buffering therefore also changes the SQL transaction unit from **W128 full projection** to **one complete type buffer**. This has different recovery semantics from accepted H16, and cannot be marketed as the same atomic-window design without a fresh acceptance contract.

## Implemented source components

- `go/internal/recordingest/private_continuous_family_router.go`
  - `privateFamilyForRecordKind` explicitly covers all supported FI kinds and rejects unknown kinds.
  - `BeginSourceWindow` verifies the source checkpoint is **already** durable before accepting any records.
  - `Add` checks globally original source order, family byte/record bounds, and flushes only the family at its own cap.
  - `EndSourceWindow` never flushes.
  - `EndOfInput` drains partial buffers and requires all typed windows through the last source window to be committed.
  - `markCompleted` prevents out-of-order typed window markers and marks a window only after the sink confirms all its buffered records are SQL-committed.
  - `privateContinuousSink` contract is deliberately explicit about SQL transaction atomicity, durable source proof and coverage verification.
- `go/internal/recordingest/private_continuous_family_router_test.go`
  - Tests two W128 windows that do not force Security, File, coverage or USN flushes.
  - Tests Security P3 4,096 event cap crossing W3→W4: W3 typed marker can follow the true capacity-triggered commit, not the W128 input boundary.
  - Tests absent durable source checkpoint, duplicate/reversed custody order, unrecognized kinds and no premature EndOfInput.
  - Tests rejected SQL sink errors retain buffered entries and suppress typed markers until successful retry.
  - Tests all supported FI record kinds have an explicit bounded family.

**Important:** These tests use a fake durable sink; passing them would establish routing behavior **only**. They do not establish PostgreSQL SQL/PKI correctness, equality of signed record/hash evidence, or runtime speedup.

## PostgreSQL source-first implementation and remaining host acceptance work

Implemented on the experimental work branch:

- `go/internal/recordingest/private_continuous_postgres_sink.go`: initializes only the private shadow generation; verifies committed signed custody identities in bounded exact-key SQL batches; commits one family at a time with existing 49-table projectors; inserts append-only `fi_recovery.projected_source_record` receipts in the SAME SQL transaction. Replay verifies matching signed digest and shadow source before skipping committed identities. SQL fail closes without a typed marker.
- `go/internal/recordingest/private_continuous_family_replay.go`: stages signed source windows durably BEFORE routing; carries partial typed buffers over W128; drains at real end-of-input and verifies contiguous typed markers.
- `go/internal/recordingest/backlog_artifact_ledger_schema.sql`: separate append-only projection receipt table in the isolated recovery namespace; no deployed SoR migration.
- `go/cmd/fi-backlog-recover/main_freebsd.go`: `-private-continuous-family` is fail-closed to isolated, indexed W128 W3-W4 with P3/F3, and is incompatible with legacy K32, partitioned Security field mode, and legacy dependency modes.
- `go/internal/recordingest/backlog_bootstrap_promote_ci_integration_test.go`: PostgreSQL 18 CI synthetic tests for two-window durable typed completion, idempotent replay, and rollback on invalid child. The separate FreeBSD-only fixture tests compile but are not executed by GitHub Actions.

**Still required for a real signed W3-W4 run:** generate and audit a dedicated disposable clone runner (the existing pinned H16 runner does not install this code/schema); verify all Security/File/USN typed child and FK coverage, cross-window capture prerequisites, source identity and receipt equality, restart after partially committed families, WAL/checkpoint behavior, and actual copy counts. Existing H16 SHA/JSON optimizations must be compared without conflating a new transaction boundary with old W128 atomic commits. The 29 W4 USN rows and 232,879 Security records are hard acceptance gates. Report timing only from the real signed test.

A projected `source_record` root without complete typed children is NOT sufficient. A final marker requires complete per-window projection receipts and the existing relational coverage queries; an entire generation with USN captures must additionally pass the generation-level capture completeness proof. Detached W128-scoped Security field partitions are intentionally disabled for continuous mode until their cross-window semantics are audited.

## Outstanding PostgreSQL hardening and validation before acceptance

1. A concrete `privateContinuousSink` backed by private `pgx` transactions that verifies each staged source row against the exact signed record hash. It must handle every typed parent/child together and initialize/flush deferred NTFS, content hash, ACE, USN and Security field writers inside the same atomic family commit.
2. Strict idempotent replay from verified cache. If a family buffer committed but the worker stopped, do not attempt duplicate inserts; verify the exact source identities and all relational evidence. Reject partial/inconsistent buffers rather than masking them with an upsert.
3. Existing detached Security field partitions are window-scoped; crossing W128 windows with a Security buffer requires correct source-to-field-partition routing. **Do not simply COPY mixed windows into the last window's detached field table.** Preserve FK validation and attach proof or adopt an audited alternative.
4. The final `typed_window` marker must verify exact signed source counts, bytes, source digests, child projection coverage and the preceding typed marker. A partial source stage is never complete relational ingestion.
5. Source-window staging currently scans input separately from typed replay. Profile this overhead; do not claim the new design improves throughput before a full committed comparison.
6. Add PostgreSQL integration tests for source-only checkpoint, family transaction rollback, crash immediately before/after a family commit, recovery from typed lag, duplicate replay, USN source-bound capture across a boundary, missing/forward capture rejection, and coverage/field FK completeness.
7. Hard-fail if any private mode is selected but typed dispatch lacks the required per-batch mode context. The earlier mixed/dependency candidate silently returned to old flushing; the branch now has a fail-closed route assertion and explicit capacity/barrier/boundary counters for diagnosing this before running the larger design.

## Acceptance sequence

- **First:** isolate and resolve the zero-active-buffer counters seen in the 96.927 s W3–W4 dependency test; preserve the recorded SQL and signed-readback pass but do not promote it.
- **Then:** compile and run the complete continuous source-first SQL sink on the disposable W3–W4 clone. Require 259,178 records and 232,879 Security records, 111 signed batches, original SHA evidence, exact SQL coverage, 29 USN dependency rows in W4, zero authoritative/Accepted writes, and observable capacity-only flush reasons. W3/W4 partial buffers may flush at the **actual end of the requested test input**; there may be no automatic flush at W3→W4.
- **Only after W3–W4 passes correctness and produces a meaningful timing comparison:** pin the exact same configuration for W3–W12 **ten windows** and require acceptance on all ten signed windows, cross-window buffers, restart/failure injection, sustained rec/s, WAL/checkpoint/I/O evidence, and zero custody or FK mismatch.
- No change to main or accepted H16 until this evidence is reviewed.

## Recorded development CI and caveats

- PostgreSQL 18 CI test `TestBacklogBootstrapPromoteFreshIsolatedPostgres/continuous-family-sql-commit-and-replay`: passed on a disposable synthetic source, including replay after committed typed windows.
- PostgreSQL 18 CI test `TestBacklogBootstrapPromoteFreshIsolatedPostgres/continuous-family-failed-child-rollback`: passed; durable source remained, failed typed transaction left no completion receipts or typed marker.
- FreeBSD cross-build and legacy typed-chunk PostgreSQL workflow: passed at the earlier CI fixture commit. These do not execute the real W3-W4 signed cache.
- Independent `govulncheck` security workflow reports GO-2026-6865 and GO-2026-6859 in existing transitive/standard-library call paths. A build/test success does not resolve these advisories.
- The optimized batched-custody-query variant requires its own CI results; no performance claim is based on synthetic tests.
- Until the signed W3-W4 candidate passes **correctness, USN dependency coverage, crash/restart verification, and a measured comparison with H16**, the 10-window W3-W12 run is **not authorized** by the acceptance criteria.
