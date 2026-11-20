# FI C1 DEV — committed-group asynchronous relational verification (8 GiB gate)

Status: **UNRELEASED development / code staged for C220 compile/race and isolated-prefix tests**. This is **not** an Accepted generation or authorized SoR publication.

## Reason for redesign

The first full-backlog C1 asynchronous experiment (14,647,307 new signed records; 15 groups; 8 GiB max WAL; 16 MiB WAL buffers) completed at 12,060.01 records/s, versus 12,863.15 records/s for the prior continuous P5 control. All 15 old read-only verification passes occurred **after** P6's final drain. Group 1 spun through 111 speculative retries for more than 16 minutes, blocking the verifier's remaining groups. That result proved correctness but **failed the intended concurrency architecture**.

The next benchmark is **two complete ~4 GiB signed groups (approximately 8 GiB total)** from a fresh, disposable, C220 clone. Do not run the full backlog before this gate passes.

## New dataflow (no per-group ingestion barrier)

1. P5 reads original receiver-admitted signed batches in one session, verifies original SHA-256/records/bytes/newline, and prepares original signed ordinal identity continuously.
2. P6's unchanged ordered source-parent SQL writer and five-family adaptive shared SQL pool write committed source and typed rows. SQL handoffs may span group boundaries. File-before-USN and source-parent SQL prerequisite ACK fences remain intact. P5/P6 buffers are **not drained at 4 GiB**.
3. Each successful **PostgreSQL COMMIT** increments exactly the corresponding signed group's *source-parent* or *typed-family* durable row count; a single SQL transaction spanning groups contributes to each. No queued/uncommitted record is credited. A separate signed-input SHA group-seal notification is also required.
4. An independent, one-shot, read-only PostgreSQL verification worker receives each group's ready notice only when its source and typed durable counts equal the signed group's manifest record total and its SHA seal is complete. It checks original `verifyBacklogShadowWindowCounts` and `verifyBacklogWindowProjectionCoverage` in a separate `REPEATABLE READ, READ ONLY` transaction. There is **no retry polling** or per-group SQL flush.
5. A failing read-only proof calls the ingestion abort callback and prevents all typed-marker advancement. The **C1-specific final typed-marker transaction no longer runs source-count, typed-root coverage, or complete-generation relational rescans**. It still validates signed descriptor digests/predecessor markers and inserts markers atomically, **only after every group has a successful independent proof**.
6. The original final signed-generation digest, marker, source-record count and anti-publication proof remains. The 8 GiB prefix always reports `full_generation=false`, `authoritative=0`, `accepted=0`.

This is an independent Go worker on a separate PostgreSQL read-only session **inside the isolated C1 recovery program**, not an operating-system subprocess. Separating the verifier into its own OS process remains a separate architectural decision; the current objective is proof of non-blocking, durable readiness scheduling.

## Regression from first commit-ready 8 GiB C220 run

The first live clone test (2026-11-20 17:23Z) passed preflight,
Go/race compilation and independent committed-readiness checks, but was
**correctly rejected**: both groups only became COMMIT READY after
`FI C1 P6 FINAL DRAIN START`. Both read-only proofs passed with
`phase=after_drain`. Group 1's signed and committed counts were
997,434, Group 2's 994,338; P6 SQL drain was 2m11.148684519s.

Root cause: original P6 capacity-only handoffs leave the very small
Coverage, USNDependency and Other family tails under their 512-record
threshold until `Finish()`, potentially withholding Group 1's last
committed typed rows even while Group 2 is already streaming.

**C1 corrective experiment:** without changing original signed boundaries,
SQL dependencies or a 4GiB group flush, a pending sparse-family buffer is
submitted when its oldest signed batch is at least **64 original signed
batch indexes behind current P5 input**. Security and NTFSFile continue
the original capacity policy. The decision is based on batch age, never
group number. This is an asynchronous SQL handoff, not a WaitAll or
typed-marker barrier; USN still requires its File prerequisite ACK.
The threshold only bounds sparse buffer admission delay: full SQL commit
latency and actual read-only query duration remain measured at runtime.
Do not claim the architecture passes until Group 1 actually completes
its relational proof during continued signed ingestion.

Additional tests check delayed sparse handoffs before final drain,
preservation of File-before-USN ordering, absence of unrelated Security
flushes, exact source counts and fail-closed sparse SQL write errors.

## Mandatory C220 gates

1. The pinned controller and runner must identify exact Git commits and verify complete signed-cache/seed/CRL/clone/storage prerequisites. No running authoritative ingest worker or canonical SoR connection.
2. Go unit tests, race tests and build must pass **before PostgreSQL clone startup**.
3. The 8 GiB cutoff must equal the same original signed-batch prefix as the existing 2 GiB/4 GiB plan; preserve the immutable seed and original signed receipt.
4. Exactly two `FI C1 COMMIT READY` notifications, with source/typed committed counts equal signed group totals, signed seal and no group-flush flag.
5. Exactly two one-shot `FI C1 ASYNC VERIFY PASS` receipts; **Group 1 MUST show `phase=during_ingest` and `attempts=1`**, and its PASS receipt must appear **before** `FI C1 P5 CONTINUOUS SIGNED STREAM PASS` (before Group 2's last signed input completes), as well as before `FI C1 P6 FINAL DRAIN START`. A first-group pass merely during final SQL flushing is an **architecture FAIL**, even when every relational check passes.
6. Final `FI C1 ASYNC VERIFY COMPLETE` must have nonzero `during_ingest` and preserve marker-gate ordering. No async failure, no incomplete/unmatched signed groups, no Accepted/publication, and clone PostgreSQL shutdown clean.
7. 5-second host/process/ZFS/disk telemetry must start before the private benchmark and be finalized on exit; archive `C1.telemetry.tar.gz`.
8. Capture both `FI C1 P6 SQL DRAIN elapsed=...` and total C1 processing duration to distinguish true P5/P6 progress from verification/marker tail.

The C220 run scripts are `go/cmd/fi-backlog-recover/run_private_c1_full_backlog_4g_controller.sh` (mode `compile` and `prefix8`) and its pinned `run_private_c1_full_backlog_4g_c220_host.sh`.

Do not run the `c1` full-backlog mode until the new 8 GiB architectural acceptance gate passes. Do not infer that reduced CPU gaps or better throughput follows from a correctness PASS; compare the completed telemetry independently.

## Fault and invariants

- A SHA mismatch prevents any signed group seal.
- SQL write/commit failure, including post-commit failure injection, is fail-closed and leaves a dirty disposable clone; never retry that clone.
- No source-parent or typed-family ACK is credited before SQL commit success; extra or missing rows fail group readiness.
- Mixed source/family handoffs spanning signed reporting groups must not flush or serially gate P5/P6 at 4 GiB.
- Missing/duplicate verification proof, failure callback, non-overlapping 8 GiB verification, and modified descriptor chain must all fail unit tests.
- The old marker-path relational scans are forbidden by an exact source audit before C220 Go build.
