# FI H16 Candidate A — two preparation workers, one SQL writer

**2026-11-13 / isolated FI development experiment / not production.**

## Why

The accepted combined-buffer H16 replay processed signed W3–W12
(1,297,765 source records, 566 signed batches) in **479.295 seconds**.
Envelope preparation is a measured CPU-facing stage. Our hypothesis is
that decoding/preparation can overlap with PostgreSQL COPY operations
without increasing the number of relational writers or breaking signed
record order. It is a hypothesis until real signed W3–W4 paired data
establishes a benefit.

## Shape

```
single signed batch file reader → four-record credit budget
                                     ↓
                             two Go preparation workers
                                     ↓
                        out-of-order completion channel
                                     ↓
                    single signed-ordinal result collector
                                     ↓
                     ORIGINAL combined H16 family buffers
                                     ↓
                       ONE PostgreSQL/COPY writer
                                     ↓
                          ONE atomic W128 commit
```

Reader, preparers and SQL writer are distinct goroutines. PostgreSQL
connections, commands, dependency projection and transactions exist
**only in the original ordered writer**. Two workers use the **same exact**
canonical-Security-JSON-once decoder, strict fallback, validation and
record SHA-256 as the frozen original. The writer retains batch-level
signed SHA, every batch byte count, original manifest record count,
typed projection order and SQL source-ID lookup. The original combined
P3/F3H16 buffer limits and ordered separate coverage/USN queues do not
change.

At most four source records may be outstanding in the parallel reader,
workers, output channel and reorder collector. Each record's raw bytes
are owned, not copied into a second bulk array. Credits are returned only
once the ordered writer takes a record. There is no new per-record size
limit or truncation. The early-abort path cancels and joins all workers
before the underlying batch file is closed; errors remain associated
with their original signed ordinal.

### Stage measurement

Each accepted source batch emits:

`FI PRIVATE PARALLEL PREP BATCH batch=... workers=2 inflight_limit=4
writers=1 records=... read=... worker_prepare=... writer_wait=...
reordered=... reorder_peak=...`

These values identify whether decode genuinely runs ahead of SQL.
`worker_prepare` is a **sum** of overlapping worker intervals,
`writer_wait` measures time the original writer waited for ordered
results, and neither can be added to the end-to-end elapsed time as a
disjoint stage.

The existing `FI PRIVATE STAGE PROFILE` output still reports the pure
preparation time sum. It should not be compared to sequential
preparation wall time without accounting for overlap.

## Exact development source

- Frozen base source `b01ff0d8cb6559797de052f34b18bd84a395dc4c`.
- H16 profile `e47b5383e19140090d691b7c20e8d6ef6e0113fa`.
- Combined-buffer code `58f5d7341ba728b4696d05ba31199cb38226befc`.
- Candidate A immutable three-file source pin
  `cef6df894555f9c7bc10cb0957c2eb745487d2a2`:
  - `testdata/h16-parallel-a/private_parallel_preparation.go`;
  - `testdata/h16-parallel-a/private_parallel_preparation_test.go`;
  - `patchers/h16_parallel_a/main.go`.
- Host runner
  `go/cmd/fi-backlog-recover/run_private_h16_parallel_a_w34_host.sh`.
- CI
  `.github/workflows/fi-h16-parallel-a-source.yml`.

The candidate is a separate optional
`-private-parallel-prep-a` flag introduced **only into a disposable
archived H16 binary**. No edits are made to the checked-out ordinary
recorder, sender, receiver, authoritative PostgreSQL SoR, or Windows FI.

## Functional gates before benchmark interpretation

1. SHA-once and strict JSON-once compile and unit tests pass from pinned
   original source plus the existing mixed/USN dependency overlays.
2. Candidate A rejects ordinary and mixed-only contexts, altered
   Security/File profiles and non-W128 private invocations.
3. Concurrency test forces work to complete out of order but verifies
   identical original source record ordinals, exact raw bytes,
   per-record SHA-256, and full-batch SHA-256.
4. Two workers genuinely overlap, maximum four in-flight records; no
   uncontrolled queue growth or per-record goroutine spawning.
5. Final LF error, preparation error precedence and early cancellation
   preserve original rejection behavior. Go `-race` must pass.
6. Real original signed W3/W4 replays exactly **111** original batch files,
   **259,178** source records, W3 Security events **116,357**, W4
   **116,522**, typed checkpoint `5|649565|4`; original signed data
   and manifest files byte-identical on readback.
7. Zero authoritative/canonical and `Accepted` writes; successful
   isolated PostgreSQL shutdown; one original W128 transaction per window.
8. Recovery log must contain exactly 111 candidate preparation proofs,
   sum to 259,178 rows, show `workers=2`, `inflight_limit=4`,
   `writers=1`, and no reorder count above the four-credit capacity.
9. Compare to exact existing combined-H16 **92.090 seconds** W3/W4
   measured on November 13; environmental variation needs another
   matched sequential control before claiming a repeatable speedup.

## Initial performance evaluation

Candidate A gets only a real signed **W3/W4 functional trial**, not a
ten-window promotion. Evaluate end-to-end wall time, process user+sys
CPU, peak RSS, 5-second host `vmstat`/`iostat`, PostgreSQL WAL bytes,
`wal_buffers_full`, PostgreSQL I/O counters, Security COPY call count,
source key lookups, buffered coverage/USN ordering, and worker wait
statistics. If CPU rises, memory spikes or the writer still waits on
records, more workers or larger queues are **not automatically
approved**. Revert to the pinned combined H16 and preserve the trial.

Unmeasured speedup, missing raw signed proof, any SQL mismatch or
authoritative write disqualifies the candidate.
