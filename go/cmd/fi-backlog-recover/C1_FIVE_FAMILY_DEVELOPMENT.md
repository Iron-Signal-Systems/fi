# C1 — five-family FI ingestion (development only)

## Name and scope

**C1** is the current **unreleased development** integration of the original
P5 and P6 work. It is not a version, release, promotion, or production
acceptance statement. Do not label earlier tests as released or accepted.

## Invariants being implemented

1. **P5 preparation:** five independently scheduled pools (Security,
   NTFS/File, Coverage, USN/Dependency, Other); 2–16 actual workers per
   family, bounded global inflight admission and original signed-byte
   verification.
2. **P6 family buffers:** one bounded buffer per family. Hand off a completed
   buffer as soon as its own row/byte capacity requires, or for a genuine
   File-to-USN dependency. Never flush another family because a signed
   batch, read chunk, or W512 reporting window ended. At true end of input,
   drain the remaining partial buffers once.
3. **SQL:** one adaptive shared pool of 1..16 PostgreSQL projection workers
   starts with one real connection and grows when ready family handoffs
   outnumber idle workers. No SQL connection belongs permanently to a family.
   Idle extra workers retire after 30 seconds. A separate ordered parent
   writer retains the signed source ledger and source-FK broadcast fences.
   Preserve source batch/ordinal, original five relational projectors,
   child COPY, FKs and keys; wait for every File SQL commit before dependent
   USN begins. No sixth family or extra staging layer.
4. **Data:** original signed cache and manifest readback; 13 record kinds;
   49-table relational source model; no second source staging, duplicate
   signed payload store, additional source artifact copy, or canonical
   fi.* writes.
5. **No premature checkpoint:** the contiguous typed-window marker can
   advance only after five family SQL writers have finished, each family
   count matches the original signed parent count, and the existing SQL
   relational checks have passed. Do not publish authoritative or Accepted
   outcomes.

## Current engineering state and explicit limitation

The C1 development path is implemented under `testdata/c1`, and a
C220-only disposable-clone controller runs it against the authenticated
W512 source. **Multiple independently committing PostgreSQL connections
cannot give all-family ACID atomicity across the shared pool and parent.** Source/typed
rows may remain on an interrupted private clone with *no completed typed
checkpoint*. The implemented C1 clean-start guard rejects any retry
against that dirty clone, instead of silently duplicating or skipping
partial rows. The C220 harness creates a fresh private clone from the
unchanged verified seed for the next attempt.

This **does not yet implement in-place transactional crash replay for an
authoritative production SoR**. That remains development work. Do not use
this path on the canonical FI database.

## Built code

- `testdata/c1/private_c1_direct.go` — original P5 signed streaming into
  the persistent P6 buffer set and clean-destination SQL guard
- `testdata/c1/private_c1_family_buffers.go` — five capacity-driven
  buffers, File-to-USN prerequisite and final-only drain
- `testdata/c1/private_c1_five_sql.go` — one adaptive shared 1..16 SQL
  connection pool scheduling five original P6 modules, an ordered source
  parent and final barrier; optional File post-commit
  failure injection restricted to C1 private development
- `testdata/c1/private_c1_modules.go` — original P6 Security, NTFS,
  Coverage, USN and Other relational projectors
- `testdata/c1/private_c1_cached_recovery.go` — private C1 selector
- `testdata/c1/private_c1_direct_test.go` and
  `testdata/c1/private_c1_correctness_test.go` — signed source, P5 worker
  persistence, buffer independence, capacity, dependency, FK and failure
  guard tests

## C220 development gates

The preflight and compile stages do not copy or start PostgreSQL. Both
run only in fi-dev with pinned source code and the verified historical
W512 seed. The compile stage runs original Go tests, the Go race detector,
and the actual FreeBSD build against the isolated C220 optimized source.

- `preflight`: source/seed, trust, filesystem and original P5/P6 proof
- `compile`: full C1 Go/race/build, no PostgreSQL started
- `c1`: two-window signed replay; 431 batches, 997434 original records,
  adaptive shared SQL workers (default cap 5; C220 test variable
  `FI_W512_C1_SQL_WORKERS_MAX` accepts 1..16) plus one ordered source
  writer, all relational checks, five family completion and clean shutdown
- `inject-file`: development-only File SQL commit succeeds but C1
  deliberately fails *after* commit; verify zero new typed-window markers
  and dirty-clone quarantine, then stop and discard that clone

C1 must retain original signed data, not overwrite the original source
seed, and must never run while the live FI ingest worker is active. Do not
bypass a failing check or modify PostgreSQL roles, grants, indexes, or
canonical FI tables to make the experiment pass.

## P5/P6 continuous handoff improvement (C1 development)

C220 two-window C1 observation: 997434 signed records in 304.735 seconds
(~3273 records/sec), with five independently committing family SQL lanes.
P5 and P6 are the original development architecture foundations, not
comparison candidates to promote or release.

The first C1 throughput correction retains the **P5 five-family priority-fill
preparation**, **P6 per-family capacity/dependency buffers**, and **five
dedicated PostgreSQL family SQL lanes**. Previous SQL backpressure forced the
signed-source reader to wait for *every* one of the four outstanding family
handoff acknowledgments whenever that family reached its four-buffer bound.
This created a burst/drain cycle and could leave a family SQL worker idle.

C1 now retires **only the oldest completed SQL handoff** when a family has
four outstanding buffers and immediately enqueues the next capacity handoff.
Unrelated families remain independent. File-to-USN dependencies still use the
full File family SQL acknowledgment fence, and the final completion barrier
still awaits all five family writers. No extra SQL writers, source
materialization, COPY-envelope changes, buffer capacities, schema or
permissions are introduced. Failure still stops admission, and no typed
checkpoint may advance after a failed SQL ACK.

C1 Go/race regression tests cover oldest-only admission, in-flight bound,
FIFO ordering, error propagation, cancellation, and the full dependency
fence.

## Second direct P5/P6 correction — ordered parent SQL must not stop preparation

Code review found that the signed reader was executing each ordered
source-parent PostgreSQL COPY synchronously while the five family SQL lanes
were otherwise asynchronous. C1 now has one *bounded, ordered* source-parent
queue (four handoffs maximum) and its original dedicated SQL connection.
Each family job waits on a broadcast completion fence for the exact latest
committed parent set it needs. This happens in its SQL worker, **not** in
the shared P5 preparation consumer. The one oldest source ACK is retired
only when the four-handoff limit is reached. Source identity, parent-first FK
visibility, and File-before-USN are unchanged. No extra data store or SQL
connection is created.

In addition, the Security family already resolved every parent ID from its
signed batch and ordinal before invoking original P6 Security bulk COPY.
A C1-only context passes those verified IDs into the original COPY code,
avoiding its duplicate SQL FK lookup; P5, P6 and normal FI retain their
original lookup. SQL row values, copy targets, FKs and field children remain
unchanged.

**These are code changes, not C220 performance results.** The exact C220
compile/race gate, signed two-window data and FK proof, five-writer replay,
post-File-commit failure injection, and ten-window continuity still must be
run; exact same-database recovery is not yet implemented. The C220 test runner writes `C1_CONTINUOUS_FAMILIES.txt` with
`backpressure_waits` and `backpressure_wall` for all five families.

**A speedup is not yet claimed.** A complete C220 signed two-window replay
must pass the same data and SQL integrity checks and the File post-commit
fault test. Judge improvement against the 304.735-second C1 starting run,
not against a new architecture or unrelated COPY tuning. The original
Security relational field COPY remains a likely throughput limiter after
removing unnecessary ACK-drain gaps.

## C1 shared adaptive SQL pool — November 19 design implementation

The original C220 C1 dedicated-family experiment measured 997,434 signed
records / 293.366 seconds = **3,399.96 records/sec**. The Security SQL
lane spent 287.468 seconds, including 221.216 seconds in Security field
COPY. Parent wait was 0.228 seconds and family backpressure 0.000309
seconds. Serial Security SQL COPY, not parent waiting, was the limiting
path. The original P5 rate was 4,190.99 records/sec.

The new C1 development branch replaces the **five pinned one-per-family
SQL writers** with **one shared ready-job queue** and a dynamically sized
worker pool. Five P5 preparation lanes and five original P6 family buffers
remain. Each submitted buffer carries its family, original signed source
rows and prerequisite parent-commit ACK. Every shared worker owns a real
PostgreSQL connection and a fresh per-transaction projector/COPY context.
Security can occupy multiple connections at once. Worker count starts at
1, grows when ready jobs exceed idle workers up to the cap, and extra
connections retire after 30 seconds idle. Each family retains bounded
outstanding jobs (at least 4; at most the configured pool cap), and the
queue has a 2x-cap bounded capacity.

The backend runtime setting is
`fi_ingest_worker_sql_workers_max="5"` in
`/etc/rc.conf.d/fi_ingest_worker`, validated 1..16 and passed to
`fi-ingest-worker -sql-workers-max`. It is distinct from the existing
`fi_ingest_worker_workers` concurrent-source-generation limit. The
ordinary FI ingest runtime does **not** yet invoke the C1 clone-only
experimental SQL pool; adding this flag does not activate C1 or change
live SQL behavior. The isolated C220 runner uses the equivalent explicit
`FI_W512_C1_SQL_WORKERS_MAX` value for its C1 test.

**The new shared-pool branch is not yet measured on C220.** Verify compile,
race, same signed two-window relational result, File post-commit fault,
1/5/8/12/16 caps, and full cross-window integrity before comparing speed.
Pool SQL times are summed across concurrent workers and must not be
confused with elapsed wall time. Any failed attempt requires a new clone.

## Remaining work

After the full C220 build and two-window/fault-injection checks pass,
extend the C1 development implementation to exact same-database
idempotent/crash restart (without duplicate payload staging) and
10-window continuity. A green CI syntax check is **not** a C220 runtime
test. All work remains development.


## C1 A/B independence correction — isolated test branch (November 20)

The diagram defines two independently scheduled functions: **A** continuously
consumes receiver-custodied source records through persistent P5 and five P6
buffers to durable PostgreSQL transactions; **B** checks already committed
SQL rows using its own read-only database connection. B never orders an
extra P6 family flush or cancels A simply because a relational proof fails.
A final typed completion marker still requires the B proof. The clone runner
may therefore record B completing after the final SQL drain; this is not an
ingestion failure and is not a reason to change A's transaction scheduling.

For this **private-clone experiment only**, A reuses receiver-verified batch
custody instead of calculating another whole-batch SHA-256 during replay.
It still checks each manifest's signed digest representation, exact byte
count, record count, original batch/record order and LF framing. Existing
per-record SHA-256 in the relational source model is NOT removed. Original
Windows sender and FI receiver signature/hash checks are unchanged.
A cached file altered after receiver verification without changing byte count
or LF framing is **not cryptographically detected by the C1 reader**:
immutable custody and a separately reviewed proof of unchanged source bytes
are mandatory before applying this optimization outside isolated clone tests.

The 64-original-signed-batch sparse age trigger was removed. Security, File,
Coverage, USN and Other buffer independently by capacity, dependencies and
true end of input only. This restores A's original independent scheduling,
without additional small PostgreSQL transactions merely to make B complete
during ingestion. The C220 test harness checks all five families, SQL parent
and child commitments, B read-only relational proof, and no authoritative
publication on a newly disposable clone.

**Important limitation:** B still runs as a separate goroutine and PostgreSQL
session inside the private C1 test executable, NOT as a separate operating
system process. This branch corrects scheduling/cancellation coupling but
does not yet implement the diagram's strict two-OS-process deployment. Do
not describe this as a fully implemented A/B process split, or deploy it to
the authoritative FI SoR.


## Two-OS-process A/B implementation (development; 2026-11-20)

Source branch: `dev/c1-two-process-20261120`. This supersedes the prior
goroutine-only C1 A/B experiment **for this private-clone test**.

- **A process:** the original long-running FI recovery executable, persistent
  five-family P5 preparers, five independent P6 family buffers, one ordered
  source-parent writer and adaptive 1..16 shared family SQL workers. A does not
  restart or flush at signed batches or 4GiB reporting boundaries and does not
  rehash the receiver-verified whole-batch payload. Original per-record digests
  and authenticated-custody receipts remain.
- **B process:** a distinct executable `fi-c1-verifier` built from the same
  pinned, clone-only source. B independently connects to the same validated
  *disposable* PostgreSQL clone, sets its connection to read-only, and runs each
  original existing source-row-count/byte and typed-relational-coverage proof
  in a `REPEATABLE READ, READ ONLY` transaction. B cannot issue P6 work.
- **A to B boundary:** one bounded anonymous stdin pipe. A sends a single
  JSON metadata plan with receipt/generation identities and original batch IDs,
  followed by `READY <window>` only after the reader has sealed the original
  batch boundaries **and** all source/family SQL transactions for the group have
  returned successful COMMIT receipts. A sends `DRAIN` and `FINISH` after
  the normal final P6 drain. B rejects skipped, repeated, absent or unordered
  group proofs. There are no source record copies or new source hashes.
- **Failure behavior:** a B failure reports a distinct nonzero process exit and
  a callback, without cancelling or throttling A. It does **withhold the final
  typed completion marker**. A failure or interrupted process cannot be
  resumed against a partially committed clone: discard and recreate the
  disposable clone. Publication/Accepted remain disabled.
- **Proof of split:** the C220 runner checks different A and B operating-system
  PIDs and a separately verified read-only PostgreSQL session. The runner
  still must demonstrate actual compilation, Go/race tests, original 8GiB
  prefix integrity and the full 15-group replay before any acceptance claim.

The B OS process starts before continuous ingestion. However, a complete
group cannot be proved until all its existing P6 family transactions commit.
Sparse families can therefore cause B's first *group-complete* proof to finish
after A's final drain. That is not grounds to change A's buffer policy merely
to meet a timing assertion. Do **not** infer query overlap solely from two
running process IDs; timing evidence is collected independently.

The diagram's targeted remediation box describes the operational response
to a discrepancy. This private implementation returns error diagnostics and
withholds completion; it **does not perform automatic targeted in-place
reprocessing** or modify the canonical SoR. A dedicated production B service,
read-only login and failure recovery policy require separate acceptance.


### B-owned final generation proof — two-stage completion (November 21)

The current two-process development branch changes the C1 completion handshake
without altering P5/P6 preparation, shared SQL workers, capacities or source
custody. The same independent B OS process now owns **both** per-group
relational SQL verification and FI's original final whole-generation proof.

1. A sends the existing ordered `READY <window>` notifications only when each
   custody-bound signed group has all ordered source + five-family SQL commits
   acknowledged. B verifies source row/byte counts and typed relationships in
   read-only `REPEATABLE READ` snapshots, independently of A.
2. A signals `DRAIN` on its normal final P6 drain and `GROUPS` after all
   required commits. B returns `FI C1 B GROUPS PROOF PASS` to A. B never
   forces a flush merely to reach this point.
3. Only after that acknowledgement may A write the **private** typed marker
   transaction. A then signals `FINAL` to the still-running B process.
4. B runs the existing original 8 GiB prefix SQL proof (for the controlled
   two-group test) or the original complete grouped relational SQL proof (for
   the whole signed generation). B returns its structured completion result
   to A. Only successful process exit and final proof allow A to finish.
   A no longer reruns these final SQL verification functions.
5. Missing, duplicate, out-of-order or corrupt protocol commands, B failures,
   unsuccessful final proof and missing final receipts all fail closed.
   Callback reporting does not cancel or throttle ongoing A SQL operations.
   A failed clone must be discarded; this code does not claim automatic
   in-place remediation or authoritative publication.

The A→B protocol carries **only existing custody identities**, the original
manifest record/byte counts and descriptor chain, and committed-group notices;
it carries no raw source records and recalculates **no whole-batch SHA-256**.
The B→A acknowledgement contains only proof status and final result. The
existing 8 GiB prefix and full-generation SQL queries are reused in B, not
duplicated with another SQL verification pass in A.

**Acceptance remains pending:** newly pinned Go/race and two-process C220
integration checks must pass before any revised performance figures or full
backlog results are claimed. In particular, verify the unchanged receiver
custody, five-family SQL totals, separate PIDs, single B process, read-only
PostgreSQL backend, no Accepted/authoritative writes and matched final
generation proof. Verification may finish after A drains because sparse
families retain their own capacity/dependency thresholds; this must not be
"fixed" by coupling A's flushing to B.

## Adaptive 32-worker full signed-backlog experiment — November 21

The isolated C220 **full** C1 replay uses `sh controller c1
20261115T153532Z` and no early stop, processing all 8,399 original
signed batches (15 new 4 GiB reporting groups after the seeded group).
All original signed, custody and SQL integrity checks remain mandatory.

- **P5:** Five separate, persistent priority-fill preparation pools:
  Security, File/NTFS, Coverage, USN/Dependency and Other. Each begins with
  **2 workers and may grow independently up to 32** when it has work. Max
  available preparation slots: **160**, not 160 fixed goroutines. This is
  implemented using a P5-specific worker ceiling; the earlier P4 dynamic
  2..16 experiment and accepted report fixtures remain unchanged.
- **P6:** The five independent capacity/dependency-buffered family handoffs
  and File-before-USN SQL commit fence remain unchanged. No reporting-group
  flushes and no B-triggered flushes.
- **SQL:** The **one** shared adaptive PostgreSQL family writer pool begins
  with **1 connection**, grows on family-queue demand to **32**, then retires
  idle extra connections after 30 seconds; workers remain interchangeable.
  The source-parent SQL writer stays separate and ordered; B uses its own
  read-only PostgreSQL session. This is **not** five dedicated SQL pools.
- **Memory/IO:** Keep the 32 global P5 record credits, 256 MiB raw-input
  budget, 8 GiB PostgreSQL max WAL size, 16 MiB WAL buffers and all PostgreSQL
  durability controls ON. Enlarging worker ceilings alone does not guarantee
  utilization or a throughput gain. The C220 test records actual peak workers.
- **Safety:** Work only against a newly disposable clone on `fast`,
  with the verified signed cache and historic baseline inputs unchanged.
  Original source records, Accepted/published rows, live FI services and
  canonical SoR are never changed by this experiment.
- **Checks:** Go/race compilation first, full run second, successful original
  15-group and total 15,140,785-record read-only B final-generation proof,
  verified SQL parent/child counts, distinct A/B PIDs, no Accepted/published
  writes, required metric receipts and telemetry. Any failed clone is
  discarded and never restarted in place.

This is an experimental **adaptive maximum** of 32 for each P5 family and
32 for the single SQL family pool; it is not a minimum or a permanently
allocated set of connections. Compare full-run wall time and actual SQL
peak with the previous 16-worker C1 run, not merely with the 8 GiB prefix.
