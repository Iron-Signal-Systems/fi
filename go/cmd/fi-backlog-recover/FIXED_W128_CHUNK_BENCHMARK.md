# Fixed W128/1 GiB recovery benchmark: internal COPY chunks

Purpose: hold the signed private recovery **window** fixed at
**131,072 source records / 1 GiB original data**, while experimentally
varying the **joined private source-ledger COPY chunk** at nominal 32K,
64K, 96K, and 128K source rows. COPY boundaries always fall between
whole original signed batches; because signed batch record counts vary,
actual COPY rows can be lower than the configured ceiling. Each row
retains its original signed batch index and record ordinal. The whole W128 window
stays ONE atomic PostgreSQL transaction for source and typed markers.

### Scope of the first implementation

`-processing-chunk-records` is opt-in, allowed only for W128
`-continuous-private` recovery, and applies to the joined
`fi_recovery.pending_source_record` COPY operation. It makes a real
cross-original-batch COPY call; previously joined source COPY flushed at
8,192 rows. This does **not** silently modify the independent P3
security-event/field COPY limits, F3 file COPY limits, or canonical
SoR ingestion. Therefore it isolates one COPY path's overhead and must
not be misrepresented as a complete change to every typed COPY
operation. To compare all typed COPYs at 32K–128K requires additional
batched-key mapping and bounded child-row streaming work and independent
atomicity acceptance testing.

The per-window output contains
`FI JOINED SOURCE COPY CHUNKS COMMITTED window=... chunk_limit=...
calls=... records=...`, emitted only after the whole transaction
commits. The four 10-minute runs must be compared using **new durable
committed records**, inclusive rate, post-prefix steady rate, system
CPU/IO/memory, and field COPY time. Do not present COPY rows as signed
generations or as new durability boundaries.

### One scan, four identical seeds, then four 10-minute runs

`run_fixed_w128_chunk_benchmarks.sh` verifies all four *new empty*
PostgreSQL instances before doing work. W128 then performs one full
signed-custody scan and commits its first W128 window outside the timed
measurements. A consistent `pg_dump --data-only` of the seeded test
database is restored, with failure-atomic restore transaction, into
the three other separate empty PostgreSQL instances. The W128 private
artifact directory is also copied to each profile's separate root.

The runner confirms all four copies have exactly one committed
`fi_recovery.typed_window`, the same window-0 descriptor SHA256, and
all 8,399 authenticated original source-batch identities. It then
sequentially executes W32 (32,768), W64 (65,536), W96 (98,304), W128
(131,072) **with the window fixed W128** and P3/F3 unchanged, ten
minutes each. Each continuous run replays signed custody as required
by the existing streaming verifier; the one-time *preparation phase* is
not repeated. Each run produces its own sampled vmstat/iostat/process
logs, stage/COPY profiles and immutable checkpoint progress in a new
output directory. On any failure the script stops without trying to
repair, reset, or overwrite a database.

The former `run_four_window_benchmarks.sh` tests four outer window
sizes, and **is not appropriate for this question**.

### Setup without remote SSH or SCP

Use an interactive authenticated `jwood@fi-dev` session for `git
fetch` and `git merge --ff-only`, then run tests and build the
FreeBSD executable from that session:

```sh
cd /home/jwood/src/fi
git fetch origin
git merge --ff-only origin/work/fi-joined-private-performance-20261102
cd go
go test -count=1 ./internal/recordingest ./cmd/fi-backlog-recover
sh -n cmd/fi-backlog-recover/run_fixed_w128_chunk_benchmarks.sh
sh -n cmd/fi-backlog-recover/provision_four_benchmark_clusters.sh
go build -o /home/jwood/fi-real-backlog-20261101/fi-backlog-recover-window-profiles ./cmd/fi-backlog-recover
sha256 -q /home/jwood/fi-real-backlog-20261101/fi-backlog-recover-window-profiles
```

On the **FreeBSD host**, use the established `jexec fi-dev cat`
transfer to copy the new executable and benchmark runner; update the
SHA in the environment file to the newly verified build value.

Provision a **new** set of disposable PostgreSQL 18 instances in
`fi-dev` (not the previous W32–W128 run or the older 55418 test
cluster). For example, with a root not already present:

```sh
jexec -U jwood fi-dev env \
  FI_BENCH_NEW_CLUSTER_ROOT=/home/jwood/fi-window-bench-20261102-B \
  FI_BENCH_BASE_PORT=55531 \
  FI_BENCH_BINARY_SHA256=<NEW_EXECUTABLE_SHA256> \
  /bin/sh /home/jwood/src/fi/go/cmd/fi-backlog-recover/provision_four_benchmark_clusters.sh
```

The provisioner refuses an existing root and initializes new ports
55531–55534. Copy its generated
`/home/jwood/fi-window-bench-20261102-B/fi-four-profiles.env`
to root's `/root/fi-four-profiles.env`, review the four host-visible
socket paths and expected ports, and set the confirmation to YES.
Set a fresh output root starting
`/var/tmp/fi-window-chunks-`; never reuse a prior output root.
Run the **new** `run_fixed_w128_chunk_benchmarks.sh`, not the old
window-size runner, after ensuring the old one is no longer active.

NO code in this flow publishes authoritative `fi.*` records,
creates an Accepted journal outcome, writes private signing keys,
or resets the legacy 32K recovery checkpoint.
