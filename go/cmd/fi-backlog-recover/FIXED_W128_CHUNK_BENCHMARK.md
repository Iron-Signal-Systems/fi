# Fixed W128/1 GiB recovery benchmark: internal COPY chunks

Purpose: hold the signed private recovery **window** fixed at
**131,072 source records / 1 GiB original data**, while experimentally
varying the **joined private source-ledger COPY chunk** at nominal 32K,
64K, 96K, and 128K source rows. COPY boundaries always fall between
whole original signed batches; because signed batch record counts vary,
actual COPY rows can be lower than the configured ceiling. Each row
retains its original signed batch index and record ordinal. The whole W128 window
stays ONE atomic PostgreSQL transaction for source and typed markers.

### Scope of the typed-chunk implementation

`-processing-chunk-records` is opt-in, allowed only for W128
`-continuous-private` recovery. The setting groups whole original signed
batches into processing chunks (32K, 64K, 96K, or 128K source records) *inside*
one W128 private recovery transaction. Within each processing chunk, eligible
typed Security and File source buffers can cross signed-batch boundaries.
All source rows keep their original source-batch identity and record ordinal.
The parent ID mapper resolves the pair, not an assumed consecutive sequence.

The independent P3 security-event/field and F3 file/child COPY row and byte
limits remain active for safety. A 96K processing chunk is therefore **not**
a 96K-row COPY of every typed table. Other typed families retain their
existing per-record paths. This comparison measures processing boundaries,
not the earlier W32/W64/W96/W128 atomic recovery-window comparison.
No canonical SoR or Accepted journal writes are enabled.

`FI TYPED CHUNK COMMITTED` records are emitted only after the W128
transaction commits, giving original batch ranges, record counts and
per-chunk processing time. Source/typed marker durability remains W128.
Unit tests cover signed-batch boundaries; real mixed-family rollback and
performance acceptance must pass before adopting a winning chunk size.

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
