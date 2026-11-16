# FI W512 Security sweep: 8 general + 8/16 Security (C220)

**Development-only, not yet benchmark-accepted.** Applies only to disposable
C220 PostgreSQL clones and the already authenticated W512 historical signed
cache; not the authoritative SoR, ordinary H16, accepted header-first, or
accepted Family P3 run.

## Frozen controls and plan

| Experiment | Prep workers | Credits | SQL writers | Elapsed (2 W512 windows) | Records |
|---|---:|---:|---:|---:|---:|
| H16 baseline | 2 shared | 4 | 1 | 285.831s | 997,434 |
| Header-first | 2 shared | 4 | 1 | 285.709s | 997,434 |
| Family P3 | 2 Security + 4 general | 32 | 1 | 289.520s | 997,434 |
| **A8 candidate** | 8 Security + 8 general | 32 | 1 | not run | 997,434 |
| **B16 candidate** | 16 Security + 8 general | 32 | 1 | not run | 997,434 |

General workers: File=2, Coverage=2, USN/dependency=2, Other=2.
All A/B runs retain the accepted header-first reader and the same per-family
existing H16 downstream SQL/transaction boundary. This is not multiple parallel
PostgreSQL writers. The historical `FI PRIVATE PARALLEL PREP BATCH workers=2
inflight_limit=4` log is a **legacy mode selector label**, not the actual sweep
topology; the strict `FI FAMILY P3 SCHEDULER`, family WORKER/LANE receipts, and
per-run manifest prove actual runtime worker/credit counts.

## Exact pins and safety

- Branch: `experiment/fi-security-sweep-8-16-w512-20261116`
- Immutable source/Go patcher/test commit:
  `351043ee55a1876823fbe0370f7c126d8c96bc49`
- W512 clone runner commit:
  `6f9dd33abdfdbd346bd2ba6d798e50dd50296046`
- Pair controller source: `go/cmd/fi-backlog-recover/run_private_security_sweep_8_16_pair_c220_host.sh`
- Pair controller pinned commit: `18b95a364653441d012330ff9b125119ca2fca42`
- Original accepted W512 source seed: `20261115T153532Z`
- Relay base port `55983`, as accepted by the original C220 relay binary.
- Both runs use a **separate fresh private PostgreSQL clone**, identical
  authenticated signed input, same W512 two-window range, same durable SQL,
  signed artifacts, and original production trust path unchanged.
- Each private Go source clone is built after an exact-anchor read-only
  seed audit and Go unit + race tests, before database clone startup.
- If A8 fails any gate, B16 **MUST NOT start**. The pair wrapper preserves
  failure logs. No weak/skip-on-failure modes.
- Runner exits only after PostgreSQL shutdown and metrics are saved.

## Complete lane/worker status, including zero-work lanes

Every signed source batch emits machine-checkable receipts:

- `FI FAMILY P3 SCHEDULER`: worker count, distribution, total credits,
  raw-byte budget and SQL writer count.
- `FI FAMILY P3 BLOCK DISPATCH`: signed record count/bytes and
  exact Security/File/Coverage/USN/Other classification.
- `FI FAMILY P3 WORKER`: family, within-lane worker index, processed
  records and bytes, cumulative payload-preparation duration, wait time
  **for incoming work**, wait time **to submit prepared results**, and complete.
- `FI FAMILY P3 LANE`: worker/active counts; dispatched, prepared and byte
  totals; cumulative preparation time and both worker-wait totals; peak
  queued item count; and complete. A zero-work family emits these too.
- `FI FAMILY P3 TOTAL`: complete, cumulative source/prepare count,
  selected Security/general worker counts, 32 credits, one SQL writer.
- `FI FAMILY P3 BUDGET`: raw bytes admitted-but-not-delivered
  high-water (limit 256 MiB), and remaining bytes (must be zero).
- Signed source, Security COPY/field COPY, File projection, SQL window
  stages, original source checkpoints and 431-batch signed readback
  are retained from the accepted P3/H16 controls.

The per-family **worker-seconds** are sums across workers, not elapsed
wall time. `input_wait_worker_seconds` indicates worker availability/idle
time; `output_wait_worker_seconds` indicates pressure handing results to
the ordered writer. Neither is PostgreSQL `wait_event` time. Measured CPU
utilization and disk pressure come from the saved `vmstat`/`iostat` files,
with PostgreSQL WAL, checkpoint and I/O snapshots in JSONL files.

Each accepted run must report **431 complete** signed-batch totals,
**2,155 lane receipts** (431×5), **6,896 worker receipts** for A8
(431×16), and **10,344 worker receipts** for B16 (431×24). Source
and prepared counts must match 997,434; every lane and worker is checked
against dispatch totals, signed readback, and the SQL relational integrity
gates. A close due to errors is marked `complete=false`, which fails
acceptance.

## Back-to-back paired outputs

The pair controller runs **A8 first, then B16**, only if A8 is accepted.
It creates a unique host
`/var/tmp/fi-w512-security-sweep-pair-<UTC timestamp>/` directory containing:

- `COMPARISON.tsv` — full elapsed seconds, record/s and source result path
  for both.
- `FAMILY_COMPARISON.tsv` — each lane's worker count, records, bytes,
  preparation worker-seconds, input/output waiting worker-seconds, and
  peak queue depth, for A8 and B16.
- `WORKER_COMPARISON.tsv` — every individual worker's corresponding
  aggregate, including idle workers.
- `HOST_CPU_COMPARISON.tsv` — sampled host CPU user/system/idle percentages,
  excluding the initial since-boot sample. Full per-device `iostat` and
  PostgreSQL WAL/I/O/checkpointer snapshots remain in each original bundle.
- `A8.console.txt` / `B16.console.txt` — complete command output.
- `A8.output-path` / `B16.output-path`, `A8.bundle.sha256` /
  `B16.bundle.sha256` — concrete result pointers/checksums.

Each original `fi-w512-family-p3-pilot2-*.tar.gz` bundle also retains
`FAMILY_TOTALS.txt`, `FAMILY_LANES.txt`, `FAMILY_WORKERS.txt`,
`FAMILY_LANE_SUMMARY.tsv`, `FAMILY_WORKER_SUMMARY.tsv`, `vmstat.txt`,
`iostat.txt`, WAL/IO/checkpointer snapshots, COPY/stage logs, and the SQL
signed-readback proof.

## Run on root@c220

1. Fetch this experiment branch in the existing `fi-dev` Git staging tree
   (do not check out or modify the staging working tree).
2. Copy the **pair controller at its pinned Git commit** to a new
   `/var/tmp` file via `jexec -U jwood fi-dev git ... show`.
3. `sh -n` the copied controller, run `preflight 20261115T153532Z`.
4. If both 8- and 16-worker preflights succeed, run
   `pair 20261115T153532Z`. This automatically runs A8, performs
   full signed and SQL gates and family accounting, then runs B16.
5. Attach the two run bundles or the paired TSVs and original system
   metrics for independent comparison.

Do not alter the relay executable, authenticated cache, signed source,
authoritative SoR, original seed, SQL durability, or host networking.

## Ten-window follow-on

The initial A/B remains the existing proven **two-window W512** test.
After both candidates pass, retain the full lane/worker telemetry in a new
ten-window clone runner: summarize **per-window and across all ten windows**,
including zero-record families, and compare matched input and database
workload. Ten-window record/batch invariants must be derived from its
authenticated descriptors and checked against expected signed records; the
two-window 431-batch/997,434 constants must not be copied blindly.
A ten-window run is not implemented or authorized by this controller.

## Exact controller invocation (root@c220)

```sh
(
set -eu
repo=/home/jwood/fi-w512-c220-stage
branch=experiment/fi-security-sweep-8-16-w512-20261116
pairpin=18b95a364653441d012330ff9b125119ca2fca42
controller=/var/tmp/fi-w512-security-sweep-pair-20261116.sh
jexec -U jwood fi-dev git -C "$repo" fetch origin \\
  "refs/heads/$branch:refs/remotes/origin/$branch"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pairpin^{commit}"
test ! -e "$controller"
jexec -U jwood fi-dev git -C "$repo" show \\
  "$pairpin:go/cmd/fi-backlog-recover/run_private_security_sweep_8_16_pair_c220_host.sh" \\
  > "$controller"
chmod 0700 "$controller"
sh -n "$controller"
sh "$controller" preflight 20261115T153532Z
sh "$controller" pair 20261115T153532Z
)
```

The controller independently checks the pinned Git source and clone runner
commits, the relay allowlisted port, two original-seed preflights, and then
runs A8 followed by B16 with **no shared PostgreSQL clone**. All previous
signed-readback, SQL-integrity and source/typed descriptor gates remain in
force. The per-worker/full lane receipts and host CPU summary are mandatory.
