# FI C220 W512 — Adaptive Priority-Fill, 2–16 Workers Per Family

**Status (2026-11-16): DEVELOPMENT CODE COMMITTED. Source-only review completed; not yet C220 Go-compiled, race-tested, SQL-replayed, benchmark-accepted, or released.**

## User-defined behavior and the existing baseline

Workers must process incoming records immediately, not wait for their
individual batch buffers to fill. Each family has **a dedicated queue** and
a preference for worker 0 before worker 1, and so on. Two workers per family
are initially active. Further workers are brought online only when every
currently active worker is occupied and more work is already waiting. A
150-ms idle interval permits highest-index overflow workers to retire
towards the two-worker floor. The scheduling decision never changes
original signed order at the SQL writer.

| Family | Min active | Max active | SQL writer |
|---|---:|---:|---:|
| Windows Security | 2 | 16 | Shared original writer |
| File | 2 | 16 | Shared original writer |
| Security Coverage | 2 | 16 | Shared original writer |
| USN / Dependency | 2 | 16 | Shared original writer |
| Other | 2 | 16 | Shared original writer |

**80 is the sum of maximum worker slots, not a concurrently permitted
in-flight record count. The global source-ordinal limit remains 32.**

All five families have one FIFO input queue and one priority dispatcher.
Each worker has a one-record mailbox; the dispatcher chooses the
lowest-index currently available worker first. It does **not** distribute
rows evenly among idle workers or use batch-full thresholds. A blocked
worker may finish after a later worker; the unchanged source-ordinal writer
reorders the result and binds SQL transactions. Each family remains
independent: a Security backlog does not prevent File or USN workers from
preparing records.

The existing P3 File/Coverage typed worker-side preparation and strict
header-first signed-byte classification remain. This **does not claim that
all other kinds are fully SQL-ready** or that PostgreSQL writing has
become concurrent. Completing all independent family SQL-ready buffers
is a separate subsequent design stage.

## Fixed-worker controls to retain

- Accepted H16: 285.831 seconds, 997,434 signed records.
- Accepted header-first: 285.709 seconds, same signed records.
- Accepted Family P3: 289.520 seconds, Security 2 and one worker per other family.
- Accepted A8: 246.481 seconds, Security 8 and 2 workers each for File,
  Coverage, USN, Other (16 total).
- Accepted B16: 245.606 seconds, Security 16 and 2 each for others (24 total).
- **Fixed G4 candidate**: Security 8 and 4 each for others (24 total);
  source and runner committed on the separate
  `experiment/fi-general-four-each-w512-20261116` branch, **not yet
  accepted on C220**.

Do **not** compare the dynamic P4 runner to a fictional passed G4 run. First
preserve its real acceptance or reject it on evidence, then use matched
two-window signed inputs to evaluate scheduling independently.

## Exact immutable pins

- Branch: `experiment/fi-priority-fill-2-16-w512-20261116`
- Core priority scheduler:
  `go/cmd/fi-backlog-recover/testdata/adaptive-p4/private_adaptive_p4.go`
- Scheduler tests:
  `go/cmd/fi-backlog-recover/testdata/adaptive-p4/private_adaptive_p4_test.go`
- Source/patcher/worker-report commit:
  `d49403b519407e6b6dc8d30c0d99c3c228d24f4a`
- Clone-only C220 runner commit:
  `953905e598b8f1d76b611ec2713470b6770728fa`
- Runner path:
  `go/cmd/fi-backlog-recover/run_private_adaptive_p4_w512_c220_host.sh`
- Original receiver-admitted W512 seed:
  `20261115T153532Z`
- PostgreSQL relay port: `55983`, already allowed by accepted C220 relay.

Only the disposable `optimized-source` copy is patched. The accepted
source, real SoR, original signing/trust material, live ingest, installed
network/jail settings and verified signed cache are **not changed**.

## Test procedure on root@c220

Use a new, non-colliding filename:

```sh
(
set -eu
repo=/home/jwood/fi-w512-c220-stage
branch=experiment/fi-priority-fill-2-16-w512-20261116
sourcepin=d49403b519407e6b6dc8d30c0d99c3c228d24f4a
runnerpin=953905e598b8f1d76b611ec2713470b6770728fa
runner=/var/tmp/fi-adaptive-p4-w512-c220-20261116.sh

jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}"
test ! -e "$runner"
jexec -U jwood fi-dev git -C "$repo" show \
  "$runnerpin:go/cmd/fi-backlog-recover/run_private_adaptive_p4_w512_c220_host.sh" \
  > "$runner"
chmod 0700 "$runner"
sh -n "$runner"
grep -Fxq "sourcecommit=$sourcepin" "$runner"
grep -Fxq 'port=55983' "$runner"

echo "===== ORIGINAL SIGNED SOURCE / PATCHER PREFLIGHT ====="
sh "$runner" preflight 20261115T153532Z

echo "===== P4 PRIVATE TWO-WINDOW TEST ====="
sh "$runner" family 20261115T153532Z
)
```

Preflight performs the read-only 16-edit original-seed anchor check,
compiles the patcher, confirms all **9** staged family assets, and
compiles/smoke-tests the 16/64-slot AWK report. During the actual private
trial, the runner also performs the Go unit and **race** tests, including
`TestPrivateAdaptiveP4*`, **before private PostgreSQL seed copying**.

The benchmark fails closed on any signed record reorder/mutation,
unrecognized family, cancellation, invalid worker event, mismatched SQL
relational or checkpoint count, missing or duplicate signed batch,
incomplete memory receipt, or any incomplete adaptive family report.
Original source/typed/artifact W512 SQL durability and atomic windows
remain untouched.

## P4 reporting / acceptance

For each of the 431 authenticated signed batches, require:

- `FI ADAPTIVE P4 SCHEDULER`: 5 lanes, min 2, max 16, max 80 slots,
  32 global credits, 256 MiB **raw** admission budget, 1 SQL writer.
- `FI ADAPTIVE P4 BLOCK DISPATCH`: exactly classified signed record
  counts and bytes across all five families.
- `FI FAMILY P3 WORKER`: each of 80 potential worker slots (even
  zero-work slots), cumulative records, bytes, prepare/input-wait and
  output-wait worker time.
- `FI FAMILY P3 LANE`: 5 lanes, source/prepare exact counts and queue
  high-water, including zero-activity families.
- `FI ADAPTIVE P4 LANE`: 5 dynamic lane receipts, min/max, actual
  **peak active**, activations, retirements, workers remaining at end,
  zero protocol errors, complete=true.
- `FI ADAPTIVE P4 COMPLETE`: one complete receipt per batch.
- `FI FAMILY P3 BUDGET`: peak admitted raw bytes <=256 MiB and
  remaining raw bytes zero after each completed signed batch.
- `FI W512 SIGNED READBACK PASS batches=431 byte_identical=true
  manifests_identical=true`, identical W1/W2 descriptors, 997,434
  relational records, zero authoritative and Accepted publication.

The archived family breakdown includes
`ADAPTIVE_LANES.txt`, `ADAPTIVE_COMPLETION.txt`,
`ADAPTIVE_LANE_SUMMARY.tsv`, `FAMILY_LANE_SUMMARY.tsv`,
`FAMILY_WORKER_SUMMARY.tsv`, process/stage timings,
`vmstat.txt`, `iostat.txt`, WAL/checkpointer/PG I/O snapshots,
original signed batch SHA proof, and per-window SQL readback.

**No ten-window acceptance is claimed.** Only after a clean two-window
test can the same dynamic instrumentation be ported to the ten-window
runner, with fresh authenticated window/batch counts derived from the
ten-window descriptors. Then continue the user's design: truly
independent SQL-ready family buffers and capacity-only handoff
semantics with the existing one SQL writer, before attempting any
parallel PostgreSQL lanes.
