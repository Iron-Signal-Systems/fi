# FI P5 — persistent priority-fill preparation workers (C220 private W512)

**Development experiment, not released. The source is committed but C220 Go tests, race tests, SQL replay and signed acceptance have not yet run.**

## Why

Accepted dynamic P4: 997,434 records across two W512 windows, 431 signed batches, 240.984 seconds and 4,139.005 records/sec. Its per-batch worker scale-ups included 5,754 for Security, 224 File, 36 USN and 2 Other. P5 aims to stop recreating workers with every signed batch.

## Exact design boundary

- Five independent preparation families: Security, File, Coverage, USN/dependencies and Other.
- Start two actual workers in each family, expand on demand to 16 per family, at most 80 slots total. Prefer lowest-numbered free worker, drain completion notices before creating overflow workers, never wait for worker buffers to fill.
- A preparation pool survives every signed batch within one **atomic W512 typed window**. The next W512 window gets a clean pool; persistence across windows is NOT yet implemented or claimed.
- Each signed batch retains original header-first reader, source ordinals, 32 total in-flight records, 256 MiB raw admission budget, source hash/readback, and one PostgreSQL writer. Original W512 transactional SQL integrity, dependencies and no-SoR/no-Accepted rules are unchanged.
- No parallel SQL writers, no completed independent SQL-ready family-buffer redesign yet.
- Parent window cancellation is drained safely by the batch session before deferred pool shutdown, and regression-tested.

## Pinned branch and assets

- Branch: experiment/fi-persistent-family-p5-w512-20261116
- Source, exact-anchor patcher, Go tests and reporters: fd618b9ce2bb045b8a4d83ba4aa9f508b7bbfd30
- Clone-only C220 runner: df92e1c30b3b59827ce40556569213871d052f7a
- Top-level controller: 0a04e35af6f405fe552f4e25784a41ac1367bf50
- Original signed seed: 20261115T153532Z; relay port 55983
- Accepted P4 control archive: /var/tmp/fi-window-chunks-family-p3-20261116T115151Z/fi-w512-family-p3-pilot2-20261116T115151Z.tar.gz
- Control SHA256: 9bbbba5dd9376eefb75c98a3bd5f6f878f7bbb0e3b25966195b0647a47a9923e

## C220 procedure (root@c220)

~~~sh
(
set -eu
repo=/home/jwood/fi-w512-c220-stage
branch=experiment/fi-persistent-family-p5-w512-20261116
pin=0a04e35af6f405fe552f4e25784a41ac1367bf50
controller=/var/tmp/fi-w512-persistent-p5-c220-20261116.sh
jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pin^{commit}"
test ! -e "$controller"
jexec -U jwood fi-dev git -C "$repo" show \
  "$pin:go/cmd/fi-backlog-recover/run_private_persistent_p5_w512_c220_host.sh" \
  > "$controller"
chmod 0700 "$controller"
sh -n "$controller"
sh "$controller" preflight 20261115T153532Z
sh "$controller" persistent 20261115T153532Z
)
~~~

Preflight performs read-only original seed anchor checks and exact synthetic AWK report tests. Actual two-window replay first compiles pinned disposable Go overlay and runs unit + Go race tests BEFORE private PostgreSQL seed copying. On any mismatch, STOP rather than bypassing a gate.

Final acceptance requires 997,434 records, exactly 431 byte-identical signed batches and manifests, matched SQL typed/source/artifact W512 receipts (499,052 and 498,382 records), two completed and joined private window pools, all five family receipts per window, 32-credit bounds, zero authoritative or Accepted writes and a clean private PostgreSQL shutdown.

Output includes P5_WINDOW_LANES.tsv, FAMILY_DYNAMIC_SUMMARY.tsv, FAMILY_LANE_SUMMARY.tsv, FAMILY_WORKER_SUMMARY.tsv, COMPARISON.tsv, host vmstat/iostat and PostgreSQL WAL/checkpointer/I/O snapshots. Persistent pool idle time across batches is not allocated to individual per-batch input-wait statistics.

After P5 is accepted, assess throughput/worker reuse versus the frozen P4 control. Then complete independent SQL-ready family buffers, capacity-only handoffs, dedicated ordered USN dependencies and ten-window testing BEFORE considering multiple PostgreSQL writers.