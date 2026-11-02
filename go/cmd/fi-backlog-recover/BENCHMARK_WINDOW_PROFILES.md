# FI single-worker private recovery: W32/W64/W96/W128 benchmark

This protocol compares **recovery checkpoint window sizes**, not internal
PostgreSQL COPY chunks. It changes no Windows collector, accepted ingestion,
authoritative system-of-record tables, or source-batch signing contract.

| Profile | Maximum source records per window | Maximum source-data bytes |
|---|---:|---:|
| W32 | 32,768 | 256 MiB |
| W64 | 65,536 | 1 GiB |
| W96 | 98,304 | 1 GiB |
| W128 | 131,072 | 1 GiB |

Windows contain whole original signed source batches. The limit reached first
determines the window; neither limit reserves RAM. The initial streaming loader
holds **at most one signed batch with a 256 MiB memory buffer cap**, and
continuous recovery streams batches to temporary files on disk.

## Absolute isolation requirements

- All four trials MUST use separate **fresh private recovery states**; never
  use or reset the existing 32K production-recovery private checkpoint chain.
  The database schema names are currently fixed, so use separate test database
  instances/isolated clusters (each with its own `fi` database), or restore a
  known-clean isolated fixture between successive trials. Do not run two
  profiles against the same existing private checkpoint set.
- Use separate empty directories with permissions `0700` for their
  `-private-root` values. Use the same read-only signed custody and recorded
  receipt in all runs. Preinstall the existing *private* ledger and shadow
  schemas with the same grants before each trial.
- Do not delete, truncate, overwrite, or migrate the original W32 recovery
  tables. The experimental CLI checks empty private checkpoint and generation
  projection tables before accepting the first W64/W96/W128 window.
- Keep **P3** Security source bulk and **F3** File bulk, source batch input,
  hardware, PostgreSQL tuning, and worker count unchanged across all trials.
  These runs compare *window* size alone; they do not test 32K-128K internal
  COPY chunks spanning source batches.

## Two-phase procedure per isolated profile

1. **Seed initial checkpoint** in the isolated empty state, outside the timed
   test. Invoke `fi-backlog-recover-tuned-joined` with the existing exact
   `-source`, `-generation-id`, `-postgres`, `-custody-root`,
   `-recorded-root`, `-private-root`, and any required
   `-source-namespaces` option. Add:
   ```
   -window-profile=W64 -security-profile=P3 -file-profile=F3 \
   -private-writes -stream-loader -start-window=0 -max-windows=1
   ```
   Replace W64 with W32, W96, or W128 for that trial. This performs
   authenticated full transfer scanning and establishes window 0. Require
   a complete, durable first typed checkpoint before proceeding.
2. **Measure continuous recovery** with the SAME isolated database, private
   root, binary, and profile, adding:
   ```
   -window-profile=W64 -security-profile=P3 -file-profile=F3 \
   -private-writes -continuous-private -start-window=1 \
   -max-windows=0 -max-runtime=10m
   ```
   Use `-start-window=1` only if precisely window 0 was seeded. Do not
   substitute a W32 checkpoint index for any other window profile.
3. Record executable SHA256, Git commit, profile, start/end UTC, the
   `FI PRIVATE STAGE PROFILE` lines, per-relation COPY counters,
   `FI REAL BACKLOG DURABLE` markers, and the `FI TEN MINUTE STOP` line.
   Sample Go process and PostgreSQL backend CPU/RSS and wait events, plus disk
   read/write throughput, WAL volume, available memory, and swap.
4. Compare both **new durable records / 600 seconds** (includes custody prefix
   scan) and **sum of completed-window records / their elapsed window times**
   (steady private ingest). Preserve the incomplete final-window duration as
   wasted work in the deadline analysis; it rolls back and is not durable.

## Operational safeguards

- A W64/W96/W128 profile rejects unsupported direct writes and mismatched
  start modes; it is *not* supported to change profile on existing checkpoints.
- A 1 GiB data budget does not mean 1 GiB of RAM, PostgreSQL WAL, or one COPY.
- The old W32 benchmark runner does not automatically apply this new selector;
  do not use it unchanged for other profiles.
- Failed isolated acceptance, OOM/swap pressure, broken hash verification,
  nonzero Accepted rows, or any authoritative modification invalidates a run.
- Because each profile seeds a different-sized first window, the timed runs
  start at different signed-source offsets. Report the actual File/Security/USN
  mix in each run; do not treat small throughput differences as definitive
  without a matched-workload replay.

To investigate **internal processing portions** of 32K/64K/96K/128K within
a fixed 128K recovery transaction, a later change must explicitly aggregate
across signed source batches while preserving source_batch_id/ordinal identity,
cross-batch security coverage ordering, deterministic source hashes, rollback
and restart behavior. The existing 4,096-record P3 flush is not equivalent to
a 32K internal COPY chunk. Do not label this window-size experiment as that
different experiment.
