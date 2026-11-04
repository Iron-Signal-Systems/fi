# FI validated optimized private recovery profile — 2026-11-04

## Selected configuration

The accepted engineering default for **further private recovery tests** is
`optfield-k32-w128-p3-f3`. It does not alter the canonical FI ingest
defaults or declare the private recovery schema production-ready.

| Setting | Value |
|---|---|
| Outer atomic/checkpoint window | W128, up to 131,072 signed source records |
| Inner processing chunk | 32,768 source records (K32) |
| Security bulk | P3 |
| File bulk | F3 |
| Security fields | Partitioned by private W128 window, with deferred validated FK and atomic attach |
| Source | Previously authenticated full generation, immutable verified cache |
| Authoritative FI writes / Accepted journal | None |

This profile is selected by the FreeBSD recovery command's
`-optimized-k32` flag. It **fails closed** if the exact tested field
partition implementation is not installed or the separate
`-private-field-partitions` flag is not enabled. Its options are fixed:
explicit, conflicting W64/K64/P1/F1 values cause an error.

Example for an already prepared and isolated W128 private checkpoint
(database, cache, and private root supplied by the operator):

```sh
fi-backlog-recover \
  -source=iss-fs-22a.iss.local \
  -generation-id=20261030T000032.061323100Z-3e38b2210771462c \
  -postgres="$FI_PRIVATE_POSTGRES" \
  -private-root="$FI_NEW_PRIVATE_ROOT" \
  -private-writes -continuous-private \
  -start-window="$FI_RESUME_WINDOW" -max-windows=0 \
  -verified-cache-root="$FI_VERIFIED_CACHE" \
  -private-field-partitions -optimized-k32
```

**Never use this preset against an authoritative database.** A W128
checkpoint chain must not be mixed with W32 checkpoint descriptors.

## Measurements: actual signed 15,140,785-record generation

Both optimized tests resumed from an identical authenticated three-window
prefix: 390,387 records through index 2. They consumed 1,166,878 more
source records in nine committed W128 windows and finished at index 11.

| Metric | Earlier unpartitioned W128 | Optimized K32 | Optimized K64 |
|---|---:|---:|---:|
| Committed-window throughput | ~1,550 records/sec | **1,970.8 records/sec** | 1,953.1 records/sec |
| New durable records in 10m | ~910,443 | **1,166,878** | 1,166,878 |
| Completed new windows | Prior benchmark | 9 | 9 |
| Total committed-window time | Prior benchmark | 592.078s | 597.455s |
| Final cumulative durable records | Different earlier run | 1,557,265 | 1,557,265 |
| Final typed checkpoint count | Different earlier run | 12 | 12 |
| Final field partition count | No | 12 | 12 |
| Signed common checkpoint descriptors | N/A | Identical | Identical |
| Authoritative / Accepted count | 0 / 0 | 0 / 0 | 0 / 0 |

- K32 was approximately 0.9% faster by committed-window throughput
  than K64 **in one test pair**; this is not proof of a universal
  difference. Keep K32 as the measured reference until a meaningful gain
  is established under a controlled repeat.
- Earlier complete two-window tests reduced Security field COPY from
  approximately 25.7 seconds to 4.6 seconds per window.
- The logical Security fields (matched by signed batch/record/field
  identity) were identical: 4,838,850 field rows in the 390,387-record
  checkpoint prefix. Physical ID hashes differed after an intentionally
  failed transaction because PostgreSQL sequences are nontransactional.
- Both optimized 10-minute tests passed SQL checkpoint and partition
  counts with zero authoritative/Accepted rows. This does not alone
  demonstrate identical contents in every other projection table.

Observed host artifacts (these are **paths on fi-backend-b**, not
committed source data):

- K32: `/var/tmp/fi-window-chunks-optfield-20261104T101811Z`
- K64: `/var/tmp/fi-window-chunks-optfield-k64-20261104T104250Z`
- Seed / isolated PostgreSQL clones:
  `/home/jwood/fi-window-bench-optfield-20261104T101811Z`

## Source promotion gate — not yet complete

The exact tested Security-field partition implementation remains in
the `fi-dev` **uncommitted working tree**. At the time of this commit,
the existing GitHub branch does not yet contain its implementation file
`go/internal/recordingest/backlog_private_field_partition.go`, the
local changes to the transaction/COPY path, or the privileged partition
DDL fixture. The branch contains benchmark drivers and now the measured
K32 profile selector, **not yet a clean-checkout-capable partition
optimization**.

Next required engineering work:

1. Capture the **exact tested fi-dev source diff** and added Go/DDL files.
   Do not rewrite the already-validated implementation from memory.
2. Review the partition lifecycle, SECURITY DEFINER rights, start-window
   behavior, rollback/restart, source-identity validation, and migration
   limitations. Do not use experimental test DDL on production.
3. Commit those verified source files on this branch and run Go tests plus
   FreeBSD/PostgreSQL 18.6 integration on a new isolated database.
4. Recheck output equivalence for all 49 tables using logical source
   identity where PostgreSQL-generated IDs may legitimately drift.
5. After those gates, decide separately whether private recovery
   architecture should be promoted toward authoritative ingestion.

No additional WAL-parameter or K64 chunk tuning is selected for now.
The next optimization investigation is Go CPU and allocation profiling
of envelope and Security event preparation, without removing strict
validation or evidence hashing.
