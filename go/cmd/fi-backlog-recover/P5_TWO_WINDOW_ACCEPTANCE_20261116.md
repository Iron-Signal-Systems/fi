# FI P5 — C220 two-window development acceptance

**Acceptance evidence reported from root@c220 on 2026-11-16.**
This is an isolated experimental W512 replay, NOT a release or
acceptance of the complete intended FI family-buffer architecture.

## Pinned provenance

- Branch: `experiment/fi-persistent-family-p5-w512-20261116`
- Source and exact-anchor patcher: `fd618b9ce2bb045b8a4d83ba4aa9f508b7bbfd30`
- C220 clone runner: `df92e1c30b3b59827ce40556569213871d052f7a`
- Paired comparison controller: `0a04e35af6f405fe552f4e25784a41ac1367bf50`
- Original signed W512 seed: `20261115T153532Z`
- Private clone results: `/var/tmp/fi-window-chunks-family-p3-20261116T123717Z`
- Private storage: `/fast/jails/roots/fi-dev/home/jwood/fi-w512-family-clone-p3-20261116T123717Z`
- Private metrics bundle:
  `/var/tmp/fi-window-chunks-family-p3-20261116T123717Z/fi-w512-family-p3-pilot2-20261116T123717Z.tar.gz`
- Bundle SHA256: `7f8f1fadfe8bc48529dfffc654fd08fd06aed5ac767d480a52bf99d2f52e184a`
- Comparison controller output: `/var/tmp/fi-w512-persistent-p5-20261116T123715Z`

## Two-window measured comparison — identical 997,434 signed records

| Candidate | Elapsed (s) | Records/sec |
|---|---:|---:|
| H16 | 285.831 | 3,489.59 |
| Header-first | 285.709 | 3,491.08 |
| A8 fixed | 246.481 | 4,046.697 |
| B16 fixed | 245.606 | 4,061.11 |
| P4 priority-fill dynamic, per-batch | 240.984 | 4,139.005 |
| **P5 priority-fill persistent, per-window** | **237.995** | **4,190.987** |

P5 vs P4: 2.989 seconds faster (1.24% lower elapsed time);
51.982 more records/second (1.26% throughput).
P5 vs H16: ~20.05% higher throughput.

One paired result cannot establish stable throughput advantage across
repeated runs or longer workload mixes. Do not interpret idle CPU or worker
scale-up reduction as proof of PostgreSQL bottleneck removal.

## P4 vs P5 worker scale-up evidence

| Family | Signed records | P4 new worker scale-ups | P5 new worker scale-ups | P5 peak spawned | P5 peak busy | P5 peak pending |
|---|---:|---:|---:|---:|---:|---:|
| Security | 892,110 | 5,754 | 28 | 16 | 16 | 24 |
| File | 104,830 | 224 | 28 | 16 | 16 | 16 |
| Coverage | 411 | 0 | 0 | 2 | 1 | 1 |
| USN / dependencies | 79 | 36 | 21 | 13 | 13 | 1 |
| Other | 4 | 2 | 2 | 4 | 4 | 1 |
| **Total** | **997,434** | **6,016** | **79** | | | |

Worker scale-up events fell by ~98.69% (6,016 -> 79).
P4 repeatedly recreates the minimum+overflow workers at signed-batch
boundaries; P5 reuses them within each of the two atomic W512 windows.
Metrics reflect actual spawn events, not records prepared per worker
nor sustained CPU saturation.

## Successful C220 gates copied from terminal receipts

- Signed original seed and trust CRL verification PASS.
- Read-only original seed anchor audit PASS: 17 exact edits, five files,
  source unchanged.
- Pinned Go source overlay/build PASS, and executable continued to clone
  replay after prior preflight.
- P5 persistent reporter preflight PASS; five family rows retained.
- P5 bounded dynamic preparation batch receipts PASS: 431 signed batches,
  five families, minimum two workers, maximum 16 per family, 80 possible
  worker slots, 32 global in-flight records.
- P5 per-window worker pool completion PASS: 2 windows, 997,434 records,
  persist across batches, pools completely joined at window completion.
- Family-level source/prepare accounting PASS: 431 batches, 997,434 rows.
- Signed readback PASS: all 431 batches byte-identical, manifests identical.
- Private SQL window acceptance PASS: 997,434 new records,
  3m57.995s elapsed, one SQL writer, authoritative=0, accepted=0.
- Private PostgreSQL shutdown clean, exit=0, original source seed unchanged.

These are the reported results of the disposable C220 development benchmark,
not evidence of testing against an installed FI Windows sender or live SoR.

## Next work — complete the intended architecture before SQL multiwriters

Keep P5 as the accepted performance/control baseline and continue in a
**separate development branch** with:

1. Distinct, owned, typed SQL-ready buffers for all five family classes
   and the applicable typed record/projector kinds. Bound every buffer
   by rows AND bytes; no unbounded queue growth.
2. Family capacity-driven handoffs: hand off only the buffer that reaches
   capacity. Do not flush other families due to a signed block or batch
   boundary. Handle end-of-input safely.
3. Separate ordered USN dependency queue; dependencies must not force
   unrelated family buffers to flush. Preserve identity, FK ordering,
   duplicate/overlapping root semantics and source ordinals where required.
4. Explicit transaction-boundary barrier: complete every record required
   by the current atomic W512 window before commit. Never mix future
   window data into the current SQL transaction. Recovery/rollback/cancel
   must leave no orphan worker tasks or partial durable visibility.
5. Keep accepted header-first signed evidence and single H16 PostgreSQL
   writer while validating the full family-buffer design in two then ten
   W512 windows, with per-window and cumulative family/worker, SQL,
   WAL, CPU, memory and I/O breakdowns.
6. **Only after complete family buffer acceptance**, investigate 2, 3
   and 4 PostgreSQL writing lanes with a recovery-safe staging and final
   atomic publish design.

No experimental optimization is a substitute for source and SQL integrity.
