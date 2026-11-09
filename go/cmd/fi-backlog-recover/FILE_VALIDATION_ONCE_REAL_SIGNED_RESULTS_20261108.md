# FileObservation single-validation replay — actual signed results (2026-11-08)

## Provenance and scope

- Real source data: verified signed FI backlog from `iss-fs-22a.iss.local`; ten W128 windows 3–12, single-worker, 32,768-record internal chunks, historical P3/F3 profiles.
- Original historical code: `9e0e6e236c95d9af91bc67a065efb47ce2318579`.
- Corrected Go source: `e02a06891600d5877bcb5a680f84bcbcdbc7c195`.
- Runner: `run_file_validation_once_signed10_host.sh`, updated runner commit `0e83d4fb6c3c9ab444a74222e9f3e6f1991bd06d`.
- Completed output: `/var/tmp/fi-window-chunks-file-once-20261108T171740Z`.
- Private PostgreSQL cluster `clone-11-08-26` on 55981, fully isolated from real authoritative SoR; stopped cleanly at end; no accepted/canonical writes.
- Verified seed: 3 windows, 390,387 source records, 4,838,850 Security fields.
- The original two-stage NTFS check is replaced with a validated source value, read by the existing parent and child FileObservation projectors; direct bulk callers still validate.

## Evidence gates (all passed)

```text
FI CLONE VALIDATION REUSE PASS windows=10 initial_validations=137777 avoided_second_validations=137777
FI CLONE SQL INTEGRITY PASS checkpoint=13|1688152|12 canonical=0 accepted=0
FI CLONE SIGNED READBACK PASS batch_files=566 byte_identical=true manifests_identical=true
FI PRIVATE EXACT WINDOW STOP start=3 windows=10 last=12 records=1297765 committed_window_time=8m54.311s authoritative=0 accepted=0
FI CLONE FINISHED exit=0
```

Successful replay and identical signed artifacts prove the change reached this private ingest path and retained tested lineage and data-integrity invariants; they do not by themselves prove general-purpose alias/immutability guarantees or improved throughput.

## Throughput results (all ten windows; same signed source)

| Version | Committed-window duration | Committed throughput | Delta vs. historical |
|---|---:|---:|---:|
| Original baseline, historical source `9e0e6e2` | 523.424 s | 2,479.4 records/s | — |
| First private validation-skip candidate | 528.153 s | 2,457.2 records/s | +4.729 s |
| Source-validated Go implementation `e02a068` | 534.312 s | 2,428.9 records/s | +10.888 s (~2.08% slower) |

Exact latest window measurements:

| Window | Records | Duration | Records/s |
|---:|---:|---:|---:|
| 3 | 129,435 | 56.135s | 2,305.8 |
| 4 | 129,743 | 53.463s | 2,426.8 |
| 5 | 130,642 | 54.770s | 2,385.3 |
| 6 | 130,755 | 51.650s | 2,531.6 |
| 7 | 128,951 | 52.777s | 2,443.3 |
| 8 | 129,842 | 51.624s | 2,515.1 |
| 9 | 129,722 | 51.520s | 2,517.9 |
| 10 | 129,213 | 52.584s | 2,457.3 |
| 11 | 128,575 | 52.687s | 2,440.4 |
| 12 | 130,887 | 57.102s | 2,292.2 |

## Interpretation — no claimed speedup

- The real signed replay confirmed 137,777 initial complete NTFS validations and 137,777 avoided second validations.
- A separate read-only ABBA Go CPU benchmark on 4,096 real signed FileObservation samples measured approximately 31.7–38.2 microseconds CPU and 88 allocations / 8.4 KB of cumulative allocation per redundant call. The extrapolated 4–5 seconds of avoidable CPU across 137,777 records is *not* equivalent to an expected 4–5 second PostgreSQL wall-clock reduction.
- Actual end-to-end wall time increased by 10.888 seconds relative to one baseline measurement. Its cause is **unresolved**. The eliminated duplicate validator is no longer the open question; possible run-to-run environment changes and actual cost of the new representation/Go machine code must be distinguished using stage totals, CPU profiles, allocation counts, and controlled paired trials.
- Do **not** promote this branch as a performance win or modify production. Avoid PostgreSQL tuning by guesswork.

## Next measurement

Compare `FI PRIVATE STAGE PROFILE` counters from `recover.log` for original, first candidate, and current corrected run, especially File projection, Security projection, envelope preparation, batch ingest, and typed-window totals. Next, profile whole Go worker CPU and heap by stage and run matched baseline/candidate alternation with checked cache/host state. Separately verify the no-mutation/aliasing contract for pointer/slice children across buffered projections.

## CI notes

Corrected source `e02a068`: FreeBSD cross-build, Linux Go tests, Go race test, CodeQL, and PostgreSQL 18 isolated acceptance suites passed. Broad Windows CI failed on platform-specific pre-existing Go build/test issues unrelated to this FileObservation change. Security workflow failed `govulncheck` on known `github.com/klauspost/compress@v1.19.0` vulnerability (fixed in 1.20.2); no dependency changes attempted as part of this performance experiment.

## Stage profile deltas from all three actual recover logs

The source of these figures is the user's post-run read-only `FI PRIVATE STAGE PROFILE` aggregation across **exactly ten** windows. In the historical Go source, `file_projection_inclusive`, `security_projection_inclusive`, and `other_projection_inclusive` partition `projection_total`; those stage timings are nested inside the outer window metrics and **must not be summed with `batch_ingest`**.

| Stage | Original | First candidate | Corrected Go | Corrected vs original |
|---|---:|---:|---:|---:|
| File projection | 77.676s | 77.736s | 75.498s | **−2.178s (−2.80%)** |
| Security projection | 120.989s | 129.247s | 129.241s | +8.252s (+6.82%) |
| Envelope preparation | 120.184s | 118.800s | 120.225s | +0.041s |
| Batch ingest | 471.680s | 475.881s | 481.364s | +9.684s |
| Total ten committed windows | 523.424s | 528.153s | 534.312s | +10.888s |

**Evidence-based conclusion:** The corrected actual Go implementation saved 2.178 seconds of File projection elapsed time versus baseline (2.238 seconds vs the first candidate). Thus, the direct File path improved, even though full ingestion did not. Security projection was almost identical in both candidate runs (129.247s vs 129.241s), each roughly 8.25 seconds behind original. There is not yet evidence distinguishing a repeatable environmental difference from candidate-dependent system interaction or an alternate code path. The outer `batch_ingest` increased more than the Security projection, requiring further decomposition (such as `source_sql`, `other_projection_inclusive`, `security_prepare`, `security_child_prepare`, `security_id_lookup`, and COPY timings). Do not attribute the remaining regression to the removed NTFS check or claim unmeasured benefits.

## Timer reconciliation and attribution correction (2026-11-08)

These are **three sequential experiments, not a paired randomized A/B trial**. Relative timing is an observation, not proof that any individual Go change caused a difference. `pgx.Tx.CopyFrom` is timed end-to-end and includes client Go row generation/encoding, relay I/O, server execution and scheduling. Its elapsed time **cannot be classified as PostgreSQL storage latency** without separate measurements. The Security bulk source file itself is byte-for-byte identical between baseline `9e0e6e2` and corrected `e02a068`, but this does not rule out changes in external or process-wide contention.

### Baseline vs. corrected total time (seconds)

```text
File projection                             -2.178
Security projection                         +8.252
Other projection                            +0.111
Projection counter remainder                +0.040
  = total projection                        +6.225
Source SQL                                  +0.448
Envelope prepare                            +0.041
Remaining batch work                        +2.970
  = batch ingest                            +9.684
Remaining outer-window work (net)           +1.204
  = ten-window committed total             +10.888
```

Security field COPY +6.713s is *nested within* Security projection +8.252s, not an additional contribution. Outer-work and other-batch residuals include measured counters omitted from this compact comparison; they are not necessarily uninstrumented idle time.

### First candidate vs. corrected implementation

```text
File projection                             -2.238
Security projection                         -0.006
Other parts of projection                   -0.147
  = total projection                        -2.391
Source SQL                                  +0.040
Envelope prepare                            +1.425
Remaining batch work                        +6.409
  = batch ingest                            +5.483
Remaining outer-window work                 +0.676
  = ten-window committed total              +6.159
```

A real File-stage time reduction occurred between the first and corrected candidate **without** a Security-stage change (+0.006s faster). The separate 6.409s difference elsewhere in batch work is a better target for finer profiling than claiming that the new NTFS validation proof caused the previously observed Security COPY slowdown.

**What is proven:** 137,777 redundant NTFS validations were eliminated and existing SQL/readback integrity gates passed. **What is unproven:** the size of any causal File-stage speedup and the reason for a 10.888-second wall-time difference. Prior isolated `GOMAXPROCS=1` validation microbenchmarks quantify CPU work, not expected wall-clock benefits under concurrent runtime, DB, ZFS and relay activity. Do not promote an optimization based on a single unpaired baseline.

Next step: record Go CPU/alloc/GC, PostgreSQL WAL/checkpoint/I/O, ARC/vdev I/O **during** controlled alternating identical-source runs (ABBA), from the same logical SQL checkpoint and with same profile and durability settings. Sequential windows 13–22 alone cannot distinguish a code change from differences in record composition or database size.

## Instrumented Security field COPY paired replay (2026-11-08)

Diagnostic source patcher: go/cmd/fi-backlog-recover/field_copy_diagnostic_patcher.go at d6409c0.
Diagnostic runner: go/cmd/fi-backlog-recover/run_field_copy_diagnostic_host.sh at a433764.
The first two launch attempts failed before ingestion because private PostgreSQL AF_UNIX socket paths exceeded FreeBSD pathname limits; shortened paths solved both. Only successful runs below count.

- BASE source 9e0e6e236c95d9af91bc67a065efb47ce2318579; output /var/tmp/fi-window-chunks-fielddiag-baseline-20261108T184820Z.
- OPT source e02a06891600d5877bcb5a680f84bcbcdbc7c195; output /var/tmp/fi-window-chunks-fielddiag-optimized-20261108T192025Z.

| Metric | BASE | OPT |
|---|---:|---:|
| Windows | 3–12 | 3–12 |
| Source records | 1,297,765 | 1,297,765 |
| Security fields | 16,298,841 | 16,298,841 |
| Security field COPY calls | 574 | 574 |
| Approximate field input bytes | 1,407,123,953 | 1,407,123,953 |
| Field COPY calls >=100 ms | 313 | 320 |
| Field COPY sum | 59.996 s | 59.945 s |
| Ten-window committed duration | 561.514 s | 561.024 s |
| Committed rate | 2311.2 records/s | 2313.2 records/s |
| Redundant FileObservation validations avoided | 0 | 137,777 |
| SQL integrity | PASS | PASS |
| Signed readback | 566 byte-identical files | 566 byte-identical files |

**Every field COPY boundary matched.** field_shape.txt SHA256 for both runs:
b3e784e97fa561c662cd690b03efccbb96c162795d3a05b91b9c76925724c2b9.
Shape includes W128 index, Security buffer flush reason, parent Security event count, field row count, and estimated source bytes in execution order. It intentionally excludes elapsed time. This rules out changed Security COPY boundaries as the explanation for the optimized-vs-baseline measured difference.

**Causality:** OPT-BASE committed time = -0.490 s (-0.087%); COPY time = -0.051 s; slow calls = +7. These are near-ties; one sequential pair does not establish an optimization gain. The uninstrumented original baseline from earlier in the day had only 27 >=100ms calls and 46.262s of field COPY time, whereas the new instrumented original baseline has 313 and 59.996s. Consequently the slow-call threshold movement **reproduces on unchanged baseline source**. However, the newly enabled per-call diagnostic printing, GODEBUG=gctrace=1, checkpoint logs, freshly initialized logical-restored PostgreSQL clone, and changing host conditions confound direct historical comparison. Inspect retained pg_before.txt / pg_after.txt (PG WAL/checkpointer/I/O), postgres.log checkpoint activity, and recover.log GC trace before asserting a cause. Do not claim instrumentation or PostgreSQL storage caused it without evidence. Avoid modifying the Security flush algorithm.

Acceptance status: private experiment only; no authoritative writes, no public promotion, no new main-branch code. Next study focus is measurement overhead versus database/host variability, plus separately quantifying whether File validation removal reduces CPU and allocations independently of wall time.

### PostgreSQL and GC deltas from retained paired diagnostic logs

Input: user-produced `pg_before.txt` and `pg_after.txt` from private baseline and optimized fixtures, plus original per-window trace output. PostgreSQL 18 view column order verified against official documentation.

| Statistic (after minus before) | BASE | OPT |
|---|---:|---:|
| WAL records | 44,621,323 | 44,623,821 |
| WAL full-page images | 604,418 | 603,282 |
| WAL bytes | 10,860,054,645 | 10,846,276,631 |
| WAL buffer-full events | 204,235 | 200,560 |
| Requested checkpoints | 20 | 20 |
| Completed checkpoints | 19 | 19 |
| Scheduled checkpoints | 0 | 0 |
| Checkpoint write-phase elapsed ms | 475,997 | 476,642 |
| Checkpoint sync-phase elapsed ms | 2,205 | 1,491 |
| Checkpointer shared buffers written | 81,673 | 84,386 |
| GC trace lines (`^gc [0-9]`) | 826 | 809 |

Interpretation: substantial WAL pressure and 20 requested checkpoints were measured **in both** runs; this is a plausible shared constraint, not an established cause of COPY differences. Checkpointer write-phase time measures asynchronous checkpoint processing and must not be added to/reduced from synchronous ingestion duration. The 13.78 MB difference in generated WAL bytes is ~0.13% of 10.86 GB. The 3,675 extra WAL-buffer-full events in BASE do not themselves establish that WAL writes blocked any particular field COPY. Earlier uninstrumented-run metrics lack comparable PG stats; a direct causal comparison is not available. Absence of grep matches for `checkpoint starting|checkpoint complete` in retained `postgres.log` does NOT negate the checkpointer counters. The next read-only review should inspect retained `pg_stat_io` rows, and only if necessary implement bounded per-call server wait sampling or client-vs-Postgres COPY timing.

### Private PostgreSQL pg_stat_io comparison (user-measured)

The private PostgreSQL 18 `pg_stat_io` deltas for both instrumented 10-window replays show:

| Statistic | BASE | OPT |
|---|---:|---:|
| Client backend WAL normal writes | 184,336 (1442.4 MiB) | 179,699 (1405.0 MiB) |
| Client backend relation bulkwrite writes (COPY-context) | 131,327 (1026.0 MiB) | 129,884 (1014.7 MiB) |
| Client backend relation normal writes | 219,843 (1717.5 MiB) | 218,825 (1709.6 MiB) |
| Background writer relation normal writes | 225,749 (1763.7 MiB) | 223,601 (1746.9 MiB) |
| Checkpointer relation normal writes | 81,672 (638.1 MiB) | 84,386 (659.3 MiB) |
| WAL writer WAL normal writes | 2,270 (3576.4 MiB) | 2,208 (3526.1 MiB) |
| Client backend WAL fsyncs | 65 | 82 |
| Checkpointer relation fsyncs | 2,624 | 2,607 |

All reported `write_time` and `fsync_time` values are 0.0 ms. Per PostgreSQL 18 official docs, these values are **zero when `track_io_timing` (relation) and `track_wal_io_timing` (WAL) are disabled**, their respective defaults. Therefore these counters do not presently quantify server I/O waiting or explain individual COPY latency. Verify the actual settings before assuming they were off. File `pg_before.txt` and `pg_after.txt` contains `evictions` at pipe-separated column 16 and `reuses` at column 17, not yet inspected. Those can help assess client-backend buffer churn without rerunning. More generally, the close A/B counters do not establish that WAL pressure caused the previously observed differences from historical uninstrumented runs. No PostgreSQL tuning changed.

### pg_stat_io client-backend relation eviction deltas (2026-11-08)

| Context | BASE evictions | OPT evictions | BASE reuses | OPT reuses |
|---|---:|---:|---:|---:|
| relation bulkread | 39,297 | 38,636 | 590,549 | 606,707 |
| relation bulkwrite | 412,099 | 412,283 | 0 | 0 |
| relation normal | 513,132 | 516,386 | 0 | 0 |
| relation init/vacuum | 0 | 0 | 0 | 0 |
| total evictions | 964,528 | 967,305 | n/a | n/a |

Relative delta in total evictions: +2,777 (+0.288%). For PostgreSQL 18 `pg_stat_io`, normal-context evictions reflect buffer replacement; bulk-context evictions reflect taking shared buffers into a size-limited ring. Counts are events, not distinct blocks, not direct evidence that a synchronous write was required each time, and cannot establish storage stalls without I/O timing or waits. The 590,549/606,707 `bulkread` reuses are ring reuse events. Do not infer that zero `bulkwrite` reuses is a data-integrity failure.

Cross-run historical context: prior uninstrumented baseline had 523.424s committed time and 46.262s Security field COPY, whereas the instrumented baseline had 561.514s committed time and 59.996s field COPY. Therefore +38.090s total includes +13.734s field COPY and **+24.356s elsewhere**; the historical slowdown is not exclusively a field COPY issue. Instrumentation, fresh DB restore, and host/time differences prevent causal attribution.

### Next control: uninstrumented historical baseline with external observers (pending host execution)

Runner: `go/cmd/fi-backlog-recover/run_clean_baseline_observed_host.sh` created at commit `3c3d1313561113864057855131bcf5eeb638765f`. Derived from the **previously successful** uninstrumented original ten-window baseline runner (`run_clone_11_08_26_host.sh`, source `9e0e6e236c95d9af91bc67a065efb47ce2318579`). Only the experiment branch was modified; no main or production edits.

Controls: replay windows 3–12, original signed payload/cache, W128 outer windows, K32 processing chunks, Security P3, File F3, PostgreSQL 18.6 logical-restored W0–W2 seed, `max_wal_size=1024 MB`, durability settings unchanged, the existing SoR/no canonical writes guardrails, exact-window validation and byte-identical signed readback.

External observations: read-only `pg_stat_wal`, `pg_stat_checkpointer`, and `pg_stat_io` snapshots just before/after the replay; captured PostgreSQL settings (including I/O timing flags); host `iostat -x -w 5` and `vmstat -w 5` sampled in background only during replay, cleaned up through the existing trap. No FI code instrumentation, `GODEBUG` unset, no per-COPY diagnostic log lines and no `log_checkpoints` override. The observers can still have small measurement effects, so results should not be claimed fully overhead-free.

Output uses the successful baseline directory naming convention, with a fresh UTC timestamp. Host must run `sh -n` first; the remote execution result is pending. Compare future `FI INGEST COPY TABLE` field timings, committed elapsed time, PostgreSQL counters, and host sampled I/O to the original 523.424s / 46.262s and subsequent instrumented 561.514s / 59.996s baseline. Do not infer a cause from one control run alone.

### Clean uninstrumented historical baseline control — completed 2026-11-09

Runner: go/cmd/fi-backlog-recover/run_clean_baseline_observed_host.sh from 3c3d131, unchanged source commit 9e0e6e236c95d9af91bc67a065efb47ce2318579.
Output directory: /var/tmp/fi-window-chunks-clone-11-08-26-20261109T095450Z.

| Metric | Original Nov 8 baseline | Instrumented Nov 8 baseline | Clean Nov 9 baseline |
|---|---:|---:|---:|
| Source records | 1,297,765 | 1,297,765 | 1,297,765 |
| Window time (s) | 523.424 | 561.514 | 595.952 |
| Rate (records/sec) | 2,479.3 | 2,311.2 | 2,177.6 |
| Field COPY (s) | 46.262 | 59.996 | Not yet extracted from recover.log |
| Calls >= 100ms | 27 | 313 | Not yet extracted from recover.log |

Clean-run checks: 10 windows index 3–12, 566 signed cached data files and manifests byte-identical; SQL integrity PASS, checkpoint 13|1688152|12, canonical=0 accepted=0, private fixture on socket length 90 bytes, no per-COPY diagnostic instrumenter, no gctrace, no checkpoint logging override. Separate observers captured 600 lines of host iostat and 131 lines of vmstat at nominal five-second intervals. PostgreSQL stats before/after and settings captured; contents not yet analyzed. Clean minus instrumented elapsed = +34.438s; clean minus original = +72.528s. No basis to assign this difference to Go tracing overhead, WAL, PostgreSQL, or host load from elapsed time alone. Next inspect clean field-COPY metrics already present in recover.log, PostgreSQL stats, and sampled iostat/vmstat without rerunning.

### Clean-run Security COPY and host telemetry (additional 2026-11-09 evidence)

Clean baseline source unchanged: 9e0e6e236c95d9af91bc67a065efb47ce2318579; output `/var/tmp/fi-window-chunks-clone-11-08-26-20261109T095450Z`.

| Metric | Original historical baseline | Instrumented baseline | Clean baseline Nov 9 |
|---|---:|---:|---:|
| Committed window elapsed (s) | 523.424 | 561.514 | 595.952 |
| PostgreSQL field COPY wrapper sum (s) | 46.254 | 59.986 | 62.315 |
| Field COPY calls | 574 | 574 | 574 |
| Field COPY rows | 16,298,841 | 16,298,841 | 16,298,841 |
| Field COPY calls >=100ms | 27 | 313 | 345 |
| Elapsed outside field COPY (s) | 477.170 | 501.528 | 533.637 |

Note: wrapper statistics are rounded individually at per-table granularity. The internal SecurityBulk summation differs by milliseconds (e.g. earlier 46.262s and 59.996s). The historical-to-clean total +72.528s comprises approximately +16.061s field COPY and +56.467s other elapsed, so diagnosing only Security COPY is insufficient. All 10 windows in the clean replay were slower than their corresponding window of the instrumented baseline; the baseline itself is not stable across runs.

Clean PostgreSQL settings: shared_buffers 128MB, wal_buffers 4MB, max_wal_size 1GB, checkpoint_timeout 5min, checkpoint_completion_target 0.9, fsync/synchronous_commit/full_page_writes on, track_io_timing/track_wal_io_timing off.

Host samples: iostat -x -w 5 for vtbd0 includes individual sample busy values of 75%, 55%, and 85% with ~4–6ms reads and ~1ms writes; this virtual block device shows potentially significant host-level I/O contention but selective samples do not prove saturation or FI-specific causal latency. Vmstat samples show mostly idle CPUs (roughly 77–90% CPU idle in examples), but host-wide idle percentage does not exclude one serial ingestion thread being CPU-bound. Full sample distributions, historical vs clean per-stage profile totals, and clean-run WAL/checkpoint deltas are still needed. Do not change PostgreSQL tuning until measured.

### Source-audited unaccounted outer-stage time: Security field partition finalize

Source: pinned baseline go/internal/recordingest/backlog_typed_window_postgres.go, in which the `finish_security_field_window(index, fieldCount)` query occurs after the timed `deferred_flush` block and before the timed `verification` block. It is timed separately by local `fieldPartitionFinish` and reported after commit in `FI PRIVATE FIELD PARTITION COMMITTED ... begin=... validate_attach=...`; it is included in `typed_total` but not directly represented in `FI PRIVATE STAGE PROFILE` nonoverlapping outer stage fields.

Per clean and original user stage sums: total typed original 517.624s; clean 590.976s. Subtracting the reported nonoverlapping `setup`, `batch_ingest`, `joined_finish`, `deferred_flush`, `verification`, `marker_commit` leaves original 19.655s and clean 40.485s, **a +20.830s residual**. This is expected to be dominated by field-partition `validate_attach` (and any small uninstrumented intervals) but MUST be checked against the ten individual `FI PRIVATE FIELD PARTITION COMMITTED` lines rather than presumed to be entirely finalize. The residual accounts for about 28% of the +73.352s typed-total increase. Verify both `validate_attach` and `verify_counts`/`verify_coverage` from retained logs. This separate candidate matters because Security field COPY itself increased +16.059s and verification +11.130s.

Clean host sample histogram: vtbd0 averaged 28.1% busy across 119 five-second samples (initial since-boot sample excluded), peaked at 85%, only three samples >=80% and none >=95%; average read latency 2.25ms, max observed queue 6. Not evidence of sustained virtual block-device saturation; possible short delays and host-side contention remain unexcluded. No production tuning or source changes made.

### Targeted private SQL finalize instrumentation staged (pending execution)

10-window original baseline exact-commit source: `9e0e6e236c95d9af91bc67a065efb47ce2318579`. The existing `finish_security_field_window` PL/pgSQL SQL from `testdata/private_field_partitions_isolated.sql` currently combines a count/min/max scan, CHECK declaration, CHECK validation scan, FK declaration, FK validation join, and partition attach into a single Go `validate_attach` interval.

Source-preserving private-only SQL instrument: `go/cmd/fi-backlog-recover/testdata/private_field_partitions_finalize_timed.sql`, commit `6980c02`. It retains the original constraints, checks, FK validation, partition attach, transaction boundaries, and SECURITY DEFINER configuration, adding six `clock_timestamp()`-derived `RAISE LOG` phase durations per nonempty window. It is installed only into a freshly restored disposable `fi-dev` clone, never into the authoritative SoR.

Experiment runner: `go/cmd/fi-backlog-recover/run_private_finalize_step_diagnostic_host.sh` commit `6159a6b`. Derived from the external-observation clean-runner, retains host disk/CPU sampling and PG before-after stats, no Go field-copy trace or GC debug, same signed workload and verification gates. Captures 60 phase lines from private PostgreSQL `postgres.log` and fails if any expected line or phase is missing. Phase labels: `count`, `check_add`, `check_validate`, `fk_add`, `fk_validate`, `attach`. Results pending user-run host output.

Interpretation: Compare phase subtotals to aggregate Go `validate_attach` per window. Difference may include other PL/pgSQL work, statement overhead and diagnostic logging. This test identifies which SQL operation is slow during the new run, not why it differed from earlier runs; an exact timestamp and per-run host behavior are needed for cause.

### Storage capacity correction and clean replay (2026-11-09)

Operator reported an overprovisioned Proxmox LVM-Thin pool at/near exhaustion, subsequently corrected. A screenshot after correction showed 4.50 TB used of 5.83 TB (77.04%, roughly 1.33 TB capacity remaining). Proxmox VM 801 FI-Receiver-B graphs showed I/O Full pressure spikes near 22% around the replay, additional visible roughly 3–6% pressure periods, little CPU pressure, and corresponding disk activity. Graphs alone do not establish the physical root cause or show capacity for every underlying layer.

Fresh **uninstrumented** baseline after storage correction, source 9e0e6e236c95d9af91bc67a065efb47ce2318579, output /var/tmp/fi-window-chunks-clone-11-08-26-20261109T104430Z:

| Measurement | Previous clean baseline | Post-correction clean baseline |
|---|---:|---:|
| Ten-window elapsed | 595.952s | 590.910s |
| Ingest rate | 2177.6 rec/s | 2196.2 rec/s |
| Source records | 1,297,765 | 1,297,765 |
| SQL integrity | PASS | PASS |
| Signed artifact readback | 566 files PASS | 566 files PASS |

Time improved 5.042s (~0.85%) but remains 67.486s slower than original November 8 uninstrumented 523.424s baseline. Guest CPU pressure was not elevated in screenshot. Post-correction clean run captured 595 host iostat and 130 vmstat lines (contents not yet inspected), plus pg_before/after and pg_settings; per-stage detailed data not yet analyzed. Therefore correcting pool headroom alone did NOT restore baseline performance, and a remaining shared storage/PG I/O bottleneck is plausible but unconfirmed.

Most recent private SQL-finalize diagnostic runner commit d07d00e4c210b9b9f32464ec06e461d993497e87 repairs its jailed executable path to the hardcoded prefix /home/jwood/fi-window-bench-optfield-* (the earlier fstep runner failed closed with FI PG relay: unexpected jailed executable, before replay). The relay allowlist itself was not modified. Await corrected diagnostic result, ideally with no concurrent FI benchmark.
