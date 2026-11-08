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
