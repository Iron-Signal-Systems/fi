# FI 2026-11-08 FileObservation redundant-validation trial — results

Status: **COMPLETED; correct under measured gates; no demonstrated throughput gain; code-retention review remains open**.

## Scope and provenance

- Historical source reference: `9e0e6e236c95d9af91bc67a065efb47ce2318579`, both runs using Go 1.27.3, PostgreSQL 18.6, one disposable `fi-dev` clone at a time, real signed cache of 8,399 batches.
- Configuration: W128, 32,768-record processing chunks, P3, F3, `max_wal_size=1GiB`, full PostgreSQL durability; start with the same three-window seed; commit windows 3–12; no timer cutoff.
- Baseline: `/var/tmp/fi-window-chunks-clone-11-08-26-20261108T150115Z`.
- Candidate: `/var/tmp/fi-window-chunks-clone-11-08-26-fileval-20261108T154127Z`.
- Candidate runner: `go/cmd/fi-backlog-recover/run_clone_11_08_26_file_prevalidation_host.sh`; prepared from historical source and adds a private-only `privatePrevalidated` marker after the existing `ntfs.ValidateObservation` check; the later bulk preparation bypasses only its second call to the same validator.
- Neither run modifies the authoritative SoR. Both terminate their own private PostgreSQL process, exit 0, and perform a positive signed-artifact readback.

## Total throughput

| Metric | Baseline | Candidate | Difference |
|---|---:|---:|---:|
| Newly durable source records | 1,297,765 | 1,297,765 | 0 |
| Committed-window seconds | 523.424 | 528.153 | +4.729 (+0.904%) |
| Committed records/sec | 2,479.4 | 2,457.2 | -22.2 (-0.90%) |
| Last private SQL checkpoint | 13 / 1,688,152 / 12 | 13 / 1,688,152 / 12 | identical |
| Verified published batch data files | 566 | 566 | 0 |
| Data and manifest byte readback | PASS | PASS | same evidence |
| SQL relational integrity | PASS | PASS | same evidence |
| Canonical/authoritative records published | 0 | 0 | none |
| Accepted journal rows | 0 | 0 | none |

## Per-window elapsed seconds

| Window | Records | Baseline | Candidate | Candidate minus baseline |
|---:|---:|---:|---:|---:|
| 3 | 129,435 | 54.471 | 56.476 | +2.005 |
| 4 | 129,743 | 51.275 | 52.683 | +1.408 |
| 5 | 130,642 | 51.193 | 53.009 | +1.816 |
| 6 | 130,755 | 50.984 | 50.874 | -0.110 |
| 7 | 128,951 | 51.060 | 50.864 | -0.196 |
| 8 | 129,842 | 51.308 | 50.412 | -0.896 |
| 9 | 129,722 | 52.735 | 50.927 | -1.808 |
| 10 | 129,213 | 52.475 | 52.522 | +0.047 |
| 11 | 128,575 | 51.442 | 54.365 | +2.923 |
| 12 | 130,887 | 56.481 | 56.021 | -0.460 |

Five windows improved and five regressed. These are two chronological executions, **not a paired or repeated statistical experiment**. Treat the observed -0.90% as within possible host/GC/checkpoint/record-mix timing variation; do not claim that removing validation caused a loss. The signed record mix and row counts were held constant.

## Correctness and next review

- The reported SQL checks and byte-equal signed artifact comparisons passed. However, aggregate row counts, marker hashes, and signed **source artifact** byte equality are not by themselves a full independent row-by-row comparison of all resulting typed SQL values across the two databases. Existing consistency gates are necessary, not absolute proof of semantic identity.
- Existing Go unit tests for the private marker and input bounds passed (the trial reports `ok github.com/Iron-Signal-Systems/fi/go/internal/recordingest 0.013s`). This is not proof of immutable provenance or complete test coverage.
- The `privatePrevalidated` bool is only set on the W128/P3 private path after the first validated FileObservation. Audit whether nested slices or pointers are mutated between first validation and `prepareFileObservationBulk`. Direct/ordinary paths must not be allowed to bypass validation, including through future API changes or accidental reuse of a marker.
- Verify a true end-to-end equivalence test across accepted and intentionally malformed observations before considering promotion to the common FI ingest path. Preserve failure classification, error ordering, and original source SHA-256 validation.
- First compare local stage evidence read-only: baseline vs candidate `FI PRIVATE STAGE PROFILE` entries, especially `file_projection_inclusive`, `batch_ingest`, `envelope_prepare`, and `security_projection_inclusive`. The CLI summary is insufficient to infer which section accelerated.
- Continue reviewing Security initial Go parsing (repeat timestamp and decimal conversions, redundant `json.Valid` on canonical Security payloads) as *separate* candidate investigations. The clean baseline runner stays immutable. No PostgreSQL tuning in this trial.

## Interpretive conclusion

The private candidate has passed the currently reported data-integrity checks and removes a duplicate validator invocation. It has **not demonstrated a committed-window throughput improvement**, but that does not alone justify rejecting genuinely redundant work. Whether it is safe to retain depends on a validated immutable-data/provenance argument and stronger differential tests. Do not merge/promote on throughput evidence alone.

## Measured internal stage profiles (from both completed recover.log files)

Reported `FI PRIVATE STAGE PROFILE` stage durations were summed across matching windows 3–12. The counters include nested measurements and **must not be summed to derive total elapsed time**.

| Counter | Baseline 10-window sum | File-prevalidation candidate sum | Delta candidate − baseline | Candidate faster windows |
|---|---:|---:|---:|---:|
| `file_projection_inclusive` | 77.676s | 77.736s | +0.060s (+0.08%) | 4/10 |
| `security_projection_inclusive` | 120.989s | 129.247s | +8.258s (+6.83%) | 0/10 |
| `envelope_prepare` | 120.184s | 118.800s | −1.384s (−1.15%) | 8/10 |
| `batch_ingest` | 471.680s | 475.881s | +4.201s (+0.89%) | 3/10 |

**Interpretation:** The repeated FileObservation validator was removed in the private candidate, but the measured File projection total was effectively unchanged. Security projection was slower in **every** candidate window despite no intended Security-path code change. This is evidence of broader run-to-run effects (such as workload timing, runtime scheduling, PostgreSQL I/O or cache state), **not** proof of their exact cause. The 0.9% overall slowdown therefore cannot be attributed confidently to the File optimization. No demonstrated File-stage speedup; no grounds to reject a safe redundancy removal solely for lacking a throughput gain.

**Next acceptance gate:** Before considering promotion, prove that the first validated `ntfs.Observation` remains semantically unchanged until bulk use, including its pointer/slice children and any references retained by the buffered batch; test malicious inputs, failed-validation paths, error ordering and rollback. A standalone `privatePrevalidated` boolean is not an adequate trust/provenance guarantee. Do not alter the baseline runner or the existing recorded output. A later Security initial-decode/conversion candidate must remain an independent experiment.
