# FI real-signed 10-window performance review — 2026-11-08

## Reference experiment

- Host: `fi-backend-b`; one isolated `fi-dev` PostgreSQL 18.6 instance named `clone-11-08-26`; the authoritative SoR is separate and not a benchmark target.
- Historical source: `9e0e6e236c95d9af91bc67a065efb47ce2318579` (used by the successful run, with only the bounded 10-window stop and one-clone relay name adapted).
- Source generation: `iss-fs-22a.iss.local` / `20261030T000032.061323100Z-3e38b2210771462c`; existing cache of 8,399 verified original signed batches, not synthetic records.
- Starting seed: three previously committed private windows, 390,387 source records and 4,838,850 Windows Security fields. Ten new windows: indexes 3–12.
- Configuration: W128, processing chunks of 32,768 source records (the *meaning* of K32), P3 Security, F3 File, `max_wal_size=1024MB`; `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`. No runtime cutoff.
- Result: 1,297,765 newly committed records over 523.424 seconds of **committed-window time** = **2,479.4 records/second**. Private checkpoint `13|1688152|12`. SQL integrity PASS; 566 published signed batch data files and manifests byte-identical to the verified cache; canonical=0; Accepted=0.
- Results: `/var/tmp/fi-window-chunks-clone-11-08-26-20261108T150115Z` on host. The private PostgreSQL cluster and restored seed were stopped after the experiment. Preserve all previous logs, including the earlier November 6 measurements, without treating the earlier uncontrolled host as an equivalent baseline.

## Per-window committed throughput

| Window | Source records | Wall time | Records/s |
|---:|---:|---:|---:|
| 3 | 129,435 | 54.471s | 2,376.2 |
| 4 | 129,743 | 51.275s | 2,530.3 |
| 5 | 130,642 | 51.193s | 2,552.0 |
| 6 | 130,755 | 50.984s | 2,564.6 |
| 7 | 128,951 | 51.060s | 2,525.5 |
| 8 | 129,842 | 51.308s | 2,530.6 |
| 9 | 129,722 | 52.735s | 2,459.9 |
| 10 | 129,213 | 52.475s | 2,462.4 |
| 11 | 128,575 | 51.442s | 2,499.4 |
| 12 | 130,887 | 56.481s | 2,317.4 |

These figures measure actual committed-window time, not seed restoration, provisioning, authentication of already verified custody, or the 10-minute wall-clock timer.

## Profile interpretation

The `FI PRIVATE STAGE PROFILE` timers have nested/overlapping sub-stages; they must **not** be summed as separate CPU or wall times.

- `envelope_prepare`: approximately 11.7–12.2 seconds/window. Security events account for ~111k–117k of the ~129k–131k source records/window.
- Security COPY components are substantial: typical `security_source_copy` ~3.2–3.5s, `security_event_copy` ~5.1–5.4s, `security_scope_copy` ~2.0–2.2s, and `security_field_copy` ~4.4–4.8s/window. Some are nested within `security_projection_inclusive` or source SQL accounting.
- File projection is typically ~7.0–7.6s/window. Window 12 includes 19,907 FileObservation records, compared with ~13k earlier; its File projection is 11.354s, consistent with higher actual File work rather than an unexplained global regression.
- Window 3's `verification` is 3.941s, versus roughly 1.3–1.7s for windows 4–11; `joined_finish` is 1.443s versus ~0.5s subsequently. This is a first-window effect *hypothesis*, not an established cause.
- One visible historical source inefficiency: `ingestSourceBatch` strictly decodes and validates each FileObservation before adding it to `fileBulk`, and `prepareFileObservationBulk` calls `ntfs.ValidateObservation` again on that same decoded value.
- Another CPU candidate: `tryPrepareSinglePassSecurity` applies `json.Valid` to `rawPayload` and later strictly decodes the envelope and typed payload. A proposed tail guard may avoid a redundant full scan, but its exact acceptance/rejection semantics require differential tests for malformed/noncanonical signed data.

## Controlled experiment order

1. **File validation candidate:** replay the *same* 10 signed windows from *the same historical source* with only an explicitly private-only provenance bit on the already-validated FileObservation value. All ordinary/production bulk callers must continue their own validation. Run unit tests and the 10-window signed SQL/artifact evidence gates. This is the simplest one-variable first test; measure actual gain, do not assume any.
2. **Security JSON guard candidate:** independently repeat the baseline-to-candidate comparison for the initial Security payload `json.Valid` pass, while retaining strict decoding, original signed-byte SHA, typed field ordering, fallback behavior, and unchanged SQL publication. Run malicious/noncanonical differential tests before performance acceptance.
3. **Security COPY optimization:** examine the gated reusable 40-column event COPY-row source only after the decode experiment. Compare memory allocations/CPU and entire committed-window throughput, not microbenchmarks alone.
4. **SQL cost:** only if CPU changes do not improve actual sustained throughput, profile indexed source-copy, field partition finish and the two verification queries. Keep WAL and PostgreSQL settings constant during these experiments.

## Mandatory experimental controls

- **One** PostgreSQL server in `fi-dev` per run, verified by real `ps -axww` postmaster detection before and after; no other benchmark clusters. Preserve 16GiB memory headroom. SoR must be verified running but never modified.
- Immutable original signed cache and signed 3-window seed; re-provision only one fresh private database for each independent run.
- Exact same 10 window indexes, same generation, same Go toolchain version `go1.27.3`, same PostgreSQL 18.6, same chunk/P3/F3/WAL settings, no concurrent experimental workloads.
- Build only from the pinned historical source with **one reviewed code change** at a time. The later experiment branch is not equivalent to that historical source: it already contains several changes, including private File prevalidation, Security row COPY and alternate payload guards. Do not silently pull all changes into an A/B candidate.
- Acceptance requires 10 durable SQL markers, matching source counts, zero authoritative/canonical accepted publication, intact source hashes and signed manifest byte equality, no PostgreSQL memory kills, and explicit fast shutdown of the private PostgreSQL process.
- Record per-window record mix, throughput, full stage timing and variance. Require a reproducible improvement across a second clean run before treating a difference of a few percent as real.
