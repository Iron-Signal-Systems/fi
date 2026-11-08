# FI initial Go ingest path — source review (2026-11-08)

**Status:** Read-only review of historical source `9e0e6e236c95d9af91bc67a065efb47ce2318579`. This document adds no runtime changes. The FileObservation single-validation experiment was running separately when the review began; it must complete its original acceptance gates before a next candidate run.

**Scope:** Private FI backend replay from the existing verified real signed cache, through per-batch record decoding/validation, typed buffering, PostgreSQL COPY and window commit. Windows collection behavior and the ordinary production ingest path were not benchmarked in this review. Prefer measured evidence over expected gains.

## Control run

`clone-11-08-26`, 2026-11-08, one PostgreSQL 18.6 clone, Go 1.27.3, source commit above, W128 / 32,768-record chunks / P3 / F3 / 1GiB WAL, real signed 8,399-batch cache. Ten durable windows indexes 3–12: 1,297,765 new records / 523.424s committed-window time = **2,479.4 records/sec**, SQL integrity PASS, 566 signed data files and manifests byte-equal to the verified cache, authoritative=0, accepted=0. Output: `/var/tmp/fi-window-chunks-clone-11-08-26-20261108T150115Z`.

## Concrete record-processing trace

1. `backlog_verified_cache_recovery.go`: recheck each signed manifest and prepare deferred filesystem staging. This is an evidence boundary and should not be removed to chase throughput.
2. `backlog_typed_window_postgres.go`: start one window transaction; maintain bounded, cross-batch, 32,768-record processing chunks; call `ingestSourceBatch` for each originally signed batch.
3. `postgres_ingest.go:ingestSourceBatch`: read each LF-terminated line via `bufio.Reader.ReadBytes('\n')`, feed batch SHA-256, then prepare and validate the signed record envelope, with per-record `RecordDigest`.
4. `security_single_pass_candidate.go:tryPrepareSinglePassSecurity`: canonical Security event path uses an outer-layout scan and `json.Valid(rawPayload)`, followed by strict one-shot JSON v2 decoding of the envelope with typed Security payload, timestamp/numeric conversions and SHA-256 of original bytes. If layout isn't canonical, the existing general decoder runs. All P3 private guards must remain constrained to the test-only path.
5. `record.go:prepareOwnedSourceRecord` / `encoding.go:decodeStrictPayload`: general path already avoids a redundant raw-byte copy and uses one-shot strict JSON decode. The old independent `json.Valid(record.Payload)` was already removed here; do not reintroduce it.
6. `security_bulk.go`, `file_source_bulk.go`, `file_observation_bulk.go`, and `backlog_joined_source.go`: separately preserve source-row identities and the signed window ledger; use PostgreSQL COPY and bounded child-field cursor; validate SQL row counts and signed marker identity before commit.

## Confirmed duplicate or repeated computation

### F1 — FileObservation validation on the historical path

`postgres_ingest.go:flushFiles` decodes `fileObservationPayload`, populates the content-hash pointer and calls `ntfs.ValidateObservation` before queuing it. `file_observation_bulk.go:prepareFileObservationBulk` calls the **same** `ntfs.ValidateObservation` again on the queued value. That validator traverses path identity, timestamps, metadata, reparse/security/SACL, streams, hashes/prefix, warnings and whole-observation consistency (`windows/ntfs/validate.go`).

The staged `run_clone_11_08_26_file_prevalidation_host.sh` candidate marks the specifically private, previously validated Go value; direct/ordinary callers retain the second check. **Acceptance blocker for promoting this optimization to common code:** explicitly audit all aliases and mutable nested fields between initial validation and bulk usage. A boolean `privatePrevalidated` is not proof of immutable provenance by itself. Test for mutation of retained nested slices/pointers and the first-error/rejection contract; no schema or SQL changes.

### S1 — Security JSON payload full scan before strict decode

`security_single_pass_candidate.go:tryPrepareSinglePassSecurity` calls `json.Valid(rawPayload)`, then `decodeStrictPayload(body, &singlePassSecurityEnvelope)`. This is an observable double scan of the same payload bytes on canonical Security rows. The body decoder uses JSON v2 with v1 semantics and unknown-member rejection. The change candidate must preserve acceptance/rejection for malformed payloads, reordered/repeated members, alternate whitespace, invalid UTF-8, signed original SHA, typed fields and RawMessage bytes. No bypass of strict decoding. Already-existing later branch tail-guard code should not be counted as a validated ten-window performance win.

### S2 — Security timestamp validation then timestamp conversion

`records.ValidateWindowsSecurityEventObservation` calls `ValidateObservedAt` on both `ObservedAt` and `TimeCreated`, invoking `validateTimestamp` (canonical fixed-width UTC timestamp, `time.Parse`, then `Format` equality). The same strings are subsequently parsed by `recordingest.parseRFC3339` into PostgreSQL time values in `prepareSecurityBulkRecord` or `tryPrepareSinglePassSecurity`.

Candidate: return canonical validated timestamps from a shared validation/preparation operation rather than reparse, without changing canonical timestamp rejection or normalized UTC value. Keep validation failure ordering stable.

### S3 — Security numeric validation then conversion

`ValidateWindowsSecurityEventObservation` checks `EventID` and `EventRecordID` via `validateDecimal`/canonical uint64 parsing. `prepareSecurityBulkRecord` and the single-pass candidate then parse `EventID` again via `parseUint(...,63)` and `EventRecordID` again with `big.Int.SetString`. Candidate: reuse validated values to construct SQL types. Preserve the stricter EventID 63-bit SQL limit, canonical string restrictions and the uint64 upper bound enforced by the shared validator.

### F2 — File metadata validation then conversion

`ntfs.ValidateObservation` delegates to `records.ValidateMetadataObservation`, which parses canonical decimal and four canonical timestamp values. `file_observation_bulk.go:prepareFileObservationBulk` re-parses four timestamps and metadata numerics for SQL values; it also decodes base64 path bindings after `ValidatePathBinding` checked their canonical representation. A typed validated representation could retain already-parsed values; any such change requires immutable provenance and exact prior error behavior. The current F1 candidate does **not** remove this second parse/conversion.

## Other candidate costs, not yet established as redundant

- `bufio.Reader.ReadBytes('\n')` allocates per record; multi-record buffering/pooling could reduce allocations/GC, but decoded payloads and Security pending buffers may hold references. Prove ownership/lifetime and zero copy safety before trying pooling. Measure allocations, GC and heap peak first.
- `security_bulk.go` emits 40 event columns via `pgx.CopyFromSlice` and constructs a `[]any` per row. The later experiment branch includes a gated reusable event COPY source, but the clean Nov 8 historical baseline did not activate it; only isolated exact-window tests can establish benefit.
- `security_bulk.go` hashes `RawXML` for its independently stored XML digest. The source record's signed SHA-256 and this raw XML digest bind different evidence and must be retained. The Go compiler may optimize `[]byte(v.RawXML)`; profile allocations before claiming an avoidable copy.
- `backlog_joined_source.go` COPY into `pending_source_record` and typed `fi.source_record` are separate evidence/projection relations, not automatically duplicate SQL. The joined ledger's SQL row-digest readback is an integrity verification, not disposable overhead.
- Source batch SHA-256 (`hasher.Write(raw)`) and per-record SHA-256 (`sha256.Sum256(raw)`) protect different invariants; no proposed removal.
- `security_field_copy_source.go` already streams field rows using a reusable four-element array and bounds COPY chunks. No further optimization claim without profiling.
- `ntfs_identity_prefetch.go` already batches uncached NTFS identities, preserving deterministic ordering and transaction conflict behavior. Investigate cache misses/identity time only with concrete profiles.

## Measurement interpretation and ordered experiments

`FI PRIVATE STAGE PROFILE` exposes nested timings; `envelope_prepare` ~11.7–12.2 s/window, Security event COPY ~5.0–5.4 s/window, Security field COPY ~4.4–4.8 s/window, File projection normally ~7–8 s/window (11.35 s in file-heavy window 12). Do **not** add nested counters. `envelope_prepare` is not exclusively JSON and not exclusively CPU time. The 10-window clock remains the deciding throughput metric.

**Next:** Let F1 conclude and inspect SQL, signed hashes, exact ten durable markers and per-window metrics; do not modify its running source or its script. Independently benchmark S2/S3 conversion reuse in microbenchmarks before making a single-change signed-data candidate. Separately test S1 under adversarial JSON differentials before its own isolated ten-window run. File F2, memory pooling, or event COPY source can follow, one at a time. For any candidate require current toolchain, one isolated database, no SoR writes, equivalent accepted/rejected records and typed values, and no throughput regression; a validated reduction in redundant processing can be worthwhile even without a significant throughput gain.
