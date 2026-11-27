# FI H16 — independently buffered Security and File records (development experiment)

**Status:** implemented and staged on the **development branch**. Pinned-source anchor checks pass. **Not yet compiled, run, or benchmarked on the FreeBSD FI host.** No release or sustained throughput claim.

## Proven baseline left untouched

- Previous verified H16 + SHA-once + JSON-once: **W3+W4, 259,178 source records in 89.931 s**, 2,881.9 records/s; 111 signed batch files and manifests byte-identical on readback.
- The subsequent no-additional-`json.Valid` run passed integrity at **98.664 s** and is **not** a speed win.
- Baseline historical Git commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`, H16 overlay `e47b5383e19140090d691b7c20e8d6ef6e0113fa`, original verified batch COW SHA-once patch, same P3/F3 and PostgreSQL settings.
- New trial is isolated in a freshly provisioned PostgreSQL clone. Authoritative SoR/journal writes remain prohibited.

## Current bottleneck and experiment

The old `ingestSourceBatch` flushes the partially filled File/USN source and projection buffer upon encountering a Security event and flushes Security upon encountering File/USN. Frequent alternation can force many small synchronous COPY operations even with P3's 4,096-event/16-MiB bound, F3's 8,192-record/32-MiB bound and Security fields' 32,768-field/8-MiB bound.

**Candidate:** the active dispatch in `postgres_ingest.go` calls `securityFileFlushBeforeKind`. With explicit `-private-mixed-family-buffers` and a real private W128/K32/P3/F3 context, Security and File/USN buffers are independent until each reaches its existing record or byte cap, or the current K32 chunk ends. **All other kinds, including WindowsSecurityCoverage and USN read/capture boundaries, still flush both first.** That fence preserves source-record ordering used by USN source-bound capture checks.

There is **no** extra goroutine, queue, consumer, sender re-verification, batch rehash, JSON syntax pass, SQL writer or transaction. One ordered SQL connection and one W128 atomic transaction remain. Typed buffers carry across intact signed batches only within K32; no change to window completeness, commit/rollback, or the signed custody boundary.

## Correctness fixes required for mixed buffers

The old source identity lookup uses an ordinal `BETWEEN` query when all buffered records are from one signed batch. That shortcut assumes the ordinals are consecutive and fails when Security 1,3,5 and File 2,4 are retained independently. The candidate calls `bulkSourceIDsAreContiguousSingleBatch` and uses the original keyed `unnest(batch_id,ordinal)` equality join for any gaps. **No contiguous-ID or source-record sequence assumption.**

The File/USN source COPY preflight previously rejected all same-batch ordinal gaps. It now accepts **strictly increasing** sparse ordinals only when the explicit private mixed mode is active, while continuing to reject duplicates/reversal; other ingesters retain the consecutive-ordinal requirement.

Tests in `private_mixed_family_buffers_test.go` cover:
- Private-only gate, correct K32 state and baseline fail-closed behavior.
- True mixed five-record sequence with fewer simulated partial COPY flushes, using the **same dispatch helper the worker calls**.
- USN boundary and coverage ordering barriers.
- Contiguous vs sparse keyed source-identity lookup SQL branch.
- File COPY input with interleaved ordinal gaps (reject in normal mode; allow to reach COPY in private mode), and rejection of duplicate ordinals.

The runner also runs the existing H16, SHA-once, JSON-once, Security event/scope/field and source-record COPY regression gates.

## Build and acceptance runner

`go/cmd/fi-backlog-recover/run_private_h16_mixed_buffers_w34_host.sh`

Inputs staged under `/home/jwood/fi-h16-mixed-buffer-assets`:
- `private_mixed_family_buffers.go` Git blob `a1170aa8f7e3e40ee8f4702a54c6ced006386a23`
- `private_mixed_family_buffers_test.go` Git blob `a841233fcaa176b49448434795141263ca163bae`
- `patch_mixed_family_buffers.go` copied from `go/cmd/fi-backlog-recover/patchers/mixed_family_buffers/main.go`, Git blob `3f29c387c190ffdf8c6a331ceb4dc6a2b8d6609a`

The runner first overlays the original H16 and proven SHA-once changes into a disposable historical Go archive. It then stages the exact pinned Security JSON source, runs the deterministic source patcher **only in the archive**, checks the active ingest dispatch, sparse lookup, File COPY, explicit CLI selector, Go test gates and builds the binary. All are performed before the signed benchmark run.

It must then pass 512 real signed Security samples; the exact W3/W4 selection of 116,357 and 116,522 one-pass Security rows; no second full-batch hash on 111 trusted batches; SQL checkpoint `5|649565|4` with 259,178 new records; authoritative=0, accepted=0; and byte-identical signed batch/manifest readback on all 111. The actual worker log must explicitly show `FI PRIVATE MIXED FAMILY BUFFERS ENABLED`.

The metrics bundle includes `SECURITY_COPY_CALLS.txt` from active `FI REAL TYPED WINDOW` output and `CHUNK_BOUNDARIES.txt` from real K32 chunk telemetry. Compare **counts/rows per COPY**, PostgreSQL wait/I/O statistics, and the complete committed-window wall time to the accepted 89.931-second baseline; stage timers are nested and not additive.

A successful correctness run is not an automatic performance promotion. **Keep the frozen baseline unless this trial delivers repeatable committed-time improvement without added I/O pressure.**

## Security and operational boundaries

The receiver authenticates the signed batch descriptor, verifies encoded and canonical data SHA while decompressing, and publishes the verified custody evidence. This private benchmark reuses the authenticated cache under the existing proof and retains per-record SHA and raw-XML SHA for relational evidence. Missing/replaced trust evidence must fail closed. No canonical SoR, sender, receiver, schema, PostgreSQL durability or main-branch change is part of this experiment.
