# FI H16 verified-cache ingest: wired performance-path audit (2026-11-12)

Status: development-only integration staged in `work/fi-joined-private-performance-20261102`. The latest additional no-`json.Valid` revision and its COPY replay **have not yet been built/run on FreeBSD**. Do not present an unrun source revision as a benchmark win.

## Verified-custody boundary

The receiver authenticates the signed descriptor and manifest, then validates the encoded-data SHA and canonical-data SHA while streaming zstd decompression. It publishes the receipt-bound verified cache **only after success**. Authentication of a signed descriptor alone is not the compressed/canonical bytes check.

The ingest side consumes verified cache in bounded windows. Under the already accepted isolated FreeBSD COW proof, it reuses authenticated batch digests rather than hashing all batch data again. **Unproved, changed, or crash-restored cache input must fail closed or take the existing independent validation path.** The per-record SHA-256 and Security raw-XML SHA-256 are distinct stored database-evidence fields and remain required. The strict typed JSON decoder is required to construct relational values; explicit `json.Valid` syntax prechecks are redundant and were removed from the newest Security candidate.

Ingest prepares the 10-minute relational window, COPYs source, File, Security event/scope/field data, validates SQL integrity and commits a durable window checkpoint. Authoritative SoR publication is separate; the disposable private replay writes **zero** authoritative/Accepted records. Do not bypass the normal authoritative publication gates.

## What was already wired in the **accepted historical H16** source

The signed W3/W4 accepted 89.931s/259,178 rows (2,881.9 rows/s) with `security_single_pass_rows=116357|116522`, 111 authenticated COW batches and no whole-batch rehash. It **already** contained these private P3 paths in historical source commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`:

| SQL COPY | Existing tested source | Source of selection |
| --- | --- | --- |
| Security `fi.source_record` | `newSecuritySourceRecordCopySource` in `source_record_copy_reusable_candidate.go` | `securitySourceRecordCopyRows(ctx,...)` in `security_bulk.go` |
| Security `fi.windows_security_event` | `newSecurityEventCopySource` in `security_event_copy_source_candidate.go` | `securityEventCopyRows(ctx,...)` in `security_bulk.go` |
| Security `fi.windows_security_event_scope` | `newSecurityScopeCopySource` in `security_scope_copy_source_candidate.go` | `copySecurityBulk`, only for private P3 |
| File/USN `fi.source_record` | `newFileSourceRecordCopySource` in `source_record_copy_reusable_candidate.go` | `fileSourceRecordCopyRows(ctx,...)` in `file_source_bulk.go` |
| Security `fi.windows_security_event_field` | `securityFieldCopyChunk` reusable four-column cursor | `copySecurityBulk` (existing bounded COPY) |

The reusable event and source rows and streaming scopes were **not** an untested optimization still waiting to be connected in the accepted H16 build. They were already exercised. The long-lived development branch had diverged, which made prior test-only candidate results misleading.

## Current branch reconciliation

Replaced `security_bulk.go` and `file_source_bulk.go` with **exact original tested H16 Git blobs**, and restored the exact historical source and tests for reusable source/scope adapters. The historical event source was already identical. Removed the two new duplicate `security_copy_sources*.go` files rather than adding a competing implementation.

The branch also contains the newer Security source `security_single_pass_candidate.go` (blob `9d7ba5fd99dc79d859023885810a95e869b8c1f1`): no explicit `json.Valid` syntax-check pass, exactly one strict typed decoder, same canonical selection, record evidence SHA and SQL behavior. Its regression test blob is `d8b7603774f91209471ce42e311caf45f3d3fd9e`. This additional change **was not part of** the original 89.931-second run.

## Execution and acceptance

New private runner: `go/cmd/fi-backlog-recover/run_private_h16_sha_once_json_copy_w34_host.sh`. It composes the exact pinned H16/verified-COW source, the latest no-extra-`json.Valid` Security source, the original wired COPY code and regression tests. It retains a separate disposable fixture and clone path, 512 actual signed Security event samples before replay, exact Security single-pass counters `116357|116522`, 111 COW-authenticated batches, SQL checkpoint `5|649565|4`, 259,178 committed source records, and byte-identical manifest/data readback.

Its unit gate now explicitly runs `TestSecurityEventReusableCOPY*`, `TestSecurityScopeReusableCOPY*`, and `TestSourceRecordReusableCOPY*` in addition to JSON-once and SHA-once tests. The entire W3/W4 timed fixture and its integrity checks **still must run on FreeBSD**; passing source/test inspection does not establish throughput.

Do not repeat the earlier 89.931s performance claim for the new no-`json.Valid` source or a claimed new COPY optimization. Both faster and slower outcomes are possible until execution.

## Next measured bottleneck

Security event COPY, Security field COPY, and File projection dominate the remaining observed stage timings. The new runner is a *reconciliation/check*, not an additional COPY speed candidate. Once it passes and is timed, focus on genuinely unwired work only. Do not change SHA policy, strict decoder, SQL transaction scope, receiver or canonical SoR as a side effect of tuning.
