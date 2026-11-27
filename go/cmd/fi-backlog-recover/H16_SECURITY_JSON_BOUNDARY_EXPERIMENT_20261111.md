# FI H16 Security JSON validation-elimination development trial

Status: **staged, not yet run in fi-dev**. Commit `fd8a264f179b37d758330cdb06726b97a1bbd2bf`. The original accepted H16 475.149-second W3-W12 control and the accepted private SHA-once source artifacts are unchanged.

## Why

The Windows sender validates record JSON before placing a record in a signed batch. Transport verified the original signed stream and established an authenticated cache. When private FI ingest processes a canonical Security envelope, `tryPrepareSinglePassSecurity` performs `json.Valid(rawPayload)` on the full nested Security payload and immediately invokes `decodeStrictPayload` on the entire same envelope, parsing that payload a second time. The duplicate prevalidation is redundant for canonical, correctly signed events.

**This is distinct from the SHA-once fix**: batch SHA-256 is already reused for the private authenticated COW handoff; typed source-record hashes, raw-XML hashes, original signed manifests, SQL row digests and exact byte/record counts remain.

## Candidate and invariants

- `testdata/fi_private_security_payload_boundary.go`: bounded-depth structural shape scanner over the raw Security JSON payload. It checks an exact single JSON object boundary, quotes, escapes, nesting and delimiters, but does not validate schema or all JSON grammar. It avoids a full independent syntax validation for canonical payloads; a deep or unusual payload falls back to the original `json.Valid` gate.
- `testdata/patch_private_security_payload_boundary.go`: fail-closed, exact-anchor patch of **only the disposable pinned H16 source archive**. If the strict decoder fails after the cheap structural scan, `json.Valid(rawPayload)` is invoked to maintain the pre-existing selected/fallback distinction for malformed source.
- `testdata/fi_private_security_payload_boundary_test.go`: known JSON edge cases and 12,000 deterministic randomized mutations compare fast-path selection to the original `json.Valid` gate; strict decoder and canonical typed value equivalence tests continue running unchanged.
- `run_private_h16_sha_once_security_json_w3_w4_host.sh`: uses the established signed W3-W4, private COW clone, P3/F3, H16, 1 GiB WAL/4 MiB buffer, independent PostgreSQL fixture and all acceptance gates. Its benchmark/test phase happens before any seed start. Exactly 111 trusted SHA-once batches and 259,178 signed records must pass full SQL and signed artifact readback.

**Important:** The sender's validation is a provenance fact, not an unconditional instruction to accept arbitrary backend JSON. Strict typed decoding, record validation, required-field enforcement, error paths, and unsupported/legacy data behavior must remain. No canonical SoR or Windows sender changes are made.

## Measurements

Compare actual committed W3-W4 window time and individual `batch_ingest`, `envelope_prepare` stages against the unprofiled private SHA-once result: **102.534 seconds** for 259,178 signed records. This prior result is *not* the accepted H16 baseline; the full accepted W3-W12 baseline remains **475.149 seconds / 2,731.3 records/s**.

The new runner also saves `security-json-benchmark.log` with Go `json.Valid` versus lightweight structural-check performance and allocations. Passing equality tests says nothing about speed. An improvement must be measured and reproduced before adopting this code beyond the private fixture.

Run the exact historical source/asset hashes and verify failures before claiming any correctness or throughput acceptance.
