# FI H16 Security fast-path regression correction

**Status:** development candidate, checked statically and with isolated scanner tests; **not yet run on real FreeBSD signed W3–W4**. Nothing is promoted to main or to the accepted H16 baseline.

## Root cause from operator output

The prior JSON-once trial completed the signed W3–W4 replay with SQL/readback correctness, but both durable profiles reported `security_single_pass_rows=0`. The original SHA-once control selected **116,357 + 116,522 = 232,879** Security records via the one-pass path. The separate Security preparation timer rose from **0.0931s** to **10.7086s**. Although the JSON-once run's *wall time* was 99.087s versus 102.534s for SHA-once control, the optimized path had **not been exercised**. Its apparent wall gain cannot be attributed to a valid fast-path optimization.

The defect was in `findCanonicalSecurityEnvelopeKeys`: after finding the outer `payload`, it interpreted the nested Security `"version"` and `"scope_id"` fields as forbidden top-level envelope duplicates. These members belong in valid `WindowsSecurityEventObservation` and `WindowsSecurityMatchedScope` payloads.

## Deliberate minimal fix

In the existing comma/marker scan, only a duplicate/aliased outer **payload** key may disqualify an otherwise canonical event, along with conservative escaped/noncanonical member-key fallbacks. Nested `version` and `scope_id` are permitted. There is no new scanner, no new whole-payload `json.Valid` traversal on the successful path, and no change to the strict typed JSONv2 decoder. The legacy decoding fallback remains.

The independently tested, verified SHA-once COW overlay is unchanged. The correction does **not** alter per-record hashes, Security source/event/scope/field COPY, K32 buffering, P3/F3, PostgreSQL configuration, window transaction scope, custody checks, or signed cache.

## Independent checks now required before accepting the fix

1. `TestSecurityJSONOnceNestedSecurityMembersRemainSelected` marshals real-format Security observations with `Version` and multiple governed `MatchedScopes`. It requires fast-path selection and exact source bytes/digest/typed projection agreement with the original strict decoder.
2. Existing canonical/noncanonical and 12,000 deterministic malformed-source probes run before any PostgreSQL fixture work. The strict decoder is unchanged. Direct isolated Go scanner tests also passed for nested members, duplicate payload aliases and 5,000 generated canonical Security envelopes; those isolated tests are *not* a substitute for the full FreeBSD Go package.
3. The runner compiles a FreeBSD test executable and runs `TestSecurityJSONOnceRealSignedPreflight` **on the host** against the actual authenticated cache before any timed replay. It requires 512 real Security event records to select the one-pass path and match independently decoded raw record evidence, digest, typed fields and numeric identity.
4. After exactly two real signed windows, the runner explicitly requires `security_single_pass_rows=116357|116522`. **Zero is a hard failure**, not a performance candidate.
5. Original SHA-once proof: all **111** source batches reuse their verified digest, with **0** batch rehashes. The signed custody readback must be byte-identical on 111 data files and manifests; PostgreSQL checkpoint must be `5|649565|4` and 259,178 records with no canonical/Accepted writes.

Only if all correctness gates pass is the W3–W4 elapsed time meaningful. Compare the **entire** committed window and the separate `envelope_prepare`, `security_prepare`, `source_read` and COPY timers to the original SHA-once control. Those stages are overlapping and cannot be added to infer elapsed wall-clock time. No unverified throughput improvement is claimed.

## Implementation / code links

- `go/internal/recordingest/security_single_pass_candidate.go`: minimal canonical-scan fix.
- `go/internal/recordingest/security_json_once_test.go`: nested Security regression / adversarial tests.
- `go/internal/recordingest/security_json_once_signed_cache_test.go`: bounded, read-only sample of 512 actual signed Security records.
- `go/cmd/fi-backlog-recover/run_private_h16_sha_once_json_without_extra_scan_w3_w4_host.sh`: exact-blob source staging, SHA-once and JSON tests, real signed preflight, window-only SQL/run and signed custody proof.

**No 10-window run or release claim** until these gates pass and measured performance is useful.
