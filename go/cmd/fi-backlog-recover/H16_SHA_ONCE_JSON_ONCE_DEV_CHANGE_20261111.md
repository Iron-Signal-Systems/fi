# FI dev performance: SHA-once plus truly single-pass canonical Security JSON

Date: 2026-11-11. **Development-only; compile and signed replay have not yet been executed for this revision.** This is NOT a change to the accepted H16 baseline or a release candidate.

## What was wrong

The last trial added an extra whole-payload structural scan rather than eliminating a redundant scan. The FreeBSD E5-2680 v2 measurements proved the structural scan was slower: 64,393–65,833 ns per JSON payload versus 37,853–40,588 ns for `json.Valid`. The W3–W4 `envelope_prepare` stage **rose by 1.012s**, even though total committed time varied from 102.534 to 100.995 seconds. That scanner is rejected and is not part of the new candidate.

## What was changed in the actual performance branch

`go/internal/recordingest/security_single_pass_candidate.go` now removes the `json.Valid(rawPayload)` traversal from the *successful, canonical* Windows Security event path. The source still:

- Reads the existing LF-terminated exact source bytes and retains SHA-256 per source record. Previously authenticated batch digest reuse is unchanged.
- Applies a single comma-delimiter scan to identify the existing canonical envelope markers, with conservative fallback for unexpected or duplicate envelope members. Does **not** add a separate pass through the payload.
- Checks the Security JSON payload's cheap object boundary before the already-required strict `decodeStrictPayload` call. Strict JSONv2 decoding of the complete envelope, typed Security value validation, required fields, numeric/time checks, and actual SQL COPY values remain unchanged.
- For a **failed** strict decode only, invokes `json.Valid(rawPayload)` to preserve the original malformed-input fallback behavior.
- Keeps `findSinglePassSecurityEnvelopeKeys` as the exact historical compatibility reference required by existing tests.

No changes to PostgreSQL SQL, indexes, transaction scope, signed cache, COW clone semantics, canonical SoR, Windows sender, WAL configuration, or the 32,768-record chunk boundary.

## Acceptance staged

`go/internal/recordingest/security_json_once_test.go` checks:

1. Canonical Security records with 0, 1, 24 and 96 child fields: byte-identical source record, digest and typed Security values against the original strict decoder.
2. Noncanonical/invalid envelopes including alternate-case duplicate payloads, unknown members, valid/invalid JSON and escaped names: the new fast path may conservatively fall back but may never select data that the original `json.Valid` rejected.
3. 12,000 deterministic one-/two-byte input mutations through real-format source records, preserving the legacy strict decoding fallback.
4. A full-record preparation microbenchmark rather than a microbenchmark of a replacement JSON scanner.

The `run_private_h16_sha_once_json_without_extra_scan_w3_w4_host.sh` runner uses exact Git blob-verified copies of the above source and tests in the **disposable historical H16 source archive**. It first passes SHA-once gates, the existing Security/JSON equivalence tests, the new Security JSON-once tests, and benchmarks, *before* starting the isolated SQL clone. Its real signed W3–W4 acceptance retains 111 original cached batches, 259,178 source records, unchanged record hashes, the expected SQL checkpoint `5|649565|4`, zero authoritative/Accepted writes and complete data/manifest byte comparison.

Prior accepted SHA-once private control (unprofiled): **102.534s**, across 259,178 real signed records. Target: improved envelope preparation, with no resulting increase in overall committed duration. This is a hypothesis, not a measured result yet. We only compare after FreeBSD operator evidence. The accepted 10-window H16 baseline remains **475.149s / 2,731.3 records/sec**.

## Follow-up

Do not run another 10-window candidate or alter source-of-record until this W3–W4 code and its output pass acceptance and demonstrate useful performance. If it does, continue reducing *actual* typed projection/COPY time with evidence from stage counters; never restore redundant batch SHA-256.
