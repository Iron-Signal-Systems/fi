# SHA-once + Security JSON boundary experiment: W3-W4 result (2026-11-11)

**Decision: do not promote bounded structural JSON scanner as an optimization.** Keep the SHA-once batch-digest decision fixed; this JSON-only candidate is an isolated development experiment, not accepted performance code.

## Signed acceptance

The FreeBSD 15.1 `fi-dev` H16 private PostgreSQL replay used historical source `b01ff0d8cb6559797de052f34b18bd84a395dc4c`, H16 overlay `e47b5383e19140090d691b7c20e8d6ef6e0113fa`, authenticated real signed W3–W4 cache, private copy-on-write batches, P3/F3, K32, 1 GB maximum WAL and 4 MB WAL buffers. SHA-once remained active for **111/111 batches**; exact source records **259,178**; SQL checkpoint **5|649565|4**; zero canonical/Accepted writes; readback of all 111 data/manifest pairs byte-identical; clone PostgreSQL shut down.

Private patched `tryPrepareSinglePassSecurity` retained strict decoder semantics and successfully completed its existing Security tests plus 12,000 seeded malformed-envelope equivalence probes. The passing test gates establish functional acceptance for this test fixture, not speed.

## Actual operator measurements

| W3+W4 measurement | SHA-once control, /var/tmp/fi-window-chunks-once2-20261111T204054Z | SHA-once + JSON boundary, /var/tmp/fi-window-chunks-json2-20261111T213927Z | Delta (candidate - control) |
| --- | ---: | ---: | ---: |
| Committed window total | 102.534s | 100.995s | -1.539s |
| Envelope preparation | 22.317698s | 23.329576s | **+1.011878s, slower** |
| Batch ingestion | 82.081521s | 84.387770s | **+2.306249s, slower** |
| Source read | 6.134135s | 6.912728s | +0.778593s |
| File+Security projection | 38.499920s | 39.183862s | +0.683942s |
| Verification | 6.986572s | 6.136762s | -0.849810s |
| Full batch SHA stage | 0.000s | 0.000s | unchanged |

Stage metrics are **nested and must not be added together**. Total 1.539-second wall-time improvement is driven by non-envelope effects and run variation, not demonstrated faster JSON preparation.

FreeBSD Xeon E5-2680 v2 isolated microbenchmark (two repetitions, 0 B/0 allocs for both):

- Existing `json.Valid(payload)`: **37,853 and 40,588 ns/op**.
- Candidate `privateSingleJSONObjectBoundary(payload)`: **65,833 and 64,393 ns/op**.
- Structural scan is about 1.6–1.7 times as slow as existing `json.Valid` on the benchmark fixture.

**Conclusion:** the scan is an extra full traversal, not an elimination of the duplicate traversal. It is not an optimization and must not be merged into H16 or adopted for the next larger replay. Do not revert SHA-once based on this result.

## Next code direction

Remove the *redundant* JSON syntax traversal from the authenticated canonical Security hot path **without substituting another full traversal**. Strict typed decoding and schema validation remain the source of truth. The fallback/unknown-envelope path must remain fail-closed and preserve the original accepted/rejected set; a naïve removal of `json.Valid(rawPayload)` is **not** automatically equivalent, because duplicate or trailing envelope members can make the sliced `rawPayload` invalid JSON while the complete envelope is parseable by a permissive decoder. Keep this distinction explicit. A next candidate needs deliberate duplicate/trailing-member tests, malformed signed input tests, and an unprofiled W3–W4 SHA-once paired run. Separate lower-risk work can investigate event/field COPY encoding and PostgreSQL pending wait paths without reintroducing full-batch hashing.

No ten-window replay of the slower JSON scanner is justified by these measurements.
