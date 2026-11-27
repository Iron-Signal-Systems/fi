# FI C1: eliminate post-ingest signed-custody replays

**Decision (2026-11-26):** In the single-jail architecture, the end of the 15,140,785-record C1 SQL drain must **not** trigger another 15-million-record signed-custody/SQL identity scan. The 20,420.37 records/s, 741.455-second full-ingest result is the frozen performance baseline. This is a **development design requirement**, not a completed implementation or an acceptance PASS.

## Confirmed source issue (as-built)

Two distinct redundant full-custody passes exist in the deployed development source:

1. `c1RunNativeBChildWithTrust` in `c1_sor_native_b_process.go`: on `FINAL`, runs `c1NativeBCompleteRelational` and then `c1NativeBVerifySignedCustodyWithTrust`, rereading all original JSONL records and querying SQL in chunks of 2,048 rows **after** 16 post-COMMIT group proofs have already returned PASS.
2. `c1NativeFullPromotionProofWithTrust` in `c1_sor_native_promotion.go`: when remapping to canonical, calls `c1NativeBCompleteRelational` then `c1NativeBVerifySignedCustodyWithTrust` **again** while holding publisher table locks.

These are full-depth repeated proofs, not cheap terminal authorization checks. The second pass under publication locks also substantially increases lock residence time.

## Required new behavior

- Original receiver durable signed custody remains protected; no deletion, modification, replacement, or weakened trust-root validation.
- A continues the tested P5/P6 ordered SourceParent and five family SQL processing; no throughput tuning as part of this change.
- Independent B performs required signed-source cryptographic verification and committed relational/record identity checks **as original reporting groups become durable**, not after the final SQL drain. B remains a distinct fi-sor OS process with its own read-only SQL connection and no authority to write or flush A's SQL work.
- Per-group verified evidence MUST bind source, generation, original batch index+ID, exact signed data SHA/bytes/count, original trust/transfer/receipt hash, committed SourceParent/typed identity and USN dependencies. A mutable or recomputable group count alone is insufficient proof of exact original signed row bytes.
- B may use a sequential one-pass original custody reader begun during ingestion, with separate SQL connection(s) and bounded backpressure. Group READY means SQL durable; no group can claim acceptance before *both* its original signed-data and DB identity verification succeed. Do not independently re-decompress the entire prefix per group.
- `FINAL` only combines already-completed exact-group evidence and a bounded metadata/ledger consistency check, refuses missing/duplicate/mismatched proofs, and publishes no data by itself.
- Publication holds required PostgreSQL locks and independently checks that the exact verified generation/receipt and committed Pending data have not changed **under the same lock/snapshot semantics** before canonical remapping. It must not repeat 15M-record original custody JSONL decode/audit. Protect against TOCTOU between B verification and publisher lock acquisition; a trusted signed B proof token without a SQL snapshot/content-stability binding is insufficient.
- Keep atomic canonical publication, independently verified Accepted journal, fresh canonical readback, fail-closed crash/replay, and original receiver READY durability/retirement order.

## Acceptance tests before replacing the running worker

1. Bad signature, modified original JSONL, changed manifest, duplicate/missing/reordered batch, and mismatched transfer digest all reject canonical Accepted.
2. Missing/wrong typed-root, missing/duplicate SourceParent ordinal, cross-batch FK, USN capture inconsistency, and incomplete committed group all reject Accepted.
3. PostgreSQL Pending mutation after B group PASS but before publisher lock must be detected and reject (or reverify on an immutable snapshot) before canonical remap.
4. Crash immediately before and after the B evidence seal and before/after canonical commit remains replay-safe. No release/live activation based solely on full-ingest success.
5. Group proof begins during ongoing P5/P6 ingestion, not after drain; each group is checked exactly once, and group proofs cover all 8,399 original signed batches and 15,140,785 records.
6. A frozen 15M signed corpus on isolated PG18 clone passes B + publication + Accepted/readback; compare ingestion clock separately from B tail and publisher wall, and report group verifier CPU/SQL throughput.

**Operational warning:** the currently running executable is pinned to its original benchmark commit. Modifying this branch cannot alter that process. Do not interrupt it or treat an incomplete canonical publication as successful.
