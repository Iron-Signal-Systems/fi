# M5D — Source-to-sealed-generation handoff verification

M5D remains **inactive**. It has no service entry point, changes no existing USN
checkpoint, and does not authorize FISender to retire raw generations. This is
complete Go source for an isolated verifier and an integrity-checked receipt.

## Verified before receipt publication

1. M5B's original source-bound manifest ledger exists and matches the pending
   USN range and correlation identity.
2. The still-present frozen raw generation contains the unchanged FI manifests,
   their checked data, and a canonical byte stream matching the signed descriptor.
3. FI's signed-generation loader checks metadata structure, signing certificate
   role, and the embedded RSA-PSS signature over the descriptor. **This does not
   establish the issuer chain, revocation, or receiver-side trust authorization.**
4. The sealed payload's encoded size and SHA-256 match the descriptor, and the
   bounded zstd decoder produces exactly the signed canonical byte length and
   SHA-256. An extra decoded byte, truncation, or incorrect hash fails closed.
5. A local source-bound handoff receipt is fsynced and atomically published. It
   records the ledger, USN range, generation ID, signed metadata digest, and
   canonical/encoded hashes. Its local SHA-256 is for corruption detection, not
   authentication against a privileged local attacker.

## Still required before service activation

* The sender's raw-generation build/recovery/retirement transitions must be
  coordinated with this verifier and protected against races; no sender hook is
  included in M5D.
* A durable authenticated sender-to-collector handoff must be recoverable even
  if raw and sealed source copies were retired.
* Actual receiver acknowledgement and exactly-once ingest linkage remain
  separate steps. A local handoff is not an acknowledgement.
* Enforce generation signing PKI chain and revocation where required by FI's
  trust policy, not merely the embedded signature.
* Historical governed-root ancestry and live USN/NTFS integration remain
  inactive. Do not migrate/reset the existing collection checkpoint on a gap.

The new `sealed-handoff-batch-*.json` receipts are included in the same
configured capture-queue byte ceiling as the raw batches and correlation cache.
