# M5B: durable source-manifest inventory (inactive)

M5A can locate complete source-bound publications in the active FI spool or a
frozen raw generation, but only while original manifests and data still exist.
M5B adds `Store.RecordSourceManifestLedger`: after verifying the source record
coverage and the FI spool's original manifests, it persists an integrity-checked
inventory outside the sender spool, tied to scope, journal, USN range, original
source digest, correlation digest, each batch ID, and each manifest/data digest.
It counts this ledger against the same bounded USN queue disk budget.

The source inventory is immutable. Repeated inspection of the same source after
an active-to-frozen rollover checks equality of its manifest identities rather
than changing the original inventory. It survives removal of a frozen directory
and remains available for later sender-side inclusion verification.

**It is NOT a sealed-generation receipt, durable receiver acknowledgement, or
proof that sender transport preserved the original records.** M5B cannot
advance the processing cursor when the originals have disappeared. A captured
manifest list is not proof of inclusion in a signed/sealed generation. In
particular, `ReadSourceManifestLedger` must never be used to infer authorization
to re-observe or publish a pending source range again.

Next: sender-coordinated source-to-sealed generation inclusion proof, exact
acknowledged retirement provenance, and crash atomicity across raw removal and
sealed publication. Until those stages and historical ancestry/migration tests
pass, keep the new service processing path inactive. No installed services or
sender generation formats are modified by this patch.
