# FI H16 / SHA-once / strict Security JSON-once: signed W3–W4 acceptance

**Date:** 2026-11-12 UTC. **Environment:** private disposable FreeBSD 15.1 fi-dev PostgreSQL 18.6 clone, real signed W3–W4 from the previously authenticated 8,399-batch cache. **Status:** functional W3–W4 accepted; observed two-window performance improvement; sustained W3–W12 uplift **not yet established**. This is development, not a production release.

## Proven source

Branch `work/fi-joined-private-performance-20261102`, verified runner revision `97961a019d84859a558c2e6a1e0688e255ef8ec2`.

- Historical FI base `b01ff0d8cb6559797de052f34b18bd84a395dc4c`
- H16 overlay `e47b5383e19140090d691b7c20e8d6ef6e0113fa`
- Reviewed JSON-once source Git blob `9a70be536f0a07687640fe1e2e48459d85430073`
- Unit + adversarial JSON tests Git blob `9250302470679dd9c23ce7daca92a9f7fbb22596`
- Verified-cache preflight Git blob `e2926386e039f05ce52d9cd44b75c56e81133d53`
- Runner Git blob `e2d01329e01c0df5ba20d00dcf5f9fc5c69c5679`
- Run output `/var/tmp/fi-window-chunks-jonce2-20261112T013718Z`; exact runner log `clone-11-08-26/recover.log`; bundle `fi-h16-sha-once-json-once-w3-w4-20261112T013718Z.tar.gz`.

## Integrity and fast-path gates: PASS

SHA-once private verified COW handoff reused **111** authenticated batch digests; **zero** complete batch rehashes; per-record hashes unchanged. Strict typed decoder unchanged, no successful-path second `json.Valid(rawPayload)` traversal. Twelve thousand deterministic malformed-input tests passed. Actual signed Security preflight selected **512** samples and preserved the original decoding/projection. Durable W3 and W4 selected **116,357 and 116,522** Security events via the one-pass path (**232,879** total), not the broken zero-selection fallback.

Ingested **259,178** source records. SQL checkpoint `5|649565|4`. Exactly **111** source batch data files and signed manifests compared byte-identically. No authoritative SoR or Accepted writes, no changed P3/F3 COPY or SQL transaction shape. Private PostgreSQL stopped cleanly.

## Measured W3–W4 performance

Previous working SHA-once run `/var/tmp/fi-window-chunks-once2-20261111T204054Z` versus corrected SHA-once + JSON-once run `/var/tmp/fi-window-chunks-jonce2-20261112T013718Z`:

| W3+W4 metric | SHA-once control | Corrected JSON-once | Delta |
|---|---:|---:|---:|
| Committed duration | **102.534s** | **89.931s** | -12.603s (**12.29%**) |
| Throughput | 2,527.7 rows/s | 2,881.9 rows/s | +14.0% |
| Batch ingestion | 82.0815s | 77.1552s | -4.9263s |
| Envelope preparation | 22.3177s | 20.7354s | -1.5823s |
| Security preparation (separate) | 0.0931s | 0.0924s | ~unchanged |
| File + Security projection | 38.4999s | 35.8189s | -2.6810s |
| Full-batch hash | 0s | 0s | unchanged |
| Security single-pass rows | 232,879 | 232,879 | unchanged |

Overlapping/nested profiling stages MUST NOT be added. Verification and PostgreSQL timings varied across runs; therefore the entire 12.603s improvement cannot be causally assigned solely to JSON traversal removal. Microbenchmark evidence from previous on-host run showed one-pass canonical Security preparation around 172–174 µs versus older two-pass baseline around 225–240 µs for the sampled fixture, but those samples do not replace real workload timing.

The historical accepted H16 ten-window throughput reference remains **2,731.3 rows/s over 475.149s** on W3–W12. The SHA-once-only 10-window run was **518.094s / 2,504.9 rows/s**. This correct JSON-once branch has **NOT** yet been evaluated over W3–W12.

## Engineering decision

Retain SHA-once plus strict Security JSON-once candidate at this frozen development reference. Do **not** restore wasted full-batch hashing; do **not** reintroduce a structural JSON scanner. Run an equivalent full real-signed W3–W12 replay before claiming sustained throughput. After that, optimize independently the Security event/field COPY path (current combined W3–W4 event-copy about 9.755s and field-copy about 9.386s), preserving per-record and raw-XML evidence SHA, bounded COPY and 10-minute-window SQL durability.

No database parameters, data model, Windows sender, SoR, or main branch changes are authorized by this result alone.
