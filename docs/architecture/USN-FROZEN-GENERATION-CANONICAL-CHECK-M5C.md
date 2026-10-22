# M5C: frozen source versus canonical generation descriptor (inactive)

M5C provides `usncapture.VerifyFrozenSourceCanonical` as a **read-only**
verification step at the sender's frozen-raw → sealed-generation boundary.
It checks the immutable M5B source-manifest inventory, independently verifies
its original manifest/data pairs inside a real frozen raw directory, and streams
all sorted raw artifacts into the exact `fi-generation-canonical/0.1` framing to
compare SHA-256, canonical byte count, original byte count, and file count
against the caller-provided canonical generation descriptor facts. It binds
identity to the raw generation directory.

This is NOT by itself a sealed-generation inclusion or durable acknowledgement
proof. Caller-supplied descriptor fields must separately be authenticated
against the signed generation and its encoded payload must be independently
verified, including the compressed-to-canonical correspondence. The frozen
source can disappear before inspection unless sender coordination prevents
removal. No checkpoint may advance from this result. No existing sender,
collector, configuration, or generation format is changed by this milestone.

Next: an authoritative sender-driven handoff that validates the signed
sealed payload against the canonical source while raw custody exists; durable
proof prior to raw removal; and acknowledgement/retirement linkage that can be
replayed after crashes. Keep FI's new capture processing pipeline inactive.
