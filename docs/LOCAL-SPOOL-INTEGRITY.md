# FI Local Spool Integrity Boundary

Phase 1 local spool manifests record the finalized data file's record count, byte
count, and SHA-256 and FI verifies the manifest/data pair before accepting an
applicable local checkpoint boundary.

This provides useful **local integrity and corruption detection**. It does not by
itself provide cryptographic authenticity against an attacker who can modify both
the spool data and its manifest, because such an attacker could recompute an
ordinary SHA-256 digest.

Phase 1 therefore treats the manifest hash as a local durable-queue integrity
check, not as a signature or MAC.

Phase 2 authenticated transport and later recorder/custody controls own stronger
authenticity, replay/duplicate, acknowledgement, and downstream custody
properties.

## Publication ownership boundary

A spool batch remains producer-private while its publication artifacts are
temporary/unpublished.

The producer must finalize the data file, construct the manifest, and verify
count, byte size, and SHA-256 while the pair remains producer-private.

Publication of the final manifest is the ownership handoff that makes the batch
discoverable to Phase 2 transport.

After publication, producer correctness must not depend on reopening the
published pair. A sender may already have discovered the pair and, after the
Gate 2 durable acknowledgement contract is satisfied, may own retirement of the
acknowledged local copy.

This prevents producer correctness from racing transport discovery and
retirement.
