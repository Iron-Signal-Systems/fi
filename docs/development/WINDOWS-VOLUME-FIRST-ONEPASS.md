# FI Windows Volume-First — One-Window Custody Coordinator

**Development branch:** `dev/windows-volume-first-20261108`  
**Status:** Isolated coordinator, concrete one-batch FI spool publisher, and fault-injection/file tests. Not an active FICollector worker, not a native USN broker client, and not a durable Windows checkpoint backend. ISS-FS-22A reinstall remains **NO-GO**.

## Exact boundary

`go/internal/windows/volumecustody/onepass.go` adds `ProcessOneWindow`, which coordinates one **already initialized, continuous** enrolled-volume epoch using narrowly defined dependencies. The sequence is:

1. Reject invalid enrollment IDs, canceled contexts or missing dependencies *before* acquiring any lease.
2. Acquire a required per-enrollment exclusive lease. The future runtime must provide a real cross-process lease covering the complete pass.
3. Load the currently saved volume-owned checkpoint, independently query native journal identity, and use `volumeepoch.Assess` to reject malformed state, changed journals, changed volumes, aged-out history and missing initial baselines *before* a bounded read.
4. Request no more than **4096** minimal change records from the selected enrollment ID, starting at the saved `NextUSN`. Revalidate the bounded window, identity, source facts and terminal boundary.
5. Freeze a defensive snapshot of returned native facts. Request complete publication of the window as **one** FI spool batch. A partial write, missing manifest or publication error does not grant cursor advancement. Publication attempts and any returned manifest paths remain recorded, because the physical outcome may be in doubt.
6. Query the same journal again after publication, verify the actual published batch/manifest bytes against the unchanged captured window, and propose only an in-memory candidate cursor. The concrete `OneBatchSpoolPublisher` now publishes through `spool.Writer` and independently verifies the completed manifest/data pair. It refuses a spool rollover before the required terminal boundary.
7. Re-read the checkpoint; reject changed state. Call the store's **required atomic compare-and-swap** against the complete previous checkpoint. Mark the returned result `CommitAttempted=true` before invoking this operation; if it returns an error, the durable outcome is **in doubt** and must be inspected at restart before reattempting.
8. Release the lease. A release failure is not allowed to conceal a successful checkpoint commit.

The result fields `PublicationAttempted`, `Published`, `ManifestPath`, `Candidate`, `CommitAttempted`, and `CheckpointCommitted` deliberately distinguish observed publication evidence, proposed cursor, attempted state mutation, and confirmed commit. A `Published=true` source window does **not** justify source-data deletion, even when the cursor remains unchanged. Neither error path deletes spool pairs or resets an NTFS journal.

## Trust boundaries not yet implemented

`LeaseProvider`, `NativeWindowSource` and `CheckpointStore` are interfaces, **not implementations of Windows authorization**. `WindowPublisher` also has a concrete `OneBatchSpoolPublisher` implementation using the existing FI spool writer; this concrete implementation is not an installed source trust boundary. Their contracts require, respectively: an exclusive cross-process enrolled-volume lease, authenticated installed-grant-bound native reads without arbitrary device paths, complete durable one-batch publication with exact terminal boundary, and a protected persistence backend with full-checkpoint atomic CAS. The current coordinator cannot establish that an injected implementation fulfills those contracts.

A fabricated source can still omit records, a separately injected publisher can misreport durability, and an unprotected checkpoint store can lie about persistence. The concrete spool publisher does not prove native installed ACLs, lifetime protection from spool rollover or hardware power-loss durability. A protected runtime must revalidate the installed grant and native same-handle volume identity before authorizing these operations. The published spool lifetime/rollover lock, interrupted publication recovery, source-independent cursor proof, multi-batch window transaction protocol, baseline onboarding and post-crash checkpoint reconciliation remain missing.

In particular, **there is NO service startup wiring, no fi-usn pipe consumption, no native gMSA checks, no real durable v2 checkpoint store and no backend acceptance**. This code must not be exposed as a production CLI entry point or passed a permit derived solely from a v2 configuration text file.

## Tests and evidence

`onepass_test.go` uses the actual FI `spool.Writer` and manifest verification in disposable directories. Fault-injected dependencies cover the required operation sequence, pre-read discontinuity, missing or corrupt checkpoint, reader/publication/journal re-query failures, mutated publisher source facts, altered post-publication identity, changed checkpoint, failed or ambiguous CAS, returned manifest retention, early/context-in-flight cancellation, lease-release errors and independence of two enrolled volumes. These do not substitute for native `adminbox` testing, real power-loss recovery or Windows service authorization.

GitHub Actions on the final exact branch commit must pass before classifying these tests as validated. The source-level work advances finding A03 but does **not close** any P0 audit finding or any V01–V20 acceptance case.

**Do not remove FI from ISS-FS-22A.** Do not re-enable legacy installer apply or start FISender.

## Concrete one-batch publication (2026-11-09)

`OneBatchSpoolPublisher` publishes the entire bounded window as FI spool source facts followed by exactly one terminal boundary. It uses the existing `spool.Writer`, detects premature finalized batches, requires exactly one complete batch, and independently verifies the published manifest/data pair. The initial shape-check uses a synthesized journal solely to validate source record structure; it is **not native journal attestation**. The real coordinator independently requests actual journal identity before and after publishing.

If appending or finalizing fails, `spool.Writer.AbandonUnpublished` closes an unfinished file **without finalizing or deleting it**. Previously published pairs are never removed by that method. Byte-based or configured-policy rollover can still split a source window: this is **a refusal and in-doubt custody case**, not permission to advance a checkpoint. The publication/result contract preserves the attempted/observed distinctions for recovery.

Tests use temporary real FI spool artifacts for successful and empty windows, malformed inputs, cancellation, invalid executable identity, incomplete-work abandonment, preservation of already published evidence, and one-window coordination using the concrete publisher. There is still no authorized native source reader, durable v2 checkpoint backend, installed spool lock, production installer or backend integration.
