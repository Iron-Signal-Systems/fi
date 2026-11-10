# FI Volume-First — Bounded Spool Custody and USN Cursor Proposal

**Development branch:** `dev/windows-volume-first-20261108`  
**Status:** Verification-only spool-file and one-window coordination components with real published-spool tests and injected native/state/lease interfaces. **NOT wired to the FICollector service, native USN reader, protected checkpoint persistence or backend.**

## Purpose and source-truth boundaries

`go/internal/windows/volumecustody` adds an initial bounded USN source record contract and a verifier for **one already published spool batch**. Its only successful output is an **in-memory proposed `volumeepoch.Checkpoint`**; it cannot update on-disk state, move an NTFS journal cursor, authorize FIObjReader, or trigger FISender.

Each captured window uses the exact enrolled volume ID, epoch, 64-bit NTFS serial, journal ID, and canonical from/next USN. It contains up to **4096** `VolumeUSNMinimalChangeV2` records plus one **terminal** `VolumeUSNReadBoundaryV2`. The terminal boundary lists the claimed source record count and exact cursor bounds. Even a zero-change interval must have its own published boundary. The proposed cursor must strictly advance from the saved checkpoint, remain at or below the current observed journal next USN, and retain the same epoch. A journal recreation, changed/replaced volume, aged-out cursor, wrong bound, wrong count, or unexpected source type fails before any spool evidence is accepted.

Each minimal fact preserves the native USN record version (2 or 3), USN, file and parent reference bytes rendered in the **original native width** (16 or 32 hex digits), and raw reason flags. It intentionally does **not** carry user attribution, inferred full path, content, hash, SACL or guessed historical policy membership. A 64-bit USN V2 reference is **not** declared equivalent to a 128-bit `FILE_ID_INFO` reference.

## Published evidence verification

`ProposeAfterPublishedWindow` resolves the configured absolute spool directory through the **existing `spool.PhysicalSpoolDir` API**, matching the spool writer's physical path (including supported Windows path aliases/junctions), and requires the manifest to be a plain regular file **directly inside that resolved active physical directory**. It refuses a sibling, work directory or foreign spool. It invokes the existing `spool.VerifyManifest`, which verifies the data file hash, file size and count, then validates the exact record kind, scope `volume:<enrollment>`, typed payloads, fact order and final boundary. It refuses any missing, repeated, foreign, malformed, incomplete, surplus or changed source facts and performs a second full manifest/data verification before returning the candidate.

The proposal is **not a custody trust token**. The expected window is supplied by a future caller, and this package cannot prove that the Windows reader collected all available NTFS records. Nor can it prove protected spool ACLs, resist all concurrent file substitution, acquire the published spool retirement lock, or atomically compare-and-swap a persisted checkpoint. The runtime must authenticate the grant, bind the actual native USN reader, retain exclusive per-volume ownership and spool lifetime protection, and verify continuity and on-disk checkpoint state again before committing any cursor.

A source batch larger than one spool batch is intentionally **not** accepted by this initial verifier; it must not advance on an incomplete multi-batch transfer. Multi-batch/source generation durability requires an explicit pass-commit protocol and proper receiver/source transaction boundaries before enabling the live worker.

## Test and acceptance classification

Tests in `verify_test.go` use the real published `spool.Writer` and `spool.VerifyManifest` in disposable directories, exercising a normal window, empty window, USN V2/V3 widths, identity/cursor/journal drift, malformed facts, wrong scope/family/count, missing manifest, alternate spool directory, Windows case-distinct configured spool aliases and corrupted published bytes. This is source-level file I/O; **it is not native Windows `adminbox` acceptance**, fails to prove crash/power-loss durability, and does not satisfy validation rows V03, V05, V07, V08 or V17.

Next step: implement an **authorized** native enrolled-volume reader into a guarded per-volume worker; produce these exact minimal facts and a bounded boundary, durably publish a complete pass using a safe retry/abort protocol, and atomically guard checkpoint persistence. The backend must explicitly understand and preserve the new source version before any operational capture is enabled.

**Deployment hold remains in force for ISS-FS-22A.**

## One-window coordination (2026-11-09)

`ProcessOneWindow` now orchestrates an **injected**, per-enrollment lease, checkpoint load, pre-read native journal query and continuity assessment, bounded native read, immutable expected-fact snapshot, publisher call, post-publication journal query, actual spool verification, saved checkpoint re-read and required atomic-CAS callback. It never implicitly opens NTFS devices, starts a service, creates an epoch or persists a checkpoint itself. Both ambiguous publication and checkpoint commit attempts are reported without deleting spool data. An injected native source, lease, publisher and store remain **untrusted external implementations** unless separately authorized and accepted.

See [one-window custody coordinator contract](WINDOWS-VOLUME-FIRST-ONEPASS.md). No V01–V20 case is promoted from NOT RUN.
