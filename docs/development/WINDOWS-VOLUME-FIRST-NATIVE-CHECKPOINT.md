# Windows Volume-First — Isolated Checkpoint Lease and Persistent CAS

**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Native Windows checkpoint I/O with cross-process file lease and test-only onboarding fixtures. Not an approved installed state store, authenticated service, or installer.

## Implemented development component

`go/internal/windows/volumecustody/state_windows.go` adds `WindowsVolumeState`, an isolated Windows implementation of the `LeaseProvider` and `CheckpointStore` interfaces used by `ProcessOneWindow`. The object takes an **already existing, absolute state directory** from a trusted future caller; it does not create the directory, initialize an enrollment, reset a missing checkpoint, adopt previous FI state or remove interrupted work.

For each canonical enrollment ID, `Acquire` opens a dedicated existing/created lease file in that directory and takes a nonblocking exclusive Windows `LockFileEx` byte-range lock. It also checks for same-instance lock reuse. Its `Release` unlocks and closes the handle. Both `Load` and `Commit` require the same instance to hold that lease. This is process-level serialization, **not the privileged-grant or ACL boundary**. Only the installed v2 collector should ever own this state once installer trust exists.

`Load` reads a bounded (4096-byte maximum), plain, strict-JSON checkpoint, rejects trailing/unknown data, validates every identity, epoch, serial, journal ID and canonical cursor through `volumeepoch.ValidateCheckpoint`, and refuses absent/corrupt evidence. No automatic baseline or discontinuity repair is performed.

`Commit` checks the complete persisted state equals the expected checkpoint and that a proposed cursor strictly advances within the same enrollment, epoch and volume/journal identity. It requires that no previous `.checkpoint.pending` file remains. It exclusively creates that pending file, flushes and closes it, and requests Windows `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH` to replace the checkpoint. **Any error after pending creation is treated as potentially in doubt:** no automatic cleanup, reset or retry occurs. Source custody, current journal continuity and lease ownership are controlled by the separate one-window coordinator; the native store is never source-read authorization.

## Security and durability limitations (deployment blockers)

- **Not yet protected:** the parent directory and ancestor chain are not created or attested by a trusted native v2 installer. Owner, DACL, reparse ancestry, service-SID/gMSA access, hostile file substitution and final native object identity need separate privileged acceptance. A plain non-symlink final directory is insufficient for the installation trust boundary.
- **No independent trusted generation anchor:** this checkpoint is runtime mutable source state, not an installed grant or a signed receipt. It must never authorize raw-volume acquisition without verifying the independently committed protected grant.
- **Not crash/power-loss qualified:** a flushed pending file plus `MOVEFILE_WRITE_THROUGH` reduces incomplete-writing exposure but does not prove device flush semantics, filesystem transaction atomicity under malicious interference, or safe recovery after a crash. If a pending file or ambiguous source publication is found, hold and investigate rather than deleting it automatically.
- **No automatic baseline creation:** the tests create an isolated fixture checkpoint explicitly. Production v2 enrollment, initial epoch, discontinuity/new baseline and existing-instance disposition must have separate signed/verified workflows.
- **No service integration:** the current FICollector, FIUSNReader, backend projector, transport, enrollment-grant and fresh-only installer remain root-centric/unwired. There is no `adminbox` qualified native test or ISS-FS-22A change.

## Test scope

Windows unit tests exercise cross-instance lease exclusion, serialized load/commit, durable re-read under a fresh lease, stale and regressing cursor rejection, epoch/journal changes, malformed or oversized checkpoint rejection, refusal of interrupted `.checkpoint.pending` evidence, absent pre-provisioned directory, and the existing real FI spool publisher plus `ProcessOneWindow` in one isolated bounded pass.

These tests can validate the executable I/O shape on a GitHub Windows runner, but do **not** satisfy V03, V07, V08, V14 or the native end-to-end `adminbox` acceptance requirements. Audit A03 stays open and the ISS-FS-22A removal/reinstall decision remains **NO-GO**.
