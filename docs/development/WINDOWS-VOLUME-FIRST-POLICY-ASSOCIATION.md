# Windows Volume-First Governed-Root Policy Association

**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Pure-Go membership decision and negative tests implemented; no native lineage resolver, FICollector wiring, privileged object authorization, or Windows acceptance.

## Purpose and limits

The new `go/internal/windows/policyassociation` package associates a *single already acquired* volume-scoped object observation with zero or more governed-root policies. It does **not** collect another USN stream, infer actor identity, resolve a file path, read ACL/content, create a privileged service token, or authorize FIObjReader. Its results describe observed policy membership, not permissions.

A host-wide `NewPlan` requires exact native bindings for every policy. `NewVolumePlan` instead validates the same approved scope but builds an isolated plan for one explicitly enrolled volume; a missing or offline root on another volume cannot stall that healthy volume. A missing binding **on the selected volume** still fails closed. A per-volume plan rejects observations and binding IDs belonging to any other volume.

The separate Windows-only `policyroot.AttestEnrolledVolumeRoots` now provides a **read-only, point-in-time** native directory ID observation for each governed root, including ancestor reparse refusal and same-volume serial checks. This is not a historical lineage resolver, production root authorization or installed-grant authentication. See `WINDOWS-VOLUME-FIRST-NATIVE-POLICY-ROOT.md`.

The caller supplies a canonical approved `config.VolumeConfig` and one independently verified NTFS file identity per configured governed root. `NewPlan` refuses missing, repeated, unknown, zero, cross-volume, or native-aliased root identities. A volume with no governed roots is valid. All bindings and depths are copied into an immutable read-only plan; configuration changes cannot implicitly widen the plan.

`Evaluate` requires the exact enrolled volume GUID and full-width serial and an NTFS object identity. For a governed volume, it uses an already verified object-to-parent lineage (128-bit file IDs), **not string path prefixes**. The result is `Matched` with a deterministic, sorted list of policy-specific memberships, `Outside` only for a complete verified non-matching lineage (or a volume with no policies), or `Unknown` when the lineage is incomplete or crosses a reparse boundary. Duplicate/cyclic/zero or oversized ancestry is rejected. Overlapping policies stay distinct; no automatic promotion from `metadata` to `security` or `content` is performed.

## Unimplemented trust-critical components

The package deliberately cannot assert that a caller's `Complete` flag is truthful. The new read-only native observer can obtain a point-in-time root directory identity, but runtime must still bind that observation to authenticated installed authority, resolve object parent links on the *enrolled volume*, account for multiple hard links, NTFS delete/rename history, and stop at reparse/mounted-volume boundaries. USN v2 64-bit IDs must be explicitly reconciled against 128-bit FILE_ID_INFO identities; padding/truncation or comparing textual paths is not an accepted substitute.

Current NTFS ancestry is **not historical ancestry**. A later rename or hard-link resolution cannot be projected backward onto an earlier USN record. If the source cannot prove containment at the relevant observation time, retain minimal change evidence and `Unknown` policy membership. Even a proven `Matched` result cannot authorize an object read; a separate exact-handle FIObjReader authorization and policy-depth check remain required.

## Evidence and acceptance

Source unit tests exercise multiple volumes, zero policies, overlap, root-self matching, outside vs unknown, reparse and incomplete lineage denial, malformed/cyclic ancestry, alias/cross-volume binding rejection, serial/GUID drift and input mutation. These are pure policy tests, not Windows-native lineage, journal custody or installer acceptance.

Next required engineering: installer-bound native root-object approval and runtime re-attestation; runtime path/link evidence with precise time semantics; per-volume capture + checkpoint durability; and source records plus backend typed policy projection. Rows V04-V06, V11, V17-V19 remain **NOT RUN**. Nothing starts FIUSNReader volume mode or changes `main`, `adminbox` services, ISS-FS-22A, or FISender.
