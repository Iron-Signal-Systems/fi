# Volume-First Read-Only Native Discovery and Installer Preflight

**Date:** 2026-11-08  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Implemented as a branch-only read-only engineering operation. NOT volume-first runtime installation, enrollment authority, or acceptance on `adminbox`.

## What is implemented

`go/internal/windows/volumediscovery/` enumerates local Windows volume GUIDs through `FindFirstVolumeW` / `FindNextVolumeW`. It does not require a drive letter and includes volume-GUID-only and directory-mount configurations in the inventory. `GetVolumePathNamesForVolumeNameW` reports mount/drive aliases as **informational only**. Each accessible NTFS volume root is opened for `FILE_READ_ATTRIBUTES` only, and `GetFileInformationByHandleEx(FileIdInfo)` supplies the full 64-bit NTFS volume serial. Filesystem identity is checked with `GetVolumeInformationW`. Missing/inaccessible/non-NTFS volumes produce distinct `Unavailable` or `Unsupported` outcomes rather than falsely appearing eligible.

`go/internal/windows/volumediscovery/plan.go` compares an explicitly declared volume set against current native discoveries. The result distinguishes `IdentityMatched`, `NotDiscovered`, `NotEligible`, and `IdentityChanged`. Newly discovered volumes remain **unenrolled**. Identity must match the declared volume GUID **and** the full-width `FILE_ID_INFO` volume serial; a 32-bit `fsutil volumeinfo` serial is not a substitute. Duplicate/malformed native snapshots fail validation.

## Operator command in branch-built `fi-install.exe`

The native installer has two **stand-alone, read-only** forms:

```powershell
.\fi-install.exe -list-volumes

.\fi-install.exe -list-volumes -volume-config C:\FI-Dev\volume-v2.conf
```

The optional file is a strict `version_id: 2.0` **scope-only** declaration as described in `WINDOWS-VOLUME-FIRST-CONFIGURATION.md`. It must be a regular file no larger than 1 MiB; unsupported syntax or old `1.1` configuration fails before native enumeration. The report is versioned JSON with:

- `action = DiscoveryOnly` or `DiscoveryAndScopePreflightOnly`;
- `collection_authorized = false` in **every** case;
- native volume GUID, filesystem, full-width serial when available, status, mount paths and informational errors;
- when given a scope, normalized configuration SHA-256 and per-volume match results including unrequested volumes.

A mismatched declared volume produces a JSON diagnostic with `all_volumes_match = false` **and nonzero exit status**. Failure to read/validate the declaration or discover volumes also returns nonzero; it must not be mistaken for successful enrollment.

These commands are dispatched **before** the original installer's SACL recovery, release-trust prompts, AD/PKI discovery, service-control, or mutations. Inventory mode rejects all ordinary installer flags, including an explicitly supplied `-apply=false` and `-plan-only`. A lone `-volume-config` is rejected; it cannot accidentally fall through to the default `-apply=true` operation.

The original `fi-install.exe` apply/plan/install/reconcile flow remains root-centric. The volume-first configuration is not activated by writing this file or running the read-only comparison.

## Security and correctness boundaries

1. Native volume enumeration is discovery, **not authorization**. The privileged USN broker cannot currently open volumes based on this report.
2. A matching GUID and serial at discovery time do not authorize journal acquisition, content reads or SACL expansion. Fresh native handle identity, explicit administrator approval, root policy authorization and rollback checks remain work for the actual installer.
3. Mount paths and names are aliases; they cannot determine the authenticated volume or current object identity.
4. An inaccessible, unsupported, changed or absent enrolled volume blocks the whole requested preflight. Unrequested extra volumes do **not** get enrolled automatically.
5. No customer content is read; no USN journal is queried; no audit policy, ACL, service or FI state is changed.
6. The `ISS-FS-22A` FISender stays stopped and no existing host is modified by branch work.

## New proposed-scope review fields (read-only only)

With `-volume-config`, JSON now additionally contains `requested_scope_review` with `version`, `requested_config_sha256`, `review_fingerprint_sha256`, `changes`, `native_identities`, `blocks_mutation`, and `requires_explicit_approval`. An ordinary first-time v2 scope comparison has no trusted existing v2 baseline, so **every proposed enrollment and policy is reported as an addition**. A matching review is not an approval receipt and never enables USN access.

See `docs/development/WINDOWS-VOLUME-FIRST-SCOPE-REVIEW.md`.



- Deterministic pure-Go tests cover explicit matching, extra volumes, missing/reformatted/offline volumes, unsupported filesystems, duplicate/malformed sources, and unsafe declarations.
- Windows-only tests exercise native GUID enumeration, mount-path MULTI_SZ handling and early cancellation on the GitHub Windows runner. A failure caused by an embedded-NUL test fixture was corrected without weakening the test.
- Installer tests cover stand-alone flag conflicts, non-mutating JSON output, configuration parsing bounds, precise drift failure and output failures.
- GitHub Windows-latest is not a supported exact Server 2016/2019/2022/2025 validation campaign. `adminbox` native validation is still required.
- Current discovery is a preflight snapshot, **not** a persisted permission or proof of continuity after reformat. A separately implemented, not activated USN broker mode now validates full-width native serials on the raw-volume handle before journal operations; this still requires installer approval wiring and native adminbox tests.

## Next integration boundary

The branch now contains a separate path-free FIUSNReader enrollment-ID protocol and read-only native USN backend, with same-handle 64-bit identity validation; see `WINDOWS-VOLUME-FIRST-USN-BROKER.md`. Those operations remain **inactive** in the installed helper. The next boundary is full installer v2 approval/configuration authority and safe service-startup selection, followed by FICollector per-volume scheduling, checkpoint/custody, policy-scoped FIObjReader/SACL access, and signed records/backend integration. Do not treat a successful scope preflight as authorization to run privileged operations.

See `docs/architecture/ADR-0002-WINDOWS-VOLUME-FIRST.md`, `docs/development/WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md`, and `docs/development/WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md`.
