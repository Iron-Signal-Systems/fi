# Windows FI v2 — Read-Only Native System Parent Identity Evidence

**Branch:** `dev/windows-volume-first-20261108`  
**Engineering status:** Native read-only Windows identity observations and fail-closed policies/tests. **NOT a trusted installer issuer, protected state commitment, elevation token, approved bootstrap or deployment authorization.**

## Why this component exists

The private `freshinstall.reserveProtectedBootstrap` code previously accepted an arbitrary supplied local parent directory. A child created *relative to a handle* is bound to that handle's object, but that **does not establish the handle originally referred to the authorized Windows system ProgramData directory**.

`go/internal/windows/freshinstall/system_parent_policy.go` and `system_parent_windows.go` now supply a **read-only evidence-gathering step** for that missing boundary. Nothing in `fi-install`, any Windows service, or the bootstrap mutation code calls this observer as an authorization gate. It does not create, modify, reconfigure, delete or adopt an FI artifact.

## Windows-native origin and identity checks

The native observer `inspectNativeSystemProgramData`:

1. Uses `windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)` and `windows.GetSystemWindowsDirectory()`, **not** `%ProgramData%`, `%SystemDrive%` or user-supplied paths. The known-folder query uses no create flag and has no write side effects.
2. Requires canonical, absolute local drive paths; common ProgramData must be exactly a **direct `ProgramData` child** of the volume root containing the shared Windows directory. UNC/device aliases, relative and traversal paths, mixed drives, nested/redirected ProgramData, unexpected leaf names and noncanonical forms fail closed. This is a deliberately narrow development policy and not a universal Windows configuration claim.
3. Queries `GetVolumeInformationW` and requires **NTFS** on the system volume. This is the filesystem prerequisite for the intended FI Windows source; it is not proof of trusted system installation.
4. Opens and retains **read-only** native handles for the root, shared Windows directory and common ProgramData directory. Each uses `FILE_FLAG_OPEN_REPARSE_POINT` and rejects a reparse point or unexpected file type.
5. Uses `GetFileInformationByHandleEx(FileIdInfo)` to preserve the complete **64-bit volume serial** and **128-bit directory file ID**. All three must be on the same volume and have distinct, nonzero directory identities.
6. Confirms the resolved native ProgramData and Windows directory paths are direct children of the original retained system root object. No bare path string is substituted for identity.

`nativeSystemParentInspection.verifyRetained()` re-queries both Windows APIs and NTFS status, re-reads the original handles' file IDs and native names, and **independently reopens** each original path to compare its full-width identity to the held object. Its native test in a **disposable directory** deliberately renames and replaces a directory while retaining the original handle, then confirms that the old path is rejected.

All handles are closed by `Close`. Neither a successful observation nor a test fixture becomes an installation grant.

## Negative tests and validation limitations

Pure policy tests reject mismatched drives, redirected paths, aliases, traversal, missing/duplicate/zero IDs and full-width serial mismatches. Windows-only tests inspect the runner's actual OS directory identities **read-only**, verify repeated observations, reject altered observations, and exercise actual directory rename/replacement in disposable test locations.

The GitHub runner is **not the privileged `adminbox` acceptance host**. These tests do not grant trust to the OS known-folder registry value, system volume provenance, root/ProgramData ancestor owner/DACL, an interactive administrator token or a signed installer grant. In particular, an administrator or SYSTEM that can alter both the known-folder mapping and objects can defeat read-only consistency tests.

## Unresolved trust and mutation handoff

The private `reserveProtectedBootstrap(parentPath)` still accepts an arbitrary caller path and **is not connected to this read-only observer**. Connecting them merely by comparing strings would recreate a TOCTOU or issuer-trust gap. A future authorized installer must use trusted system-root provenance, independently verified owner/DACL and token/issuer/consent state, then create children relative to the exact retained and authenticated handle under a complete write-ahead creation transaction.

No independent cryptographic installed-grant commitment, disabled-service creation, recovery and restart acceptance, or tested native Windows Server token authorization exists. **A05 remains P0/open; V14/V16 remain NOT RUN. ISS-FS-22A removal and reinstall remain NO-GO.**


## Root and ProgramData owner/DACL exposure observation — 2026-11-11

The branch now has `system_parent_acl_policy.go` and `system_parent_acl_windows.go` for **read-only** root/common ProgramData owner/DACL checks through the same native retained handles. The conservative policy blocks unknown ACE semantics or potentially unprivileged create/write/delete/owner rights, including `INHERIT_ONLY` grants. Normal ProgramData ACLs can be classified as **BLOCKED**; no ACL repair is authorized. This is **not** a real-token AccessCheck or verified system issuer, and it is not wired to installer apply. See [System Parent ACL Audit](WINDOWS-VOLUME-FIRST-SYSTEM-PARENT-ACL.md).

**2026-11-11 read-only AccessCheck observation:** The native system-parent observer now has a separate AccessCheck diagnostic using the retained ProgramData directory handle and a short-lived query-only Windows check token. It verifies exact requested rights and rechecks descriptor and native file identities. It cannot prove trusted system-directory issuer, operator consent or an atomic observe-to-create transaction. See `WINDOWS-VOLUME-FIRST-INSTALLER-PARENT-ACCESS.md`.


## RootDirectory-based ProgramData identity cross-check — 2026-11-11

The branch now has a **read-only** `openNativeProgramDataFromRoot` observer. It calls `NtCreateFile(FILE_OPEN)` with the native `OBJECT_ATTRIBUTES.RootDirectory` set to the **already retained system-volume root handle** and a fixed, single-component leaf `ProgramData`. It explicitly requests read-only attributes/control; neither `FILE_CREATE` nor `FILE_OPEN_IF` is allowed. `FILE_OPEN_REPARSE_POINT` and native directory/reparse-type checks block a substituted junction or symbolic link. The opened directory's full-width `FILE_ID_INFO`, native direct-child relationship and resolved path must match the separately retained OS-known-folder `ProgramData` observation. Root, Windows and ProgramData original observations are revalidated before/after the independent open.

Windows tests inspect the runner's actual system directories **without mutation**, and use disposable roots to demonstrate that RootDirectory follows the original retained root even after its old path has been renamed and replaced. Missing/closed root handles, absent ProgramData leaf and reparse substitutions fail closed. This **does not** open a create-capable ProgramData handle, create FI-Installer, authenticate a compromised system root, grant a signer or establish a trusted pre-bootstrap write-ahead transaction. A05 remains P0/open; V14/V16 are NOT RUN.
