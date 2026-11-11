# Windows FI v2 — Protected Installer Journal Parent

**Development branch:** `dev/windows-volume-first-20261108`  
**Native acceptance host:** `adminbox`  
**Status:** The private native journal writer checks parent owner/protected DACL before `CREATE_NEW` and child-file inherited owner/DACL before acknowledging a reservation. A separate **package-private Windows protected `FI-Installer` creation experiment now exists**, but an authorized parent issuer/ancestor chain, production bootstrap orchestration, installer CLI integration and privileged acceptance remain **NOT IMPLEMENTED / NOT RUN**.

## Why this boundary exists

A fresh FI v2 installation cannot place its first write-ahead journal under the not-yet-created `C:\ProgramData\FI` source directory. It needs an independently protected installer transaction location **before** any FI program/configuration/service mutation. The proposed separate root is `C:\ProgramData\FI-Installer`. It is *installer custody*, not FICollector's runtime state.

The `freshinstall` read-only collision check now checks **eight** artifacts: the five existing FI service names and three fixed FI-owned paths (`C:\Program Files\FI`, `C:\ProgramData\FI`, `C:\ProgramData\FI-Installer`). Any presence or uncertain observation blocks a new install. A later attempt must not silently reuse an incomplete journal. An operator must separately determine and approve the disposition of prior development evidence.

This does not support in-place upgrades or migration; the v2 path remains strictly first-install-only.

## Exact parent ACL contract

`go/internal/windows/freshinstall/journal_parent_policy.go` defines a deliberately narrow DACL decision. The parent security descriptor must have:

- **Owner:** exactly Local SYSTEM (`S-1-5-18`) or BUILTIN Administrators (`S-1-5-32-544`). No arbitrary local/domain identity and no defaulted owner.
- **DACL:** present, non-null, explicitly **protected from inheritance** (`SE_DACL_PROTECTED`), and not defaulted.
- **ACEs:** exactly two explicit access-allowed entries, one for SYSTEM and one for BUILTIN Administrators, each granting Windows `FILE_ALL_ACCESS` (`0x001F01FF`) with `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` (`0x03`). ACE order is immaterial.
- **No other entries:** no Everyone, Authenticated Users, Users, Creator Owner, domain accounts, extra ACEs, deny ACEs, unknown/callback ACEs, inherited ACEs, alternate flags or unexpanded generic access masks.

For documentation only, the intended parent descriptor is equivalent to:

```text
O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)
```

An equivalent protected descriptor owned by BUILTIN Administrators is allowed by the policy. These are design encodings, **not** directions to change an existing server's DACL.

The policy requires inheritable full control for SYSTEM and Administrators because the subsequent journal must not inherit rights from any less trusted identity. This strict policy may reject otherwise-functional folders, including a normally inherited temporary directory. That is the intended fail-closed behavior.

## Native inspection boundary

`go/internal/windows/freshinstall/journal_parent_security_windows.go` reads the owner and DACL from an already-opened **Windows directory handle** with `GetSecurityInfo`, not by a second named-path lookup. It validates a non-null security descriptor, extracts its owner, defaulting/protection flags and bounded ACE list, then delegates authorization to the strict pure policy. Ordinary directories with additional ACEs can be *inspected*, but are never accepted by that policy.

The native journal writer retains the parent directory handle and compares its resolved identity to the new journal's handle. **The default private constructor now calls `verifyJournalParentHandle` on that retained parent BEFORE `CREATE_NEW`.** It checks the file's native owner/DACL through the newly created file handle before reporting reservation success. An unacceptable child file remains **in doubt** because creation has already occurred; no automatic cleanup or retry is permitted. Neither check authenticates installer issuer, protected-parent creation or ancestor provenance, and the writer is not wired to the installer CLI.

There is no production API accepting an arbitrary user-supplied path and elevating it to FI installation authority.

## New protected bootstrap child creation experiment

`freshinstall/bootstrap_windows.go` now has a separate **private** create-only `FI-Installer` child reservation. It retains parent/child native directory handles, uses the exact protected SYSTEM/Administrators descriptor in a native parent-handle-relative `NtCreateFile(FILE_CREATE)` call, refuses a preexisting child, verifies the resulting child handle's owner/DACL, and never deletes an in-doubt directory. This is a code-level native primitive, **not an installer entry point or trusted system-parent attestation**. The operator approval and installed-grant transaction are not connected. See [bootstrap experiment contract](WINDOWS-VOLUME-FIRST-PROTECTED-BOOTSTRAP.md).

## New journal FILE effective-DACL contract

`journal_file_policy.go` requires the newly created file's actual owner to be SYSTEM or BUILTIN Administrators, and exactly two **inherited**, full-control, access-allowed ACEs (SYSTEM and Administrators) with no additional trustees, generic masks, deny ACEs or unexpected flags. The file itself must have a present, non-defaulted DACL. `journal_file_security_windows.go` obtains the descriptor from the **same newly created handle**, after checking file type and retained-parent identity. A mismatch is a **failed/in-doubt creation**, never a reason to delete, retry or silently repair security after creation. The future privileged installer must arrange acceptable file ownership at creation time.

## Security limits not yet resolved

A correct-looking DACL does not, by itself, prove that the directory was created by FI's authorized installer or that the parent path, ancestors, issuer, token or signing key have not been compromised. In particular:

1. A package-private native experiment now creates the bootstrap child with **parent-handle-relative `NtCreateFile(FILE_CREATE)` and an explicit protected `OBJECT_ATTRIBUTES.SecurityDescriptor` at creation time** (see `WINDOWS-VOLUME-FIRST-PROTECTED-BOOTSTRAP.md`). A future installer must still prove that the parent is independently trusted on the local system volume; do not create with inherited or broad access and attempt post-create repair.
2. After creation, it must verify the owner's SID, DACL, directory identity, actual parent handle, and journal's effective inherited security **from native handles**, not merely by path strings or self-reported config.
3. It must establish and retain exclusive installation ownership, reject preexisting or reparse-point bootstrap roots, and persist crash evidence without automatic deletion or retry.
4. The future protected grant, signer public-key trust, native operator identity, and creation-only FI backend must all be bound to this installation. A protected directory is not a cryptographic signing authority.
5. Controlled `adminbox` and supported Windows Server acceptance must exercise ACL/owner failures, tampered ACEs, substituted paths, failed writes, sudden interruption, restart and service-SID boundaries.

Parent and child-file policies have cross-platform Go negative-path tests. Windows-only tests decode SDDL-derived native security descriptors for both acceptable and unacceptable parent/file ACLs, and the default writer is tested against an ordinary unprotected runner directory before any journal is created. The earlier temporary-directory journal I/O tests use an explicitly named `_test.go`-only constructor: they demonstrate `CREATE_NEW` and flush semantics, not installed ACL authority. They do **not** create an actual protected FI bootstrap directory on an installed server or establish real-world privilege boundaries.

**Nothing in these tests authorizes installing FI or starting volume-wide monitoring.** `ServeEnrolledVolumes` remains fail-closed, and `main` and deployed FI hosts remain unchanged.

See [creation journal](WINDOWS-VOLUME-FIRST-CREATION-JOURNAL.md), [fresh-install contract](WINDOWS-VOLUME-FIRST-FRESH-INSTALL.md), [installer requirements](WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md), and [validation matrix](WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md).

## Read-only system ProgramData identity observation (2026-11-11)

The branch now includes a separate native Windows read-only observer of the OS-known `ProgramData` path, shared Windows directory, system-volume NTFS status, and independent full-width FILE_ID_INFO on retained root/parent/Windows handles, plus a recheck against fresh name lookups. The observer rejects moved/replaced objects and nonstandard/redirected paths. It is **not a trusted issuer or permission to run the private bootstrap**. Real parent owner/DACL/ancestor provenance and transaction authorization remain blockers. See [system parent evidence](WINDOWS-VOLUME-FIRST-SYSTEM-PARENT-EVIDENCE.md).
