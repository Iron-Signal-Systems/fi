# FI Windows Volume-First — Read-Only Native Installer Parent AccessCheck

**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Private Windows `AccessCheck` and negative-path tests implemented. **NOT operator approval, trusted host issuer, installed grant, installer execution authority or release acceptance.**

## Scope and why this is necessary

Being an elevated administrator and reading a sensible ProgramData DACL do not establish whether Windows grants a particular token the right to create the protected FI-Installer child. `freshinstall/installer_parent_access_windows.go` now uses the actual Windows `AccessCheck` engine against an owner/group/DACL security descriptor obtained from the already retained native ProgramData directory HANDLE.

The observation requests exactly `FILE_ADD_SUBDIRECTORY` (0x00000004) and `READ_CONTROL` (0x00020000) independently. No `MAXIMUM_ALLOWED`, unmapped generic desired rights, file creation, existing ACL modification or Windows service change is permitted.

## Native security contract

Windows `AccessCheck` requires an impersonation-FORMAT token with `TOKEN_QUERY`. The code opens the current process token with `TOKEN_QUERY|TOKEN_DUPLICATE`, then calls `DuplicateTokenEx` to create a **SecurityIdentification-level impersonation-format token with only TOKEN_QUERY**. Neither this temporary token nor the original process token is attached to any thread, used to impersonate anyone, or given privilege-adjustment rights. Both are closed after inspection.

The observer runs on a pinned OS thread and refuses thread impersonation before and after the check. It independently samples the process token's user/elevation/group/integrity and verifies that the short-lived access-check token represents the same process user. It reads owner, group and DACL from the **retained ProgramData handle**, converts the self-relative descriptor to absolute form for `AccessCheck`, supplies Windows' file `GENERIC_MAPPING`, and uses a fixed 1 KiB privilege-set buffer. A malformed buffer/status/granted mask, unknown rights, or privilege-assisted result is never installer approval.

Native identity and path reattestation occurs before and after, and a second descriptor read must match the first. These checks **detect changes** but cannot make a sequence of native API calls atomic or establish an independently trusted Windows system-directory issuer.

## Independent preconditions

`AssessInstallerParentAccess` checks the conjunction of:

- High-integrity, UAC-elevated, enabled Administrators interactive primary-token evidence without restrictions or thread impersonation.
- Native root, Windows and ProgramData full-width directory identities on the OS-known NTFS system volume.
- Conservative owner/DACL exposure policy for the existing shared ProgramData directory (rejects unknown ACEs and potentially unprivileged create/write/delete permissions).
- Two successful **exact-right** native `AccessCheck` results, with no privilege-assisted grant.

A valid Windows access decision does **not** bypass the separate shared-parent ACL exposure policy. Normal ProgramData ACLs can allow ordinary users to create directories and therefore fail FI's conservative policy. **Do not rewrite existing Windows root or ProgramData permissions to force a pass.**

## Verification and unresolved acceptance

Pure tests reject missing, denied, privilege-assisted, mismatched and overbroad AccessCheck results; unsafe token, ACL and native volume evidence also fail. Windows-native tests invoke the real AccessCheck engine against ephemeral **in-memory SDDL** allowing and denying rights for the current test process SID, plus invalid token/right cases. A real Windows CI runner's ProgramData descriptor is queried **read-only**; a blocked host is not install acceptance.

The AccessCheck result is a point-in-time DACL/token observation, not the final `NtCreateFile` access decision under all integrity, privilege, filesystem and concurrency conditions. This private code is **not connected** to `fi-install`, `reserveProtectedBootstrap`, SCM or running Windows FI services. There is no authenticated operator intent, verified issuer/ancestry, safe retained-handle write-ahead transaction, protected signed-grant commitment or native `adminbox` acceptance.

**A05 remains P0/open; V14/V16 remain NOT RUN; ISS-FS-22A remains NO-GO for removal and fresh installation.**
