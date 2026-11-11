# Windows FI v2 — Read-Only System Parent ACL Exposure Audit

**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Pure policy plus native Windows owner/DACL decoder and tests. **No installer apply, ACL repair, installed-state commitment, or service authorization.**

## Distinct security policies

The **existing shared system-volume root and ProgramData** have a different security contract from the newly created `FI-Installer` bootstrap directory. The latter must use an exact, protected, explicit SYSTEM/Administrators DACL supplied at creation time; it is **not** an ACL template for rewriting `C:` or common ProgramData.

`system_parent_acl_policy.go` implements a conservative read-only **exposure classifier** for the existing directories. `AssessSystemParentACL` requires owner SYSTEM (`S-1-5-18`) or BUILTIN Administrators (`S-1-5-32-544`), a present/non-null/non-defaulted DACL, and 1–64 understood simple allow/deny ACEs. An inherited DACL can be normal and is not itself rejected. Unsupported object/callback/conditional ACEs, unknown flags, unexpanded generic rights and malformed trustees are refused.

A trustee **other than** SYSTEM or Administrators may have only known read/list/traverse/synchronize rights (`FILE_LIST_DIRECTORY`, `FILE_READ_EA`, `FILE_TRAVERSE`, `FILE_READ_ATTRIBUTES`, `READ_CONTROL`, `SYNCHRONIZE`). Any possibly granted file/subdirectory creation, delete, attribute/EA modification, `WRITE_DAC`, `WRITE_OWNER`, unknown or generic rights are **blocked**. Neither a preceding deny ACE nor `INHERIT_ONLY` causes the policy to overlook a broad allow.

This classifier is **not** a Windows `AccessCheck` evaluated for a real installation token. It does not prove Windows directory issuer, whether a particular elevated token can create the child, or whether privileged host state is uncompromised. It intentionally can refuse ordinary Windows ProgramData ACLs that permit users special create-folder access. **Never automatically strip, overwrite, repair or take ownership of system root/ProgramData ACLs to force a passing result.**

## Native read-only implementation

`system_parent_acl_windows.go` uses `GetSecurityInfo(SE_FILE_OBJECT, OWNER|DACL)` on the exact **retained native root and ProgramData directory handles** from `inspectNativeSystemProgramData`; these handles now request `READ_CONTROL` as well as `FILE_READ_ATTRIBUTES`. The native parser checks descriptor/owner validity, present/non-null DACL, ACE type and size, and decodes bounded native allow/deny ACE trustees and masks.

`inspectParentAccess()` performs independent original-vs-reopened path and 64-bit volume serial/128-bit directory ID rechecks **before and after** reading the descriptors. `assessParentAccess()` then separately evaluates the root and ProgramData policy. None of these functions writes ACLs or changes Windows state. An unexpected ACE or uncertain descriptor yields a classified error, **not permission to install**.

## Regression coverage and acceptance limits

Pure negative tests exercise untrusted/defaulted owners, null/defaulted DACLs, excessive ACEs, unknown trustees, generic rights, inherited/creator-owner write access, ordinary-user or domain create/write/delete/owner grants, and allow ACEs preceded by deny. Windows native SDDL tests verify decoding of safe and unsafe ACL shapes. The Windows runner also reads actual system root/ProgramData DACLs **without changing them**. Its host ACL may be correctly classified as **BLOCKED**, which is not a native installer qualification pass.

The private bootstrap still accepts a supplied parent pathname and is **not wired to this observer**. Missing: independently trusted root/ProgramData ancestor issuer, verified installer identity/Windows token effective rights, authenticated administrator consent, secure parent-handle-to-creation transaction handoff, protected signed installed-grant commitment, restart/power-loss recovery and controlled `adminbox` testing.

**A05 remains P0/open. V14/V16 are NOT RUN. ISS-FS-22A removal or reinstall remains NO-GO.**
