# FI Windows Volume-First — Protected Bootstrap Directory Creation Experiment

**Branch:** `dev/windows-volume-first-20261108`  
**Development status:** Package-private Windows native create-only primitive and isolated Windows tests. **NOT authorized installer apply, host provenance, an installation grant, or a service startup gate.** No code in `fi-install` calls this primitive.

## Purpose

`go/internal/windows/freshinstall/bootstrap_windows.go` implements `reserveProtectedBootstrap(parentPath)` as a narrowly bounded Windows experiment for the **first** creation of the fixed `FI-Installer` child directory under an **already existing local** parent. In the future design, the intended parent is the trusted system `C:\\ProgramData` and the destination is `C:\\ProgramData\\FI-Installer`. A path supplied by an ordinary caller or a matching ACL does not authenticate that intended system parent.

This primitive does not create or repair parent directories; it does not install FI, grant privileges, reconcile old files, write a signed grant, create services, run the creation transaction, or authorize raw-volume source capture. It stays unexported and outside `go/cmd/fi-install`. The installed Windows services and `main` are unchanged.

## Exact create-only boundary

1. Validate an existing absolute local-drive parent; reject volume roots, path aliases with reparse ancestors, missing/non-directory components and a supplied directory already named `FI-Installer`. Existing FI install footprints still require the separate eight-item `freshinstall.Assess` check by a future trusted installer.
2. Open and retain the **parent directory handle** with `FILE_FLAG_OPEN_REPARSE_POINT`, directory-type checks and no delete-sharing. Resolve the original native parent identity, then recheck the ancestor path before mutation.
3. Construct and validate an actual Windows `SECURITY_DESCRIPTOR` whose **initial** owner is BUILTIN Administrators and whose protected explicit DACL has **exactly** the inheritable full-control SYSTEM and Administrators ACEs. The intended SDDL is `O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`. No fallback to inherited, world-writable or post-creation repaired ACLs is permitted when an elevated token lacks owner-assignment privileges.
4. Call Windows `CreateDirectoryW` with a **non-null SecurityAttributes** referencing that protected descriptor. A preexisting target produces an explicit collision error and must not be adopted, overwritten or deleted. A failed/uncertain create is reported in doubt.
5. Reopen and retain the newly created child handle with no delete-sharing, reject reparse/file-type substitution, and confirm native child-parent path identity while both handles remain open. Re-inspect the **actual child handle's** owner/DACL with `verifyJournalParentHandle`. Success is reported only after the exact protected policy is observed.
6. `windowsBootstrapReservation.Close()` closes the retained handles but **never removes the directory**. An in-doubt or completed bootstrap is not silently retried on a later installer run.

**No rollback or service rights are implied.** Path ancestry is inspected by path before mutation but not yet authenticated by a trusted, retained, handle-relative chain to the system-volume root. The CreateDirectoryW name is path-based (not kernel handle-relative). A maliciously replaceable parent or ancestor remains a blocker despite the retained final-parent handle. A correctly protected bootstrap child cannot by itself prove installation issuer, token, consent, host or machine-state commitment.

## Native development tests

`bootstrap_windows_test.go` uses disposable Windows runner directories to test the desired descriptor, preexisting-artifact preservation, invalid parents, reparse aliases when supported, retained child/parent rename exclusion, create-only collision, a journal reservation using the **default strict native journal writer**, and concurrent creation with one successful reservation.

Tests requiring an Administrators-owned newly created directory run only when the runner can actually assign that owner. If Windows denies owner assignment, the test skips with an explicit privilege warning **only when no child was created**; this does not constitute successful native protected creation. Pure SDDL policy and preexisting-artifact tests still run. These tests do not qualify the privileged `adminbox` installer identity or Windows Server crash behavior.

## Remaining A05 / V16 blockers

A future installer must still establish authenticated operator approval and native token/issuer trust, unambiguously identify the intended local system volume and **trusted immutable `C:\\ProgramData` parent/ancestor chain**, perform the full fresh-host collision check and enforce one exclusive installation transaction. It must connect creation to the durable write-ahead journal **without a gap before the first mutation**, pin the signed initial volume grant to independently protected installation state, create all five disabled services with intended gMSA/service-SID rights, implement owned-artifact-only failure handling and recovery, and pass controlled `adminbox` and reboot/power-loss acceptance.

The current bootstrap experiment is **not installed-state trust or a release candidate**. A05 remains **P0/open**; V14 and V16 remain **NOT RUN**. Do not uninstall or modify FI on ISS-FS-22A.
