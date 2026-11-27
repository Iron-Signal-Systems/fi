# FI Deployment Tooling

This directory contains explicit administrator-run deployment actions. Deployment
tooling is not normal FI collector/runtime remediation authority.

## Windows Phase 1 data ACL hardening

`Harden-FI-Data-ACL.ps1` is an **administrator-run deployment action** for the
FI-owned runtime directories:

```text
C:\ProgramData\FI\state
C:\ProgramData\FI\spool
```

It is written for Windows Server 2016 / Windows PowerShell 5.1 behavior.

The intended root ACL shape is:

```text
SYSTEM                  Full
BUILTIN\Administrators  Full
FICollector gMSA        Modify
```

`FIUSNReader` receives no FI-specific state/spool ACE. The helper is still a
local Administrator on the validated Server 2016 design, so this is a runtime
responsibility boundary rather than a claim that Windows ACLs can sandbox a
local Administrator.

### Why the script normalizes populated children

On a populated FI directory, simply removing inheritance from the parent and
then granting the new parent ACEs is not sufficient. Existing children can lose
inherited ACEs without automatically receiving the later parent grants.

The deployment script therefore uses this order:

1. verify every current child ACL is accessible;
2. stop `FICollector` if it is running;
3. seed SYSTEM, Administrators, and FICollector access across existing children;
4. remove inheritance from the FI-owned root;
5. apply the hardened root ACL;
6. reset existing children so they inherit from the hardened root;
7. recursively verify that no child is inaccessible and no `BUILTIN\Users` ACE
   remains; and
8. restart `FICollector` if the script stopped it.

The preflight deliberately refuses to continue when it encounters an
inaccessible FI-owned child or an unexpected explicit ACE on the state/spool
root. It does not silently take ownership of customer data or overwrite an
unreviewed custom ACL.

### Run

From elevated Windows PowerShell on the FI file server:

```powershell
cd <repo-or-kit>\tools\deployment
.\Harden-FI-Data-ACL.ps1 -ConfirmChange
```

Then run the read-only boundary verification:

```powershell
..\scripts\07-FileServer-Config-ACL.ps1
```

A successful Test 07 must include a clean recursive ACL traversal for both
`state` and `spool`. `icacls /T /C` process exit code alone is not accepted as
proof because Windows Server 2016 can return exit code `0` while still reporting
individual `Access is denied` failures in its output.

## Current deployment reference and historical scope

The Linux Phase 3 `fi-ingest-worker` and its former `tools/deployment/linux/`
packaging are **historical**; the Linux deployment subtree is **not present on
current `main`**. Do not use an older service or host bootstrap as the live
C220 procedure.

The current development backend is FreeBSD 15.1 with the `fi-receiver` and
`fi-sor` service jails. See [current C220 deployment tooling](freebsd/README.md)
and [as-built architecture](../../docs/architecture/FI-C220-CURRENT-BACKEND.md).
The separate native Windows configuration-driven installer is documented in
[Windows installer](../../docs/WINDOWS-INSTALLER.md).

The Windows ACL-hardening script above is an administrator-run reference action;
it is **not** an extra mandatory step after a successfully approved and
converged current native FI installation.
