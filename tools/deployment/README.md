# FI Deployment Tooling

This directory contains explicit administrator-run deployment actions. Deployment
tooling is not normal FI collector/runtime remediation authority.

## Windows source runtime configuration

The current complete Windows source runtime is configured with:

```text
tools\deployment\windows\Configure-FI-Source-Runtime.ps1
```

This is an explicit elevated administrator-run deployment action. It is not FI
normal runtime remediation authority.

The script requires the expected target computer name, four reviewed service
accounts, and the expected SHA-256 value for each runtime executable:

```text
ExpectedComputerName
CollectorAccount
USNReaderAccount
ObjReaderAccount
SenderAccount

CollectorSHA256
USNReaderSHA256
ObjReaderSHA256
SenderSHA256
```

The fixed production service contract is:

```text
FICollector
    "C:\Program Files\FI\fi.exe" -service

FIUSNReader
    "C:\Program Files\FI\fi-usn.exe"

FIObjReader
    "C:\Program Files\FI\fi-obj.exe"

FISender
    "C:\Program Files\FI\fi-sender.exe"
```

Deployment verifies the target host and exact runtime binary hashes before
accepting the reviewed runtime configuration.

The sender ownership boundary is explicit:

```text
SCM FISender
    |
    +-- exactly one fi-sender.exe
```

`FI-GMSA-Sender-V2-Drain` is legacy sender ownership and must not remain an
active production runtime owner after `FISender` assumes SCM ownership.

Example invocation:

```powershell
.\windows\Configure-FI-Source-Runtime.ps1 `
    -ExpectedComputerName 'ISS-FS-01' `
    -CollectorAccount 'ISS\gFI-FS01$' `
    -USNReaderAccount 'ISS\gFI-USN-FS01$' `
    -ObjReaderAccount 'ISS\gFI-OBJ-FS01$' `
    -SenderAccount 'ISS\gFI-FS01$' `
    -CollectorSHA256 '<REVIEWED-SHA256>' `
    -USNReaderSHA256 '<REVIEWED-SHA256>' `
    -ObjReaderSHA256 '<REVIEWED-SHA256>' `
    -SenderSHA256 '<REVIEWED-SHA256>' `
    -ConfirmChange
```

Use the hashes from the reviewed build being deployed. Do not substitute hashes
from an earlier characterization or acceptance run merely because the file names
match.

The 2026-09-27 Server 2016 lifecycle acceptance established that all four
services survive a real cold reboot, both local broker pipes return, the sender
returns under singleton SCM ownership, the legacy sender task remains disabled,
USN continuity catches up work performed while FI was stopped, and the recovered
change proceeds through sender, receiver, and PostgreSQL relational ingest.

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

## Linux Phase 3 ingest-worker packaging

Permanent Linux relational ingest-worker service packaging lives under:

```text
tools/deployment/linux/
```

That subtree owns the Phase 3 systemd unit, installer, package validation, and
operator instructions for the permanent ingest worker.

It does not replace Phase 6 integrated installation/release packaging.
