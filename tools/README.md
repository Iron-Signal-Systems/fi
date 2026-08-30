# FI USN Split-Privilege Verification Kit

This kit is intended for a **customer Windows administrator** to verify FI's
USN split-privilege security and recovery behavior without needing to understand
the Go implementation.

It was written for **Windows Server 2016 / Windows PowerShell 5.1** behavior.

## What is being verified

```text
FICollector
  restricted per-host gMSA
  NOT local Administrator
  service SID: NT SERVICE\FICollector
        |
        | local named pipe
        | DACL + runtime service-SID authentication
        v
FIUSNReader
  separate per-host gMSA
  local Administrator on this host only
        |
        v
NTFS USN Journal
```

The verification demonstrates:

1. The collector remains non-admin.
2. Only the helper owns the raw-volume administrative boundary.
3. The real `FICollector` service can use the helper.
4. An ordinary elevated local administrator process is rejected by runtime
   service-SID authentication even though an administrator can reach the pipe.
5. A remote machine cannot use the helper pipe.
6. If the helper stops, FI does **not** advance the USN checkpoint.
7. `FICollector` remains running and other FI output continues while the helper
   is down.
8. When the helper returns, FI catches up changes that occurred during the
   outage.
9. Disabling the helper gMSA prevents a fresh helper service logon after the
   already-running helper is stopped.
10. Re-enabling the gMSA permits recovery and USN catch-up.
11. FI configuration has no broad `BUILTIN\Users` access.
12. The restricted collector has no direct FI configuration write permission.

The kit does **not** claim that FI configuration ACLs can sandbox
`FIUSNReader` after that privileged service is compromised. `FIUSNReader` is
intentionally a local Administrator on the validated Server 2016 design.
A local Administrator is already inside the Windows administrative trust
boundary and can take ownership or change ACLs.

The security boundary FI is proving is therefore:

```text
compromise of non-admin FICollector
        |
        v
does not become local Administrator
        |
        v
only the narrow authenticated FI-USN broker is available
```

---

## Before testing

Open **elevated Windows PowerShell** where the instructions say to do so.

The scripts automatically read:

```text
C:\ProgramData\FI\config\fi.conf
C:\ProgramData\FI\state
C:\ProgramData\FI\spool
```

If exactly one `governed_root` is configured, the scripts use it
automatically.

If multiple governed roots are configured, pass the root explicitly:

```powershell
.\02-FileServer-Positive-USN.ps1 -GovernedRoot "D:\DepartmentShare"
```

The scripts create uniquely named temporary files inside the governed root and
remove them after successful validation.

---

# Recommended customer test sequence

## Test 01 — Baseline

**Run on the FI FILE SERVER:**

```powershell
cd <where-you-extracted-the-kit>\scripts
.\01-FileServer-Baseline.ps1
```

Expected final result:

```text
[PASS] TEST 01 PASSED.
```

This checks:

- both services are running;
- service identities;
- helper is local Administrator;
- collector is not local Administrator;
- `FICollector` service SID type is `UNRESTRICTED`;
- local `FI-USN` pipe exists;
- USN checkpoint exists; and
- FI config does not contain broad `BUILTIN\Users` ACL entries.

---

## Test 02 — Positive USN collection

**Run on the FI FILE SERVER:**

```powershell
.\02-FileServer-Positive-USN.ps1
```

Expected:

```text
[PASS] USN checkpoint advanced ...
[PASS] The test file appeared in FI USN spool output.
[PASS] TEST 02 PASSED.
```

This proves `FICollector` can obtain USN data through `FIUSNReader` and commit
the result through the normal collector path.

---

## Test 03 — Reject an ordinary elevated administrator

**Run on the FI FILE SERVER from an ordinary elevated administrator
PowerShell:**

```powershell
.\03-FileServer-Local-Authorization.ps1
```

Expected:

```text
[PASS] Local administrator process connected to the pipe.
[PASS] Ordinary local administrator was rejected by runtime service-SID authorization.
[PASS] Both FI services remained running.
[PASS] TEST 03 PASSED.
```

The helper response must correspond to:

```text
Status    = failure
ErrorCode = 5 (Access Denied)
Error     = FICollector service SID is required
```

This is an important distinction: reaching the local pipe is not sufficient to
obtain privileged USN access. The caller token must contain the enabled,
non-deny-only:

```text
NT SERVICE\FICollector
```

service SID.

---

## Test 04 — Helper failure, frozen checkpoint, and catch-up

**CONTROLLED OUTAGE**

This deliberately stops `FIUSNReader` for roughly 35 seconds.

**Run on the FI FILE SERVER:**

```powershell
.\04-FileServer-Failure-Recovery.ps1 -ConfirmDisruptive
```

Expected:

```text
[PASS] FIUSNReader stopped.
[PASS] FICollector remained running.
[PASS] USN checkpoint did not advance while helper was down.
[PASS] FI spool continued receiving output while helper was unavailable.
[PASS] FIUSNReader restarted.
[PASS] USN checkpoint advanced after helper recovery ...
[PASS] The change created during helper outage appeared in catch-up output.
[PASS] TEST 04 PASSED.
```

The key invariant is:

> FI must never advance its USN checkpoint when the privileged USN read fails.

---

## Test 05 — Reject remote pipe use

**Run from a SEPARATE ADMIN BOX, not on the FI file server:**

```powershell
.\05-AdminBox-Remote-Pipe.ps1 -FileServer "YOUR-FILE-SERVER"
```

Expected:

```text
[PASS] Remote pipe connection was rejected.
```

The exact Windows error text may vary. The connection itself must not succeed.

Afterward, verify both FI services remain running on the file server.

---

# Optional Test 06 — gMSA disable / restart / recovery

This test proves an important Windows operational behavior:

- disabling the helper gMSA does **not** revoke an already-running local process
  token;
- after `FIUSNReader` is stopped, a fresh service logon must fail while the gMSA
  is disabled;
- re-enabling the gMSA allows the helper to restart; and
- FI then catches up the changes made during the outage.

This test changes Active Directory state and should be done during an approved
maintenance/test window.

## 06A — Disable helper gMSA

**Run on a DOMAIN CONTROLLER or AD admin system:**

```powershell
.\06A-DC-Disable-Helper-gMSA.ps1 `
    -HelperGMSA "gFI-USN-YOURHOST" `
    -ConfirmDisruptive
```

Use the AD gMSA object name **without** the domain prefix and without the
trailing `$`.

The validated account-management operation is:

```powershell
Set-ADServiceAccount -Identity "gFI-USN-YOURHOST" -Enabled $false
```

Expected:

```text
[PASS] <gMSA> is disabled.
```

## 06B — Prove fresh helper logon is blocked

**Run on the FI FILE SERVER:**

```powershell
.\06B-FileServer-Verify-Disabled-gMSA.ps1 -ConfirmDisruptive
```

Expected:

```text
[PASS] Already-running FIUSNReader remained running after AD account disable.
[PASS] FIUSNReader is stopped.
[PASS] Fresh FIUSNReader service logon failed while helper gMSA is disabled.
[PASS] FICollector remained running.
[PASS] Created a governed-root change while helper cannot start.
[PASS] USN checkpoint remained frozen while FIUSNReader could not start.
[PASS] TEST 06B PASSED.
```

The script records temporary test information under:

```text
C:\ProgramData\FI\state\fi-usn-verification-gmsa-disabled.txt
```

## 06C — Re-enable helper gMSA

**Run on the DOMAIN CONTROLLER / AD admin system:**

```powershell
.\06C-DC-Enable-Helper-gMSA.ps1 `
    -HelperGMSA "gFI-USN-YOURHOST"
```

The validated account-management operation is:

```powershell
Set-ADServiceAccount -Identity "gFI-USN-YOURHOST" -Enabled $true
```

Expected:

```text
[PASS] <gMSA> is enabled.
```

## 06D — Prove recovery and catch-up

**Run on the FI FILE SERVER:**

```powershell
.\06D-FileServer-Verify-gMSA-Recovery.ps1
```

Expected:

```text
[PASS] FIUSNReader started after gMSA re-enable.
[PASS] FICollector remained running.
[PASS] USN checkpoint advanced after recovery ...
[PASS] The gMSA-downtime change appeared in FI catch-up output.
[PASS] TEST 06D PASSED.
```

---

## Test 07 — Verify the FI config ACL boundary

**Run on the FI FILE SERVER:**

```powershell
.\07-FileServer-Config-ACL.ps1
```

This test is **read-only**. It does not change ACLs.

Expected output includes:

```text
[PASS] BUILTIN\Users is absent from FI config ACLs.
[PASS] FICollector account <account> has only explicit non-write Allow access ...
[PASS] FIUSNReader account <account> has only explicit non-write Allow access ...
[PASS] FICollector account <account> is not a local Administrator.
[PASS] FIUSNReader account <account> is a local Administrator as required ...
[PASS] TEST 07 PASSED.
```

The intended ACL shape is:

```text
C:\ProgramData\FI\config
    SYSTEM                  Full
    Administrators          Full
    FICollector gMSA        Read/Execute
    FIUSNReader gMSA        Read/Execute

C:\ProgramData\FI\config\fi.conf
    SYSTEM                  Full
    Administrators          Full
    FICollector gMSA        Read
    FIUSNReader gMSA        Read
```

The important distinction is:

- **FICollector** is non-admin and must not have FI configuration write access.
- **FIUSNReader** has only an explicit read ACE for normal operation, but its
  local-Administrator membership means it has Windows administrative authority.
  The config ACL is not claimed as a security boundary against compromise of the
  helper itself.

`FIUSNReader` runtime code should still remain read-only toward FI configuration
and must not own checkpoint, spool, or collector-state writes.

---

# What counts as a successful verification

A customer administrator should be able to record all of the following:

```text
[ ] Collector is not local Administrator
[ ] Helper is local Administrator on this host only
[ ] FICollector service SID is enabled
[ ] Positive USN collection advances checkpoint
[ ] Test filename appears in USN output
[ ] Ordinary elevated local admin is rejected by service-SID authentication
[ ] Remote pipe connection is rejected
[ ] Helper outage freezes USN checkpoint
[ ] Collector remains running during helper outage
[ ] Other FI spool activity continues
[ ] Helper restart advances checkpoint
[ ] Downtime change appears after catch-up
[ ] Config ACL has no broad BUILTIN\Users access
[ ] Collector has no direct FI config write/modify/administrative ACE

Optional:
[ ] Disabled helper gMSA cannot perform a fresh service logon
[ ] Re-enabled helper gMSA restores service
[ ] gMSA-downtime change appears after catch-up
```

Keep the console output with the installation/change record if the organization
requires operational validation records.
