# FI Windows Split-Privilege Verification Kit

This is the operator runbook for FI's Windows split-privilege verification
scripts.

The goal is that a Windows administrator can answer:

```text
What do I run?
Where do I run it?
Which release-specific script applies?
What result should I expect?
```

without reading the Go implementation.

## Validated Windows Server releases

The current Phase 1 acceptance baseline is green on:

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
```

See `docs\WINDOWS-SERVER-VALIDATION.md` for version-specific findings.

A later Windows Server release must be characterized independently.

---

# 1. Common-script rule

Common verification scripts live in:

```text
tools\scripts
```

Release-specific scripts live under:

```text
tools\scripts\2019
tools\scripts\2022
```

Use this rule:

> **Run the common script unless the README for your Windows Server release says
> to use a release-specific script for that test number.**

Do not copy a 2022-specific workaround into another release just because that
release is newer.

---

# 2. Current script routing

| Test | Server 2016 | Server 2019 | Server 2022 |
|---|---|---|---|
| 01 Baseline | common 01 | common 01 | common 01 |
| 02 Positive USN | common 02 | common 02 | common 02 |
| 03 Local authorization | common 03 | common 03 | common 03 |
| 04 Helper failure / catch-up | common 04 | common 04 | common 04 |
| 05 Remote pipe rejection | common 05 | common 05 | common 05 |
| 06A-06D gMSA recovery | common 06 | common 06 | common 06 |
| 07 Config/state/spool ACL | common 07 | common 07 | `2022\07-...` |
| 08 Collector service-token boundary | common 08 | common 08 | `2022\08-...` |

Windows Server 2019 also has an engineering raw-volume characterization script:

```text
tools\scripts\2019\01-USN-Access-Characterization.ps1
```

That is not a replacement for customer Test 01.

Windows Server 2022 has raw-volume characterization source under:

```text
go\cmd\usnprobe\2022
```

The release READMEs explain those engineering-only items.

---

# 3. Before testing

## 3.1 Identify the operating system

Run on the FI file server:

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption,Version,BuildNumber
```

Validated builds:

```text
2016 -> 14393
2019 -> 17763
2022 -> 20348
```

If the release/build is different, do not silently assume the closest existing
release procedure applies.

## 3.2 Read the release README

Server 2019:

```text
tools\scripts\2019\README.md
```

Server 2022:

```text
tools\scripts\2022\README.md
```

Server 2016 uses the common numbered kit.

## 3.3 PowerShell

Run scripts from elevated Windows PowerShell where instructed.

The current kit has been exercised in the validated Windows PowerShell 5.1
environments.

## 3.4 FI paths

The scripts use deployed FI paths such as:

```text
C:\ProgramData\FI\config\fi.conf
C:\ProgramData\FI\state
C:\ProgramData\FI\spool
```

If exactly one `governed_root` is configured, scripts that support automatic root
selection use it.

If multiple governed roots exist, provide the intended root when the script
supports `-GovernedRoot`.

## 3.5 Temporary objects

Activity tests create uniquely named temporary files.

Successful tests remove their own temporary objects unless the individual script
states otherwise.

## 3.6 Administrator-run data ACL hardening

The verification kit itself does not silently repair FI ACLs.

For deployment-time hardening of FI-owned state and spool directories, use:

```powershell
cd <repo-or-kit>\tools\deployment
.\Harden-FI-Data-ACL.ps1 -ConfirmChange
```

The deployment script briefly stops `FICollector` if it is running, normalizes
existing children, applies the hardened root ACL, verifies the full trees, and
restarts the collector.

See:

```text
tools\deployment\README.md
```

Populated directories are normalized **before** inherited access is removed.
Existing children must never be assumed to receive later parent grants
automatically.

---

# 4. What the numbered kit proves

The numbered kit verifies the deployed split-privilege boundary:

```text
FICollector
    restricted per-host gMSA
    non-admin
        |
        | local named pipe
        | DACL + NT SERVICE\FICollector runtime authorization
        v
FIUSNReader
    separate per-host gMSA
    local Administrator on this host only
        |
        +-- bounded USN query/read
        |
        +-- bounded mechanical containment when required
```

It proves operational behavior, not merely static configuration.

The kit does **not** claim that FI ACLs can sandbox `FIUSNReader` after that
privileged service is compromised. `FIUSNReader` runs inside the local Windows
administrative trust boundary on the currently validated design.

The boundary being proved is:

```text
compromise of non-admin FICollector
        |
        v
does not automatically become local Administrator
        |
        v
only the narrow authenticated FI-USN broker is available
```

---

# 5. Recommended sequence

Run the tests in this order.

Do not skip ahead after a failure and then treat later PASS results as proof that
the failed boundary is acceptable.

---

## Test 01 — File-server baseline

**Run on the FI FILE SERVER in elevated Windows PowerShell.**

From `tools\scripts`:

```powershell
.\01-FileServer-Baseline.ps1
```

Expected final result:

```text
[PASS] TEST 01 PASSED.
```

This checks:

- both FI services;
- service identities;
- managed-account settings;
- helper local-Administrator membership;
- collector non-admin status;
- `FICollector` service SID;
- local FI-USN pipe presence;
- USN checkpoint presence; and
- basic FI configuration ACL inspection.

Stop here if the baseline fails.

---

## Test 02 — Positive USN collection

**Run on the FI FILE SERVER.**

```powershell
.\02-FileServer-Positive-USN.ps1
```

Expected:

```text
USN checkpoint advances
test file appears in FI spool output
TEST 02 PASSED
```

This proves the real collector can obtain USN data through the real helper and
commit the result through the normal FI path.

---

## Test 03 — Local runtime authorization

**Run on the FI FILE SERVER from an ordinary elevated administrator
PowerShell.**

```powershell
.\03-FileServer-Local-Authorization.ps1
```

Expected:

```text
local administrator can reach the pipe DACL
broker rejects the request
ErrorCode = 5
FICollector service SID is required
both FI services remain running
TEST 03 PASSED
```

The important boundary is:

```text
Builtin Administrators in pipe DACL
        !=
authorized FI-USN broker client
```

The runtime token must contain the enabled, non-deny-only:

```text
NT SERVICE\FICollector
```

service SID.

---

## Test 04 — Helper failure and catch-up

**CONTROLLED OUTAGE**

**Run on the FI FILE SERVER.**

```powershell
.\04-FileServer-Failure-Recovery.ps1 -ConfirmDisruptive
```

The corrected Test 04 does **not** assume a fixed 35-second sleep is enough.

It:

1. records the accepted USN checkpoint;
2. records the latest configured-collection runtime boundary;
3. stops `FIUSNReader`;
4. confirms `FICollector` remains running;
5. creates a governed test change;
6. waits until `FICollector` actually executes a new configured collection cycle
   while the helper is unavailable;
7. confirms the USN checkpoint did not advance;
8. confirms helper unavailability was recorded explicitly;
9. confirms FI spool activity continued;
10. restarts `FIUSNReader`;
11. waits for the checkpoint to advance; and
12. confirms the outage change appears in catch-up output.

Expected final result:

```text
[PASS] TEST 04 PASSED.
```

Key invariant:

> **A failed or unavailable FIUSNReader must not advance accepted USN
> continuity.**

---

## Test 05 — Remote pipe rejection

**Run from a SEPARATE ADMIN BOX, not the FI file server.**

```powershell
.\05-AdminBox-Remote-Pipe.ps1 -FileServer "YOUR-FILE-SERVER"
```

Expected:

```text
[PASS] Remote pipe connection was rejected.
```

The exact Windows error wording may differ. The connection itself must not
succeed.

---

# 6. Optional Test 06 — gMSA disable / fresh logon / recovery

Test 06 changes Active Directory state.

Run it only in an approved maintenance/test window.

The sequence is split because the AD operation and file-server behavior occur on
different systems.

## 06A — Disable the helper gMSA

**Run on a DOMAIN CONTROLLER or AD administration system.**

```powershell
.\06A-DC-Disable-Helper-gMSA.ps1 `
    -HelperGMSA "gFI-USN-YOURHOST" `
    -ConfirmDisruptive
```

Use the AD service-account object name without the domain prefix and trailing
`$`.

## 06B — Prove a fresh helper service logon is blocked

**Run on the FI FILE SERVER.**

```powershell
.\06B-FileServer-Verify-Disabled-gMSA.ps1 -ConfirmDisruptive
```

## 06C — Re-enable the helper gMSA

**Run on the DOMAIN CONTROLLER or AD administration system.**

```powershell
.\06C-DC-Enable-Helper-gMSA.ps1 `
    -HelperGMSA "gFI-USN-YOURHOST"
```

## 06D — Prove service recovery and USN catch-up

**Run on the FI FILE SERVER.**

```powershell
.\06D-FileServer-Verify-gMSA-Recovery.ps1
```

Expected final state:

```text
FIUSNReader starts again
USN catch-up resumes from the prior accepted checkpoint
downtime change appears
```

---

# 7. Test 07 — Config / state / spool ACL boundary

This test is read-only.

It must not be used as an ACL repair script.

## Server 2016

```powershell
.\07-FileServer-Config-ACL.ps1
```

## Server 2019

```powershell
.\07-FileServer-Config-ACL.ps1
```

## Server 2022

Use the release-specific script:

```powershell
.\2022\07-FileServer-Config-ACL.ps1
```

Do **not** replace the common Test 07 with the Server 2022 version.

Expected properties include:

- complete config inspection;
- no broad `BUILTIN\Users` config access;
- no direct collector config write/ACL-administration permission;
- complete state and spool inspection;
- no broad `BUILTIN\Users` state/spool entries;
- collector Modify without ACL-administration rights;
- no FI-specific helper state/spool ACE;
- collector remains non-admin;
- helper remains in the intended local administrative boundary;
- managed-account settings remain correct; and
- collector service SID remains enabled.

For the common Test 07, expected final result is:

```text
[PASS] TEST 07 PASSED.
```

### Why Test 07 inspects `icacls` output, not only `$LASTEXITCODE`

Windows validation established that:

```text
icacls <path> /T /C
```

can report an individual:

```text
Access is denied.
```

while still leaving `$LASTEXITCODE` at `0`.

A clean process exit code alone is therefore not accepted as proof that the ACL
tree was inspected successfully. Test 07 also checks command output for access
failures and the `Failed processing` summary.

The intended state/spool root shape is:

```text
C:\ProgramData\FI\state
    SYSTEM                  Full
    Administrators          Full
    FICollector gMSA        Modify

C:\ProgramData\FI\spool
    SYSTEM                  Full
    Administrators          Full
    FICollector gMSA        Modify
```

`FIUSNReader` does not own checkpoint, spool, or collector-state writes.

---

# 8. Test 08 — Collector exact service-token boundary

This verifies more than account identity.

It proves an ordinary process using the collector account is not equivalent to
the real Windows `FICollector` service token.

## Server 2016

```powershell
.\08-FileServer-Collector-Boundary.ps1
```

## Server 2019

```powershell
.\08-FileServer-Collector-Boundary.ps1
```

## Server 2022

Use:

```powershell
.\2022\08-FileServer-Collector-Boundary.ps1
```

The boundary is:

```text
account identity alone
        !=
NT SERVICE\FICollector service token
```

Expected result:

```text
real FICollector service token accepted
ordinary same-account process not treated as the service
TEST 08 PASS
```

---

# 9. Release-specific engineering characterization

The numbered customer verification kit and engineering characterization are
different.

The numbered kit verifies a deployed accepted design.

Characterization answers:

```text
Why does this Windows release require that design?
Did this release change Windows behavior?
```

## Windows Server 2019

See:

```text
tools\scripts\2019\README.md
tools\scripts\2019\01-USN-Access-Characterization.ps1
go\cmd\usnprobe\2019
```

## Windows Server 2022

See:

```text
tools\scripts\2022\README.md
go\cmd\usnprobe\2022
```

Do not run engineering characterization against a production file server merely
because the customer verification kit passed.

---

# 10. Windows Security Event Log

The Security Event Log is a separate FI source.

A passing USN test does not prove Security-log readability or audit-policy/SACL
coverage.

During deployment acceptance, verify:

- the restricted collector can read the local Security log through the approved
  Windows rights/group model;
- the FI Security checkpoint advances after accepted collection; and
- required Advanced Audit Policy and SACL configuration are present where
  governed-file activity is expected.

FI runtime does not silently enable audit policy or add governed-root SACLs.

---

# 11. Record the result

Use:

```text
docs\VERIFICATION-RECORD.md
```

Record:

- Windows Server release;
- exact build;
- FI version/build or commit;
- service identities;
- governed root;
- each numbered test;
- release-specific characterization if performed;
- Security source acceptance;
- protected-object acceptance where applicable; and
- any exception.

Keep console output with the deployment/change record when required.

---

# 12. What counts as a green numbered verification

```text
[ ] Collector is non-admin
[ ] Helper owns the narrow privileged Windows boundary
[ ] Managed-account settings are correct
[ ] Collector service SID is enabled
[ ] Positive USN collection advances checkpoint
[ ] Test filename appears in spool
[ ] Ordinary elevated local admin is rejected by runtime authorization
[ ] Remote broker access is rejected
[ ] Helper outage freezes accepted USN continuity
[ ] Collector remains running during helper outage
[ ] Helper recovery catches up the outage change
[ ] Config ACL boundary passes
[ ] State/spool ACL boundary passes
[ ] Collector exact service-token boundary passes
```

The full deployment record should also preserve these specific properties:

```text
[ ] FICollector is not local Administrator
[ ] FIUSNReader is local Administrator on this host only
[ ] FICollector managed-account setting is TRUE
[ ] FIUSNReader managed-account setting is TRUE
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
[ ] Config inspection is complete with no broad BUILTIN\Users access
[ ] Collector has no direct FI config write/modify/ACL-administration ACE
[ ] State tree is fully traversable with no broad BUILTIN\Users entries
[ ] Spool tree is fully traversable with no broad BUILTIN\Users entries
[ ] Collector has Modify on FI state/spool without ACL-administration rights
[ ] Helper has no FI-specific state/spool ACE
[ ] Collector exact service-token boundary passes
```

Optional:

```text
[ ] Disabled helper gMSA cannot obtain a fresh service logon
[ ] Re-enabled helper gMSA restores service
[ ] gMSA-downtime change appears after catch-up
```

For Server 2022, also follow its release README for the protected-system-object
containment behavior required by that release's accepted design.
