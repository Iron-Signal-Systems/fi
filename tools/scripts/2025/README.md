# FI Windows Server 2025 Build 26100 Validation

This directory records the independent Windows Server 2025 characterization and
production acceptance performed for:

```text
Windows Server 2025 Standard Evaluation
Version 10.0.26100
Build 26100
Lab host: ISS-FS-25
```

The result is green for the **exact characterized build `26100`**.

This does not mean every later Windows Server 2025 build automatically inherits
the same raw-volume or protected-object behavior.

## Relationship to the common verification kit

The common customer verification sequence remains:

```text
tools\scripts\01-...
through
tools\scripts\08-...
```

All common Tests 01 through 08 were run and passed on Server 2025 build `26100`.

The scripts in this `2025` directory are separate release-specific engineering
characterization and final production acceptance. Their numeric prefixes do not
replace the common test numbers.

## Accepted identity model

```text
FICollector
    ISS\gFI-FS25$
    non-admin
    managed account: TRUE
    service SID: UNRESTRICTED

FIUSNReader
    ISS\gFI-USN-FS25$
    local Administrator on ISS-FS-25
    managed account: TRUE
```

Production paths:

```text
FICollector:
"C:\Program Files\FI\fi.exe" -service -service-collection-every 1m -service-supporting-refresh-every 30m

FIUSNReader:
"C:\Program Files\FI\fi-usn.exe"
```

## Raw-volume result

Independent Server 2025 characterization established:

```text
Non-admin                         FAIL
Non-admin + SeManageVolume        FAIL
Local Administrator               PASS
FILE_READ_DATA                    least tested successful raw-volume access
```

The result records observed Windows behavior. FI does not claim an undocumented
internal reason for the local-Administrator requirement.

## Protected containment result

A protected ETL object under:

```text
C:\Windows\System32\LogFiles\WMI\RtBackup
```

reproduced this sequence on build `26100`:

```text
normal zero-access OpenFileById        FAIL / Access Denied
SeBackupPrivilege initially disabled
enable SeBackupPrivilege               PASS
same zero-access OpenFileById          PASS
restore exact prior privilege state    PASS
same zero-access OpenFileById          FAIL / Access Denied
```

That independently justified the same bounded scoped retry mechanics previously
validated on Server 2022, but only behind the Server 2025 exact-build gate for
`10.0.26100`.

No `SeRestorePrivilege` or broader target-object desired access is required.
Privilege restoration failure fails the operation closed.

## Release-specific sequence

### 01 — USN access characterization

```text
01-USN-Access-Characterization.ps1
```

Establishes the non-admin baseline and the explicit
`SeManageVolumePrivilege` characterization state.

### 02 — Local Administrator characterization

```text
02-USN-Local-Administrator-Characterization.ps1
```

Establishes the local-Administrator result and the least successful useful
raw-volume access mask.

### 03 — Protected containment characterization

```text
03-Protected-Containment-Characterization.ps1
```

Characterizes protected File-ID containment and exact privilege restoration.

### 04 — Install production pair

```text
04-Install-Production-Pair.ps1
```

Installs the reviewed production collector/helper candidates, hardens the FI
program/data boundaries, configures the exact service identities and paths, waits
for the real helper pipe, starts the collector, and requires the first real
configured collection to complete.

Reviewed Server 2025 candidate hashes used during acceptance:

```text
FICollector
CE58D165636F132ABC60902D242D9262BE1A422C18107B937629C98D255E1926

FIUSNReader
22F90B3976D2B69FB5FD8DC4B137B1DAA08767A72AAED92A6E0D0FE462810217
```

### 05 — Production protected containment acceptance

```text
05-Production-Protected-Containment-Acceptance.ps1
```

Exercises the production broker path against the characterized protected target,
requires the bounded containment result, restores the exact production collector
service path, and requires a fresh normal configured collection.

### 06 — Controlled service restart acceptance

```text
06-Service-Restart-Acceptance.ps1
```

Stops both production services, creates one governed-root change while they are
stopped, proves the USN checkpoint remains frozen, restarts the helper and waits
for the actual broker pipe, restarts the collector, requires checkpoint
advancement and a fresh complete configured collection, and verifies the exact
stopped-service change appears in catch-up spool output.

Accepted result:

```text
PASS
```

### 07 — Cold reboot / startup acceptance

```text
07-Cold-Reboot-Acceptance.ps1 -ConfirmDisruptive
```

Stops both services, creates one uncollected governed-root change, verifies the
checkpoint is frozen, initiates a target-local reboot through the existing WinRM
channel, detects an actual new boot instance, and verifies:

```text
FICollector auto-started
FIUSNReader auto-started
FI-USN pipe returned
USN checkpoint advanced
fresh ConfiguredCollection = Complete
pre-reboot change appeared in catch-up spool
exact production PathName values survived
managed-account settings survived
FICollector service SID remained UNRESTRICTED
```

Accepted result:

```text
PASS
```

## Common acceptance results

On build `26100`, the common numbered kit established:

```text
01 File-server baseline                       PASS
02 Positive USN collection                    PASS
03 Local runtime service-SID authorization    PASS
04 Helper failure and catch-up                PASS
05 Remote pipe rejection                      PASS
06A-06D helper gMSA disable/recovery          PASS
07 Config/state/spool ACL boundary            PASS
08 Exact FICollector service-token boundary   PASS
```

The gMSA disable/recovery sequence additionally proved that disabling the AD gMSA
does not invalidate an already-created helper token, but a fresh helper service
logon fails while the gMSA is disabled. Re-enabling the account restores service
and catch-up from the accepted checkpoint.

## Support boundary

Do not generalize from `26100` to another Server 2025 build.

For an uncharacterized Server 2025 build:

1. run common verification;
2. repeat raw-volume characterization;
3. repeat protected containment characterization;
4. compare observed behavior with build `26100`;
5. add or expand a build gate only if the new build is independently proven; and
6. record the result in `docs\WINDOWS-SERVER-VALIDATION.md`.

Release/build-specific behavior stays visible and bounded.
