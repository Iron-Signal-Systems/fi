# FI Windows Server Validation

This document records the Windows Server releases currently characterized and
accepted for the FI Phase 1 Windows File & Identity Intelligence runtime.

It records tested FI behavior. It does not assume later Windows Server releases
behave identically.

## Current validated releases

| Windows Server | Version / build | FI status |
|---|---:|---|
| Windows Server 2016 | 10.0.14393 | Green |
| Windows Server 2019 | 10.0.17763 | Green |
| Windows Server 2022 | 10.0.20348 | Green |
| Windows Server 2025 | 10.0.26100 | Green |

A later Windows Server release or an uncharacterized build must be characterized
independently before FI assumes that its raw-volume, service-token, Security
Event Log, File-ID, or protected-object behavior is identical.

Windows Server 2025 build `26100` was characterized independently. FI does not
treat an adjacent or future Server 2025 build as equivalent merely because the
release name is the same.

---

## Common split-privilege architecture

Every monitored Windows file server uses two service identities:

```text
FICollector
    per-host collector gMSA
    non-admin
        |
        | \\.\pipe\FI-USN
        | local-only
        | NT SERVICE\FICollector service SID required
        v
FIUSNReader
    separate per-host helper gMSA
    local Administrator on that host only
```

`FICollector` owns normal FI collection and durable state:

- configuration and governed-root processing;
- NTFS collection;
- USN parsing;
- File-ID re-observation;
- governed-root decisions;
- hashing;
- Windows Security collection;
- SMB/local/AD collection;
- spool;
- checkpoints;
- continuity; and
- operation history.

`FIUSNReader` exposes only bounded privileged operations required by the Windows
source boundary:

- query the USN Journal for a configured volume;
- read one bounded USN Journal buffer from a configured volume; and
- perform one bounded mechanical File-ID containment check when the collector
  cannot re-open an object because Windows returned Access Denied.

The containment operation does not return target file paths, metadata, ACLs,
hashes, content, or organizational conclusions.

---

## Direct-volume USN characterization

### Windows Server 2016

Server 2016 established the original split-privilege requirement.

Reduced-access raw-volume handles were tested before accepting the helper model.
The restricted helper identity could not obtain a usable USN query/read path.
Running the narrow helper inside the local Windows administrative boundary made
the required direct-volume operation usable.

The older 2016 privilege-only characterization did not independently establish
the same explicit in-process `SeManageVolumePrivilege` result later tested on
2019 and 2022. FI therefore does not retroactively claim that exact 2019/2022
matrix for 2016.

### Windows Server 2019

2019 explicitly enabled `SeManageVolumePrivilege` when present and tested
multiple access masks.

```text
Non-admin                         FAIL
Non-admin + SeManageVolume        FAIL
Local Administrator               PASS
FILE_READ_DATA                    least tested successful raw-volume access
```

`SeManageVolumePrivilege` alone was insufficient.

Production raw-volume query/read therefore uses `FILE_READ_DATA`, not
`GENERIC_READ`, and keeps `FIUSNReader` as the narrow local-Administrator helper.

### Windows Server 2022

Server 2022 reproduced the 2019 raw-volume result:

```text
Non-admin                         FAIL
Non-admin + SeManageVolume        FAIL
Local Administrator               PASS
FILE_READ_DATA                    least tested successful raw-volume access
```

No raw-USN architecture change was required for Server 2022.

### Windows Server 2025

Server 2025 build `26100` independently reproduced the same raw-volume matrix:

```text
Non-admin                         FAIL
Non-admin + SeManageVolume        FAIL
Local Administrator               PASS
FILE_READ_DATA                    least tested successful raw-volume access
```

The non-admin baseline could open some reduced-access volume handles, but USN
query/read did not become usable. Explicit `SeManageVolumePrivilege` on the
non-admin helper token did not make the required direct-volume USN operation
usable.

The local-Administrator helper succeeded. Production raw-volume query/read
therefore remains `FILE_READ_DATA` through the narrow local-Administrator
`FIUSNReader` boundary.

No undocumented Windows-internal explanation is assumed from this result.

---

## Governed-root containment behavior

USN is volume-wide. FI cannot treat the filename inside an old USN record as
proof that the current object is governed.

```text
USN changed-object identity
        |
        v
FICollector File-ID re-observation
        |
        +-- success
        |      -> collector determines current governed scope
        |
        +-- object disappeared
        |      -> unavailable
        |
        +-- Access Denied
               |
               v
        FIUSNReader CheckContainment
               |
               +-- Contained
               +-- Outside
               +-- Unavailable
```

The helper result is mechanical. The helper does not become a second collector.

### Windows Server 2019 protected-object acceptance

Protected outside-scope and protected in-scope objects were validated through the
production broker path.

A protected outside object was filtered without becoming
`ScopeUnresolvedIncluded`.

A protected in-scope object that the non-admin collector could not re-observe was
kept as an explicit access-denied collection result with helper-established
current containment.

### Windows Server 2022 protected system objects

Server 2022 exposed an additional behavior with protected system ETL objects.

For objects such as files under:

```text
C:\Windows\System32\LogFiles\WMI\RtBackup
```

the local-Administrator helper could receive:

```text
OpenFileById
desired access = 0
ERROR_ACCESS_DENIED
```

Characterization established:

```text
normal zero-access OpenFileById        FAIL / Access Denied
enable SeBackupPrivilege
same zero-access OpenFileById          PASS
restore prior privilege state
same zero-access OpenFileById          FAIL / Access Denied
```

`SeBackupPrivilege` alone was sufficient for this specific Server 2022
containment operation.

No `SeRestorePrivilege` was required.

No broader target-object desired access was required.

### Server 2022 production rule

Only Windows version/build:

```text
10.0.20348
```

is eligible for the release-specific fallback.

```text
normal zero-access OpenFileById
        |
        +-- success
        |      -> normal containment
        |
        +-- Access Denied
               |
               +-- build != 20348
               |      -> existing behavior
               |
               +-- build == 20348
                      |
                      +-- enable SeBackupPrivilege
                      +-- retry same zero-access OpenFileById
                      +-- resolve mechanical containment
                      +-- restore exact prior privilege state
```

If privilege restoration fails, the helper fails the operation.

The 2022 behavior is not automatically enabled for 2016, 2019, or an
uncharacterized Windows Server release/build.

### Windows Server 2025 protected system objects

Server 2025 build `26100` was characterized independently against a protected ETL
object under:

```text
C:\Windows\System32\LogFiles\WMI\RtBackup
```

The observed sequence was:

```text
normal zero-access OpenFileById        FAIL / Access Denied
SeBackupPrivilege initially disabled
enable SeBackupPrivilege               PASS
same zero-access OpenFileById          PASS
restore exact prior privilege state    PASS
same zero-access OpenFileById          FAIL / Access Denied
```

The tested target was outside the configured governed root and the mechanical
containment result was `Outside`.

The Server 2025 characterization therefore justified the same bounded
`SeBackupPrivilege` retry mechanics used for Server 2022, but only behind an
independent exact-build gate for:

```text
10.0.26100
```

The Server 2025 wrapper delegates to the already-proven bounded retry mechanics
because the independently observed behavior was identical. This does not turn
the fallback into generic Windows behavior.

The production rules remain:

- normal zero-access `OpenFileById` is always attempted first;
- only Access Denied enters the release/build-specific fallback;
- `SeBackupPrivilege` is enabled only for the retry;
- the exact same zero-access File-ID open is retried;
- no `SeRestorePrivilege` is enabled;
- no broader target-object access is requested;
- the exact prior privilege state is restored before return;
- restoration failure fails the operation closed;
- the broker protocol is unchanged; and
- no target path or expanded target data is returned to `FICollector`.

Adjacent or future Server 2025 builds are not automatically eligible for the
build-26100 fallback.

### Server 2025 production acceptance

The production pair was accepted on Windows Server 2025 Standard Evaluation,
version/build `10.0.26100`.

The accepted production service configuration was:

```text
FICollector
    account: ISS\gFI-FS25$
    non-admin
    managed account: TRUE
    service SID: UNRESTRICTED
    PathName:
      "C:\Program Files\FI\fi.exe" -service
      -service-collection-every 1m
      -service-supporting-refresh-every 30m

FIUSNReader
    account: ISS\gFI-USN-FS25$
    local Administrator
    managed account: TRUE
    PathName:
      "C:\Program Files\FI\fi-usn.exe"
```

Production acceptance established:

- first configured collection completed through the normal service startup path;
- protected containment returned the correct bounded result through the
  production broker;
- common Tests 01 through 08 passed;
- a disabled helper gMSA could not obtain a fresh service logon;
- re-enabling the helper gMSA restored service and catch-up;
- helper outage froze the accepted USN checkpoint and catch-up recovered the
  exact outage change;
- the real `FICollector` service token could write its own state/spool but could
  not write config, replace/delete FI binaries, or obtain helper
  `CHANGE_CONFIG`, `WRITE_DAC`, or `WRITE_OWNER`;
- controlled stop/start of both production services preserved checkpoint
  continuity and caught up the exact stopped-service change; and
- a cold host reboot auto-started both gMSA services, recreated the local broker,
  preserved the exact production service configuration, advanced USN continuity,
  produced a fresh `ConfiguredCollection` result of `Complete`, and caught up
  the exact pre-reboot change.

---

## Security Event Log validation

FI reads the local Windows Security log under the restricted `FICollector`
identity.

The collector does not require local Administrator membership for that source.

The operational model uses local `Event Log Readers` membership where required.

The Security Event Log collection/checkpoint path has been validated across the
current 2016, 2019, 2022, and 2025 acceptance work.

Detailed audit event generation still depends on Advanced Audit Policy, SACL
coverage, access path, and Windows behavior.

---

## Verification kit routing

The common verification kit lives under:

```text
tools\scripts
```

Release-specific deviations live under:

```text
tools\scripts\2019
tools\scripts\2022
tools\scripts\2025
```

The rule is:

> Use the common test unless a validated release-specific script exists for that
> release and test number.

The step-by-step routing is documented in:

```text
tools\README.md
```

---

## Current release-specific files

### Windows Server 2019

```text
go\cmd\usnprobe\2019\
tools\scripts\2019\01-USN-Access-Characterization.ps1
tools\scripts\2019\README.md
```

The 2019 characterization is engineering validation, not customer Test 01.

### Windows Server 2022

```text
go\cmd\usnprobe\2022\main_windows_2022.go
tools\scripts\2022\07-FileServer-Config-ACL.ps1
tools\scripts\2022\08-FileServer-Collector-Boundary.ps1
tools\scripts\2022\README.md
```

Server 2022 uses the common sequence except where the release README routes to a
2022-specific test.

### Windows Server 2025

```text
go\cmd\usnprobe\2025\main_windows_2025.go
go\cmd\containmentprobe\2025\
go\cmd\containmentclientprobe\2025\
go\internal\windows\usnraw\containment_server2025_windows.go
go\internal\windows\usnraw\containment_server2025_windows_test.go
tools\scripts\2025\01-USN-Access-Characterization.ps1
tools\scripts\2025\02-USN-Local-Administrator-Characterization.ps1
tools\scripts\2025\03-Protected-Containment-Characterization.ps1
tools\scripts\2025\04-Install-Production-Pair.ps1
tools\scripts\2025\05-Production-Protected-Containment-Acceptance.ps1
tools\scripts\2025\06-Service-Restart-Acceptance.ps1
tools\scripts\2025\07-Cold-Reboot-Acceptance.ps1
tools\scripts\2025\README.md
```

The Server 2025 directory contains engineering characterization and final
release-specific production acceptance. It does not replace the common customer
Tests 01 through 08; those common tests were also run and passed on build
`26100`.

---

## Acceptance properties shared by the current releases

The validated split-privilege design preserves these properties:

- `FICollector` remains non-admin.
- `FIUSNReader` is the narrow privileged helper.
- both services use separate per-host identities;
- the collector service SID is part of broker runtime authentication;
- ordinary elevated local administrators do not automatically qualify as the
  broker client;
- remote pipe use is rejected;
- configured volumes are derived from administrator-controlled governed roots;
- helper failure cannot advance accepted USN continuity;
- catch-up resumes from the prior accepted checkpoint;
- config remains administrator-controlled;
- state and spool remain collector-owned;
- the collector cannot replace or reconfigure the privileged helper through its
  normal service token; and
- uncertainty remains explicit when FI cannot mechanically resolve a required
  source fact.

---

## Support rule for another Windows Server release

Do not copy a release-specific workaround forward merely because the next release
is newer.

For a new Windows Server release:

1. run the common verification sequence;
2. run raw-volume characterization;
3. reproduce a known-good prior-release procedure before changing it;
4. change one variable at a time;
5. add a release-specific implementation only when the release requires one; and
6. record the result here.
