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

A later Windows Server release must be characterized independently before FI
assumes that its raw-volume, service-token, Security Event Log, File-ID, or
protected-object behavior is identical.

Windows Server 2025 is not implicitly treated as Server 2022.

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

The 2022 behavior is not automatically enabled for 2016, 2019, or a later
Windows Server release.

---

## Security Event Log validation

FI reads the local Windows Security log under the restricted `FICollector`
identity.

The collector does not require local Administrator membership for that source.

The operational model uses local `Event Log Readers` membership where required.

The Security Event Log collection/checkpoint path has been validated across the
current 2016, 2019, and 2022 acceptance work.

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
