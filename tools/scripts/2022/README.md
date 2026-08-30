# FI Windows Server 2022 Verification Notes

This directory contains Windows Server 2022-specific verification deviations.

The normal customer sequence still begins with the common numbered kit under:

```text
tools\scripts
```

Only use a 2022-specific script where this README says to do so.

## Validated release

```text
Windows Server 2022
Version 10.0.20348
Build 20348
```

A different build family must not be assumed to require the same
release-specific behavior.

## Numbered verification routing

```text
01 -> common
02 -> common
03 -> common
04 -> common
05 -> common
06 -> common
07 -> 2022\07-FileServer-Config-ACL.ps1
08 -> 2022\08-FileServer-Collector-Boundary.ps1
```

The complete operator sequence is in `tools\README.md`.

## Why Test 07 and Test 08 are release-specific

The common verification baseline is intentionally kept stable.

When Server 2022 exposed release-specific behavior during acceptance, the
adjustment was isolated under this directory rather than rewriting the common
baseline for already-green releases.

## Raw-volume characterization

Server 2022 raw-volume characterization source:

```text
go\cmd\usnprobe\2022\main_windows_2022.go
```

Validated result:

```text
Non-admin                         FAIL
Non-admin + SeManageVolume        FAIL
Local Administrator               PASS
FILE_READ_DATA                    least tested successful raw-volume access
```

No raw-USN architecture change was required for Server 2022.

## Protected system ETL containment difference

Server 2022 exposed a different File-ID behavior for protected system objects.

The failure was localized to target `OpenFileById`:

```text
root open                            PASS
root final normalized GUID path     PASS
target zero-access OpenFileById     FAIL / Error 5
```

Protected objects included system ETL files under locations such as:

```text
C:\Windows\System32\LogFiles\WMI\RtBackup
```

The failure was not caused by governed-root path comparison.

## SeBackup characterization

Controlled characterization established:

```text
before enable
    zero-access OpenFileById      FAIL / Error 5

enable SeBackupPrivilege
    privilege present            TRUE
    privilege enabled            TRUE

while enabled
    same zero-access OpenFileById PASS

restore prior privilege state
    restored                     TRUE

after restore
    same zero-access OpenFileById FAIL / Error 5
```

`SeBackupPrivilege` alone was sufficient for this specific containment
operation.

No `SeRestorePrivilege` is used.

No broader target desired access is requested.

## Production Server 2022 rule

The production implementation is gated to:

```text
10.0.20348
```

Sequence:

```text
normal zero-access OpenFileById
        |
        +-- PASS
        |     -> normal containment
        |
        +-- ERROR_ACCESS_DENIED
              |
              +-- build 20348
                    |
                    +-- enable SeBackupPrivilege
                    +-- retry same zero-access OpenFileById
                    +-- resolve Contained / Outside / Unavailable
                    +-- restore prior privilege state
```

The fallback is used only after the ordinary zero-access open already returned
Access Denied.

A privilege-restoration failure fails the containment operation.

## Production acceptance result

The release-specific production integration test established:

```text
correct Server 2022-specific helper active       PASS
collector checkpoint frozen while collector down PASS
outside object explicitly denied to helper       PASS
in-scope control marker selected                  PASS
denied outside object filtered                    PASS
ScopeUnresolvedIncluded                           absent
FIUSNReader error 5                               absent
scope_unresolved_object_count                     0
ConfiguredCollection                              Complete
FICollector                                       Running
FIUSNReader                                       Running
```

That closes the protected-system containment issue for the validated build.

## What this does not mean

The 2022 workaround is not a generic Windows rule.

It does not establish that:

- Server 2016 needs the fallback;
- Server 2019 needs the fallback; or
- Server 2025 should inherit the fallback.

Each release is characterized before FI changes release-specific behavior.
