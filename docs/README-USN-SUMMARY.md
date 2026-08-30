# FI USN Architecture Summary

FI uses the NTFS USN Journal to discover filesystem changes efficiently and to
maintain continuity between observations.

The USN Journal is not treated as the current authoritative state of a file. It
tells FI that an NTFS object changed and provides object identity and change
facts. FI then performs fresh observation and determines whether the current
object belongs to a configured governed root.

## Validated Windows Server releases

The current Phase 1 split-privilege design has been validated on:

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
```

Later Windows Server versions are characterized independently.

See `docs/WINDOWS-SERVER-VALIDATION.md` for release-specific findings.

## Per-host service identities

Each monitored Windows server uses two unique gMSAs:

```text
<HOST>
    gFI-<HOST>$          -> FICollector
                            restricted / non-admin

    gFI-USN-<HOST>$      -> FIUSNReader
                            local Administrator on that host only
```

The main collector is not made Administrator in order to read the USN Journal.

## Local broker

`FICollector` communicates with `FIUSNReader` through:

```text
\\.\pipe\FI-USN
```

The pipe rejects remote clients.

Its DACL permits SYSTEM, Builtin Administrators, and the
`NT SERVICE\FICollector` service SID. Runtime authorization separately requires
the enabled, non-deny-only `NT SERVICE\FICollector` service SID.

An ordinary process does not qualify merely because it runs as the same collector
gMSA.

## FIUSNReader operations

The privileged helper exposes only bounded operations:

```text
QueryJournal(governedRoot)

ReadJournal(
    governedRoot,
    startUSN
)

CheckContainment(
    governedRoot,
    fileReferenceNumber,
    sequenceNumber
)
```

`QueryJournal` and `ReadJournal` perform the narrow direct-volume USN work.

`CheckContainment` exists for the narrow case where the non-admin collector
cannot re-open a changed object by File ID because Windows returned Access Denied.

The containment operation returns only:

```text
Contained
Outside
Unavailable
```

It does not return the target path, metadata, ACL, hash, content, or an
organizational conclusion.

## Raw-volume access

2019 and 2022 characterization established:

```text
Non-admin                         FAIL
Non-admin + SeManageVolume        FAIL
Local Administrator               PASS
FILE_READ_DATA                    least tested successful raw-volume access
```

Production raw-volume query/read therefore uses `FILE_READ_DATA` rather than
`GENERIC_READ`.

FI does not enable `SeManageVolumePrivilege` as a production substitute for the
helper's local-Administrator service-token boundary.

## Server 2022 protected-object containment

Windows Server 2022 build `20348` exposed a protected-object difference.

For some protected system ETL objects, the helper's normal zero-access
`OpenFileById` can return Access Denied.

Only on build `20348`, and only after that normal zero-access open returns Access
Denied, FI temporarily enables `SeBackupPrivilege`, retries the same zero-access
open, determines mechanical containment, and restores the exact previous
privilege state.

This fallback:

- is not enabled for 2016;
- is not enabled for 2019;
- is not automatically enabled for 2025 or another future release;
- does not use `SeRestorePrivilege`;
- does not request broader target-object access; and
- does not move path, metadata, ACL, hash, or content collection into the helper.

## FICollector remains the collector

`FICollector` remains responsible for:

- USN parsing;
- normal File-ID re-observation;
- governed-root collection policy;
- NTFS metadata/security/stream/reparse collection;
- hashing;
- spool persistence;
- continuity assessment;
- checkpoint advancement;
- Windows Security collection; and
- SMB/local/AD supporting sources.

The helper performs a mechanical containment check only when Windows access
prevents the restricted collector from resolving that fact directly.

## Configuration is the source of truth

Allowed USN volumes are derived from FI's administrator-controlled governed-root
configuration.

There is no separate USN allowlist.

Because USN is volume-wide, the broker can observe raw journal metadata for
changes elsewhere on an approved volume. That does not make the entire volume
governed.

## Design rule

> **If an operation does not require the privileged Windows source boundary, it
> does not belong in FIUSNReader.**

For the complete trust boundary, authentication flow, release-specific
containment behavior, failure semantics, and deployment requirements, see
`docs/security/usn-privilege-boundary.md`.
