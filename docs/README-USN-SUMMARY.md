# FI USN Architecture Summary

FI uses the NTFS USN Journal to discover filesystem changes efficiently and to
maintain continuity between observations.

The USN Journal is not treated as the current authoritative state of a file. It
tells FI that an NTFS object changed and provides object identity and change
facts. FI then performs fresh observation and determines whether the current
object belongs to a configured governed root.

## Validated Windows Server releases

The split-privilege Windows behavior underlying the Phase 1 design has been
characterized on:

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
Windows Server 2025    10.0.26100
```

Exact Candidate #4 Gate 1 acceptance is tracked separately:

```text
Windows Server 2016    10.0.14393    COMPLETE
Windows Server 2019    10.0.17763    PENDING
Windows Server 2022    10.0.20348    PENDING
Windows Server 2025    10.0.26100    PENDING
```

The four-operation broker, including live `ReadSACL`, is currently accepted
only on Server 2016 build `14393`. Earlier 2019/2022/2025 characterization
does not by itself establish Candidate #4 acceptance.

Later Windows Server releases and uncharacterized builds are characterized
independently.

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

ReadSACL(
    governedRoot,
    fileReferenceNumber,
    sequenceNumber
)
```

`QueryJournal` and `ReadJournal` perform the narrow direct-volume USN work.

`CheckContainment` exists for the narrow case where the non-admin collector
cannot re-open a changed object by File ID because Windows returned Access Denied.

`ReadSACL` performs a separately authorized exact-object privileged SACL read.
The helper returns only the bounded raw SACL security descriptor. FICollector
parses the descriptor and constructs the resulting FI record. Responses are
rejected when empty or larger than 128 KiB.

The containment operation returns only:

```text
Contained
Outside
Unavailable
```

`CheckContainment` does not return the target path, metadata, ACL, hash,
content, or an organizational conclusion. `ReadSACL` is a separate broker
operation with its own exact-object authorization and bounded descriptor
response.

## Raw-volume access

2019, 2022, and independently characterized Server 2025 build `26100`
established:

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

## Protected-object containment on Server 2022 and Server 2025

Windows Server 2022 build `20348` exposed a protected-object difference for some
protected system ETL objects. Server 2025 build `26100` independently reproduced
the same bounded behavior.

For those characterized builds, the helper's normal zero-access `OpenFileById`
can return Access Denied. Only after that normal attempt fails, FI enters the
release/build-specific path:

```text
20348 -> Server 2022 scoped retry
26100 -> Server 2025 scoped retry
other build -> no automatic fallback
```

The scoped retry temporarily enables `SeBackupPrivilege`, retries the exact same
zero-access File-ID open, determines mechanical containment, and restores the
exact previous privilege state before returning.

This fallback:

- is not enabled for 2016;
- is not enabled for 2019;
- is not assumed for an adjacent or future Server 2025 build;
- does not use `SeRestorePrivilege`;
- does not request broader target-object access;
- fails closed if exact privilege restoration fails; and
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

The helper performs only the narrow privileged operations defined above.
`FICollector` retains USN parsing, collection policy, descriptor parsing,
record construction, hashing, persistence, continuity, and checkpoint ownership.

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
