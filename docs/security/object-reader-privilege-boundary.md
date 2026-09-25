# FI NTFS Object Reader Privilege Boundary

## Purpose

This document defines the Windows privilege, authorization, deployment, and
failure boundary for `FIObjReader`.

`FIObjReader` exists so the normal non-administrative `FICollector` can retain a
bounded current-state observation of an exact governed NTFS object when that
object's DACL prevents the collector from opening it itself.

`FIObjReader` is separate from `FIUSNReader`.

```text
FICollector
    non-admin
        |
        +-- FIUSNReader
        |     raw-volume USN operations
        |     bounded containment
        |     bounded SACL read
        |
        +-- FIObjReader
              exact governed NTFS object observation
              backup-authority open
```

## Runtime identity

The characterized service model is:

```text
service:  FIObjReader
binary:   fi-obj.exe
pipe:     \\.\pipe\FI-OBJ
identity: dedicated per-host gMSA
```

The Windows Server 2016 characterization used:

```text
host:             ISS-FS-01
Windows build:    10.0.14393
service identity: ISS\gFI-OBJ-FS01$
```

The helper gMSA was not a local Administrator and was not a member of Backup
Operators.

The characterized rights were:

```text
SeServiceLogonRight
SeBackupPrivilege
SeSecurityPrivilege
```

It did not require:

```text
SeRestorePrivilege
SeManageVolumePrivilege
```

The live steady-state token showed `SeBackupPrivilege` and
`SeSecurityPrivilege` assigned but disabled. After successful observation both
were again disabled.

## Separation from FIUSNReader

FIUSNReader requires a stronger local boundary because direct-volume USN
query/read has required local-Administrator-capable raw-volume access on the
currently characterized Windows Server releases.

That requirement must not automatically apply to protected governed-object
observation.

```text
FICollector
    non-admin ordinary governed-object access

FIObjReader
    non-admin
    SeBackupPrivilege
    SeSecurityPrivilege

FIUSNReader
    local Administrator where required
    raw-volume USN authority
```

A compromise of FIObjReader remains security-significant because the process can
exercise privileged read authority over configured governed roots. It is not a
general local-administration service.

## Broker authorization

FIObjReader exposes one logical operation:

```text
ObserveObject(
    governedRoot,
    fileReferenceNumber,
    sequenceNumber
)
```

The caller does not supply authoritative FI scope identity.

The helper:

1. captures administrator-configured governed roots at startup;
2. derives canonical FI scope identity internally;
3. requires an exact configured-root match;
4. validates NTFS File Reference Number and sequence number;
5. rejects remote use;
6. authenticates the connected client token; and
7. requires the enabled, non-deny-only `NT SERVICE\FICollector` service SID.

An ordinary process running as the collector gMSA does not qualify merely
because the account name matches.

The protocol is fixed and versioned. It is not an arbitrary filesystem RPC
surface.

## Prohibited expansion

FIObjReader must not become:

```text
arbitrary ReadFile
arbitrary OpenPath
generic filesystem proxy
generic FSCTL proxy
raw-byte download service
command runner
PowerShell host
registry administration helper
service-control helper
remote administration endpoint
ACL modification service
ownership modification service
```

The helper is intentionally structured around one exact governed NTFS object
identity.

## Fallback trigger

Normal FI collection remains primary:

```text
USN identifies changed NTFS object
        |
        v
FICollector normal exact File-ID observation
        |
        +-- success
        |      -> DirectWindowsNTFS
        |
        +-- initial OpenFileById = ERROR_ACCESS_DENIED
               |
               v
        FIObjReader ObserveObject
               |
               +-- success
                      -> BackupAuthorityWindowsNTFS
```

The fallback is entered only for that initial exact-open Access Denied condition.

Failures later in metadata collection, security processing, hashing, path
consistency, identity validation, scope validation, or context handling do not
automatically enter FIObjReader.

## Object authority and containment

The helper receives the configured governed root plus exact NTFS File Reference
Number and sequence number.

The caller cannot provide a trusted FI `scope_id`.

Scope identity is derived from the administrator-controlled configured root
using FI's shared canonical scope derivation.

The helper independently validates that the requested current object is inside
the exact configured governed root before returning the bounded observation.

## Privilege use

`SeBackupPrivilege` is scoped around the exact backup-authority object open.

`SeSecurityPrivilege` is scoped around the required SACL read.

FI restores the exact prior token privilege state before the privileged
operation returns.

Privilege restoration failure fails the operation.

The service is expected to remain at steady state with both privileges disabled.

## Returned observation

A successful operation returns FI's bounded structured NTFS observation, not an
unrestricted file stream.

The observation may include:

```text
volume identity
NTFS object identity
parent binding
current path binding
metadata
owner and primary group
DACL
SACL
stream inventory
reparse state
bounded 16-byte content prefix
content hashes
observation status
warnings
```

Content hashing occurs inside the bounded helper operation.

Successful provenance is explicit:

```text
collection_entry_method = NTFSFileID
collection_method       = BackupAuthorityWindowsNTFS
```

Ordinary collection remains:

```text
collection_method = DirectWindowsNTFS
```

Collection authority describes how that particular observation was obtained. It
is not a permanent property of the NTFS object.

## Deployment requirements

The characterized deployment requires:

```text
dedicated per-host gMSA
Log on as a service
SeBackupPrivilege
SeSecurityPrivilege
no local Administrator membership
no Backup Operators membership
no SeRestorePrivilege requirement
no SeManageVolumePrivilege requirement
read access to required FI program/configuration paths
local-only broker
FICollector service-SID authentication
administrator-controlled governed-root configuration
```

FIObjReader is installed separately from FIUSNReader.

Source-object ACL inheritance is not an FIObjReader prerequisite.

FI does not modify governed-object ACLs to make collection succeed.

## Windows Server 2016 characterization

The first end-to-end characterization was completed on Windows Server 2016 build
`10.0.14393` using `ISS-FS-01`.

The controlled object remained:

```text
volume:
\\?\Volume{0eafbd57-0000-0000-0000-100000000000}\

file_reference_number: 270203
sequence_number:        1070
```

An explicit read/read-execute deny was applied to the normal collector identity.

The observed DACL contained:

```text
AccessDenied   ISS\gFI-FS01$
AccessAllowed  ISS\gFI-FS01$  inherited
```

FIObjReader returned complete observations with zero warnings, structural and
security state, a 16-byte content prefix, and content hashes.

The observed SHA-256 was:

```text
120cb326d97a9ef5f4d53a07d361ed1145a5bed4e7d4c65dcd80023faaf898a9
```

While the deny remained active, a controlled timestamp-only change produced
`BasicInfoChange` and the same content hash. FI again used
`BackupAuthorityWindowsNTFS`.

After the original ACL was restored, the same FRN/sequence was observed through
ordinary `DirectWindowsNTFS`, and the explicit deny was absent.

The relational history therefore preserved the transition from
backup-authority collection back to ordinary direct collection.

## Artifact provenance

The characterized source commit was:

```text
b5e5f7ed0648f392dd54a1777f1671aab619893d
```

Deployed SHA-256 values were:

```text
FICollector
b8a0ada73a065356d263e24ae4a3c3108d5badd938ecb8662b35d329671c6400

FIObjReader
1b8311f7f51bcfa020a048c1ea6be979804baecc148f29594845921377e21e46
```

Both matched artifacts built from that commit.

## Backend compatibility result

The first immutable generation carrying `BackupAuthorityWindowsNTFS` reached an
older strict relational worker that did not recognize the new semantic value.

The older worker failed closed with:

```text
SOURCE_RECORD_REJECTED
UnsupportedValue: collection_method
```

and committed zero relational source records for that rejected attempt.

Immutable generation custody and append-only retry history remained intact.

After deployment of a compatible ingest worker built from the characterized
commit, the same immutable generation retried through durable journal state and
completed:

```text
records_seen      20
records_committed 20
outcome           Accepted
```

The earlier rejection remained in ingest history.

Producer changes that introduce a new enumerated semantic value require explicit
compatibility coverage and rollout ordering for every downstream strict decoder
or validator.

Unknown semantic values must continue to fail closed rather than being silently
coerced.

## Support boundary

The Windows Server 2016 build `14393` result establishes this behavior only for
the tested release/build.

It does not automatically establish identical FIObjReader behavior on Windows
Server 2019, 2022, 2025, or future releases/builds. Those releases require
independent characterization before equivalent support claims are made.
