# FI Windows Server 2019 Verification Notes

This directory contains Windows Server 2019-specific engineering
characterization.

The normal customer verification sequence remains the common numbered kit under:

```text
tools\scripts
```

Do not replace common tests with a 2019-specific version unless a 2019-specific
script actually exists.

## Validated release

```text
Windows Server 2019
Version 10.0.17763
```

## Normal verification routing

```text
01 -> common
02 -> common
03 -> common
04 -> common
05 -> common
06 -> common
07 -> common
08 -> common
```

Run the sequence documented in `tools\README.md`.

## Raw-volume characterization

Engineering characterization script:

```text
01-USN-Access-Characterization.ps1
```

Associated Go probe:

```text
go\cmd\usnprobe\2019
```

This is engineering characterization, not customer Test 01.

Validated result:

```text
Non-admin                         FAIL
Non-admin + SeManageVolume        FAIL
Local Administrator               PASS
FILE_READ_DATA                    least tested successful raw-volume access
```

Production consequence:

- `FIUSNReader` remains the narrow local-Administrator helper;
- raw USN query/read uses `FILE_READ_DATA`;
- production does not rely on `SeManageVolumePrivilege`; and
- `GENERIC_READ` is broader than the tested access FI requires.

## Protected-object containment

Windows Server 2019 acceptance proved the helper's bounded File-ID containment
operation can resolve protected objects that restricted `FICollector` cannot
directly re-observe.

The helper returns only:

```text
Contained
Outside
Unavailable
```

It does not return target paths, metadata, ACLs, hashes, or content.

No Server-2022-style scoped `SeBackupPrivilege` fallback is enabled for build
`17763`.

## Do not copy forward release behavior

If a later Windows Server version behaves differently:

1. reproduce the 2019 procedure;
2. change only release/host/account/path identifiers;
3. characterize the actual failure; and
4. add a release-specific change only if the release requires one.
