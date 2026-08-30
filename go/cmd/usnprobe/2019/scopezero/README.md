# Windows Server 2019 zero-access File-ID scope characterization

This probe is intentionally separate from production FI code.

It answers one question:

> Can the restricted FI collector gMSA open protected NTFS objects/parents by
> File ID with `dwDesiredAccess = 0` and resolve their handle-derived final path,
> when the same identities fail with `FILE_READ_ATTRIBUTES`?

The probe compares two access masks for every supplied identity:

- `NoAccess` = `0x00000000`
- `FileReadAttributes` = `0x00000080`

For each open that succeeds it calls `GetFinalPathNameByHandleW` with
`FILE_NAME_NORMALIZED | VOLUME_NAME_GUID` and mechanically compares the
returned path to the governed-root final path.

It does not alter FI production source or semantics.

Service name:

`FIScopeProbe2019`

Files:

- input: `C:\FI-Test\scopezero-2019\input.json`
- result: `C:\FI-Test\scopezero-2019\result.json`
- error: `C:\FI-Test\scopezero-2019\error.txt`
