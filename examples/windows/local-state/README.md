# FI Local Runtime DACL Provisioning

These scripts provision and verify the NTFS access rules for FI-owned local
runtime data under `%ProgramData%\FI`.

They are **administrator-run deployment/provisioning tools**. `fi.exe` does not
call them and does not grant itself permissions.

## Intended boundary

The runtime identity receives:

| Path | Runtime access |
| --- | --- |
| `%ProgramData%\FI` | `ReadAndExecute`, this directory only |
| `%ProgramData%\FI\config` | `ReadAndExecute` |
| `%ProgramData%\FI\state` | `Modify` |
| `%ProgramData%\FI\spool` | `Modify` |

`SYSTEM` and the local `Administrators` group retain `FullControl` on all four
FI-owned locations. Each location receives a protected DACL so unrelated parent
permissions do not silently expand FI runtime access.

`config` is intentionally not writable by the FI runtime identity. `state` and
`spool` must be writable because FI creates and replaces checkpoints, operation
and resource journals, supporting-SID state, spool data, manifests, and temporary
files there.

These scripts do **not** configure access to governed roots, the Windows Security
log, USN journal access, SMB/identity sources, LDAPS, service logon rights, or the
FI executable location. Those are separate least-privilege deployment tests.

## Provision

Run in elevated **Windows PowerShell 5.1**:

```powershell
cd C:\Users\jwood.admin\src\fi\examples\windows\local-state

.\Set-FILocalStateAcl.ps1 -RuntimeIdentity 'ISS\svc-fi$'
```

Use the actual FI gMSA/account name when it exists.

Preview with PowerShell's normal `-WhatIf` support:

```powershell
.\Set-FILocalStateAcl.ps1 -RuntimeIdentity 'ISS\svc-fi$' -WhatIf
```

## Verify

```powershell
.\Test-FILocalStateAcl.ps1 -RuntimeIdentity 'ISS\svc-fi$'
```

The verifier exits with code `1` if any expected directory is missing, the DACL
is not protected, or the explicit rule set differs from the intended model.

## Important

Changing these DACLs is an administrative deployment action against FI-owned
runtime directories. It is not governed-file collection behavior and must not be
confused with FI's normal runtime boundary of observing customer source systems
without remediation.
