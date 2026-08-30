# Windows Server 2019 USN Access Characterization Probe

This directory contains the Windows Server 2019 USN access characterization
source.

Source:

```text
go\cmd\usnprobe\2019\main_windows_2019.go
```

Probe version:

```text
windows-server-2019-usn-characterization/0.2
```

Version 0.2 explicitly attempts to enable `SeManageVolumePrivilege` in its own
service token before running the raw-volume access matrix.

This matters because assigning a Windows user right places the privilege in a
new logon token, but privileges may be disabled. A characterization result must
distinguish:

```text
privilege not present in token
privilege present and successfully enabled
raw-volume access result after enablement
```

Build:

```powershell
cd C:\Users\jwood.admin\src\fi\go

go build `
    -o C:\FI-Test\fi-usn-probe-2019.exe `
    .\cmd\usnprobe\2019
```

Runtime artifacts:

```text
Executable:
C:\FI-Test\fi-usn-probe-2019.exe

Service:
FIUSNProbe2019

Input:
C:\FI-Test\usnprobe\input-2019.json

Result:
C:\FI-Test\usnprobe\usn-access-matrix-2019.json

Error:
C:\FI-Test\usnprobe\usn-access-matrix-2019-error.txt
```

The probe does not use or create `C:\ProgramData\FI`.

It is an engineering characterization tool, not an FI production runtime
component.
