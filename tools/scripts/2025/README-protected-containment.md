# Windows Server 2025 Protected Containment Characterization

This characterization is intentionally separate from production FI behavior.

Target release:

```text
Windows Server 2025
10.0.26100
```

Purpose:

1. select an existing protected NTFS system file;
2. obtain its NTFS file reference number and sequence number;
3. open a separate governed-root handle;
4. attempt the exact production-style zero-access `OpenFileById`;
5. only when that attempt returns Access Denied, enable `SeBackupPrivilege`
   inside the characterization process;
6. retry the exact same zero-access `OpenFileById`;
7. restore the process token to its prior privilege state;
8. repeat the zero-access call after restore.

The probe does not change production FI code and does not grant a persistent
`SeBackupPrivilege` assignment to the gMSA.

Expected Server 2022-like pattern:

```text
before privilege              Access Denied
enable SeBackupPrivilege      success
same zero-access OpenFileById success
restore prior state           success
after restore                 Access Denied
```

A different result on build 26100 must be treated as Server-2025-specific
behavior until independently understood.
