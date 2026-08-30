# USN Access Characterization Probe

`usnprobe` is an **engineering/lab characterization tool**.

It is not part of the FI product runtime and is not used by `FICollector` or
`FIUSNReader`.

The probe exists because Windows Server versions can differ in direct-volume and
USN behavior. It was used to test raw-volume access masks and
`FSCTL_QUERY_USN_JOURNAL` / `FSCTL_READ_USN_JOURNAL` behavior during the
Windows Server 2016 privilege investigation.

Its results informed the current split-privilege design:

```text
FICollector    -> restricted / non-admin
FIUSNReader    -> narrow privileged raw-volume USN helper
```

Do not deploy `usnprobe` as an FI production service or treat it as a supported
collector command.

Keep it only as long as it remains useful for controlled Windows-version
characterization. If it is no longer needed for that purpose, remove the tool
rather than expanding it into another runtime component.
