# FI USN Architecture Summary

FI uses the NTFS USN Journal to discover filesystem changes efficiently and to maintain continuity between observations.

The USN Journal is not treated as the current authoritative state of a file. It tells FI that an NTFS object changed and provides the object's file identity. FI then performs a fresh NTFS observation by File ID and proves whether that object is currently inside a configured governed root.

On Windows Server 2016, FI's current direct-volume USN access requires administrative privilege. FI therefore separates that access from the main collector.

Each monitored Windows server uses two unique gMSAs:

```text
<HOST>
    gFI-<HOST>$          -> FICollector
                            restricted / non-admin

    gFI-USN-<HOST>$      -> FIUSNReader
                            local Administrator on that host only
```

The privileged `FIUSNReader` service performs only the direct-volume operations required to query and read the USN Journal. FICollector communicates with it through an authenticated local named pipe.

FICollector remains responsible for:

- USN parsing
- File-ID re-observation
- current governed-root containment
- hashing
- spool persistence
- continuity assessment
- checkpoint advancement
- other FI collection sources

The allowed USN volumes are derived from FI's existing administrator-controlled governed-root configuration. There is no separate USN allowlist.

The design rule is:

> **If an operation does not require privileged direct-volume access, it does not belong in FIUSNReader.**

For the complete design, authentication flow, security controls, failure behavior, and incident-response model, see:

`docs/security/usn-privilege-boundary.md`
