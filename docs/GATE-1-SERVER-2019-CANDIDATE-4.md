# FI Gate 1 Candidate #4 — Windows Server 2019 Verification

Record date: 2026-09-04

Status: **COMPLETE**

This record captures exact Candidate #4 Gate 1 acceptance on Windows Server 2019
build `17763`. It is separate from earlier Windows release/build
characterization and does not extend acceptance to adjacent builds.

## Test host

```text
Host:       ISS-FS-19
OS:         Microsoft Windows Server 2019 Standard Evaluation
Version:    10.0.17763
Build:      17763
Install:    Server Core
Domain:     iss.local
```

## Candidate #4 artifact identity

Collector:

```text
Artifact: fi-candidate-4.exe
Installed: C:\Program Files\FI\fi.exe
Size:      6,649,344 bytes
SHA-256:   6D641A73D0CE116BA09C16885371164BF580D36631DD6F031090B2EE5DC86C13
```

Privileged helper:

```text
Artifact: fi-usn-candidate-4.exe
Installed: C:\Program Files\FI\fi-usn.exe
Size:      3,346,944 bytes
SHA-256:   A71A769F25E9CCB0C9ACAF8CAFBE6C751AEB8F3884FC5EBD1BF7723B3BBF2263
```

Build characteristics:

```text
Go:          go1.27.0
GOOS:        windows
GOARCH:      amd64
CGO_ENABLED: 0
trimpath:    enabled
```

## Deployed identity and service boundary

The accepted deployment used separate per-host gMSAs:

```text
FICollector: ISS\gFI-FS19$
FIUSNReader: ISS\gFI-USN-FS19$
```

Accepted properties:

- `FICollector` is non-administrative.
- `FIUSNReader` is inside the local Administrator boundary required by the
  characterized raw-USN design.
- Both services use managed accounts.
- `FICollector` service SID type is `UNRESTRICTED`.
- `FICollector` owns normal config/state/spool work and checkpoints.
- `FIUSNReader` exposes only `QueryJournal`, `ReadJournal`, `CheckContainment`,
  and `ReadSACL` over the local FI-USN broker boundary.

Deployment acceptance report:

```text
C:\ProgramData\FI\gate1-results\gate1-deployment-ISS-FS-19-0fa57b5fb91a.json
SHA-256: 8828B98C008653BA7ACC25F4F63F3D7A037CE5629AB4A248615A1EC083EEF0B0
```

Readiness record:

```text
C:\ProgramData\FI\gate1-results\gate1-readiness-ISS-FS-19-e70e3bca0e28.json
SHA-256: C14A27779C18364C4EDED5F828ABE619D657043BE6F98C25B845FB03FDED0A51
```

## Exact FICollector service-token boundary — Test 08

The lab-only collector-boundary probe was built from the reviewed current source
inputs and staged only for the controlled test.

Probe build input Git blobs:

```text
go/cmd/collectorboundaryprobe/main_windows.go
4742981306b09e003e113ac26ca9c472f24a84e5

go/go.mod
bbcec54b05d1bcf3a76fca856b92e67fba478a23

go/go.sum
37ee2d44caf72120ea223c3ea3312b3a5cad450a
```

Built probe:

```text
Size:    4,512,768 bytes
SHA-256: AFCB5D27503E35488126BE1DA1DFE1B097306312F82972124429F61B63254039
```

The actual `FICollector` service token was then validated. It could perform the
intended config-read/state-write/spool-write/query-status operations and was
denied write/delete access to installed FI executables and denied
`CHANGE_CONFIG`, `WRITE_DAC`, and `WRITE_OWNER` access to `FIUSNReader`.

Result:

```text
C:\ProgramData\FI\state\collector-token-boundary-probe.json
SHA-256: FEB775269E572BD4F25EBBDC50F262A3FD4670C376994175718C81B2CD9DC111
Overall: PASS
Failure count: 0
```

The production service command line and exact Candidate #4 binaries were restored
and verified after the controlled test. The lab probe executable was removed.

## Local governed-file activity — Test 10A

Two Server 2019 activity records are retained.

The first run is intentionally retained as failed history:

```text
Run ID:   3971b61b7ffa
SHA-256:  74ECE6F039F7ED7D2D3E435ED688C4955F82B5C4ACE683264B46B5C97E76C439
Result:   FAIL
Reason:   denied-read/denied-write audit and FI-spool custody records were missing
```

The corrected accepted run is:

```text
Run ID:   9d7d39184f9a
SHA-256:  A51380644A8525DA213712854F4CC81BE156C52202E1CDD981C90C65BDC204C6
Result:   PASS
```

The accepted run established:

- create, modify/write, successful read, rename, move, delete, hard-link,
  ACL-change, and ownership-change workload execution;
- denied read and denied write with matching Windows Security audit records;
- preservation of the exact denied-read and denied-write Security events in
  finalized FI spool custody;
- live SACL current-state observation as `Present`, `Interpreted`, and
  `Complete`; and
- a fully post-workload configured collection with outcome `Complete` and
  `1/1` governed roots completed.

## True remote SMB — Tests 10B / 10C

Accepted remote SMB correlation:

```text
Run ID:   2e6ef094e4a3
Report:   C:\ProgramData\FI\gate1-results\gate1-remote-smb-correlation-ISS-FS-19-2e6ef094e4a3.json
SHA-256:  09A903B93599088645920D17C27F5397AF4D861D5AA6FE6E01CD453D22E2D54E
Result:   PASS
```

Observed facts:

```text
Security query truncated: False
Event 5145 count:         21
FI spool match total:     2
Latest FI collection:     Complete
Remote source IP:         192.168.1.220
Share:                    \\*\C$
```

FI spool contained both the original and renamed remote-SMB test filenames.
The 5145 records preserve source/share/path semantics; their presence is not
interpreted as proof of any fact Windows did not record.

## Collector restart and USN catch-up

The controlled collector restart test preserved checkpoint continuity and caught
up after restart.

Accepted observed checkpoint movement:

```text
Before: 340309304
After:  340320760
```

The post-restart configured collection completed and durable spool custody was
accepted.

## FIUSNReader outage and catch-up

A controlled helper outage was exercised under run ID `ad71a63c17e0`.

Observed facts:

```text
Baseline USN checkpoint: 340343528
Checkpoint while helper unavailable: 340343528
Checkpoint after helper recovery: 340358976
```

During the helper outage:

- `FICollector` remained running;
- the configured collection explicitly recorded the unavailable FIUSNReader
  pipe;
- the USN checkpoint did not advance; and
- other collector work/spool creation continued.

A file created during the outage was present in catch-up spool after helper
recovery.

Accepted report:

```text
C:\ProgramData\FI\gate1-results\server2019-helper-outage-ad71a63c17e0.json
SHA-256: FE3FA4515942AF697196E0D05C499338BEEF8E989440084DD665A0A7FF75BCF5
Result: PASS
```

## Live ReadSACL acceptance

The accepted Server 2019 activity run contains a live FI USN object observation
with readable current SACL state:

```text
State:              Present
Data format:        Interpreted
Observation status: Complete
```

This closes the exact Candidate #4 `ReadSACL` acceptance requirement on Windows
Server 2019 build `17763` while descriptor parsing and FI record construction
remain in the non-admin collector.

## Test 12D — controlled AD-LDAPS dependency observation

Test 12D is the bounded passive observer. The dependency fault was created and
removed outside the observer itself.

The repository-canonical payload identity is:

```text
Git blob, canonical LF:
08723bc8be60dd6e95710a977d84cd4222cb1ae6

Canonical LF SHA-256:
EA92830748A0F474F2EF107E1BF95B10475FE9E42DA5A43AF4DF4A7D4FC69F27
```

The staged Windows copy used CRLF line endings. Its logical content was proven
identical by normalization:

```text
Raw staged CRLF SHA-256:
85F267F036D3B6CF3ADC69DF13BE1BE07E827BF285494071766F2E8E952AB19E

LF-normalized staged SHA-256:
EA92830748A0F474F2EF107E1BF95B10475FE9E42DA5A43AF4DF4A7D4FC69F27

LF-normalized staged Git blob:
08723bc8be60dd6e95710a977d84cd4222cb1ae6
```

No logical/content drift was present; only line-ending representation differed.

Accepted observation records:

```text
Before
F308CA4A2717FE9CE184B1A07BB147BD83BE1C55866754AB6772D57FD5B5AE0F

During
983A525DDA1B9515A088DBB5E1640561D73562024514E756887A8558794660B6

After
9314FF98F0AF2AE801F9DFFAC8863C115CB1BDCCDD5D9C23EBA02C981A782013
```

The controlled outbound TCP/636 block existed from:

```text
2026-09-04T22:34:53.9243535Z
through
2026-09-04T22:35:56.4196523Z
```

During that interval:

- `DC16.iss.local:636` was independently confirmed unreachable from
  `ISS-FS-19`;
- `FICollector` remained running;
- `FIUSNReader` remained running; and
- a fresh configured collection completed at
  `2026-09-04T22:35:52.864270700Z` with outcome `Complete`.

The exact firewall rule was removed, TCP/636 recovered on the first bounded
verification attempt, a fresh post-restoration collection completed at
`2026-09-04T22:36:53.550327700Z`, and the independently armed SYSTEM rollback was
disarmed only after restoration had been proven.

Claim boundary: this proves continued configured governed-root collection during
a real LDAPS transport outage and verified restoration. The outage did not span a
scheduled supporting-source refresh, so this record does **not** claim that an AD
supporting refresh itself failed and recovered during this interval.

## Final safety state

At closure:

- `FICollector` was `Running`;
- `FIUSNReader` was `Running`;
- exact Candidate #4 executable hashes remained installed;
- no Test 12D firewall fault remained;
- no Test 12D rollback scheduled task remained; and
- the Test 08 lab-only probe executable had been removed.

## Acceptance conclusion

Windows Server 2019 build `17763` is **COMPLETE** for exact Candidate #4 Gate 1
acceptance.

This acceptance is limited to the exact release/build and exact Candidate #4
artifacts identified above. It does not declare production collection cadence,
production sizing, or any adjacent/future Windows build accepted by similarity.

Overall Gate 1 remains open for exact Candidate #4 acceptance on Windows Server
2022 build `20348`, Windows Server 2025 build `26100`, remaining representative
production-characterization work, and final cross-version Gate 1 review.
