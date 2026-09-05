# FI Gate 1 Candidate #4 Result Record

Record date: 2026-09-04

Overall Gate 1 status: **OPEN**

Windows Server 2016 Candidate #4 status: **COMPLETE**

Windows Server 2019 Candidate #4 status: **COMPLETE**

This record tracks exact Candidate #4 Gate 1 acceptance separately from earlier
Windows release/build characterization.

A prior characterization result does not automatically establish acceptance of a
later FI candidate.

## Candidate #4 artifact identity

Source repository base commit:

```text
3e79bb62525a607a2682b4badbf338884a95226e
Update USN checkpoint ownership comments
```

The Candidate #4 executables were built from the reviewed local Phase 1 working
tree based on that commit.

Collector:

```text
Artifact: fi-candidate-4.exe
Size:     6,649,344 bytes
SHA-256:  6D641A73D0CE116BA09C16885371164BF580D36631DD6F031090B2EE5DC86C13
```

Privileged helper:

```text
Artifact: fi-usn-candidate-4.exe
Size:     3,346,944 bytes
SHA-256:  A71A769F25E9CCB0C9ACAF8CAFBE6C751AEB8F3884FC5EBD1BF7723B3BBF2263
```

Build characteristics:

```text
Go:          go1.27.0
GOOS:        windows
GOARCH:      amd64
CGO_ENABLED: 0
trimpath:    enabled
```

The executable SHA-256 values, not a filename alone, identify the exact
acceptance artifacts.

## Exact Windows build matrix

| Windows Server | Version / build | Windows behavior characterized | Candidate #4 |
|---|---:|---|---|
| Windows Server 2016 | 10.0.14393 | YES | COMPLETE |
| Windows Server 2019 | 10.0.17763 | YES | COMPLETE |
| Windows Server 2022 | 10.0.20348 | YES | PENDING |
| Windows Server 2025 | 10.0.26100 | YES | PENDING |

Adjacent builds are not accepted by similarity.

## Windows Server 2016 Candidate #4 campaign

Test host:

```text
ISS-FS-01
Windows Server 2016
10.0.14393
```

Gate 1 closure-kit results:

| Test | Result | Acceptance scope |
|---|---|---|
| 09 | PASS | Reproducible exact-build-gated two-service/two-gMSA deployment |
| 10A | PASS | Local governed-file activity matrix |
| 10B | PASS | True remote SMB workload |
| 10C | PASS | Server-side SMB/event/spool correlation |
| 11 | PASS | Exact deployment/service/gMSA/binary/ACL boundary acceptance |
| 12A | PASS | Collector restart and USN catch-up |
| 12B | PASS | Bounded lab spool-write denial and recovery |
| 12C | PASS | Bounded lab governed-root unavailability and recovery |
| 12D | PASS | Bounded passive Before/During/After dependency observation |
| 13 | PASS | Repeated bounded real `-perf-root` baseline |
| 14 | PASS | Bounded 1,000-file churn campaign |
| 15 | PASS | Bounded spool-pressure campaign |
| 16 | PASS | Immutable FI operation/resource summary |

The Gate 1 kit extends the existing common/release-specific FI verification
procedures; it does not erase the earlier Windows characterization record.

During Candidate #4 deployment verification, common Tests 01, 07, and 08 were
also re-run successfully.

## Windows Server 2019 Candidate #4 campaign

Test host:

```text
ISS-FS-19
Windows Server 2019
10.0.17763
```

The exact Candidate #4 collector/helper hashes matched the artifacts identified
above throughout the acceptance campaign.

Accepted Server 2019 results include:

- reproducible exact-build-gated two-service/two-gMSA deployment;
- exact deployment/service/gMSA/binary/config/state/spool ACL acceptance;
- actual `FICollector` service-token boundary validation under
  `ISS\gFI-FS19$`;
- a corrected local governed-file activity matrix with denied-read and
  denied-write Windows Security records preserved into FI spool custody;
- live current-state SACL observation through the four-operation broker;
- true remote SMB workload and server-side 5145/event/spool correlation;
- collector restart and USN catch-up;
- controlled helper outage with frozen checkpoint and exact catch-up;
- bounded baseline and operation/resource observation; and
- bounded passive AD-LDAPS Before/During/After dependency observation with
  verified restoration.

The earlier Server 2019 activity run `3971b61b7ffa` is deliberately retained as
failed history. The accepted corrected run is `9d7d39184f9a`.

Key accepted report hashes:

```text
Deployment
8828B98C008653BA7ACC25F4F63F3D7A037CE5629AB4A248615A1EC083EEF0B0

Readiness
C14A27779C18364C4EDED5F828ABE619D657043BE6F98C25B845FB03FDED0A51

Accepted 10A activity
A51380644A8525DA213712854F4CC81BE156C52202E1CDD981C90C65BDC204C6

10C remote SMB
09A903B93599088645920D17C27F5397AF4D861D5AA6FE6E01CD453D22E2D54E

Test 08 collector-token boundary
FEB775269E572BD4F25EBBDC50F262A3FD4670C376994175718C81B2CD9DC111

Helper outage / catch-up
FE3FA4515942AF697196E0D05C499338BEEF8E989440084DD665A0A7FF75BCF5

12D Before
F308CA4A2717FE9CE184B1A07BB147BD83BE1C55866754AB6772D57FD5B5AE0F

12D During
983A525DDA1B9515A088DBB5E1640561D73562024514E756887A8558794660B6

12D After
9314FF98F0AF2AE801F9DFFAC8863C115CB1BDCCDD5D9C23EBA02C981A782013
```

Detailed Server 2019 verification is recorded in:

```text
docs/GATE-1-SERVER-2019-CANDIDATE-4.md
```

The Server 2019 sweep intentionally did not repeat every candidate-wide
stress/lab-fault campaign already established on Server 2016. Exact Server 2019
acceptance required the Windows-build-sensitive deployment, service-token,
activity/Security/SMB, broker/ReadSACL, restart/catch-up, helper-outage, bounded
dependency, baseline, and resource boundaries to be proven on build `17763`.

## Test 12D dependency observation

The original Test 12D implementation is **RETIRED** because its validation
harness was not acceptably bounded.

The Gate 1 requirement itself is not retired.

The replacement 12D implementation is a bounded passive observer. It does not
stop, restart, disable, enable, or reconfigure the dependency being observed.

Accepted replacement canonical LF payload SHA-256:

```text
EA92830748A0F474F2EF107E1BF95B10475FE9E42DA5A43AF4DF4A7D4FC69F27
```

The controlled Server 2016 exercise used an externally controlled outbound
TCP/636 AD-LDAPS fault with an independently armed SYSTEM rollback before the
fault was introduced.

Server 2016 observed records:

```text
Before report SHA-256:
E4DC5305F872C039E710DDD324A797D922B6BED5CA5B92D80B4E938FD0BF954D

During report SHA-256:
A8F0EFCF11B8BEAE87118536622D80B47F55840C32ECECE01491E8AE2B8E2EB0

After report SHA-256:
58940662CDB2B82241F079C766FEBBD72A9AB22F4E8431ABCDA9B1D278DCE856
```

The Server 2016 dependency outage began at:

```text
2026-09-04T14:30:33.0683073Z
```

A new `ConfiguredCollection` completed during the outage:

```text
2026-09-04T14:31:34.3617938Z
Outcome: Complete
```

The TCP/636 fault was removed and independently verified absent before the
rollback task was removed.

The retained Server 2016 runtime window contained a successful supporting-source
refresh from before the outage. Therefore that exercise does **not** claim that
an AD supporting refresh itself failed and recovered during the outage. It proves
the bounded 12D observer requirement and continued configured governed collection
during the controlled dependency transport fault.

The Server 2019 campaign repeated the bounded AD-LDAPS transport-fault observation
on build `17763`. The staged Windows script used CRLF line endings, while the
repository-canonical payload uses LF. Identity was proven by normalization:

```text
GitHub main / canonical LF Git blob:
08723bc8be60dd6e95710a977d84cd4222cb1ae6

Canonical LF SHA-256:
EA92830748A0F474F2EF107E1BF95B10475FE9E42DA5A43AF4DF4A7D4FC69F27

Raw staged CRLF SHA-256:
85F267F036D3B6CF3ADC69DF13BE1BE07E827BF285494071766F2E8E952AB19E

LF-normalized staged SHA-256:
EA92830748A0F474F2EF107E1BF95B10475FE9E42DA5A43AF4DF4A7D4FC69F27
```

The Server 2019 controlled TCP/636 block existed from
`2026-09-04T22:34:53.9243535Z` through
`2026-09-04T22:35:56.4196523Z`. A fresh configured collection completed during
the outage at `2026-09-04T22:35:52.864270700Z` with outcome `Complete`.
TCP/636 then recovered on the first bounded restoration check, and a fresh
post-restoration collection completed at `2026-09-04T22:36:53.550327700Z`.

The Server 2019 outage did not span a scheduled supporting-source refresh, so the
accepted claim remains limited to continued configured governed collection during
a real LDAPS transport outage and verified dependency restoration.

## Four-operation privileged broker

Candidate #4 uses four bounded `FIUSNReader` operations:

```text
QueryJournal
ReadJournal
CheckContainment
ReadSACL
```

The Server 2016 and Server 2019 campaigns live-validated the current `ReadSACL`
path.

The SACL operation:

- authorizes the exact configured governed root plus NTFS file-reference number
  and sequence number;
- returns only the bounded raw SACL security descriptor;
- rejects an empty descriptor;
- rejects a descriptor larger than 128 KiB;
- enables `SeSecurityPrivilege` only around the privileged SACL read;
- restores the exact prior privilege state before return; and
- leaves descriptor parsing and FI record construction in the non-admin
  `FICollector`.

Equivalent live Candidate #4 SACL acceptance remains pending on Server 2022 and
2025.

## Historical containment

Candidate #4 closes the deleted-child/deleted-parent historical-containment case
using bounded same-USN-batch NTFS identity relationships.

The accepted design does not trust a stale path and does not blanket-include an
object merely because current path resolution is unavailable.

Server 2016 result: **PASS**

## Content-prefix custody

Candidate #4 live validation used:

```text
Source:
C:\FI-Lab\fi-candidate4-content-prefix.bin

Source size:
51 bytes

First 16 bytes as text:
FI-MAGIC-PREFIX!

First 16 bytes as Base64URL:
RkktTUFHSUMtUFJFRklYIQ
```

The observed object identity was:

```text
File reference number: 116384
Sequence number:       4
```

The content-prefix observation was preserved through the durable FI custody
boundary.

Server 2016 result: **PASS**

## Performance and resource characterization

Tests 13 through 16 are acceptance characterization, not production sizing.

Notable Server 2016 campaign facts include:

- Test 14 exercised a bounded 1,000-file churn workload.
- Test 15 exercised five 500-file waves and increased spool storage by
  112,951,217 bytes, approximately 107.72 MiB, while remaining within the
  configured 512 MiB hard cap.
- Test 16 completed in approximately 128.8 seconds and summarized immutable
  operation/resource records.
- Test 16 observed 1,484 re-observations:
  - 1,287 Complete;
  - 197 Partial;
  - 0 Failed; and
  - 0 Interrupted.

The bounded Test 16 partial sample was operation/source-stage level and is not
interpreted as proof of governed-object collection failure.

Server 2019 exact acceptance included bounded baseline and operation/resource
observation on build `17763`; the full candidate-wide churn/spool-pressure stress
campaign was not repeated as a Server-2019-specific closure requirement.

Production cadence remains:

```text
NOT_EVALUATED
```

The Gate 1 test deployment command line uses:

```text
collection:                1m
supporting-source refresh: 30m
```

Those values are acceptance configuration, not production defaults.

## Local source verification

Immediately before the original Candidate #4 documentation reconciliation, the
Candidate #4 source tree passed:

```text
Candidate #4 changed/new Go files gofmt clean    PASS
go vet ./...                                    PASS
go test ./...                                   PASS
git diff --check                                PASS
Gate 1 PowerShell 5.1 parser validation         PASS
```

The Gate 1 parser validation covered all 15 scripts in the closure kit.

A pre-existing formatting difference in
`go/internal/windows/ntfs/convert.go` was inspected separately and deliberately
left untouched because it is not part of the Candidate #4 delta.

## Gate 1 remaining work

Windows Server 2016 Candidate #4 acceptance is complete.

Windows Server 2019 Candidate #4 acceptance is complete.

Gate 1 remains open overall for:

1. exact Candidate #4 acceptance on Windows Server 2022 build `20348`;
2. exact Candidate #4 acceptance on Windows Server 2025 build `26100`;
3. repeated representative performance/source-impact measurement where needed
   across the intended supported deployment set;
4. production collection/supporting-refresh cadence selection from accumulated
   measurements; and
5. final review of this result record across the intended exact release/build
   set.

No prior characterization result may be substituted for exact current-candidate
acceptance.
