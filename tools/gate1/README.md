# FI Gate 1 Closure Test Kit

This directory extends the existing common/release-specific FI verification kit.
It does not replace `tools/scripts/01` through `08` or the authoritative Windows
Server validation record.

The current characterized Windows Server build set is exact:

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
Windows Server 2025    10.0.26100
```

Adjacent or future builds are not accepted by similarity.

Characterization of a Windows release/build is not the same as exact Candidate
#4 Gate 1 acceptance. The current Candidate #4 campaign state is recorded in
`docs/GATE-1-RESULT-RECORD.md`.

## Safety classes

### Read-only / observation

- `11-FileServer-Deployment-Acceptance.ps1`
- `12D-FileServer-Dependency-Observation.ps1`
- `16-FileServer-Operation-Resource-Summary.ps1`
- `10C-FileServer-Remote-SMB-Correlation.ps1`
- `Invoke-FIGate1-Readiness.ps1` with no optional workload/fault switches

### Controlled test workload

These create, modify, read, rename, or delete isolated test material and require
an explicit confirmation switch:

- `10A-FileServer-Activity-Matrix.ps1 -ConfirmWorkload`
- `10B-RemoteClient-SMB-Activity.ps1 -ConfirmWorkload`
- `13-FileServer-Performance-Baseline.ps1 -ConfirmSourceImpact`
- `14-FileServer-Churn-Campaign.ps1 -ConfirmWorkload`
- `15-FileServer-Spool-Pressure.ps1 -ConfirmWorkload`

`13` performs a full recursive `-perf-root` source read/hash workload. When
`FICollector` is already running, choose explicitly between an isolated
measurement (`-StopCollectorForRun`) and a deliberately concurrent measurement
(`-AllowConcurrentCollector`).

### Controlled service interruption

- `12A-FileServer-Collector-Restart-Recovery.ps1 -ConfirmDisruptive`
- existing `tools/scripts/04-FileServer-Failure-Recovery.ps1 -ConfirmDisruptive`

### Lab-only fault injection

- `12B-FileServer-Spool-Write-Denial.ps1 -ConfirmStorageDenial`
- `12C-FileServer-Governed-Root-Unavailable.ps1 -ConfirmRootUnavailable`

Those scripts default to a governed root clearly named `FI-Test`, `FI-Lab`,
`Lab`, or `Test`, save the original state they change, and restore it in a
`finally` path. Do not use `-AllowNonTestRoot` merely to bypass the safety check.

### Deployment-changing

`09-FileServer-Deploy-Test-Pair.ps1` is a reproducible Gate 1 **test/acceptance**
deployment, not the final commercial installer and not a declaration of final
production cadence. It:

- refuses uncharacterized Windows builds;
- requires exact reviewed SHA-256 values for both binaries;
- requires separate domain-qualified gMSA identities;
- requires the collector to remain non-admin and helper to already be inside the
  intended local-Administrator boundary;
- installs/admin-controls program and config paths;
- uses the existing FI state/spool ACL hardener;
- performs a fail-fast preflight before stopping services or replacing files;
- refuses existing service identity changes; existing command-line changes require
  explicit `-ReconfigureExistingServices`;
- marks both services as managed-account services and automatic start;
- enables the `FICollector` service SID;
- adds the collector to Event Log Readers;
- starts helper then collector and requires a configured collection; and
- routes directly into Gate 1 deployment acceptance.

It does **not** silently create customer data roots, rewrite customer data ACLs,
change Advanced Audit Policy, or install SACLs. `-GrantTestRootReadAccess` is
available only for a clearly named test/lab root.

The `1m` collection / `30m` supporting-source command line is fixed in this Gate 1 test installer because the existing Test 08 restoration contract is fixed to that exact acceptance command line. These are **not** accepted production defaults. Production cadence remains `NOT_EVALUATED` until the performance campaign is reviewed.

Example:

```powershell
& .\tools\gate1\09-FileServer-Deploy-Test-Pair.ps1 `
  -CollectorCandidate 'C:\FI-Test\fi-candidate.exe' `
  -CollectorSHA256 '<64-HEX-SHA256>' `
  -HelperCandidate 'C:\FI-Test\fi-usn-candidate.exe' `
  -HelperSHA256 '<64-HEX-SHA256>' `
  -CollectorAccount 'ISS\gFI-FS01$' `
  -HelperAccount 'ISS\gFI-USN-FS01$' `
  -GovernedRoot 'C:\FI-Lab' `
  -ReplaceExistingFilesAndConfig `
  -ReconfigureExistingServices `
  -GrantTestRootReadAccess `
  -ConfirmDeploy
```

## Script map

| Script | Purpose |
| --- | --- |
| `09-FileServer-Deploy-Test-Pair.ps1` | Reproducible exact-build-gated Gate 1 test deployment |
| `10A-FileServer-Activity-Matrix.ps1` | Local create/read/write/deny/rename/move/delete/ACL/owner/SACL/hard-link/local-SMB workload |
| `10B-RemoteClient-SMB-Activity.ps1` | True SMB workload from a separate client |
| `10C-FileServer-Remote-SMB-Correlation.ps1` | Read-only server-side event/spool correlation for the 10B RunID |
| `11-FileServer-Deployment-Acceptance.ps1` | Exact service/gMSA/build/binary/ACL boundary acceptance |
| `12A-FileServer-Collector-Restart-Recovery.ps1` | Collector stopped-window USN catch-up |
| `12B-FileServer-Spool-Write-Denial.ps1` | Lab-only durable-spool-unavailable invariant |
| `12C-FileServer-Governed-Root-Unavailable.ps1` | Lab-only configured-source-unavailable behavior/recovery |
| `12D-FileServer-Dependency-Observation.ps1` | Passive before/during/after observation around an externally controlled dependency fault |
| `13-FileServer-Performance-Baseline.ps1` | Repeated real `-perf-root` measurements; no invented thresholds |
| `14-FileServer-Churn-Campaign.ps1` | Bounded USN/Security/spool/process-I/O churn characterization |
| `15-FileServer-Spool-Pressure.ps1` | Bounded spool growth with hard spool, source-dataset, and free-space caps |
| `16-FileServer-Operation-Resource-Summary.ps1` | Summarize FI immutable operation/resource journals by operation kind |
| `Invoke-FIGate1-Readiness.ps1` | Orchestrate selected Gate 1 checks; intrusive workloads remain opt-in |

## Recommended sequence

### 1. Deploy/redeploy a clean Gate 1 test pair

Use `09` on an exact characterized build after the gMSAs are provisioned and
locally available. Existing service identities are never changed. If an existing command
line differs, the installer fails before mutation unless
`-ReconfigureExistingServices` is supplied explicitly. Existing differing
binaries/config likewise require `-ReplaceExistingFilesAndConfig`.

### 2. Run baseline deployment acceptance

```powershell
& .\tools\gate1\11-FileServer-Deployment-Acceptance.ps1
```

For the controlled exact service-token boundary as well:

```powershell
& .\tools\gate1\11-FileServer-Deployment-Acceptance.ps1 `
  -IncludeCollectorBoundary
```

### 3. Generate the local activity matrix

```powershell
& .\tools\gate1\10A-FileServer-Activity-Matrix.ps1 `
  -ConfirmWorkload
```

The script restores per-file DACL/owner/SACL mutations before cleanup and emits
a JSON record. Core workload execution failures cause a terminating failure **after**
the report is written. Event/FI semantics still require review; a script cannot
turn a missing event into proof that no activity occurred.

### 4. Generate true remote SMB activity

On a separate client:

```powershell
& .\tools\gate1\10B-RemoteClient-SMB-Activity.ps1 `
  -UNCPath '\\FILESERVER\Share\GovernedFolder' `
  -ConfirmWorkload
```

Copy the printed 12-character RunID. On the FI file server, after a collection
cycle:

```powershell
& .\tools\gate1\10C-FileServer-Remote-SMB-Correlation.ps1 `
  -RunID '<RUNID>'
```

Review the resulting 5145/NTFS event XML and FI spool matches for true remote
source/share semantics.

### 5. Recovery/fault campaign

Collector restart:

```powershell
& .\tools\gate1\12A-FileServer-Collector-Restart-Recovery.ps1 `
  -ConfirmDisruptive
```

Existing helper outage/frozen-checkpoint/catch-up test:

```powershell
& .\tools\scripts\04-FileServer-Failure-Recovery.ps1 `
  -ConfirmDisruptive
```

Lab-only spool custody fault:

```powershell
& .\tools\gate1\12B-FileServer-Spool-Write-Denial.ps1 `
  -ConfirmStorageDenial
```

Lab-only configured-root unavailable:

```powershell
& .\tools\gate1\12C-FileServer-Governed-Root-Unavailable.ps1 `
  -ConfirmRootUnavailable
```

For AD/LDAPS, Security-log, SMB/local-identity, or other dependency failures,
do not make this kit cause a broader infrastructure outage. `12D` is a bounded
passive observer only. The original unsafe 12D validation harness is retired and
must not be used. Capture FI before, during, and after an isolated externally
controlled fault:

```powershell
& .\tools\gate1\12D-FileServer-Dependency-Observation.ps1 `
  -Dependency AD-LDAPS -Stage Before
# create the approved isolated lab fault by the environment-specific procedure
& .\tools\gate1\12D-FileServer-Dependency-Observation.ps1 `
  -Dependency AD-LDAPS -Stage During
# restore dependency
& .\tools\gate1\12D-FileServer-Dependency-Observation.ps1 `
  -Dependency AD-LDAPS -Stage After
```

### 6. Performance/source-impact campaign

Isolated recursive baseline:

```powershell
& .\tools\gate1\13-FileServer-Performance-Baseline.ps1 `
  -Runs 3 `
  -StopCollectorForRun `
  -ConfirmSourceImpact
```

Bounded churn:

```powershell
& .\tools\gate1\14-FileServer-Churn-Campaign.ps1 `
  -ConfirmWorkload
```

Bounded spool pressure:

```powershell
& .\tools\gate1\15-FileServer-Spool-Pressure.ps1 `
  -ConfirmWorkload
```

FI service-operation/resource summary:

```powershell
& .\tools\gate1\16-FileServer-Operation-Resource-Summary.ps1 `
  -Hours 24
```

Repeat on representative datasets/workloads. Do not choose production intervals
from a single run.

## Orchestrator

With no optional workload/fault switches, the orchestrator performs deployment
acceptance plus a read-only operation/resource summary:

```powershell
& .\tools\gate1\Invoke-FIGate1-Readiness.ps1
```

Opt into the work you actually intend to run:

```powershell
& .\tools\gate1\Invoke-FIGate1-Readiness.ps1 `
  -IncludeCollectorBoundary `
  -IncludeLocalActivity `
  -IncludePerformanceBaseline `
  -StopCollectorForPerformance `
  -IncludeCollectorRestart `
  -IncludeHelperOutage `
  -IncludeChurn `
  -IncludeSpoolPressure
```

`-IncludeLabFaultInjection` additionally runs the spool-write-denial and
configured-root-unavailable tests and is restricted to clearly named lab/test
roots.

## Results

Default result location:

```text
C:\ProgramData\FI\gate1-results
```

Performance results:

```text
C:\ProgramData\FI\gate1-results\performance
```

Retain exact FI hashes, Windows build/patch level, workload parameters, raw JSON,
and the associated change/test record.

## Acceptance rule

A script PASS proves only the invariant encoded by that script. Gate 1 closes
only after `docs/GATE-1-RESULT-RECORD.md` is reviewed across the intended exact
Windows release/build set and representative workloads. Missing source facts
remain missing/incomplete; they never become proof that no activity occurred.
