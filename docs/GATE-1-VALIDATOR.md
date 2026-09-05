# FI Gate 1 Unified Validator

`tools\gate1\Validate.ps1` is the operator-facing entry point for repeat Gate 1
acceptance on an already characterized Windows Server release/build.

It does not replace the individual Gate 1 scripts. It discovers the installed FI
configuration, selects the exact build profile, orchestrates the existing tests,
and saves one durable validation package.

## Normal use

Run from an elevated Windows PowerShell session on the controller/admin system
that contains the FI repository:

```powershell
& .\tools\gate1\Validate.ps1 `
    -Server ISS-FS-22 `
    -Save 'C:\FI-Validation\2022'
```

The Windows release is discovered from the target. `-Version` is optional and is
an assertion only:

```powershell
& .\tools\gate1\Validate.ps1 `
    -Server ISS-FS-22 `
    -Version 2022 `
    -Save 'C:\FI-Validation\2022'
```

If the detected build does not match the requested version, validation stops
before disruptive tests.

## Characterized build profiles

```text
Windows Server 2016    10.0.14393
Windows Server 2019    10.0.17763
Windows Server 2022    10.0.20348
Windows Server 2025    10.0.26100
```

Adjacent builds are not accepted by similarity.

The validator compares the installed binaries to the exact Gate 1 pair recorded
in `tools\gate1\validation-profiles.psd1` before running disruptive tests.

## Target discovery

The target system is the source of truth for per-server configuration. The
validator discovers:

- Windows version/build;
- `C:\ProgramData\FI\config\fi.conf` and the configured governed root;
- `FICollector` and `FIUSNReader` service identities;
- service executable paths and startup state;
- installed binary SHA-256 values; and
- FI-USN pipe presence.

A separate per-server config file is not required.

## Default validation sequence

The default run performs:

1. repository/validator preflight;
2. remote target discovery and exact artifact comparison;
3. staging of the current Gate 1 script kit;
4. exact deployment/service/gMSA/ACL acceptance;
5. the current common Test 08 collector service-token boundary;
6. production protected-object containment through the real FIUSNReader broker;
7. 10A local governed activity with Windows Security/FI correlation;
8. collector restart and USN catch-up;
9. helper outage, checkpoint freeze, and catch-up;
10. true remote SMB 10B/10C correlation; and
11. final exact hashes/services/pipe verification plus artifact collection.

The full candidate-wide churn/spool-pressure campaign is not repeated by the
quick validator. Those remain separate characterization/performance tools.

## Temporary prerequisites and restoration

The validator is allowed to make only bounded test prerequisites and records
each one in `validation-report.json`.

### 10A

When required, the validator temporarily:

- enables `File System` Success/Failure auditing; and
- adds the minimum failure-audit ACE needed for the current validator identity on
  the governed test root.

Any validator-created audit policy change or SACL ACE is restored immediately
after 10A.

### True remote SMB

The validator records the original TCP/445 reachability state. If inbound SMB is
blocked and the target is on a `DomainAuthenticated` profile, it temporarily
creates one inbound Domain-profile TCP/445 rule scoped only to the controller's
actual source IPv4 address.

It also temporarily enables `Detailed File Share` Success/Failure auditing when
required.

After 10B/10C, the validator removes its firewall rule, restores the audit-policy
setting, and verifies TCP/445 returned to its original reachability state.

### Probe binaries

Test probes are built from the current repository source when needed, staged only
for the test, and removed afterward. Their SHA-256 values are recorded in the
final report.

## Visible waits

No validator-owned bounded wait longer than ten seconds is silent. Long waits
print elapsed time, timeout/remaining time, and the condition being awaited.

The common Gate 1 helper wait functions should follow the same ten-second
heartbeat rule.

## Output package

Example:

```text
C:\FI-Validation\2022\
    validation-summary.txt
    validation-report.json
    resolved-system-state.json
    SHA256SUMS.txt
    logs\
        validation-transcript.txt
        containment-probe-build.stdout.txt
        containment-probe-build.stderr.txt
        collector-boundary-probe-build.stdout.txt
        collector-boundary-probe-build.stderr.txt
    raw\
        client\
        server\
    tools\
        fi-gate1-containment-probe.exe
        fi-collector-boundary-probe.exe
```

`validation-summary.txt` is the operator-readable result. `validation-report.json`
is the machine-readable record. Raw test artifacts are retained under `raw`.

`SHA256SUMS.txt` covers the saved package except itself.

## Cross-version validator acceptance

The validator itself is not accepted until the same entry point has been run
successfully against all four characterized servers:

```powershell
& .\tools\gate1\Validate.ps1 -Server ISS-FS-01 -Save 'C:\FI-Validation\2016'
& .\tools\gate1\Validate.ps1 -Server ISS-FS-19 -Save 'C:\FI-Validation\2019'
& .\tools\gate1\Validate.ps1 -Server ISS-FS-22 -Save 'C:\FI-Validation\2022'
& .\tools\gate1\Validate.ps1 -Server ISS-FS-25 -Save 'C:\FI-Validation\2025'
```

2016, 2019, and 2022 are regression runs of already accepted behavior. The 2025
run also participates in completing exact current-pair Gate 1 acceptance on build
26100.

## Safety switches

For targeted troubleshooting only:

- `-SkipContainment`
- `-SkipRecovery`
- `-SkipRemoteSMB`
- `-ContainmentProbePath <path>` to use a reviewed prebuilt containment probe
- `-RequireCleanRepository`
- `-Force` to overwrite a prior report in the same save directory

A normal Gate 1 run should not use the skip switches.
