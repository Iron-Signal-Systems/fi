FI Gate 1 build - Windows Server 2019 simple acceptance sweep
================================================================

This package is pinned to the existing lab setup recovered from the prior
Server 2019 work:

  Controller:       AdminBox
  File server:      ISS-FS-19
  Windows build:    17763
  Domain:           iss.local
  Governed root:    C:\FI-Governed-Test
  Collector gMSA:   ISS\gFI-FS19$
  Helper gMSA:      ISS\gFI-USN-FS19$

Gate 1 build:
  collector SHA256:
    6D641A73D0CE116BA09C16885371164BF580D36631DD6F031090B2EE5DC86C13

  helper SHA256:
    A71A769F25E9CCB0C9ACAF8CAFBE6C751AEB8F3884FC5EBD1BF7723B3BBF2263

Pinned FI repository checkpoint:
  c5157b255f1d33cc0fd33ca1ddb0708348728912

No GitHub/repository write is performed by this package.

The package intentionally does NOT repeat every Server 2016 stress/fault
campaign. It uses the current committed Gate 1 tooling to perform one bounded
Server 2019 core sweep, one true remote SMB pass, and passive 12D observations.


Server 2019 governed-root note
------------------------------
C:\FI-Governed-Test was created and explicitly granted collector RX during the
original Server 2019 lab deployment. The committed Gate 1 deployment helper's
-GrantTestRootReadAccess safety guard only accepts path components named exactly
FI-Test, FI-Lab, Lab, or Test; it intentionally does not classify
FI-Governed-Test as a disposable test root.

v2 therefore does NOT ask the committed deployment helper to rewrite the
governed-root ACL. It preserves the already-established Server 2019 lab root
ACL and lets deployment/acceptance fail normally if that existing access is
insufficient.

This also makes v2 safe to resume after the v1 run stopped at that guard. The
v1 run had already installed the exact Gate 1 build binaries and updated the
service/config boundary before the guard fired; rerunning v2 is intended and
idempotent for that state.

Files
-----

01-Server2019-Sweep.ps1
  Default: read-only preflight.
  With -ConfirmSweep: stages exact Gate 1 build, deploys/redeploys the pair,
  runs the current Gate 1 readiness orchestrator with the selected 2019
  acceptance checks, validates live ReadSACL through 10A, and validates an
  exact known 16-byte content prefix from the finalized FI spool.

02-RemoteSMB-2019.ps1
  Runs on AdminBox. It prefers an existing non-special SMB share that exposes
  C:\FI-Governed-Test. If none exists it falls back to:
    \\ISS-FS-19\C$\FI-Governed-Test
  It runs true remote SMB Test 10B, waits for a bounded post-workload FI
  collection, runs server-side Test 10C, and requires both a matching 5145 and
  an FI spool match.

03-12D-2019.ps1
  Passive only. It never changes AD, LDAPS, Windows Firewall, networking, or FI
  services. Run Before, then establish the separately controlled bounded LDAPS
  fault, run During with confirmation, restore the dependency, and run After
  with confirmation.

04-Finalize-Server2019.ps1
  Consolidates results into one PASS/FAIL/INCOMPLETE acceptance summary.

Recommended sequence
--------------------

1) Read-only preflight:

  Set-ExecutionPolicy -Scope Process Bypass -Force
  Set-Location 'C:\FI-Test\FI-Gate1-Server2019-Sweep'
  .\01-Server2019-Sweep.ps1

2) If preflight is clean, execute the core sweep:

  .\01-Server2019-Sweep.ps1 -ConfirmSweep

3) True remote SMB from AdminBox:

  .\02-RemoteSMB-2019.ps1 -ConfirmWorkload

4) Passive 12D Before:

  .\03-12D-2019.ps1 -Stage Before

5) Establish the separately controlled bounded LDAPS transport fault.
   The 12D script does NOT create it.

6) Passive 12D During:

  .\03-12D-2019.ps1 -Stage During -ConfirmExternalFaultActive

7) Restore LDAPS completely.

8) Passive 12D After:

  .\03-12D-2019.ps1 -Stage After -ConfirmDependencyRestored

9) Finalize:

  .\04-Finalize-Server2019.ps1

Result directory on AdminBox:
  C:\FI-Test\FI-Gate1-Server2019-Results

Safety / scope
--------------
- Exact host/build/hash/repository checks fail closed.
- 01 is read-only unless -ConfirmSweep is present.
- 02 requires -ConfirmWorkload.
- 03 is passive and bounded; it cannot create the dependency fault.
- No churn, spool-pressure, spool-write-denial, or governed-root-unavailable
  stress/fault campaign is repeated automatically.
- No GitHub write.
