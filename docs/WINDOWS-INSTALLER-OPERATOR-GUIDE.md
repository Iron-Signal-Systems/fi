# FI Windows Native Installer â€” Operator Guide

## Scope

This is the current administrator workflow for the native signed FI Windows
source installer. The installer is a desired-state reconciler, not an operator
script collection. Normal source collection does not modify governed customer
files, DACLs, SACLs, AD identities, or Windows audit policy.

Read the exact actions presented by the signed installer before approving them.
The documented lab results do not authorize a production deployment.

## Supported exact builds and acceptance boundaries

The current installer code has exact discovery and FIObjReader rights mutation
gates for Windows Server 2016 (`14393`), 2019 (`17763`), 2022 (`20348`), and
2025 (`26100`). Server 2025 was separately characterized and tested in earlier
runtime/installer work; it is not blocked by the rights gate. The dated October
17, 2026 integrated receiver/PostgreSQL result was on Server 2022, not a repeat
of that particular candidate on all four builds. Release approval remains
separate from lab and historical acceptance.

## Prerequisites and signed package

Use an elevated administrator terminal on the intended Windows file server and
a fully authenticated FI signed release package. The package carries
`fi-install.exe`, its signed runtime payloads, the reviewed manifest/signature,
and applicable release authorization. The installer rejects untrusted or
unauthorized packages rather than allowing an operator to skip verification.

For a new source, prepare a reviewed FI 1.1 operational configuration file with
receiver address/name, governed roots, spool, stage, and state paths as required
by the validated configuration contract. The installer validates and binds
approval to the exact normalized content. Do not create or change this file
with ad hoc scripts to make the installer pass. Existing installed configurations
are authoritative; configuration-change workflow is not silently provided by
new-install flags.

## Plan without mutation

From the signed package directory:

```powershell
.\fi-install.exe -config C:\path\fi.conf -plan-only
```

Planning mode is strictly read-only; review build profile, AD/PKI, trust,
configuration, Windows audit/SACL prerequisites, FI privileges, ACLs, SCM,
and runtime plans. On an already-installed source, use:

```powershell
.\fi-install.exe -plan-only
```

`-plan-only` is required for inspection; normal mode applies by default.

## Install or reconcile

For the intended new source, run exactly:

```powershell
.\fi-install.exe -config C:\path\fi.conf
```

For an already-installed source using its retained installed configuration:

```powershell
.\fi-install.exe
```

The signed installer performs authoritative discovery, prerequisite evaluation,
plan review, explicit approval, re-discovery, approved mutation, and final
convergence verification. In configuration-file mode, the normalized config
approval token is `APPROVE-CONFIG <first-16-of-digest>`. The native PKI path
currently supports enrollment; `reuse` and `create` are not apply-supported.
Where prompted, select the approved enrollment option; do not substitute
manual AD/PKI scripts.

- **Approval 1** covers shared AD and PKI changes, including required gMSAs,
  enrollment authorization, and any separately approved CA template
  publication. The CA publication boundary has its own explicit approval.
- The installer rediscoveries authoritative state before sealing Approval 2.
- **Approval 2** covers local configuration, release trust, packages,
  service identities, direct rights, local groups, FI ACLs, SCM, runtime,
  Windows audit policy, and governed-root SACLs. Read the exact mutation plan.
- Approval tokens are digest-bound. Changed state invalidates the approval;
  do not retry with a stale token or bypass the preflight gate.

## Windows Security prerequisites and failure behavior

Approval 2 includes native configuration of these effective audit subcategories:
Audit Policy Change (Success), File System (Success/Failure), Handle
Manipulation (Failure), and Detailed File Share (Success/Failure). Advanced
audit-policy precedence must be effective and the Security event channel
readable. The installer applies only the missing audit bits and missing
Success/Failure change and descendant-read SACL audit ACEs for explicitly
governed roots; it does **not** change governed-object DACLs.

These are **persistent administrator-approved Windows host settings**, not
ordinary FI-owned state. Inherited SACL changes may not be byte-exactly
reversible via supported Windows named-security APIs. If another step later
fails, the Windows audit/SACL prerequisites can remain applied. A subsequent
installer run discovers them anew and reconciles remaining actions. A pending
legacy SACL transaction/rollback journal must be investigated; the installer
refuses unsafe automatic recovery. Never promise automatic rollback of the
whole host audit-policy/SACL tree.

No separate audit-policy or SACL PowerShell scripts are part of the required
production installer workflow.

## Receiver activation and pending state

The installer performs an authenticated mutual-TLS handshake before enabling
normal sender operation; the activation probe sends no FI generation payload.
If receiver activation fails, review the offered Abort, Retry, or Receiver
Pending choice. Pending is a deliberate accepted state with FISender
Manual/Stopped/PID 0, not a working sender. Correct receiver trust or
availability and rerun the native installer. Do not manually start the sender
in place of the receiver activation gate.

## Successful convergence and verification

Normal live activation requires the final installer report to show Approval 2
PASS, authoritative discovery converged, and `FI INSTALLER RESULT: PASS`.
Check on the intended Windows host:

```powershell
Get-CimInstance Win32_Service |
    Where-Object { $_.Name -in @(
        'FICollector','FIUSNReader','FIObjReader',
        'FICRLRefresher','FISender'
    ) } |
    Select-Object Name, State, StartMode, StartName, ProcessId
```

For an activated source, all five are expected Automatic/Running. In deliberate
Receiver Pending, FISender instead remains Manual/Stopped. The installer is the
authoritative owner of service configuration; do not repair a failed approval
by manually changing service state, identities, security policy, or binary ACLs.

Signed installer records are under `C:\ProgramData\FI\install`. Verify source
registration, completed receiver generation custody, and authoritative
PostgreSQL ingest on the backend before claiming end-to-end acceptance. A
running process alone does not prove durable ingest.

## Safe retry and rollback boundaries

If the installer fails, keep the transaction record and original failure.
Inspect the plan and authoritative rediscovery, then rerun the same signed
installer through its normal approval flow after correcting prerequisites.
FI-owned local transaction steps are rollback-managed, but approved Windows
host audit/SACL changes can persist and must be rediscovered. Do not use a
one-off remediation script to silently circumvent a blocked installer gate.

A sender-only reconciliation must not restart an already healthy FICollector or
require a new collector startup record. Collector-specific startup readiness is
required when package replacement, FICollector runtime mutation, or initial
service creation actually starts the collector. Service stability remains
required for sender-only repair.

## Dated lab acceptance and outstanding release gates

- October 9, 2026: Server 2019 executable migration, receiver pending,
  interrupted-migration recovery and idempotency.
- October 10, 2026: Server 2019/FreeBSD backend integrated recovery.
- October 12, 2026: Server 2019 M22K4N installed runtime, file history,
  PostgreSQL ingest and reboot survival; original warnings retained.
- October 17, 2026: Server 2022 M22K4Q authenticated installer, FISender-only
  reconciliation, all five services running, receiver TLS, and four
  authoritative generations totaling 1,033 committed records.
- Earlier Windows Server 2025 exact-build runtime, protected-object, cold
  reboot, and native-installer work remains accepted within its tested scope.

The October 17 signed lab binary was built before the October 17 Go 1.27.2
security dependency update. Passing the later source/CI vulnerability scan
does not retroactively rebuild or sign that lab binary.

Outstanding Phase 6 release gates include fresh and upgrade installation
campaigns for each selected release target, outage recovery and sustained-load
coverage, candidate-specific rollback, signed-release reproducibility,
backend recovery, and formal release decision. See
`fi-roadmap/docs/roadmap/phase-06-integrated-deployment-and-release.md`.
