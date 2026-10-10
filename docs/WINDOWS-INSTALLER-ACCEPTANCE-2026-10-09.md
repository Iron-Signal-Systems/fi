# FI Windows Installer Acceptance — 2026-10-09

## Purpose

This record captures the accepted live Windows installer recovery and
executable-name migration result that preceded source commit:

```text
d2527b6827448b75a0b77b8b71fac68499477367
windows: complete multirelease installer recovery and runtime migration
```

Branch:

```text
windows-installer-multirelease-20261005
```

The validation host was Windows Server 2019 build `17763`.

The receiver was intentionally unavailable during the final receiver-pending
acceptance path.

## Canonical runtime names

The accepted canonical runtime names are:

```text
FICollector      C:\Program Files\FI\fi-collector.exe
FIUSNReader      C:\Program Files\FI\fi-usn-reader.exe
FIObjReader      C:\Program Files\FI\fi-obj-reader.exe
FICRLRefresher   C:\Program Files\FI\fi-crl-refresher.exe
FISender         C:\Program Files\FI\fi-sender.exe
```

The retired legacy names were:

```text
C:\Program Files\FI\fi.exe
C:\Program Files\FI\fi-usn.exe
C:\Program Files\FI\fi-obj.exe
C:\Program Files\FI\fi-crl-refresh.exe
```

## Defect exposed by the first migration attempt

The first executable-name migration attempt changed SCM paths to the new names
while the already-running service processes still had the old images mapped.

The resulting state demonstrated that:

```text
SCM desired path != actual running process image
```

is a real interrupted-migration condition.

Windows correctly kept the mapped legacy executable files in use, so transaction
cleanup could not retire them.

The installer was changed so SCM configuration is not treated as proof of the
actual runtime image.

## Recovery contract

The accepted recovery logic establishes:

- SCM PID plus `Win32_Process.ExecutablePath` as the authority for the current
  running image;
- explicit planning of a controlled restart when SCM already points at the
  canonical path but the current PID still executes a legacy image;
- capture of pre-mutation running/stopped service state;
- package and runtime rollback ownership;
- post-restart verification of the canonical process image;
- pre-mutation SHA-256 binding of legacy executables;
- immediate rehash before legacy retirement;
- refusal to delete a changed legacy executable;
- refusal to delete a symlink/non-regular legacy object; and
- legacy retirement only after process-image convergence.

## Approval 2 routing correction

The interrupted-migration recovery plan can contain PACKAGE/RUNTIME mutations
without any Approval 1 AD/PKI change.

The local installer route therefore uses the generic:

```text
RequiresApproval2Controller
```

predicate.

A stale inner Server-2016-specific execution guard was also removed so a valid
PACKAGE/RUNTIME-only local repair reaches the Approval 2 controller.

The regression suite verifies that:

- PACKAGE/RUNTIME recovery requires Approval 2;
- it does not require Approval 1; and
- the generic Approval 2 execution path no longer falls back to the stale
  Server-2016-only predicate.

## Receiver Pending acceptance

During the accepted final path, the receiver activation probe could not establish
the required mTLS connection.

The operator selected Receiver Pending.

The installer rebuilt the installed-state plan so:

```text
FICollector      Automatic / Running
FIUSNReader      Automatic / Running
FIObjReader      Automatic / Running
FICRLRefresher   Automatic / Running
FISender         Manual / Stopped
```

The pending rebuilt plan converged with:

```text
NO CHANGE SCM      FICollector
NO CHANGE RUNTIME  FICollector
NO CHANGE SCM      FIUSNReader
NO CHANGE RUNTIME  FIUSNReader
NO CHANGE SCM      FIObjReader
NO CHANGE RUNTIME  FIObjReader
NO CHANGE SCM      FICRLRefresher
NO CHANGE RUNTIME  FICRLRefresher
NO CHANGE SCM      FISender
NO CHANGE RUNTIME  FISender
NO CHANGE PACKAGE  installed FI executables
```

The final result was:

```text
PASS_WITH_RECEIVER_PENDING
```

## Post-convergence idempotency

A separate read-only post-hoc acceptance isolated the receiver-pending rebuilt
plan from the initial normal-state activation plan.

It proved:

```text
CREATE actions:                  0
RECONCILE actions:               0
Approval 2 after Pending:        not required
Approval 2 token after Pending:  not requested
APPLY phase after Pending:       not entered
FI mutations:                    0
service restarts:                0
running PIDs:                    unchanged
install records:                 unchanged
legacy runtime files:            absent
FISender:                        Manual / Stopped / PID 0
```

The four running service images were the canonical names and their PIDs remained
unchanged throughout the converged rerun.

## Accepted engineering conclusion

The following defects are closed for the accepted Server 2019 path represented
by this commit:

1. legacy-to-canonical runtime executable-name migration;
2. recovery when SCM was updated but the old process image remained running;
3. safe legacy executable retirement;
4. local PACKAGE/RUNTIME Approval 2 routing;
5. receiver-pending plan rebuild;
6. FISender Manual/Stopped pending behavior; and
7. converged-state receiver-pending idempotency.

This record does not expand the current build mutation profile beyond the
installer prerequisite gates documented in `docs/WINDOWS-INSTALLER.md`.
