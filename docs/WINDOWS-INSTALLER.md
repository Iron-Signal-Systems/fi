# FI Windows Installer

## Status and authority

`fi-install.exe` is the native FI Windows source installer and desired-state
reconciler.

This document describes the installer contract implemented on branch
`windows-installer-multirelease-20261005` at accepted source commit:

```text
d2527b6827448b75a0b77b8b71fac68499477367
windows: complete multirelease installer recovery and runtime migration
```

FI remains pre-alpha. This document records the behavior implemented and
validated by the current source. It is not a general production-readiness or
compatibility guarantee.

The installer is an explicit administrator-run deployment action. Its mutation
authority is separate from FI's normal runtime behavior. Normal FI collection
does not gain authority to modify governed customer files, directories,
permissions, identities, shares, or customer configuration merely because the
installer can perform approved deployment changes.

## Installer model

The installer is desired-state based:

```text
authoritative discovery
        |
        v
prerequisite evaluation
        |
        v
desired-state plan
        |
        +-- BLOCKED
        +-- QUESTION
        +-- NO CHANGE
        +-- CREATE
        +-- RECONCILE
        |
        v
explicit approval boundary
        |
        v
pre-mutation rediscovery
        |
        v
transactional mutation
        |
        v
authoritative rediscovery
        |
        v
NO CHANGE convergence
```

The installer does not treat an old plan as continuing authority after
discovered state changes. Approval digests are revalidated before mutation.
State drift invalidates the approval and causes the installer to fail closed.

## Current Windows build profile

The source contains exact Windows Server profiles for:

| Windows Server | Build | Discovery profile | Current installer mutation contract |
|---|---:|---|---|
| 2016 | 14393 | Enabled | Enabled |
| 2019 | 17763 | Enabled | Enabled |
| 2022 | 20348 | Enabled | Blocked by current FIObjReader rights-acceptance gate |
| 2025 | 26100 | Enabled | Blocked by current FIObjReader rights-acceptance gate |

The distinction is deliberate.

`installerMutationSupportedBuild` recognizes all four exact builds, but the
environment prerequisite and desired-state plan also require the exact
FIObjReader rights contract to be enabled. At this commit,
`objReaderRightsMutationEnabledBuild` permits only builds `14393` and `17763`.
Server 2022 and Server 2025 therefore remain fail-closed for the integrated
installer mutation path even though their broader Gate 1 Windows behavior has
been characterized and accepted separately.

An adjacent or future Windows build is not accepted merely because the release
name matches.

## Package and executable layout

The reviewed release package contains `fi-install.exe` and the FI Windows
runtime payloads.

The canonical installed runtime names are:

| Service | Installed executable |
|---|---|
| `FICollector` | `C:\Program Files\FI\fi-collector.exe` |
| `FIUSNReader` | `C:\Program Files\FI\fi-usn-reader.exe` |
| `FIObjReader` | `C:\Program Files\FI\fi-obj-reader.exe` |
| `FICRLRefresher` | `C:\Program Files\FI\fi-crl-refresher.exe` |
| `FISender` | `C:\Program Files\FI\fi-sender.exe` |

The recognized legacy executable-name migration set is:

```text
fi.exe              -> fi-collector.exe
fi-usn.exe          -> fi-usn-reader.exe
fi-obj.exe          -> fi-obj-reader.exe
fi-crl-refresh.exe  -> fi-crl-refresher.exe
fi-sender.exe       -> fi-sender.exe
```

`fi-sender.exe` does not require an executable-name migration.

## Five-service runtime

The current Windows source runtime consists of five SCM-owned services:

```text
FICollector
    collection / interpretation / spool and checkpoint ownership

FIUSNReader
    bounded privileged raw-volume USN and exact-object operations

FIObjReader
    bounded protected-object observation

FICRLRefresher
    transport-PKI CRL acquisition, validation, activation, and refresh journal

FISender
    generation transport / receiver delivery
```

The exact service contract is:

| Service | Account | Start | Service SID | Binary path |
|---|---|---|---|---|
| `FICollector` | derived collector/sender gMSA | Automatic | UNRESTRICTED | `"C:\Program Files\FI\fi-collector.exe" -service` |
| `FIUSNReader` | derived USN-reader gMSA | Automatic | UNRESTRICTED | `"C:\Program Files\FI\fi-usn-reader.exe"` |
| `FIObjReader` | derived object-reader gMSA | Automatic | UNRESTRICTED | `"C:\Program Files\FI\fi-obj-reader.exe"` |
| `FICRLRefresher` | derived CRL-refresher gMSA | Automatic | NONE | `"C:\Program Files\FI\fi-crl-refresher.exe"` |
| `FISender` | collector/sender gMSA | Automatic normally; Manual while Receiver Pending | NONE | `"C:\Program Files\FI\fi-sender.exe"` |

New automatically started services are started in this order:

```text
FIUSNReader
FIObjReader
FICollector
FICRLRefresher
FISender
```

`FISender` is not started while the installation is in Receiver Pending state.

## Derived gMSA identities

The installer derives per-host service identities from the computer name and
domain NetBIOS name.

The current role mapping is:

```text
FICollector/FISender -> <DOMAIN>\gFI-<HOSTTOKEN>$
FICRLRefresher       -> <DOMAIN>\gFI-CRL-<HOSTTOKEN>$
FIUSNReader          -> <DOMAIN>\gFI-USN-<HOSTTOKEN>$
FIObjReader          -> <DOMAIN>\gFI-OBJ-<HOSTTOKEN>$
```

The installer does not silently truncate a generated `sAMAccountName` that would
exceed the legacy 20-character limit. It blocks instead.

## Service rights and local-group boundary

The desired direct-right contracts are:

```text
FICollector/FISender
    SeServiceLogonRight

FICRLRefresher
    SeServiceLogonRight

FIUSNReader
    SeServiceLogonRight
    plus direct local Administrators membership

FIObjReader
    SeServiceLogonRight
    SeBackupPrivilege
    SeSecurityPrivilege
```

The object-reader contract forbids `SeRestorePrivilege` and
`SeManageVolumePrivilege`.

The desired direct local-group contracts include:

```text
FICollector/FISender
    Administrators:   no
    Event Log Readers: yes

FICRLRefresher
    Administrators:    no
    Event Log Readers: no
    Backup Operators:  no

FIUSNReader
    Administrators: yes

FIObjReader
    Administrators:   no
    Backup Operators: no
```

The narrow FIUSNReader local-Administrator boundary remains an intentional
characterized Windows trust boundary. The full collector does not run as local
Administrator.

## FICRLRefresher

`FICRLRefresher` is the dedicated transport-PKI revocation-maintenance service.

Its installed executable is:

```text
C:\Program Files\FI\fi-crl-refresher.exe
```

Its primary FI-owned paths are:

```text
C:\ProgramData\FI\config\fi-transport-trust.conf
C:\ProgramData\FI\pki\crl
C:\ProgramData\FI\pki\crl\fi-transport-ca.crl.pem
C:\ProgramData\FI\crl-refresh
C:\ProgramData\FI\crl-refresh\crl-refresh.jsonl
```

The refresher:

- loads the pinned FI transport trust configuration;
- derives the CRL source from the pinned transport certificate;
- supports HTTP/HTTPS and signed/sealed LDAP acquisition paths;
- validates the candidate CRL against the pinned transport issuer and
  certificate;
- activates only a validated candidate;
- journals the refresh transaction boundary before acquisition or activation;
- journals completion as `Activated`, `NoChange`, or `Error`;
- retries a failed refresh after one hour;
- normally schedules another attempt no later than 24 hours after success; and
- schedules earlier when required to attempt refresh 24 hours before CRL expiry.

If the refresh-start journal entry cannot be persisted, the refresh mutation is
not attempted.

## FI-owned paths governed by the installer

The current installer plans and validates FI-owned state including:

```text
C:\Program Files\FI
C:\ProgramData\FI\config
C:\ProgramData\FI\state
<configured spool directory>
<physical-spool-sibling collector work directory>
<configured stage directory>
C:\ProgramData\FI\release-trust
C:\ProgramData\FI\pki\crl
C:\ProgramData\FI\crl-refresh
C:\ProgramData\FI\install
```

The collector work directory is derived from the physical active spool path as a
same-volume sibling:

```text
.<spool-base-name>-collector-work
```

For example, a physical active spool named `spool` produces a sibling named:

```text
.fi-spool-collector-work
```

This directory is separate from the active spool so active-spool rollover does
not move an in-progress collector batch.

The installer applies explicit least-privilege ACL contracts to FI-owned roots,
CRL state, trust configuration, runtime executable access, and CNG private-key
files. Administrative ownership remains with Administrators or SYSTEM.

## Invocation

The installer applies by default.

```text
fi-install.exe
```

Explicit planning-only mode is:

```text
fi-install.exe -plan-only
```

`-plan-only` disables mutation even though `-apply` defaults to true.

Current deployment-input flags are:

```text
-config <path>
-receiver-address <address>
-receiver-name <dns-name>
-spool-dir <absolute-path>
-stage-dir <absolute-path>
-state-dir <absolute-path>
-governed-root <path>       repeatable
-pki-choice <choice>
-plan-only
-apply
```

For a new install, default paths are:

```text
stage: C:\ProgramData\FI\transport-v2-drain\stage
state: C:\ProgramData\FI\state
```

The spool directory and at least one governed root are required deployment
inputs.

### Configuration-file mode

`-config` loads an FI `1.1` operational configuration and validates it against
the exact supported normalized FI contract.

`-config` cannot be combined with:

```text
-receiver-address
-receiver-name
-spool-dir
-stage-dir
-state-dir
-governed-root
```

`-pki-choice` remains a separate installer choice.

The installer binds configuration approval to the source mode, source path/hash
when applicable, fixed install destination, normalized configuration SHA-256,
and exact normalized bytes.

The explicit configuration approval token is:

```text
APPROVE-CONFIG <first-16-of-digest>
```

If a validated FI configuration already exists, new-install deployment inputs
are not silently allowed to override it. The current code requires a future
explicit configuration-change workflow instead.

## PKI choice

The planner displays three conceptual PKI choices:

```text
reuse
enroll
create
```

The current native apply path supports only:

```text
-pki-choice enroll
```

`reuse` and `create` remain planning concepts but do not currently have native
mutation backends. Apply mode blocks them.

The current source enrollment path uses existing AD certificate-template
definitions and an existing FI certificate-enrollment authorization group. The
installer does not create a production KDS root key automatically.

The existing enrollment group is:

```text
ISS-FI-Certificate-Enrollment
```

The source computer must have or be granted the required enrollment
authorization. The installer verifies the requester can make the required
membership change when needed and requires `klist.exe` for the SYSTEM Kerberos
refresh used before enrollment.

## Shared CA template publication

If the required FI template definitions exist in AD but are not published by the
issuing Enterprise CA, the installer treats publication as a separate
shared-infrastructure change.

The publication set includes the two source enrollment templates and
`FI-Receiver-TLS`.

The installer does not use that approval to create template definitions, change
template ACLs, alter template cryptographic settings, alter CA keys, or issue a
certificate.

The approval displays the exact CA, authoritative DC, existing template
definitions/OIDs, current publication list, resulting publication list, and
exact `certutil.exe -SetCATemplates` argument.

The explicit token is:

```text
APPROVE-CA-TEMPLATES <first-16-of-digest>
```

A mandatory rediscovery occurs before the CA mutation. Changed CA/template state
invalidates the approval.

## Approval boundaries

The desired-state plan classifies mutating actions into two principal
boundaries.

### Approval 1 — shared infrastructure

Approval 1 covers:

```text
AD
PKI
```

Examples include gMSA/AD state and source PKI enrollment.

Approval 1 grants no local Approval 2 authority.

### Approval 2 — local FI source state

Approval 2 covers local FI mutation authorities, including:

```text
LOCAL ID
CONFIG
RELEASE TRUST
PACKAGE
RIGHTS
GROUPS
SCM
ACL
RUNTIME
```

Approval tokens are exact and fail closed:

```text
APPROVE-1 <first-16-of-boundary-digest>
APPROVE-2 <first-16-of-boundary-digest>
```

Any other input is rejection.

The digest binds the reviewed mutation set and relevant package/release identity.
For a new install, Approval 1 is followed by authoritative rediscovery. The old
pre-Approval-1 plan is invalidated and a new Approval 2 boundary is sealed from
the post-Approval-1 state.

Immediately before Approval 2 mutation, the installer rediscoveries local state
again and requires the current Approval 2 digest to equal both:

- the digest sealed after Approval 1; and
- the digest explicitly approved by the operator.

If not, no local mutation is performed.

## Receiver mTLS activation

Before enabling normal sender runtime, the installer performs an authenticated
TLS activation probe to the configured receiver.

The probe performs an authenticated TLS handshake only.

```text
No FI payload is transmitted by the activation probe.
```

The probe validates the configured transport identity, root/issuer trust, current
CRL state, receiver certificate identity, and TLS connection required by the
activation path.

If activation fails, the operator is offered:

```text
[A] Abort
[R] Retry
[P] Receiver Pending
```

## Receiver Pending

Receiver Pending allows the source installation to converge without pretending
the receiver is operational.

The exact sender state is:

```text
FISender
    Start: Manual
    State: Stopped
    PID:   0
```

The other approved local FI state may converge normally.

On a new install, choosing Pending causes the post-Approval-1 Approval 2 plan to
be rebuilt and re-sealed with the sender Manual/Stopped state.

On an installed source, choosing Pending rebuilds the local Approval 2 plan
against installed configuration and preserves only the transient
`ReceiverPending` control bit. New-install command-line deployment values are
not allowed to leak back into installed-state reconciliation.

A successful pending result is reported as:

```text
FI INSTALLER RESULT: PASS_WITH_RECEIVER_PENDING
```

The operator must correct receiver availability and rerun `fi-install.exe`.
FISender is not enabled until the receiver activation probe succeeds.

## Package and release trust

The installer requires the release package to be fully authenticated and
FI-authorized before mutation.

The release boundary includes:

- `fi-install.exe` Authenticode verification;
- Authenticode verification for every manifest-listed payload;
- signer certificate and SPKI identity;
- payload SHA-256 matching the reviewed manifest;
- detached `manifest.p7s` verification;
- a trusted manifest signer chain;
- manifest-signer authorization by the effective FI release-trust policy; and
- installer/payload signer authorization by the same active FI release-signing
  policy.

The FI release-policy authority SPKI SHA-256 is injected into the installer build
and is intentionally empty in ordinary source builds. An installer without the
pin fails closed.

Installed release trust lives under:

```text
C:\ProgramData\FI\release-trust
```

The policy files are:

```text
release-trust.json
release-trust.p7s
```

Release-trust generation rules reject rollback. A package transition must either:

- be byte-identical to the installed policy at the same generation; or
- advance exactly one generation and bind the prior installed policy SHA-256.

A signer listed only in `next_signers` is known but not yet authorized to sign an
active release.

## Transaction and rollback ownership

Approval 2 mutations remain rollback-owned until authoritative post-mutation
discovery proves convergence.

Before runtime/package changes, the installer captures stable service runtime
state. If a later local step fails, rollback runs in reverse step order and the
previous service running/stopped state is restored where possible.

The installer does not destroy transaction rollback material merely because the
mutation operations returned success. Final authoritative discovery and a
NO CHANGE plan are required first.

Package, service, and runtime work additionally verifies broker readiness,
service stability, and collector runtime readiness when the approved plan
requires those gates.

## Executable-name migration

The installer handles the legacy-to-canonical executable rename as a controlled
transaction, not as a blind file replacement.

Important rules are:

1. SCM configuration and the actual running process image are separate facts.
2. For a running service, the actual image is discovered from the SCM PID and
   `Win32_Process.ExecutablePath`.
3. SCM pointing at a new path while the current PID is still executing a legacy
   image is treated as an interrupted migration state, not as convergence.
4. Legacy binaries authorized for retirement are snapshotted and SHA-256 bound
   before mutation.
5. Services are stopped/restarted under transaction ownership as required to
   release old image locks and converge the actual process image.
6. The post-restart process image must match the desired canonical executable.
7. Immediately before retirement, each legacy file is inspected and rehashed.
8. A legacy file that changed after review is not deleted.
9. A symlink or non-regular legacy file is not deleted.
10. Rollback restores package/service/runtime state on a failed transaction.

The installer therefore does not infer executable migration success merely from
an updated SCM path.

## Local Approval 2 recovery routing

An installed source that requires only local PACKAGE/RUNTIME/SCM/etc.
reconciliation does not require a synthetic Approval 1.

The generic local route is `RequiresApproval2Controller`.

This explicitly supports recovery from interrupted executable-name migration,
including a state where:

```text
SCM path       = canonical new executable
running image  = legacy executable
legacy file    = still present
new file       = already installed
```

The local repair path refuses a plan containing Approval 1 AD/PKI mutations.

## Install records

Durable installer records live under:

```text
C:\ProgramData\FI\install
```

The record format is:

```text
fi-install-record/1.0
```

The directory and record files are protected for Administrators and SYSTEM.

Records are written through a temporary file, flushed, secured, published with a
write-through move, read back for verification, and SHA-256 hashed.

A record captures:

- transaction identity and timestamps;
- host/build/profile;
- approved plan and mutation set;
- Approval 1/2 required/given state;
- package release identity;
- manifest and signer state;
- installer and payload signer identities;
- installed-before and installed-final payload hashes;
- release-trust state;
- applied mutation authorities;
- rollback attempted/errors; and
- post-mutation/final convergence state.

Transaction kind is either:

```text
mutation
verified_no_op
```

The result records `PASS` or `FAIL` for recorded transactions. The top-level
installer additionally reports `PASS_WITH_RECEIVER_PENDING` when the exact
receiver-pending final state is accepted.

No JSON field is intentionally represented with `null`; unavailable audit values
use explicit values such as `no_record` or `not_known`.

## Idempotency

A fully converged rerun is expected to produce a NO CHANGE desired-state plan.

For an installed source whose receiver remains unavailable and where the operator
selects Receiver Pending, the rebuilt pending plan must be evaluated—not the
initial normal-state sender-activation plan.

The accepted Server 2019 convergence test established:

```text
receiver-pending rebuilt plan: zero CREATE
receiver-pending rebuilt plan: zero RECONCILE
Approval 2 after Pending:      not required
APPLY phase:                    not entered
FI mutations:                   zero
service restarts:               zero
running PIDs:                   unchanged
install-record set:             unchanged
legacy runtime files:           absent
FISender:                       Manual / Stopped / PID 0
final result:                   PASS_WITH_RECEIVER_PENDING
```

## Current accepted live migration result

The current branch acceptance record is documented separately in:

```text
docs/WINDOWS-INSTALLER-ACCEPTANCE-2026-10-09.md
```

That record covers the Server 2019 executable-name migration, interrupted
migration recovery, Approval 2 routing correction, receiver-pending convergence,
legacy-binary retirement, and post-convergence idempotency.

## Source references

The primary implementation authority is under:

```text
go/cmd/fi-install/
go/internal/windows/install/
go/cmd/fi-crl-refresh/
go/internal/windows/crlrefresh/
go/internal/spool/workdir.go
```

Where this document and executable behavior conflict, executable source is the
current implementation authority until the documentation is corrected.
