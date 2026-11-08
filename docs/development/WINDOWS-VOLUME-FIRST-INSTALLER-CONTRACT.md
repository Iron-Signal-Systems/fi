# FI Windows Volume-First — Fresh Installation Contract

**Status:** Development only. Read-only discovery, fresh-host inspection, scope review, signed-intent verification and signed installed-grant verification are partial foundations. No volume-first installer apply, native signed state installation or end-to-end source acceptance exists.  
**Branch:** `dev/windows-volume-first-20261108`  
**Windows engineering and test host:** `adminbox`  
**Deployment model:** **NEW INSTALL ONLY. No FI present. No in-place update, repair, migration, adoption or reconfiguration.**

## Nonnegotiable installation model

The volume-first release **replaces** the legacy root-centric Windows FI code after development acceptance. It is not installed over existing FI. There is no supported v1.1-to-v2 upgrade, legacy checkpoint reuse, inherited spool custody, configuration conversion or auto-reconciliation.

Before the new installer starts any mutation, the machine must have **no locally installed FI services or FI-owned installation/state trees**. An operator handles disposal of prior development hosts/artifacts **outside** the new installer, after making any intended evidence-retention decision. The installer must neither silently delete that evidence nor assume an old source can be resumed.

A successful initial installation creates a new installation identity, generation 1, a new signed grant with **no predecessor**, new per-volume journal epochs and fresh checkpoints. An explicitly approved previously deployed shared AD/PKI issuer may be used if compatible, but that is a separate credential/trust decision; it does not turn a local FI installation into a supported update.

## Implemented branch-only clean-host preflight

The read-only command:

```powershell
.\fi-install.exe -check-clean-install
```

is isolated from all legacy installer operations, including the existing default `-apply=true`. It rejects any additional installer flags, including `-apply=false`, `-plan-only`, `-list-volumes`, `-volume-config`, `-config`, or positional arguments. Explicitly disabled read-only selectors (`-check-clean-install=false` or `-list-volumes=false`) also fail before the old default apply path.

The underlying `go/internal/windows/freshinstall` package queries these exact local Windows SCM service names: `FICollector`, `FIUSNReader`, `FIObjReader`, `FICRLRefresher`, `FISender`. It also checks `C:\Program Files\FI` and `C:\ProgramData\FI` with `Lstat`, treating directories, files and reparse points as existing artifacts. Every result is `Absent`, `Present` or `Unknown`, with a reason for uncertainty. Any `Present` or `Unknown` causes `install_blocked=true` and a nonzero exit. All checks run to completion to report every collision. No cleanup, reconfiguration, service start or SACL change occurs.

A passing preflight is only a **point-in-time observation**. The future native installer must revalidate this on the actual write boundary, prevent concurrent installation from racing that check, and additionally validate v2 policy and native volume identity before any privileged operations.

The separate branch-only `-list-volumes [-volume-config <scope-v2.conf>]` command remains read-only and is **not** an installation action.

## Implementation surfaces required for the future fresh installer

| Area | Required fresh-only behavior |
| --- | --- |
| Entrypoint | New v2 install path must **never** fall through to legacy `BuildPlanWithInputs`, `UPDATE / RECONCILE`, local repair, migration or update logic |
| Read-only checks | Strict absence of all fixed FI services, program directory and ProgramData FI tree; fail closed on SCM/filesystem ambiguity; no silent cleanup |
| Scope | Explicit NTFS volume GUID + full 64-bit volume serial enrollment; zero or more governed roots controlling deeper policy; no automatic all-volume selection |
| Approval | First-install scope review from an empty baseline; all requested volumes/policies are additions requiring consent, even a volume with zero governed roots |
| Consent | Verify a fresh-install signed transaction intent with sequence 1, empty prior-config digest and no trusted old FI baseline; authenticate the real Windows administrator and issuer |
| Windows privileges | Least-privileged gMSAs, bounded service-SID pipe authentication, correct signed binaries, AD/PKI trust and native volume authorization |
| Protected state | Create-only identity, protected issuer public key and configuration; new generation-one signed installed grant and independent immutable commitment; no old-state adoption |
| Write transaction | Install only newly created FI artifacts; failure reverses **only this transaction's new effects**, never erases prior FI evidence to converge |
| Service startup | Verify committed installed authority, operational config, exact enrolled volume identity and journal lifecycle before enabling volume-wide collector/broker |
| Validation | Native `adminbox` test matrix including clean install, refusal on remnants/uncertainty, mid-install failure, restart, two-volume faults and end-to-end signed custody |

**Important:** Installer rollback during a failed **fresh** installation is necessary. That is unrelated to an upgrade rollback. Recovery must be explicit and evidence-preserving, and the installer must not erase preexisting FI to appear clean.

## Creation-only transaction journal foundation

A package-private, **not activated** transaction engine now exists in `go/internal/windows/freshinstall/creation_journal.go`. Its eight fixed creation phases have write-ahead intent/verified-creation events and bounded replay. A crash between intent and acknowledgement yields **in-doubt**, not permission to repeat or delete an artifact. Journal SHA-256 links detect sequence corruption, **not** privileged writer identity; a native protected append-and-sync sink, ownership-limited rollback and exclusive Windows create-only backend remain to be implemented and accepted. No service may be started based solely on this journal. See `WINDOWS-VOLUME-FIRST-CREATION-JOURNAL.md`.

## Source/test status

- `go/internal/windows/freshinstall/`: pure policy and Windows-native SCM/filesystem read-only preflight, with collision/unknown failure tests.
- `go/cmd/fi-install/`: isolated `-check-clean-install` action, blocked mixed flags, JSON report, nonzero on existing or uncertain local FI.
- `go/internal/windows/volumereview/`: `BuildFreshInstall` and `RevalidateFreshInstall` disallow an installed baseline.
- `go/internal/windows/volumeconsent/`: `VerifyFreshInstall` refuses a previous generation/config.
- `go/internal/windows/volumegrant/`: `VerifyFreshInstallation` refuses grant generations greater than one and predecessor grants.
- **Not yet integrated:** native production signer, protected Windows commitment and ACLs, complete v2 operational config, the transactional installer, the FIUSNReader startup handoff, FICollector pipeline and backend ingestion.

This remains **development work**, not accepted installation functionality. Read-only preflight and pure cryptographic verification do not authorize source reads. `ServeEnrolledVolumes` remains explicitly disabled until a complete protected fresh-install transaction and native acceptance are proved.

See `WINDOWS-VOLUME-FIRST-FRESH-INSTALL.md`, `WINDOWS-VOLUME-FIRST-SCOPE-REVIEW.md`, `WINDOWS-VOLUME-FIRST-CONSENT-RECEIPT.md`, `WINDOWS-VOLUME-FIRST-INSTALLED-GRANT.md` and `WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md`.

**Noninterference:** Keep all changes in the development branch. Do not modify `main` or the installed `ISS-FS-22A` source; do not start FISender.
