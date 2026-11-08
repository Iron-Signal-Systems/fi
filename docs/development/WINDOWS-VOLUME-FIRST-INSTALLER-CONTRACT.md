# Windows Volume-First Native Installer Work Contract

**Status:** Branch-only read-only inventory/preflight implemented. A separate volume-ID USN broker path exists but is **not enabled by FIUSNReader's v1.1 startup**. Full v2 installer approval/apply/reconciliation/rollback, secure configuration handoff, protected-object policy authority and native `adminbox` tests are outstanding.
**Branch:** `dev/windows-volume-first-20261108`
**Windows engineering/test machine:** `adminbox`

The native `fi-install.exe` is a first-class part of the refactor. Do not ship or report the source collector change as working if install/reconcile, privileges, configuration, rollback, and documentation still assume root-owned USN.

## Mandatory implementation surfaces

| Area | Existing source area | Change required |
| --- | --- | --- |
| Strict configuration | `go/internal/config/config.go` | Versioned, normalized, explicitly enrolled volumes and zero+ root policies per volume; no implicit all-volume mode |
| Discovery and approval | `go/internal/windows/install/deployment_config_windows.go` | Separate eligible/discovered volumes from deliberate enrollment; revalidate identity and approval hash before mutation |
| Root validation | `go/internal/windows/install/governed_root_validation_windows.go` | Prove root-to-approved-volume binding and mount/reparse boundaries; handle GUID/mount-only volumes |
| Approval 2 reconciliation | `go/internal/windows/install/approval2_config_windows.go` and related files | Bind policy/audit/SCM/identity mutation to approved exact normalized configuration and fresh rediscovery |
| Privileged broker | `go/internal/windows/usn/` | Restrict volume journal requests to enrolled volume identity and authenticated service, without arbitrary device access |
| Audit policy and SACL | `go/internal/windows/install/` | No blanket SACL rollout on enrolled volumes; changes only on approved policy scope with explicit administrator consent |
| Service lifecycle | `go/internal/windows/install/` SCM and recovery paths | Preserve the separate five-service and gMSA security model, transactional rollback, staged recovery, and idempotent repeat runs |
| Install configuration authority | `go/cmd/fi/config_authority_windows.go` | Fail closed on unsupported/deprecated versions and unknown/unenrolled volumes |
| Operator docs | `docs/WINDOWS-INSTALLER.md`, `docs/WINDOWS-INSTALLER-OPERATOR-GUIDE.md`, `docs/WINDOWS-SERVER-VALIDATION.md` | Keep examples and exact-build evidence aligned with code actually tested |

## Read-only scope-change contract implemented; no authority granted

The new `go/internal/windows/volumereview/` package and branch-only `-list-volumes -volume-config` inventory command now report a canonical requested-v2 scope hash, each enrollment's current native match, typed authorization-relevant changes, and a deterministic review fingerprint. Proposed changes **always require explicit approval**; a mismatch blocks the operation. Revalidation compares the entire review against freshly discovered identities and rejects stale or modified evidence.

These are **preflight inputs**, not an authenticated approval. Future Approval 2 work must still bind a trusted installed baseline, host identity, approved policy effects, exact native object roots, and operator consent to a protected and verifiable receipt, then recheck state at the write boundary. No current `1.1` install plan or runtime begins collecting volumes as a result of this code. See `docs/development/WINDOWS-VOLUME-FIRST-SCOPE-REVIEW.md`.



1. Read-only `-plan-only` reports volumes and policy changes accurately without writes.
2. A discovered volume is not enrolled by default. Addition of any volume, system-volume enrollment, policy widening or new audit/SACL authority requires explicit new approval.
3. Reformat, drive-letter change, volume replacement, root move, mounted-folder alias and policy removal are distinguished.
4. Configuration parse/normalize/round-trip is deterministic and rejects duplicates and unknown settings; approval digest binds intended volume identities, policies and configuration bytes.
5. Existing root-only configurations cannot silently trigger wider monitoring. A clean development installation is permitted, but migration cannot be guessed or hidden.
6. Fail closed on stale approval, missing privilege, unavailable AD/PKI, trust error, volume drift and unsupported filesystem.
7. Interruptions mid-install/upgrade preserve journal and spool custody and produce recoverable, explicit partial-application/rollback evidence.
8. Identical reruns are idempotent; removal and reconfiguration must not erase source history to make the installer converge.
9. Signed artifacts, constrained service privileges, safe ACLs and existing CRL trust remain mandatory.
10. All installer behavior requires native Windows tests on `adminbox`, not only a Go cross-compile.

## Evidence before declaring installer functionality complete

Record source commit, package/executable hashes, exact Windows build, configuration digest, plan, approved actions, failed actions, rollback/reconciliation state, service states and test logs. Test fresh install, rerun, update, decline, stale approval, multi-volume install, policy edits, reformat/replacement, outage/reboot and uninstall. Retain failures and later passes in separate evidence records.

**Current status:** Branch-only read-only inventory, native identity preflight, and deterministic scope-change review exist. Full v2 installer apply/approval/reconcile/rollback, protected manifest handoff, FIUSNReader startup selection, and native `adminbox` acceptance remain unimplemented. These partial preflight features do not satisfy installation acceptance.
