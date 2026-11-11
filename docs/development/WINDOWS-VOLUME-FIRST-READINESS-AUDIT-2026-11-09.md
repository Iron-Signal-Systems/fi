# FI Windows Volume-First — Branch Readiness and Installer Audit

**Audit date:** 2026-11-09  
**Development branch:** `dev/windows-volume-first-20261108`  
**Source baseline examined:** `41d94bb035994348708f78cd33b5c9c32314a4ce`  
**Base/main at audit:** `806d87ebe75f13bcf06ed0dbc2e7653297b7009e`  
**Decision:** **NO-GO FOR FI REMOVAL OR FRESH V2 INSTALLATION ON ISS-FS-22A**. The branch can be reviewed as incomplete engineering work; it is not an installable, accepted replacement. No approval to uninstall, clear spools, delete checkpoints, update `main`, or start FISender is conferred by this report.

## Audit scope, method, and limitations

The branch differed from `main` by **248 commits and 80 changed files** (GitHub compare at the stated SHA). Reviewed the changed-file inventory and the v2 components across configuration, Windows read-only discovery, policy-root inspection, USN broker authorization, epoch continuity, scope review, signed consent, signed installed-grant verification, fresh-host inspection and creation journal. Traced the native installer entry point, Windows helper service entry points, FICollector service/USN scheduling, operational configuration authority, legacy installer apply path, supporting PowerShell deployment tools, documentation and GitHub workflows. Compared against the proposed source architecture and V01–V20 validation matrix.

GitHub Actions at the audited source SHA: Linux tests **PASS**, Windows tests **PASS**, Go race detector (Linux) **PASS**, `govulncheck` (Linux-reachable packages) **PASS**, Phase 2 wire fuzzing **PASS**, Go CodeQL security-extended **PASS**. These tests establish compilation and selected unit/native-fixture behavior, **not** signed installer artifact identity, approved Windows service rights, raw-volume functionality on `adminbox`, crash/power-loss recovery, or operational acceptance on ISS-FS-22A. No build-qualified and signed v2 installation package was identified or created during this audit. No live machine access or on-host validation was performed.

This is an engineering source/contract/readiness audit, not proof that every old source line has been re-characterized or that unexecuted native paths are defect-free. Existing root-centric acceptance records are historical and must remain intact.

## Blocking findings

| ID | Severity | Finding and evidence | Required before removal/reinstallation |
| --- | --- | --- | --- |
| A01 | **P0 — installation blocker** | **There is no v2 installer apply path.** `go/cmd/fi-install/main_windows.go` diverts `-list-volumes`, optional `-volume-config`, `-inspect-policy-roots` and `-check-clean-install` into read-only commands. Its default `-apply=true` still reaches the *legacy* desired-state installer. `go/internal/windows/install/deployment_config_windows.go` explicitly requires `config.Version11` and governed-root input. A branch-built executable can therefore run the **old** install plan if invoked normally. | Implement and validate a separate fresh-only v2 apply entry point, protected transaction and explicit failure of unsupported legacy update/reconcile operations; do not treat the old default apply as the replacement installer. |
| A02 | **P0 — privileged startup blocker** | `go/cmd/fi-usn/main_windows.go` and `go/cmd/fi-obj/main_windows.go` load v1.1 config and governed roots. `usnbroker.ServeEnrolledVolumes` returns `ErrVolumeModeRequiresApproval` by design. The internal enrollment-ID dispatch is not a callable, authenticated installed service. | Authenticate committed v2 installed-grant state at service startup, re-attest native enrollment identity, preserve separate helper identities and service-SID pipe checks, and test authorized/denied operations on native Windows Server. |
| A03 | **P0 — source custody blocker** | `go/cmd/fi/service_usn_windows.go` still schedules and locks individual governed roots; its checkpoint owner is derived from root scope. `volumeepoch/continuity.go` is pure assessment, not persistence or runtime capture. There is no one-source-per-volume FICollector pipeline, durable per-volume epoch/USN checkpoint, verified spool handoff, or volume-fault isolation in the live v2 path. | Implement new per-volume capture, baseline/gap handling, bounded fairness, source evidence outside governed roots, verified custody before checkpoint advance and restart/replay tests. |
| A04 | **P0 — data contract blocker** | The branch compare includes no changes to the PostgreSQL schema, source record/ingest packages or typed backend projectors. Volume epochs, minimal outside-root USN records and governed-root policy associations are not integrated end-to-end. | Implement/version the new source records, backend schema, ingest, typed projection and query contracts; prove signed generation acceptance, replay and lineage. |
| A05 | **P0 — installer security/rollback blocker** | `volumeconsent` and `volumegrant` are **pure verification components**; the native administrator signer/issuer, independently protected initial commitment, full operational v2 configuration, protected journal parent creation, authenticated service handoff and v2 installer resource-creation/ownership-only rollback are missing. `freshinstall/creation_journal_windows.go` contains only an unexported, isolated native journal I/O writer, not a complete transaction. | Implement real Windows protected bootstrap, secure principal/ACL/gMSA/PKI setup, disabled-until-authorized services, create-only transactional apply, crash/in-doubt recovery and precise ownership-limited rollback. |
| A06 | **P0 — acceptance blocker** | `WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md` has V01–V20 **NOT RUN**. No controlled `adminbox` tests for the complete design, no native signed-install-to-reboot evidence, no target-Server-build results, no FICollector-to-FreeBSD receiver/backend acceptance and no exact signed release package for v2. `TestNativeEnrolledVolumeUSNReadOnly` is intentionally opt-in and has no reported `adminbox` result. | Run and record V01–V20 with exact source SHA, executable/signature hashes, OS/build, input scope, expected/observed results and failures; never promote CI smoke tests to native acceptance. |

## Nonblocking but required review cleanup and engineering follow-ups

| ID | Priority | Observation |
| --- | --- | --- |
| A07 | **P1 — documentation safety** | The operator guide still describes a root-centric, FI 1.1 installation procedure. Its original banner called the creation journal `mock-only` although an isolated native Windows file writer is now present. The implementation inventory said the v2 parser was not wired to the installer, although it is used by read-only inventory, and also said there was no native journal write/sync implementation. Those statements have been corrected as part of this audit. A v2 stop-gate notice is placed above the legacy instructions. |
| A08 | **P1 — evidence preservation** | No current native inventory of ISS-FS-22A installed identities, spool/unsent generations, signed receipts, certificates, checkpoints, old service configuration, audit/SACL settings or backend custody has been captured in this audit. Removing FI before evidence is preserved may erase unrecoverable developmental source history. The still-stopped FISender must not be started as an implied audit step. |
| A09 | **P1 — native behavior** | GitHub Windows tests prove selected isolated directory and journal primitives, not privileged server service identities or policy-root attestation of actual enrolled NTFS volume GUIDs on `adminbox`. Raw-volume opt-in integration and reparse/hard-link/rename/delete/ACL failure cases need server characterization. |
| A10 | **P2 — read-only inspection efficiency** | The opt-in root inspector enumerates the native Windows volume inventory per enrolled volume, in addition to the initial CLI inventory. It is explicitly read-only and cannot grant authority, but should be measured/bounded and consolidated carefully without discarding fresh same-handle identity re-attestation at authorization boundaries. |
| A11 | **P2 — source provenance** | Current root-directory FileIdInfo observations do not establish historical parentage. USN V2 file references must be reconciled to the native 128-bit identity, and rename/delete/hardlink/reparse evidence must yield `Unknown` when historical containment cannot be proved. This must be tested before FIObjReader grants deep observation. |

## What is positive and usable for development review

- The branch has strict explicit v2 scope parsing, volume GUID plus full-width serial enrollment comparisons, read-only native inventory, explicit governed-root identities, a per-volume policy association model, and opt-in diagnostic preflight with nonzero failure outcomes.
- Helper wire operations accept enrollment IDs rather than client-supplied raw-device paths; the public v2 helper startup fails closed pending approval. The existing source privilege split is documented.
- Signed short-lived approval intent and signed installed-grant verifiers have negative-path tests and require separately pinned trust inputs; no claim is made that those sources yet exist on a protected Windows installation.
- Journal design distinguishes durable intent from owned-created acknowledgements and treats an ambiguous interruption as `in-doubt`, not cleanup authorization. Existing native writer is deliberately private.
- CI, CodeQL and Linux security validation pass on the audited code baseline. No changes to `main`, active Windows services or the backend were made by the audit.

## Approval gates — in required order

1. Close A01–A05 in code and align every operational/installer document with **implemented** behavior. A clean Windows source with **no FI** must be the only supported first-install input; no existing local FI artifacts are auto-deleted or adopted.
2. Produce and authenticate one exact signed v2 installer/service package. Verify first-install consent, native protected commitment, gMSA/service-SID boundaries, source read restrictions and transactional rollback in an isolated controlled environment.
3. Run native `adminbox` V01–V16 positive, denied, crash/restart and per-volume failure tests, with exact build and evidence. Demonstrate historically ambiguous objects remain `Unknown` rather than invented containment.
4. Run V17–V19 full transport and backend acceptance, including source custody before checkpoint, bounded multi-volume load and correct per-epoch projection. Verify no legacy schema assumptions.
5. Before **any** removal from ISS-FS-22A, separately capture its current SCM/PKI/gMSA/audit/SACL configuration, installed build/signatures, source enrollment and journal identifiers, local state/checkpoints, spool/unacknowledged generation manifest pairs, recovery/installer logs and downstream custody. Establish an independently reviewed recovery/disposition decision and a maintenance window. This audit did **not** verify that host's current state or authorize its alteration.
6. Re-audit the exact final commit and signed artifacts. Obtain explicit operator approval to remove the old **development** installation only after gates 1–5 have passed. If any gate remains unproven, the answer remains **NO-GO**.

## Documentation classification

`docs/WINDOWS-INSTALLER.md` and `docs/WINDOWS-INSTALLER-OPERATOR-GUIDE.md` describe the existing legacy installer and are **NOT** approved v2 deployment instructions. Dated October 2026 Windows acceptance records describe earlier builds and must not be rewritten as v2 acceptance. `docs/development/WINDOWS-VOLUME-FIRST-*.md` and ADR-0002 describe the proposed replacement and its incomplete engineering foundation. The validation matrix remains authoritative for unrun acceptance.

**Disposition:** The audit report is ready for engineering review; the branch is **not** approved to replace installed FI. Do not interpret this document, a CI green check or a read-only preflight success as permission to clear ISS-FS-22A.

## Remediation follow-up — 2026-11-09 (A01 remains open)

The development branch now invokes `requireVolumeFirstReadOnlyMode` before any inherited v1.1 installer discovery or mutation. Default invocation, old `-apply` and `-plan-only` usage, and mixed commands are denied; only explicit standalone read-only actions remain. This mitigates the **legacy fallback** part of A01, with unit tests and an actual Windows executable CI smoke test. **The original A01 finding and its audit-baseline evidence above remain intact. A01 is still P0/open** until there is a complete authenticated **v2 fresh-install apply** transaction. No other P0 finding is closed. See `WINDOWS-VOLUME-FIRST-INSTALLER-EXECUTION-GATE.md`.

## Additional A03 development evidence — 2026-11-09 (not closure)

An isolated `volumecustody` package now verifies **actual published FI spool bytes** for one bounded volume-owned minimal USN window, including a terminal read-boundary record, before returning an **in-memory cursor proposal**. It preserves USN V2/V3 native reference width and rejects incomplete/tampered source batches. This is progress toward the custody boundary in A03, but **A03 remains P0/open**: no authenticated native reader, per-volume FICollector worker, multi-batch atomic publication/retry, protected spool lifetime, durable checkpoint write or backend consumption is integrated. No on-host `adminbox` evidence has been recorded. See `WINDOWS-VOLUME-FIRST-SPOOL-CUSTODY.md`.

## Further A03 development progress — 2026-11-09 (still NO-GO)

A new isolated `ProcessOneWindow` coordinator now imposes ordering on enrolled-volume source passes: exclusive-lease dependency, canonical checkpoint and pre-read journal assessment, bounded native reader dependency, actual spool custody verification, post-publication journal continuity check, checkpoint re-read and required durable-CAS callback. Mutation by a publisher cannot rewrite the captured facts being verified, and ambiguous publication or checkpoint commits are recorded rather than considered safe to discard. Fault-injected tests use real temporary FI spool files.

**This is not P0/A03 closure**: no authenticated native FIUSNReader client, cross-process per-volume lease, protected v2 checkpoint store, crash recovery, complete one-batch publisher, FICollector service wiring or FreeBSD backend support is installed or accepted. Audit rows V01–V20 remain NOT RUN. See `WINDOWS-VOLUME-FIRST-ONEPASS.md`.

## Concrete single-batch spool publisher — 2026-11-09 (A03 remains open)

An isolated `OneBatchSpoolPublisher` now writes bounded FI volume source facts and a terminal source boundary as one verifiable FI spool manifest/data pair. It refuses premature rollover and incomplete windows. New `spool.Writer.AbandonUnpublished` support closes incomplete work without accidentally publishing partial custody evidence or deleting previously published artifacts. Tests exercise disposable real files and the isolated one-pass coordinator.

This **does not close A03**: the native authenticated volume reader, Windows service runtime, protected cross-process per-volume lease, real persistent v2 checkpoint CAS, crash recovery, bounded multi-batch publication and FreeBSD backend integration remain absent. The installed ISS-FS-22A source and `main` are unchanged; V01–V20 remain NOT RUN.

## Windows-native checkpoint I/O experiment — 2026-11-10 (A03 still P0)

The isolated volume-first `WindowsVolumeState` now implements real Windows cross-process lease exclusion and bounded canonical checkpoint reads, plus full-state CAS writing via an exclusively created flushed pending file and `MoveFileExW` write-through replacement. Fault-path tests reject stale cursors, changed epoch/identity, corrupt state and ambiguous pending files; source-window coordinator tests can use this file backend and the actual FI spool publisher in an isolated Windows runner.

**This is not installed trusted state.** There is no protected-parent issuer/ACL/ancestor attestation, initial native enrollment and signed grant, authenticated service handoff, controlled reboot/power-loss acceptance, or FI backend/schema integration. All source and installer P0 findings remain open and ISS-FS-22A remains untouched.

**Lease-lifetime fix (2026-11-10):** The Windows volume state now retains its in-process operation mutex across each complete checkpoint file read/commit instead of merely during its lease lookup. This prevents a concurrent Release from dropping the native cross-process lock while a write is in progress. Added an isolated concurrency regression test. It does not replace required installed-state ACL/owner and native startup attestation.

**Checkpoint representation hardening (2026-11-10):** Native state loading now requires a byte-exact canonical JSON encoding, preventing JSON duplicate keys, alternate whitespace and noncanonical persisted forms from being silently accepted. This remains a development file-state check, not signed or installer-protected authority.

## Native journal parent/child security gate — 2026-11-10 (A05 remains P0)

The private Windows creation-journal writer now enforces the retained native parent directory's exact SYSTEM/Administrators owner/protected DACL check **before** `CREATE_NEW`, then checks the newly created file's owner and exact inherited privileged ACEs **before** acknowledging `ReserveNew`. An invalid effective child DACL leaves an in-doubt file for manual disposition; no deletion or automatic retry is permitted. The original native temporary-directory writer tests explicitly use an isolated `_test.go` constructor, not a production security bypass. Pure and native-SDDL negative tests cover wrong owners, unexpected trustees, explicit/noninherited ACEs, full-control mismatch, and added entries.

**A05 stays P0/open:** native protected-parent creation, verified ancestor provenance, authenticated issuer/operator consent, independent installed-grant commitment, service identities/SCM handoff, fully implemented resource-creation transaction, rollback and Windows `adminbox` acceptance remain missing. The journal writer is still private and disconnected from the installer executable. ISS-FS-22A must not be removed.

## Protected directory created with initial ACL — 2026-11-11 (A05 remains P0)

A private `freshinstall.reserveProtectedBootstrap` Windows experiment now creates only a fixed `FI-Installer` child under an existing supplied local parent, with an explicit protected SYSTEM/Administrators owner/DACL provided directly to `CreateDirectoryW`. The function never adopts a preexisting child, retains native parent/child handles without delete-sharing, verifies actual new directory identity and DACL, and leaves any failed/ambiguous creation for manual inspection rather than deleting it. The helper is unexported, has no connection to installer apply or FI service startup, and is tested only in isolated temporary Windows directories.

**A05 remains P0/open:** this is not authenticated creation under the real trusted system `ProgramData` directory; no trusted ancestor/issuer chain, operator approval/token, exclusive installation journal ordering, protected grant commitment, native resource-creation transaction, crash/reboot safety, or `adminbox` privileged acceptance has been established. A05/V14/V16 stay NOT RUN; ISS-FS-22A installation remains NO-GO. See `WINDOWS-VOLUME-FIRST-PROTECTED-BOOTSTRAP.md`.

## 2026-11-11 Go standard-library security advisory

GitHub Security Validation detected `GO-2026-6859` on the branch's Go `1.27.3` standard library in the `govulncheck` job. Go `1.27.4` was released 2026-11-10 and fixes that advisory; `go/go.mod` now requires `go 1.27.4`, with both CI and Security Validation selecting the module's toolchain. This changes only the development branch and does not establish release readiness. The final exact-commit vulnerability check must pass before a green status is claimed. Public advisory: https://pkg.go.dev/vuln/GO-2026-6859 .
