# Windows Volume-First Development Validation Matrix

> **Readiness decision 2026-11-09:** **NO-GO** to remove or reinstall FI on ISS-FS-22A. Green GitHub CI is not completion of the V01–V20 native acceptance cases. See [branch readiness audit](WINDOWS-VOLUME-FIRST-READINESS-AUDIT-2026-11-09.md).

**Status:** All cases NOT RUN. This matrix is a development requirement, not a test report.
**Branch:** `dev/windows-volume-first-20261108`
**Windows development/test machine:** `adminbox`

The branch now has a signed short-lived installer-intent verification package (`go/internal/windows/volumeconsent`) with unit tests. **It is not an installed v2 authority**: native signer, administrator approval token, protected installation state, transactional apply/rollback and privileged service startup remain NOT RUN/NOT IMPLEMENTED.

The branch now includes a read-only `freshinstall` SCM/path preflight and first-install-only verification wrappers. The supported v2 deployment starts with no FI, first approval sequence 1 and initial grant generation 1; no in-place update or migration is intended. The branch also includes a pure-Go signed installed-grant verifier with replay/tamper/scope/host/sequence regression tests. **The protected native grant commitment store, signer, transactional installation, privileged service handoff, and actual Windows acceptance are NOT RUN/NOT IMPLEMENTED.** See `WINDOWS-VOLUME-FIRST-INSTALLED-GRANT.md`.

The branch includes isolated, pure-Go governed-root policy association for zero/overlapping roots with explicit `Unknown` ancestry, plus a separate read-only Windows directory-identity attestation helper. The standalone installer inventory now has an opt-in read-only governed-root inspection report with per-volume success/failure evidence, exact CLI isolation and blocking on malformed/unavailable identity. See `WINDOWS-VOLUME-FIRST-ROOT-PREFLIGHT.md`. The native helper verifies each enrolled volume root ancestor without following reparse points. Neither proves historical USN path containment or authenticated native installer authority. No integrated v2 source collection, privileged service verification, or V04/V05/V06 acceptance is established. See `WINDOWS-VOLUME-FIRST-POLICY-ASSOCIATION.md` and `WINDOWS-VOLUME-FIRST-NATIVE-POLICY-ROOT.md`.

The branch now includes a bounded creation-only journal protocol, in-memory fault-injection tests, a private Windows-native journal writer and a separate protected `FI-Installer` child creation experiment with isolated temporary-directory tests. Its normal writer now verifies strict parent owner/protected DACL **before native journal creation**, and the new child's effective inherited owner/DACL **before accepting the creation**. The new create-only experiment does provision an **explicitly protected child DACL at creation**, but it does **not authenticate the trusted system parent/ancestor issuer or committed installed state**, create v2 FI resources or prove crash-consistent native rollback. Acceptance must explicitly test failure between durable intent, native creation and durable acknowledgement, and refuse auto-retry or deletion when ownership is ambiguous. See `WINDOWS-VOLUME-FIRST-CREATION-JOURNAL.md` and `WINDOWS-VOLUME-FIRST-JOURNAL-PARENT-SECURITY.md`. All native transaction and power-loss tests remain **NOT RUN**.

The Windows runner's isolated journal tests are source-level/native-I/O evidence only. **No row requiring an authenticated installation, protected ACL, service SID/gMSA or controlled `adminbox` environment has passed**. The final dev branch commit and exact runner results must accompany any future promotion request.

**Narrow branch safety check:** Windows CI now builds and launches the actual branch `fi-install.exe` and verifies default and legacy flags are blocked before any installer discovery. This is an **A01 fallback mitigation only**, not V14/V16 native v2 installer acceptance. See `WINDOWS-VOLUME-FIRST-INSTALLER-EXECUTION-GATE.md`.

**New Windows file-state development (2026-11-10):** An isolated Windows `WindowsVolumeState` implements a nonblocking cross-process volume lease, strict bounded checkpoint read and whole-state file CAS using a flushed pending file and write-through native rename. It does **not** establish the protected installer directory, installed grant, service authority, power-loss acceptance, or full source custody; V03/V07/V08 remain NOT RUN. See `WINDOWS-VOLUME-FIRST-NATIVE-CHECKPOINT.md`.

**New isolated custody coordination and verification:** `go/internal/windows/volumecustody` checks published spool file bytes against a one-batch, bounded volume USN window and returns only an in-memory checkpoint candidate. Its new one-window coordinator requires an injected exclusive lease, native reader and atomic-CAS store; the new concrete complete-window publisher uses the FI spool writer but is not an installed native service, with pre/post source identity checks and explicit in-doubt failure reporting; these are not installed native implementations. No live reader, spool lifetime lock, persistence transaction, source service or backend linkage exists. These tests do **not** satisfy V03, V05, V07, V08 or V17. See `WINDOWS-VOLUME-FIRST-SPOOL-CUSTODY.md` and `WINDOWS-VOLUME-FIRST-ONEPASS.md`.

## Rules of evidence

The branch includes an opt-in read-only `TestNativeEnrolledVolumeUSNReadOnly` test for `adminbox`, described in `WINDOWS-VOLUME-FIRST-USN-BROKER.md`. Its existence is NOT a PASS. All native acceptance rows remain NOT RUN until actual evidence is recorded.



Each test must record the exact source SHA, signed artifact and executable hashes, Windows build, source topology, starting configuration and custody, procedure, expected and observed outcomes, failure details and final state. Never count historical root-centric test results as proof of the redesigned implementation. Never treat compilation, unit tests or a benchmark as native Windows failure-path acceptance.

| ID | Required demonstration | Initial state |
| --- | --- | --- |
| V01 | Discover NTFS volumes with letters, mount directories and GUID-only identifiers; reject unsupported filesystems | NOT RUN |
| V02 | Discovered but unenrolled volumes generate no collected records; approved enrollment changes exactly selected volumes | NOT RUN |
| V03 | Two+ enrolled volumes each have independent USN capture, durable checkpoint, journal identity and epoch | NOT RUN |
| V04 | A volume with zero, one and overlapping governed roots captures each USN change once and produces appropriate policy memberships | NOT RUN |
| V05 | Changes outside governed roots yield bounded minimal evidence without unauthorized content, ACL or privileged object reads | NOT RUN |
| V06 | Rename, hard links, delete/recreate, inaccessible objects, ADS, reparse and cross-volume mount/move preserve correct identity and unknowns | NOT RUN |
| V07 | Journal recreation, aged-out history, volume reformat/replacement and repeated GUID/mount locator produce explicit gaps and new epoch | NOT RUN |
| V08 | Forced stop/reboot during acquisition, spool, manifest publication and checkpoint advance preserves custody and deterministic restart | NOT RUN |
| V09 | Volume failure/offline/missing journal does not block healthy volumes or independent Security processing | NOT RUN |
| V10 | Windows Security 4663 presence/absence, SACL coverage gap, circular log wrap and unavailable log yield correct attribution/coverage | NOT RUN |
| V11 | Non-admin FICollector, authenticated local pipe and helper narrow enrolled-volume authorization; reject unapproved raw-volume access | NOT RUN |
| V12 | FIObjReader is invoked only for bounded authorized exact-object observation, not a generic path/file proxy | NOT RUN |
| V13 | Resource limits, multi-volume fairness, spool pressure and large 10M-object workload; measure every stage separately | NOT RUN |
| V14 | Native installer read-only discovery, scope approval, normalized config, duplicate rejection and plan-only non-mutation | NOT RUN |
| V15 | Installer stale approval, unauthorized volume addition, scope widening, audit change and volume identity drift fail closed | NOT RUN |
| V16 | Fresh installation on an FI-free host, rejection if any of the five services/three FI-owned paths including the bootstrap journal root exist or cannot be inspected, stale-check race handling, rollback only of new transaction artifacts, service restart, no-update refusal | NOT RUN |
| V17 | New source records retained across verified spool, signing, sender/receiver retry, replay, duplicate handling and generation-size boundary | NOT RUN |
| V18 | Fresh PostgreSQL schema and Go ingest/projectors preserve epoch/gap lineage and governed policy associations | NOT RUN |
| V19 | Current docs, installer operator guides, schemas and test artifacts match observed implementation; historical tests remain unaltered | NOT RUN |
| V20 | `ISS-FS-22A` service configuration and stopped FISender remain untouched by development branch work | NOT RUN |

## Safety properties that block further integration when violated

- No checkpoint advances before verified custody; a retry does not delete history.
- No collector privilege expansion, unauthenticated pipe, generic raw-volume proxy or arbitrary protected-object reader.
- No implicit enrollment or SACL propagation from discovery.
- No invented file paths, actors, continuity or missing history.
- No conflation of source acquisition, deep observation, sender throughput, recorder custody and relational projection.
- No claim that `main`, a deployment, or a release has been updated merely because a branch commit exists.

## Development test closeout

Record PASS / FAIL / INCOMPLETE with source/build/environment/log references, every observed failure and its later retest. Include measured resource rates and backlog slope where relevant. Source and installer changes must have regression tests for both success and failure paths; native Windows tests run on `adminbox`. Any change to `main` is a separate explicitly authorized future integration decision.

**2026-11-11 native protected bootstrap experiment:** Isolated Windows tests now exercise a private `FI-Installer` directory creation with creation-time security attributes, retained native handles, collision rejection, strict journal writer integration and concurrent creation. These do not meet V14/V16: the real system parent, elevated installer identity, host-wide clean-state lock, write-ahead transaction, installed commitment and restart/power-loss behavior are unproven. Privilege-restricted runner skips are not counted as native creation success. See `WINDOWS-VOLUME-FIRST-PROTECTED-BOOTSTRAP.md`.

**Bootstrap rename caveat (2026-11-11):** A real Windows runner permitted renaming a protected bootstrap directory despite retained no-delete-share handles. The package now re-verifies original native parent/child paths and security at the internal handoff; any move fails closed. This is not atomic path pinning, so V14/V16 remain NOT RUN and protected ancestor/handle-relative creation is a prerequisite before installer activation.

**2026-11-11 parent-handle-relative bootstrap creation:** The private `FI-Installer` child now uses `NtCreateFile` with `RootDirectory` bound to the retained parent, fixed leaf name and protected descriptor at creation. A Windows test requires relocation of its disposable parent and validates creation under the held object; invalid descriptors and preexisting target refusal are covered. This resolves the second-by-path child-create gap, but **does not** authenticate the initial system parent, installed commitment, signer/operator, or full creation-journal transaction. V14/V16 remain NOT RUN.

**2026-11-11 system parent identity observation:** Added read-only Windows OS known-folder/Windows-directory resolution, NTFS system-volume verification, root/ProgramData/Windows 64-bit serial + 128-bit file identity comparison, and repeated handle/name re-attestation with real disposable-directory rename/replacement tests. This is **not installed issuer or operator trust** and does not bind native bootstrap creation to an authenticated system parent. All V14/V16 privileged/installer acceptance remains NOT RUN. See `WINDOWS-VOLUME-FIRST-SYSTEM-PARENT-EVIDENCE.md`.


**2026-11-11 read-only root/ProgramData access exposure:** New native Windows handle-based owner/DACL inspection and bounded allow/deny ACE policy for **preexisting system directories** (distinct from the FI-Installer child protected ACL). Pure and native-SDDL negative tests cover untrusted owner/defaulting, absent DACL, unknown ACEs, generic rights, unprivileged create/write/delete/owner rights, inherited creator-owner ACEs, and denies masking broad grants. The Windows CI runner reads but **does not change** its root/ProgramData ACL; a conservative **BLOCKED** finding is not installation acceptance. V14/V16 and all protected issuer/token/transaction acceptance remain **NOT RUN**. See `WINDOWS-VOLUME-FIRST-SYSTEM-PARENT-ACL.md`.

**2026-11-11 native interactive installer token observation:** Added a private, read-only actual Windows process-token inspection, with pure negative tests for UAC-limited admins, missing enabled Administrators membership, lower/System integrity, restricted/AppContainer tokens, thread impersonation, and incomplete privilege data, plus Windows native process-token/invalid-handle tests. Sensitive privilege present/enabled flags are observed but not adjusted. **Windows CI passing does not prove that the CI token qualifies, validate the intended `adminbox` administrator, establish an effective AccessCheck or close V14/V16.** All privileged installer consent and transaction acceptance remains NOT RUN. See `WINDOWS-VOLUME-FIRST-INSTALLER-TOKEN-PREFLIGHT.md`.

**2026-11-11 native token group query correction:** Windows CI initially rejected the `Token.IsMember` primary-token query because no thread was impersonating. The implementation now inspects the primary token's `TokenGroups` SID/attributes directly and rejects deny-only Administrators membership without token duplication or impersonation. Acceptance still depends on the exact final branch Windows CI run and does not activate installer apply, V14 or V16.

**Windows token Boolean ABI validation (2026-11-11):** Native `TokenHasRestrictions` returned a 1-byte Boolean on the GitHub runner. The read-only observer now verifies 1-/4-byte Windows Boolean shapes with negative tests for unexpected widths and noncanonical values. A passing Windows runner confirms only these inspection mechanics, not elevated administrator eligibility on `adminbox` or installer approval.

**2026-11-11 Windows native ProgramData effective-access evidence:** New pure conjunction tests refuse unsafe or missing token, NTFS/file-identity, DACL or exact `AccessCheck` rights. Windows-only tests use the actual AccessCheck engine on in-memory descriptors granting and denying exact rights to the real test user, plus invalid token/unknown request tests. The CI runner's common ProgramData descriptor is inspected **read-only** and may legitimately be **BLOCKED**. This does not qualify native installer operator consent or controlled `adminbox` privileged acceptance; V14/V16 remain NOT RUN. See `WINDOWS-VOLUME-FIRST-INSTALLER-PARENT-ACCESS.md`.


**2026-11-11 operator SID / signed receipt regression (A05 still P0):** Pure-Go tests in `volumeconsent/operator_binding_test.go` cover an authentic first-install signed approver matching the observed identity and rejection of mismatched/absent/malformed native identity, wrong signer, expired receipt, other machine, changed NTFS serial and tampered approver. Windows-only `freshinstall/installer_operator_consent_windows_test.go` checks that an actual native process-token inspection cannot accept a missing signed receipt. Inspect Windows and Linux CI at the exact final commit before recording these as PASS. Native elevated `adminbox` consent issuance, CNG key ownership, journal handoff, signed installed-grant commitment and V14/V16 remain NOT RUN. See `WINDOWS-VOLUME-FIRST-INSTALLER-OPERATOR-BINDING.md`.


**2026-11-11 native journal RootDirectory regression:** Windows-only tests must prove that `FILE_CREATE` follows the retained parent after a disposable directory is renamed, refuses an existing journal, invalid and closed parent handles, and preserves exclusive single-writer and write-ahead recovery behavior. The result is NOT protected ProgramData issuer trust, end-to-end A05 consent, V14/V16 or adminbox acceptance.


**2026-11-11 A05 protected bootstrap / journal continuity:** Windows-native regression tests cover a complete record journal written from the existing bootstrap's retained child directory handle, denial of nil/closed reservations, a deliberately invalid diagnostic path that must not redirect creation, and denial after a permitted directory rename. The earlier journal collision, exclusive-writer and replay tests remain required. Tests of exact privileged protected-owner creation can **skip** if a GitHub runner lacks owner-assignment privilege; this is not `adminbox` acceptance. A05 remains open and V14/V16 remain NOT RUN.


**2026-11-11 root-relative ProgramData native read-only tests:** Windows native tests cross-check the actual runner's ProgramData object with a fixed leaf opened relative to its retained system-volume root handle, test renamed/replaced disposable roots, and reject closed/invalid root handles, absent ProgramData children and reparse-point leaf substitution. No actual ProgramData changes occur. This validates relative-open identity behavior, **not** issuer trust, the first write, or privileged native `adminbox` acceptance. A05 remains P0; V14/V16 remain NOT RUN.
