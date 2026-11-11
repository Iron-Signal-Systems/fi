# Windows Volume-First Creation-Only Transaction Journal

**Date:** 2026-11-08  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Bounded transaction-event contract plus an isolated Windows-native create-new/flush writer and a **private protected bootstrap child creation experiment**. The strict native parent/child ACL checks remain enforced. No trusted parent issuer/ancestor provenance, installer activation, native FI creation backend or service-start authority exists.

## Purpose and scope

The new FI v2 Windows installation is **fresh-install only**. A host containing an FI service, binary tree or FI-owned state cannot be upgraded, repaired or silently emptied by the installer. `freshinstall.Assess` and the native `-check-clean-install` command must reject it.

`go/internal/windows/freshinstall/creation_journal.go` now defines the **creation-only event order** for the future installer. It is a write-ahead evidence protocol, not permission to mutate. The runner is intentionally **package-private**. It now has a separate unexported Windows-native **journal I/O implementation** in `creation_journal_windows.go`, but still **no native FI resource creation backend**, authenticated protected-parent provenance, SCM, AD/PKI or registry mutation path. No new installer CLI calls it, and FI services are still not activated in volume mode.

## Required creation phases

The fixed ordered transaction contains the following named phases:

1. `CreateProgramRoot`: exclusively create the FI program root if the host is clean;
2. `CreateDataRoot`: exclusively create the FI data root;
3. `ProtectNewRoots`: set and verify protected ACLs on only the newly created FI roots;
4. `CreateSignedBinaries`: exclusively install and verify signed executables;
5. `CreateOperationalConfig`: exclusively write fully validated v2 operational configuration;
6. `CreateSignedScopeGrant`: exclusively create the already authenticated/signed initial installed grant;
7. `CreateDisabledServices`: create the five separately privileged SCM services **disabled**, with no startup;
8. `CommitProtectedState`: commit the independently protected initial grant/configuration state after every created artifact has been verified.

These are **future backend contracts**, not implemented native steps. Any implementation must be create-only with host-state revalidation, no replacement or adoption of preexisting data, a transaction-specific identity, exact privileged actor authority, and evidence that completed effects are durable. A step is not permitted to claim success merely because its mutating system call returned without a verification error.

## Write-ahead journal semantics

Each event contains an explicitly declared v2 journal version, monotonically increasing sequence, first-install ID, exact **scope SHA-256, operational-configuration SHA-256, signed installer approval receipt SHA-256 and signed installed grant SHA-256**, fixed step/event type, predecessor digest, and own SHA-256. The four prepared digests must remain constant for every event in the transaction. The journal binds to their exact bytes for post-crash investigation but does not itself authenticate them. The envelope is canonical JSON, newline terminated, bounded to 2 KiB per event and at most 18 records. The predetermined sequence is:

```text
Begin
CreateIntent(CreateProgramRoot)
CreatedAndSynced(CreateProgramRoot)
...
CreateIntent(CommitProtectedState)
CreatedAndSynced(CommitProtectedState)
CreationComplete
```

The future `CreationSink.ReserveNew` must first **atomically and exclusively create a previously absent journal under a verified protected Windows parent**; an existing or in-doubt journal must refuse a second installation attempt. Only after that reservation may `CreationSink.AppendAndSync` durably write and sync the **complete** journal event before returning success. Each `CreateIntent` must reach durable custody **before** the matching native mutation. `CreatedAndSynced` is emitted only after native creation, verification and persistence complete. If writing an intent, native creation, or writing the acknowledgement fails, the transaction stops.

A crash or write failure can leave the underlying native artifact partially or completely created even if the last recorded state says only `CreateIntent`. Such a transaction must be **quarantined for explicit manual recovery**. The new installer must not guess that an artifact can be deleted, silently roll it back, automatically restart the transaction, or call `CreationComplete`. Completion is never equivalent to signed configuration authorization or permission to start FI services.

The parser `InspectCreationJournal` rejects malformed, noncanonical, reordered, duplicate, overlong, truncated and cross-installation events. A journal ending at any point before explicit completion returns `ErrCreationInDoubt` and the last known successfully acknowledged step. A missing final newline is rejected as a potentially truncated record, not parsed as a legitimate completion.

**Important trust boundary:** The SHA-256 chain is **corruption/order evidence only**, not an HMAC or digital signature. A malicious writer can recompute it. The future Windows-native journal file must have independently verified issuer/path/ACL/ownership trust and durable append semantics. No journal state is an authorization token. Similarly, a clean host observation is point-in-time only and does not prevent concurrent creation by another process; the native installer still needs a trusted exclusive creation/lock boundary.

## Native Windows journal I/O (development-only)

The branch now includes an unexported `windowsCreationSink` implementing `CreationSink` using Windows native file handles:

- The intended parent must already exist on a local drive, must not be the drive root, and its ancestor paths are rejected if they include a Windows reparse point, junction, or non-directory.
- The parent is opened with `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS` and retained with no delete-sharing for the transaction. Its handle attributes are checked, and its final resolved path is compared with the requested path.
- The single fixed journal filename is created with `CREATE_NEW`, no sharing, `FILE_FLAG_WRITE_THROUGH`, and `FILE_FLAG_OPEN_REPARSE_POINT`. Any already existing journal causes refusal rather than repair, truncate, overwrite, or adoption.
- The newly opened file handle is checked for unexpected type/reparse and resolved path. A record is accepted only as one bounded newline-terminated frame; after each write, the file is explicitly synchronized before success is returned.
- A failed or partial write permanently poisons the sink. Closing it does not delete the journal. An interrupted transaction remains for manual disposition; another process invoking create-new against that same name cannot silently restart it.

Windows-only file I/O tests use an explicitly named **`_test.go`-only constructor** to run in isolated temporary directories, not `C:\\ProgramData\\FI`, and check file-backed complete replay, existing-journal collision, interrupted native creation, a second-process retry, **concurrent CREATE_NEW reservation exclusivity**, no journal file-sharing until the handle closes, retained-parent rename refusal during transaction and successful release afterward, invalid parents and frames, and reparse parent/target rejection when runner permissions permit symbolic-link creation. Windows short-name (8.3) aliases are tolerated by comparing the native parent and file handles' resolved paths instead of rejecting equivalent textual spellings. These are **native file I/O tests on GitHub Windows runners**, not a privileged installation acceptance on `adminbox`.

**Important remaining trust gap:** The parent directory is supplied by the caller. The default writer now **checks native parent owner/protected DACL and the new file's effective owner/inherited DACL on retained handles**, but this does **not authenticate the directory's issuer, ancestor provenance, administrator consent, signer or machine identity**. It must not be invoked from an installer on an untrusted writable parent. A private parent-relative `NtCreateFile(FILE_CREATE)` experiment now supplies the exact protected ACL at bootstrap-child creation time and returns the newly created native handle, but there is still **no authenticated trusted-parent/ancestor authority**, no protected signing-key handoff, no complete installer transaction and no crash/power-loss durability proof. Unit tests validate success/error results of Windows I/O calls, **not** persistence across sudden power failure.

The branch now enforces its strict parent owner/protected DACL evaluator and a separate inherited child-file DACL policy from the private default journal writer; see `WINDOWS-VOLUME-FIRST-JOURNAL-PARENT-SECURITY.md`. **Neither policy provisions or independently authenticates the parent, and the writer is not wired to v2 installer apply.** The future protected bootstrap must solve that trust boundary before exposure. The existing helper is private specifically so a partially tested file-writing capability cannot be mistaken for an installation authority.

## Test coverage

Branch unit tests verify:

- exact eight-step creation order and 18-event fully completed journal;
- durable Begin and intent are required **before** each native mutation;
- failure writing Begin, any intent/acknowledgement, or completion blocks successful installation;
- native mutation failure preserves uncertain ownership rather than calling an unproven rollback;
- pending intents, missing terminal completion and partial/truncated journal writes cannot be interpreted as success;
- duplicate, unknown, reordered, maliciously rehashed, mismatched identity/sequence and oversized journal events are refused;
- nil source/sink and malformed installation IDs or scope digests are refused.

The pure protocol runner's fault-injection backend/sink are **in memory only**. Separate Windows-native journal I/O tests do create isolated temporary-directory files; neither test class installs FI services, alters system PKI, or modifies real source custody.

## Still required before any actual installation

- Provision a native **protected, trusted** journal parent and prove owner/DACL/handle/ancestor integrity, exclusive lifetime, safe child creation without reparse/directory substitution, plus controlled ACL inheritance. The isolated native journal writer does not yet satisfy that complete acceptance gate.
- Integrate the native append-and-sync journal writer with the protected parent, atomic first-install state, checked journal recovery and evidence-based transaction ownership. Test real crash/flush behavior, not just successful `Sync` return values.
- Authenticate administrator consent and CNG signing authority, then validate a fresh v2 signed grant and scope before any privileged operation.
- Build a complete v2 operational config, protected local installation commitment and creation-only Windows SCM backend, with correct gMSA/service SIDs and no service activation until authority is verified.
- Define **owned-artifact-only** rollback for steps with durable confirmed ownership, while preserving and surfacing ambiguous partial writes for operator review. Do not use legacy in-place replacement rollback helpers.
- Test interrupts after every durable record and native mutation, including power loss/restart; record exact failure and evidence. Run native acceptance on **`adminbox`**.

Refer to `WINDOWS-VOLUME-FIRST-FRESH-INSTALL.md`, `WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md`, `WINDOWS-VOLUME-FIRST-CONSENT-RECEIPT.md` and `WINDOWS-VOLUME-FIRST-INSTALLED-GRANT.md`.

**No changes to `main`, county FI sources, ISS-FS-22A, FISender, or the backend.**

**Native protected journal gate (2026-11-10):** The normal `newWindowsCreationSink` constructor denies an untrusted parent owner/DACL before `CREATE_NEW`. Once the journal is created, `ReserveNew` inspects its effective inherited file ACL/owner through the open native handle before returning success. An unacceptable child file remains **in doubt**; no cleanup or automatic retry occurs. The bypass used for older temporary-directory file I/O fixtures is only constructed in `_test.go`. These are source-level safeguards, not proof of an authorized native bootstrap or an accepted Windows Server installation.

**Private bootstrap experiment (2026-11-11):** `reserveProtectedBootstrap` can now create the fixed `FI-Installer` child of an existing local parent with protected SYSTEM/Administrators security attributes supplied **at creation**, verify retained native parent/child handles, and reject any existing child. It never deletes or adopts uncertain artifacts. This method is not wired to `fi-install`, does not prove that a supplied parent is the real trusted system `ProgramData`, and does not initialize trusted signing/grant state. See [protected bootstrap contract](WINDOWS-VOLUME-FIRST-PROTECTED-BOOTSTRAP.md).

**Native child handle-rooting (2026-11-11):** `reserveProtectedBootstrap` now creates its fixed child through `NtCreateFile` using the **retained native parent handle as RootDirectory**. It never reopens the child by path to establish authority. A Windows regression test deliberately relocates a disposable parent before creation and requires the new child to follow that held parent object. This does not authenticate the original `ProgramData` parent or enable installer apply.
