# Windows Volume-First Creation-Only Transaction Journal

**Date:** 2026-11-08  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Bounded transaction-event contract plus an isolated Windows-native create-new/flush writer and tests. The writer has **no production trusted-parent/ACL authority**, no installer activation, no native FI creation backend, and no service-start authority.

## Purpose and scope

The new FI v2 Windows installation is **fresh-install only**. A host containing an FI service, binary tree or FI-owned state cannot be upgraded, repaired or silently emptied by the installer. `freshinstall.Assess` and the native `-check-clean-install` command must reject it.

`go/internal/windows/freshinstall/creation_journal.go` now defines the **creation-only event order** for the future installer. It is a write-ahead evidence protocol, not permission to mutate. The runner is intentionally **package-private**. It now has a separate unexported Windows-native **journal I/O implementation** in `creation_journal_windows.go`, but still **no native FI resource creation backend**, trusted-parent provisioning, SCM, AD/PKI or registry mutation path. No new installer CLI calls it, and FI services are still not activated in volume mode.

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

Windows-only tests run in **isolated temporary directories**, not `C:\\ProgramData\\FI`, and check file-backed complete replay, existing-journal collision, interrupted native creation, a second-process retry, **concurrent CREATE_NEW reservation exclusivity**, no journal file-sharing until the handle closes, retained-parent rename refusal during transaction and successful release afterward, invalid parents and frames, and reparse parent/target rejection when runner permissions permit symbolic-link creation. Windows short-name (8.3) aliases are tolerated by comparing the native parent and file handles' resolved paths instead of rejecting equivalent textual spellings. These are **native file I/O tests on GitHub Windows runners**, not a privileged installation acceptance on `adminbox`.

**Important remaining trust gap:** The parent directory is supplied by the caller. This writer can check the path and opened handle but **does not verify the parent owner's native security descriptor, required protected DACL, signer authority, or independent machine identity**. It must not be invoked from an installer on an untrusted writable parent. There is no production bootstrap to provision that parent with an ACL at creation time, no protected signing-key handoff, no tested kernel-level handle-relative child creation race defense, and no crash/power-loss durability proof. Unit tests validate success/error results of Windows I/O calls, **not** persistence across sudden power failure.

The branch now has a strict read-only parent-owner/DACL evaluator and a native handle-based Windows descriptor reader; see `WINDOWS-VOLUME-FIRST-JOURNAL-PARENT-SECURITY.md`. They **do not create the parent and are not yet wired into the journal writer**. The future protected bootstrap must solve that trust boundary before exposure. The existing helper is private specifically so a partially tested file-writing capability cannot be mistaken for an installation authority.

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
