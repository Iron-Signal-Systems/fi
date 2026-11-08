# Windows Volume-First Creation-Only Transaction Journal

**Date:** 2026-11-08  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Pure-Go bounded transaction-event contract and failure-path tests. NOT a native installer, durable disk journal, completed installation or service-start authority.

## Purpose and scope

The new FI v2 Windows installation is **fresh-install only**. A host containing an FI service, binary tree or FI-owned state cannot be upgraded, repaired or silently emptied by the installer. `freshinstall.Assess` and the native `-check-clean-install` command must reject it.

`go/internal/windows/freshinstall/creation_journal.go` now defines the **creation-only event order** for the future installer. It is a write-ahead evidence protocol, not permission to mutate. The runner is intentionally **package-private** and has no native filesystem, SCM, AD/PKI or registry backend. No new installer CLI calls it, and FI services are still not activated in volume mode.

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

The future `CreationSink.AppendAndSync` must durably write and sync the **complete** journal event before returning success. Each `CreateIntent` must reach durable custody **before** the matching native mutation. `CreatedAndSynced` is emitted only after native creation, verification and persistence complete. If writing an intent, native creation, or writing the acknowledgement fails, the transaction stops.

A crash or write failure can leave the underlying native artifact partially or completely created even if the last recorded state says only `CreateIntent`. Such a transaction must be **quarantined for explicit manual recovery**. The new installer must not guess that an artifact can be deleted, silently roll it back, automatically restart the transaction, or call `CreationComplete`. Completion is never equivalent to signed configuration authorization or permission to start FI services.

The parser `InspectCreationJournal` rejects malformed, noncanonical, reordered, duplicate, overlong, truncated and cross-installation events. A journal ending at any point before explicit completion returns `ErrCreationInDoubt` and the last known successfully acknowledged step. A missing final newline is rejected as a potentially truncated record, not parsed as a legitimate completion.

**Important trust boundary:** The SHA-256 chain is **corruption/order evidence only**, not an HMAC or digital signature. A malicious writer can recompute it. The future Windows-native journal file must have independently verified issuer/path/ACL/ownership trust and durable append semantics. No journal state is an authorization token. Similarly, a clean host observation is point-in-time only and does not prevent concurrent creation by another process; the native installer still needs a trusted exclusive creation/lock boundary.

## Test coverage

Branch unit tests verify:

- exact eight-step creation order and 18-event fully completed journal;
- durable Begin and intent are required **before** each native mutation;
- failure writing Begin, any intent/acknowledgement, or completion blocks successful installation;
- native mutation failure preserves uncertain ownership rather than calling an unproven rollback;
- pending intents, missing terminal completion and partial/truncated journal writes cannot be interpreted as success;
- duplicate, unknown, reordered, maliciously rehashed, mismatched identity/sequence and oversized journal events are refused;
- nil source/sink and malformed installation IDs or scope digests are refused.

The test backend and journal sink are **in memory only**. No Windows system files, services, PKI or source custody are mutated by these tests.

## Still required before any actual installation

- Prove native protected parent path and no reparse/directory substitution; create files and directories with **exclusive no-replace** semantics.
- Implement a protected append-and-sync journal with Windows-specific durability/ACL checks and recovery behavior after abruptly terminated installers.
- Authenticate administrator consent and CNG signing authority, then validate a fresh v2 signed grant and scope before any privileged operation.
- Build a complete v2 operational config, protected local installation commitment and creation-only Windows SCM backend, with correct gMSA/service SIDs and no service activation until authority is verified.
- Define **owned-artifact-only** rollback for steps with durable confirmed ownership, while preserving and surfacing ambiguous partial writes for operator review. Do not use legacy in-place replacement rollback helpers.
- Test interrupts after every durable record and native mutation, including power loss/restart; record exact failure and evidence. Run native acceptance on **`adminbox`**.

Refer to `WINDOWS-VOLUME-FIRST-FRESH-INSTALL.md`, `WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md`, `WINDOWS-VOLUME-FIRST-CONSENT-RECEIPT.md` and `WINDOWS-VOLUME-FIRST-INSTALLED-GRANT.md`.

**No changes to `main`, county FI sources, ISS-FS-22A, FISender, or the backend.**
