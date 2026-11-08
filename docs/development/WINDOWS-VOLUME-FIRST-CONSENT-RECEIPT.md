# FI Windows Volume-First Consent Receipt — Transaction Verification Contract

**Date:** 2026-11-08  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Cryptographic **verification foundation and tests implemented**. No production signer, trusted-key provisioning, native host attestation, installer apply/persistence, or broker startup authorization exists.

## Scope and invariants

This contract concerns a **short-lived installer transaction approval**. It is **not** the durable installed scope grant that FICollector and FIUSNReader must validate after restart, and **not** a path to override the deliberately blocked `usnbroker.ServeEnrolledVolumes` entry point.

`go/internal/windows/volumeconsent/receipt.go` implements `volumeconsent.Verify` using a bounded canonical JSON envelope and a domain-separated **ECDSA P-256 / SHA-256 signature**. Windows CNG supports P-256 and SHA-256 on the intended Windows Server family, making a future protected CNG signer feasible without storing a private key in FI source or plaintext configuration. **That production signer is not implemented.**

The `Receipt` contains a signed `Payload` and a base64-encoded **ASN.1 DER ECDSA signature**. The signature covers `FI-WINDOWS-VOLUME-APPROVAL-v1\0` concatenated with the canonical JSON encoding of the payload. The pure-Go `volumeconsent.CNGP256SignatureToDER` helper now converts Windows CNG's 64-byte IEEE P1363 signature (R || S) to DER, rejecting wrong lengths, zero/out-of-range scalars and malformed output. A future protected `NCryptSignHash` signer must use this conversion after authenticating operator consent; direct raw CNG output must not be accepted as a DER receipt signature.

## Exactly what an approval must bind

The signed payload has fixed `version = fi-windows-volume-approval/1` and `action = ApplyVolumeScope`. It includes:

- **MachineSID:** The native Windows machine identity that the installer will independently validate. Signed text alone cannot prove its OS origin or protect against an improperly cloned computer.
- **InstallationID:** A nonzero, random 128-bit installation identity represented as 32 lowercase hexadecimal characters. It must be created and persisted under the future protected installer authority; it is not derived from a filename, host name or receipt.
- **ApproverSID:** The approving operator's Windows SID for audit evidence. The installer must authenticate the operator's **actual Windows token and administrative role** at consent time. A SID string inside the signed receipt is not proof that the person approved anything.
- **Sequence:** Nonzero approval generation compared against independently protected current installation state; replay must be blocked by the installer's durable generation and rollback rules.
- **PreviousConfigSHA256:** Canonical digest of the *independently trusted installed v2 configuration*, or empty only for a genuine fresh v2 installation.
- **RequestedConfigSHA256:** Canonical digest of the proposed new volume enrollment and governed-root policy declaration.
- **ReviewFingerprintSHA256:** Fingerprint of the exact `volumereview.Review` the operator examined, including policy changes and live NTFS identity/eligibility evidence.
- **IssuedAtUTC / ExpiresAtUTC:** Canonical UTC times. Maximum approval lifetime 15 minutes; no issue time more than two minutes in the future.

The verifier receives `Expected` separately, comprising a **trusted** P-256 public key, OS-observed machine SID, protected installation ID, protected approval sequence, protected existing-config digest and trustworthy current time. `Expected` must **never** be populated from the receipt's claimed values.

## Verification behavior

The verifier rejects excessive (>8 KiB), malformed, noncanonical or duplicate-key JSON; unknown fields; invalid action/version/identifiers/digests/time; malformed base64 or DER signatures; wrong/absent/non-P-256 keys; untrusted signer; host/installation/sequence mismatch; expired or premature approvals; changed installed config; and changes in the requested config, review body, native volume GUID, full-width NTFS serial or availability. It recomputes `volumereview.Revalidate` from **fresh independently collected discovery**.

Successful verification establishes only that **this signed intent matches the separately trusted state and current scope review**. It performs no filesystem, AD/PKI, SACL, journal, state or service mutation and does not authorize raw-volume or object reads.

The source and tests use Go's standard `crypto/ecdsa` and `crypto/sha256`; test keys are generated solely **in memory** and are never committed. There is no FI signing private key, symmetric secret, certificate authority, customer hostname, or installed identity in the repository.

## Production work not yet implemented

1. Bind installer to **trusted and pinned local/site signer public key** via a protected trust/PKI chain, including permitted key use, rotation, expiry and revocation policy. A public key supplied alongside a receipt by its submitter is untrusted. Define issuer role separation from FICollector and FIUSNReader.
2. Implement a non-exportable CNG P-256 private signing key accessible **only** to the authorized installation/approval actor, with explicitly audited key ACL and certificate/key lifecycle. Do not generate ephemeral private keys and then automatically trust their public halves.
3. Obtain genuine Windows machine identity and authenticated approver SID through native security APIs; verify role and avoid writable/reparse-contaminated sources. Do not treat the on-disk receipt as a source of trusted host facts.
4. Establish a protected, random installation ID, atomic durable approval sequence and trustworthy installed v2 baseline. Define crash/retry/rollback semantics that never permit reuse of a retired approval generation or silent narrowing/widening.
5. Display the exact canonical configuration, **minimal whole-volume capture outside roots**, higher-depth policies, Windows Security prerequisites and native identity evidence to an operator; obtain explicit consent before signing.
6. At the actual installer write boundary, rediscover volumes, revalidate the signed receipt, verify root-to-volume object identity and SACL/audit plan, then apply the approved changes transactionally. The existing v1.1 installer implementation must not be silently repurposed.
7. After a successfully committed installation, produce a separate **durable installed authority** with protected ACL/trust validation. Only then design a service startup verifier and remove the fail-closed volume broker startup block in a reviewed change.
8. Complete native on-prem `adminbox` tests, supported Windows Server matrix, fault-injection/rollback, service-SID/gMSA tests, and the independent FICollector per-volume source custody and backend records.

## Current test evidence boundaries

CI exercises cryptographic verification, canonical parsing, wrong-signer and wrong-curve checks, SID/ID syntax, wrong host, wrong installation identity, reused generation, expired/future approval, changed installed baseline, modified policy root/depth, changed/reformatted/offline native volume, tampered review and response failure paths. **Passing CI does not establish a production signer, trusted platform/host identity, actual operator approval, correct Windows ACLs or native privileged acceptance.**

References: [Microsoft CNG key storage and P-256 support](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval) and [Microsoft CNG signing](https://learn.microsoft.com/en-us/windows/win32/seccng/signing-data-with-cng). See `WINDOWS-VOLUME-FIRST-SCOPE-REVIEW.md`, `WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md`, `WINDOWS-VOLUME-FIRST-USN-BROKER.md` and `WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md`.

**Noninterference:** No changes to `main`, deployed FI services on `ISS-FS-22A`, stored configuration/PKI, or the deliberately stopped FISender.
