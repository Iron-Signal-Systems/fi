# Windows Volume-First Durable Installed-Grant Verification

**Date:** 2026-11-08  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Pure-Go signed-grant *verification and negative tests implemented*. NO Windows installer persistence, no independently protected native commitment, no production signer/key provisioning, and no enabled FIUSNReader volume service.

## What is new

`go/internal/windows/volumegrant/grant.go` verifies a signed **durable installed scope declaration** against independently trusted installation state, the exact normalized version 2.0 volume/policy configuration, and the actual installed operational-configuration bytes (bounded to 1 MiB). Until the future complete v2 operational schema is implemented, it verifies the byte digest but **not** semantic correctness of those operational bytes. This is deliberately a different artifact from the **short-lived installer transaction intent** checked by `volumeconsent.Verify`.

The verifier cannot issue grants, write files, select trust keys, authenticate an installer operator or authorize a journal read. It returns an **error only**, not an object that can be passed to the privileged broker as an authority token.

## Signed manifest and independent commitment

The envelope is canonical bounded JSON, `SignedGrant{manifest,signature_base64}`, limited to 8 KiB. The signature uses **ECDSA P-256 with SHA-256** over:

```text
FI-WINDOWS-INSTALLED-VOLUME-GRANT-v1\0 || canonical-json(manifest)
```

The manifest binds all of the following:

| Field | Contract |
| --- | --- |
| `version` / `mode` | Exactly `fi-windows-installed-volume-grant/1` and `VolumeFirst` |
| `machine_sid` | Host identity presentation only; future native code must obtain and verify it from trusted Windows state. Machine SIDs may be cloned and cannot alone secure an installation |
| `installation_id` | Nonzero 128-bit identity, lower-case hex; future installer must generate/persist it securely |
| `generation` | **1** for the supported fresh-install v2 service grant; later generations are excluded from this install path |
| `commit_id` | Nonzero 128-bit commit transaction identity; future installer must use strong randomness |
| `scope_config_sha256` | Hash of exact canonical v2 enrolled-volume and governed-policy declaration |
| `operational_config_sha256` | Hash of complete *future* v2 operational configuration, distinct from scope-only v2 |
| `approval_receipt_sha256` | Audit reference to installer consent receipt; presence is not proof of its validation |
| `previous_grant_sha256` | **Empty** for the supported initial grant; there is no previous installed FI grant to adopt |
| `committed_at_utc` | Canonical UTC timestamp, rejected if implausibly in the future relative to trusted time |

The verifier also requires separately sourced `TrustedState`. Its most important field is **`grant_sha256`**, the exact SHA-256 digest of the complete signed-grant file, committed independently of that file. It also must pin a trusted issuer public key, machine/installation identity, committed generation, previous-grant hash, scope digest, complete operational-configuration digest and independently trustworthy current time.

The verifier **rejects** signed grants if the file is correctly signed but no longer equals the protected committed digest. A previously valid signature therefore does not, by itself, permit replaying a retired configuration. It also rejects an altered scope policy even when the envelope is unchanged.

**Trust warning:** `TrustedState` is a caller-supplied verification interface, NOT a Windows protected store. Reading the values back from the presented grant defeats the contract. An attacker who can replace both the grant and the protected commitment, or compromise the trusted signing key, is outside the security guarantee of this pure verifier. The future design must explicitly constrain Windows ACLs, CNG key usage, local administrator privileges, sequence anti-rollback and crash recovery. Local `SYSTEM` or an administrator controlling both security boundaries cannot be assumed untrusted merely because a signed file exists.

## Verification decision and service-boundary consequences

`volumegrant.VerifyFreshInstallation(grant, independentlyTrustedState, v2Scope, installedOperationalConfigBytes)` is the v2 fresh-install validation entry. It rejects a later generation or predecessor before checking signed authority. The lower-level generic `Verify` exists for isolated cryptographic tests and is **not** an installer update path. It checks strict canonical JSON, supported signature algorithm/key, signed manifest invariants, the exact pinned envelope digest, host/installation identity, generation and preceding hash, complete operational-config digest and recomputed scope hash.

The result **does not** imply that any currently attached NTFS volume matches the enrollment. A future service must independently rediscover each enrolled volume and enforce full-width identity, availability, journal epoch continuity and root policy authority. An offline volume must not become implicitly available or cause an unrelated healthy volume's data to be misattributed.

**FIUSNReader volume-mode startup stays blocked** by `ErrVolumeModeRequiresApproval`. This new verifier must not be wired into service startup until the native protected-state reader, trust issuer, complete v2 operational configuration and installer transaction semantics are implemented and tested together. A valid test fixture cannot authorize a service.

## Existing implementation and tests

Implemented on the Windows branch:

- Pure-Go domain-separated P-256 signature verification; no production private key or standalone signer.
- Strict, unknown-field-rejecting, canonical and size-bounded JSON; no duplicate-key aliasing.
- Independent exact-grant hash pin, monotonic generation and predecessor binding.
- Host/installation/operational-configuration/scope binding, and canonical UTC checks.
- Tests for a valid signed pinned grant, bad trust/signature/host/installation, changed configuration, policy widening and changed serial, modified signed envelope, wrong/missing grant pin, expired generation rollback, invalid predecessor chain and invalid timestamps.
- Test private keys are disposable and in-memory only.

**Not implemented or tested:** protected native commitment persistence, Windows file/registry ACL proof, impersonation/token access policy, production CNG signer, atomic rollback/restart state, full operational v2 manifest, installer fresh-create/apply, actual FIUSNReader startup, native `adminbox` privilege tests or backend ingestion.

## Required next engineering gates

1. Design and prove the native **trusted local commitment** and issuer-pinning store: install path ownership, no reparse substitutions, ACL inheritance restrictions, distinct permitted service identities, and safe read-only verification on service restart. Document real limitations of Windows administrators and `SYSTEM`.
2. Bind an authenticated administrator's action to the short-lived `volumeconsent` receipt and a production protected CNG signer with explicit key lifecycle. Neither the public key nor the install identity may be accepted from an untrusted receipt.
3. Implement an atomic and crash-consistent **fresh-install** transaction creating the v2 operational config, initial generation-one signed grant, independently protected commitment and new services/state. Test unexpected power loss and rollback **only for artifacts this transaction created**, with no in-place upgrades, preexisting FI deletion or older grant adoption.
4. Prove the new volume mode with native helper, journal and service-SID tests on `adminbox`; keep all five service privileges separated.
5. Integrate FICollector's independently durable volume epochs, root policy enforcement, source-schema changes and backend projection with complete test custody.

Refer to `WINDOWS-VOLUME-FIRST-CONSENT-RECEIPT.md`, `WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md`, `WINDOWS-VOLUME-FIRST-USN-BROKER.md` and `WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md`.

No code in this component touches `main`, the installed `ISS-FS-22A` services, FISender or PostgreSQL.
