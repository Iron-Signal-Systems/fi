# FI Windows Volume-First — Signed Approver / Native Process-Token Binding

**Engineering date:** 2026-11-11  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Development-only, read-only verification foundation. Source/tests staged; check the final commit's CI before claiming validation. NOT installer approval, issuance, service startup or native adminbox acceptance.

## Purpose and trust boundary

The existing `volumeconsent.VerifyFreshInstall` verifies a bounded, canonical, P-256 signed, short-lived fresh-install scope receipt against separately trusted machine identity, issuer public key, installation ID, initial sequence, review and fresh NTFS discovery. Its signed `approver_sid` field was previously audit attribution only: a correctly signed receipt for operator A did not demonstrate that the current process was running as operator A.

`volumeconsent.VerifyFreshInstallForOperator` now adds a mandatory exact equality between the signed `approver_sid` and an independently observed process-token user SID. **It always performs the full signed receipt and first-install review verification before trusting the receipt's approver field.** A missing, malformed or mismatching observed SID fails closed. Successful equality is an identity consistency property, NOT proof that the operator approved the displayed scope at the time of issuance.

The private Windows-native `freshinstall.verifyNativeInstallerOperatorReceipt` obtains the actual process primary-token evidence via `inspectNativeInstallerProcessToken`, requires the existing conservative `AssessInstallerTokenEvidence` policy, then passes only that observed token SID to the signed-consent verifier. Neither an installer argument, environment variable, receipt-supplied SID, config file nor thread impersonation supplies the token subject. A SYSTEM or medium-integrity process does not qualify as an interactive elevated operator under the existing token policy.

## What this does not authorize

- No signed-receipt **issuance**, human confirmation UI, smartcard/CNG private-key access or authenticator assurance. An elevated administrator token alone is not explicit transaction consent.
- No trust-anchor bootstrap: `Expected.TrustedPublicKey`, host identity, installation ID, sequence and time must still come from independently protected native sources, not the presented receipt.
- No protected ProgramData parent creation or handle-to-transaction handoff; no write-ahead transaction activation, signed installed-grant commitment, service installation, SACL change or FI source read.
- No assurance that a different elevated administrator could not use a legitimate receipt to start a process as the matching user, or that a compromised local administrator/SYSTEM cannot subvert local state. The future transaction must authenticate interactive approval, issuer role and lifetime separately.
- No support for in-place update, migration, repair or adoption of preexisting FI state.

## Code and negative tests

- `go/internal/windows/volumeconsent/operator_binding.go`: full canonical signature/host/review validation followed by exact native-observed/signed-approver SID binding.
- `go/internal/windows/volumeconsent/operator_binding_test.go`: positive fresh sequence-one match; independent mismatched operator; blank/malformed SID; wrong signer; expired receipt; other host; changed NTFS serial; tampered signer-covered approver.
- `go/internal/windows/freshinstall/installer_operator_consent_windows.go`: private read-only actual Windows process-token bridge enforcing the administrator-token policy before matching the signed receipt.
- `go/internal/windows/freshinstall/installer_operator_consent_windows_test.go`: a real Windows process token cannot authorize a missing receipt, regardless of runner elevation. This is a negative regression test, NOT privileged adminbox acceptance.

## Remaining A05 gates

First prove a trusted issuer/key-lifecycle design and a fresh read-only native `adminbox` acceptance with the intended installer operator. Then design authenticated, affirmative per-transaction consent and a non-exportable CNG signing authority with role-separated key ACLs. Only after independently trusted parent provenance, secure live-handle handoff, durable creation journal, independently protected installed-grant commitment and interruption/recovery tests may a separate reviewed fresh-only apply path be considered.

**HOLD:** A05 remains P0/open; the development `fi-install.exe` explicitly refuses legacy apply/plan, `FIUSNReader` volume service startup remains blocked, `main` is unchanged, and existing `ISS-FS-22A` FI services, FISender and state must not be modified.
