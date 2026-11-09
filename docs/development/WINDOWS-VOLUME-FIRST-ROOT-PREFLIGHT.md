# Windows FI v2 — Read-Only Installer Governed-Root Inspection

**Branch:** `dev/windows-volume-first-20261108`  
**Engineering date:** 2026-11-09  
**Status:** Branch-only opt-in read-only CLI and negative/positive tests. This is NOT a signed installer approval, installation, live collector, or `adminbox` acceptance.

## Command and isolation

The existing native installer remains root-centric. The new flag is deliberately opt-in and **requires both** standalone read-only volume inventory and an explicit normalized scope declaration:

```powershell
.\fi-install.exe -list-volumes -volume-config C:\FI-Dev\volume-v2.conf -inspect-policy-roots
```

The flag alone, `-list-volumes -inspect-policy-roots` without `-volume-config`, an explicitly disabled read-only selector, or any `-apply`, `-plan-only`, `-check-clean-install` or legacy install flag combination is rejected before the old installer code runs. A strict v2 scope-only file no larger than 1 MiB is required; there is no implicit enrollment, configuration migration or service startup.

The existing `-list-volumes` and `-list-volumes -volume-config` behavior is retained. Only the opt-in form performs governed-root inspection. It uses the existing read-only native volume inventory and deterministic scope review first. Root identities are then independently re-observed on the selected, currently matching NTFS volume by `policyroot.AttestEnrolledVolumeRoots`, which opens directory metadata only and rejects reparse boundaries, missing roots, access failures, or full-width serial drift. It does not read content, change audit/SACL state or query a USN journal.

## Evidence and failure policy

The JSON report contains the existing `requested_volume_preflight` and `requested_scope_review` plus:

- `action = DiscoveryScopeAndPolicyRootPreflightOnly`;
- `collection_authorized = false` **always**, including on a successful inspection;
- `policy_roots_inspected = true` only for the explicit opt-in command;
- `policy_root_checks_complete`, which is true only if every declared enrolled volume and its root bindings passed the read-only checks;
- `preflight_blocked`, true when either native scope review or policy-root inspection failed;
- ordered `policy_root_inspections` per enrollment with `IdentitiesObserved`, `NoPolicies`, `VolumeNotMatched`, or `RootAttestationFailed`. Successful observed policy roots include the policy ID and native 128-bit file ID rendered as 32 lower-case hexadecimal characters.

An unavailable/replaced volume is **not** inspected; no partial binding evidence from that volume is exported. Each other independently matched volume is still examined so one failed source does not hide healthy source observations. Missing/duplicate/foreign/zero root identities fail the affected volume. Any failed or unmatched enrollment forces a **nonzero exit** after the JSON evidence is written. Malformed input or globally inconsistent comparison aborts without manufacturing a complete report.

A volume with zero declared governed roots is explicitly `NoPolicies`; this never grants implicit content, ACL or privileged reads. `policy_root_checks_complete=true` describes only this temporary read-only inspection, not a future installer permission, verified signing authority, effective SACL coverage, or established historical parent-child lineage.

## Tests and outstanding gates

Dependency-injected tests cover explicit command-line isolation, disabled-selector refusal, successful one-root inspection, a zero-root volume, incomplete/malformed/repeated and cross-volume bindings, denied native observations with no partial identities, unmatched volume skip, two-volume failure isolation and complete-error reporting. Native `policyroot` tests remain isolated Windows directory tests, not live production host acceptance. The exact final branch CI outcome is recorded in GitHub Actions, not inferred from test presence.

Still absent: authenticated administrator consent, fresh-install signed scope/grant commitment in protected Windows storage, native installer write transaction and crash recovery, enrollment-scoped service activation, verified `adminbox` runtime acceptance, journal-owned FICollector capture, true historical root association, backend records and PostgreSQL ingest. Installer and collector are **not** ready for deployment.

Related contracts: `WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md`, `WINDOWS-VOLUME-FIRST-NATIVE-POLICY-ROOT.md`, `WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md`.
