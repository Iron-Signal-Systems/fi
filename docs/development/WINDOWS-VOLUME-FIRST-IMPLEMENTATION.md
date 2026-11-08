# Windows Volume-First Engineering Implementation Inventory

**Status:** Active branch development. Volume discovery, epoch checks, policy parsing, and a separate volume-ID USN broker mode exist. Live collector, service startup, installer apply, and backend integration are NOT implemented.
**Branch:** `dev/windows-volume-first-20261108`
**Windows work machine:** `adminbox`

## Implemented work as of 2026-11-08

- `go/internal/windows/volumeepoch/continuity.go` and tests: per-enrolled-volume/epoch checkpoint and journal identity assessment; explicit first-baseline, continuity, journal-changed, volume-changed, aged-out, lowest-valid, ahead-of-journal and invalid-input states. Pure validation only; no state creation/advance/reconciliation.
- `go/internal/config/volume_v2.go` and tests: strict `2.0` scope declarations for one or more volumes, zero or more governed-root policies, 64-bit serial validation, deterministic normalization, duplicate/scope/path rejection. This API is deliberately not wired into legacy `config.Parse` or the installer until full native preflight and approval semantics are implemented. See `docs/development/WINDOWS-VOLUME-FIRST-CONFIGURATION.md`.
- Development branch security gate corrected to Go `1.27.3` and `github.com/klauspost/compress` `1.20.2`, with CI using the go.mod toolchain. This is branch-local security remediation, not a release statement.
- `go/internal/windows/volumediscovery/`: native Windows volume GUID enumeration, read-only NTFS/FILE_ID_INFO attestation, mount alias reporting, and pure fail-closed comparison with explicit volume enrollment. Windows-runner native smoke tests and deterministic mismatch tests are included. No helper/collector integration or monitoring authority is created.
- `go/cmd/fi-install/`: branch-only `-list-volumes` standalone read-only inventory and optional `-volume-config <path>` preflight, dispatched before all mutation-capable old installer paths. Configuration loading is bounded to a regular <=1 MiB file; mismatches return nonzero and a readable JSON report. This is **not** the actual volume-first install/approval/rollback implementation.
- `go/internal/windows/usnbroker/` implements the **separate, not activated** volume-ID mechanics, but the exported `ServeEnrolledVolumes` startup is now explicitly fail-closed with `ErrVolumeModeRequiresApproval`. No future service may start the privileged mode from an unapproved v2 file. The internal broker path binds immutable enrollment IDs to native identity, and wire codes 6/7 select IDs rather than paths; legacy-mode helpers deny those codes.
- `go/internal/windows/usnraw/volume_windows.go` now validates the entire 64-bit NTFS serial using read-only `FSCTL_GET_NTFS_VOLUME_DATA` on the same raw handle used for bounded journal query/read. Mock-dispatch and malformed/unauthorized input regression tests are included. See `docs/development/WINDOWS-VOLUME-FIRST-USN-BROKER.md`.
- The five installed Windows services and native installer apply/reconciliation code remain root-centric. `go/cmd/fi-usn/main_windows.go` still starts the v1.1 broker. Real privileged native integration on `adminbox` has not occurred; Windows-latest CI does not prove that acceptance.

## Read-only installer scope-review progress (2026-11-08)

- `go/internal/windows/volumereview/` now produces a deterministic **non-authorizing** scope review and snapshot fingerprint. Its typed changes distinguish volume additions/removals, full-width volume identity replacement, root-policy additions/removals, and any policy alteration. The review is order-independent and excludes drive-letter aliases from identity binding.
- `volumereview.Revalidate` refuses stale/mismatched native observations, changed proposed/old configurations, and modified review fields. SHA-256 provides a deterministic reference only; it is **not a signature or a protected approval receipt**.
- Branch-only `fi-install.exe -list-volumes -volume-config <path>` now includes `requested_scope_review` in its non-mutating JSON report. Existing `1.1` installation/service startup is untouched. See `docs/development/WINDOWS-VOLUME-FIRST-SCOPE-REVIEW.md`.
- Still not implemented: authenticating an administrator's approval, protected host-bound v2 config/receipt installation, native root object identity and audit/SACL approval, transactional rollback, broker selection at service startup, volume worker custody, and backend changes.


## Signed installer transaction-intent verification (2026-11-08)

- `go/internal/windows/volumeconsent/receipt.go` now verifies short-lived, host-bound signed **installer intent** using CNG-compatible ECDSA P-256/SHA-256. It checks a separately trusted public key, native machine SID, protected installation ID/approval generation, old/new scope digest and an exact fresh `volumereview` comparison.
- Tests cover valid signatures, incorrect trusted key/curve, malformed/duplicate JSON, changed host/installation/sequence, stale installed configuration, expiration, tampered policy and changed native volume. The branch also implements strict P-256 Windows CNG raw-signature-to-DER conversion, with end-to-end receipt verification and malformed scalar tests. Test-only signing keys are ephemeral in-memory values; none are stored in this repository.
- **Not implemented:** production CNG signer/issuer trust, native operator authentication, protected instance/generation state, transactional v2 config/receipt installation, durable installed grant and service handoff. Exported volume broker startup remains blocked by `ErrVolumeModeRequiresApproval`.
- See `docs/development/WINDOWS-VOLUME-FIRST-CONSENT-RECEIPT.md`.

## Durable installed-grant verification (2026-11-08)

- `go/internal/windows/volumegrant/` independently verifies a domain-separated ECDSA P-256 signed durable v2 scope grant against a separately pinned exact-envelope digest, committed generation and predecessor, native host/installation identity inputs, canonical scope digest and a distinct full-operational-configuration digest. Tests prove that a correctly signed but uncommitted grant is rejected and old signed grants cannot substitute for a later protected generation.
- The new verifier is **only a pure verification component**. No trusted Windows state storage, key provisioning, native signing/administrator consent, transactional installer mutation, service-startup verifier or durable authority handoff is implemented. Installed FIUSNReader remains root-centric and the exported volume-mode broker startup refuses activation.
- See `docs/development/WINDOWS-VOLUME-FIRST-INSTALLED-GRANT.md` and `docs/development/WINDOWS-VOLUME-FIRST-CONSENT-RECEIPT.md`.

## Dependency order

1. Define explicit volume enrollment, volume/epoch identity, minimal USN change record, policy membership and discontinuity contracts.
2. Add strict normalized operational configuration, volume enumeration, mount/GUID resolution and approval semantics without enabling capture until enrollment.
3. Refactor the existing FIUSNReader bounded broker from root journal acquisition to approved-volume capture; keep FIObjReader separate.
4. Refactor FICollector into per-volume checkpoint-owning USN pipelines plus a policy evaluator. Independent Security worker remains host-level.
5. Implement correct volume epoch and gap behavior for removal, reformat, reset, aged-out journal, renamed/moved objects, and unattainable current state.
6. Rebuild local capture, durable spool and retry logic to preserve source facts before checkpoint advance; ensure multi-volume fairness and resource ceilings.
7. Update `fi-install.exe` and its complete test suite in the same work set as runtime changes. No workaround/manual post-install scripts.
8. Rebuild the experimental PostgreSQL schema, Go validation, ingest and typed projectors around the new source record model. No legacy-schema compatibility requirement.
9. Validate correctness, security, native Windows failures and installer recovery before running comparative load benchmarks.
10. Keep authoritative documentation aligned with each source change, preserving dated historical test failures and acceptance facts.

## Source inventory requiring investigation

| Workstream | Candidate source paths |
| --- | --- |
| Configuration | `go/internal/config/config.go`, `go/cmd/fi/config_authority_windows.go` |
| USN continuity | `go/internal/windows/checkpoint/`, `go/internal/windows/usn/` |
| Collector runtime | `go/cmd/fi/configured_windows.go`, `service_root_windows.go`, `service_usn_windows.go`, `usn_gap_windows.go`, `service_security_windows.go` |
| Privileged tools | `go/cmd/fi-usn/`, FIObjReader broker and corresponding tests |
| Source contracts | `go/internal/records/`, spool/custody validators |
| Installer | `go/internal/windows/install/`, including discovery, config, approval, SACL/audit, SCM and rollback |
| Backend | `database/`, `go/internal/recordingest/` and downstream typed projection/query |
| Documentation | `README.md`, `AGENTS.md`, `docs/COLLECTOR-CONTRACT.md`, `docs/README-USN-SUMMARY.md`, `docs/security/`, `docs/WINDOWS-INSTALLER*.md`, `docs/database/`, `fi-roadmap/` |

## Baseline and non-interference

- Branch created from `main` at `806d87ebe75f13bcf06ed0dbc2e7653297b7009e` on 2026-11-08.
- Existing live `ISS-FS-22A` remains an old root-centric installed build. Its sender was intentionally stopped after the prior backlog.
- Investigation of `F:\FI-Governed-10M` journal/volume discontinuity is historical diagnostic evidence, not a successful correction.
- Branch creation or documentation does not touch `main`, Windows services, PKI, filesystem SACLs or PostgreSQL.
- Implemented, tested, runtime-verified and not-yet-started work must remain explicitly distinguished.
