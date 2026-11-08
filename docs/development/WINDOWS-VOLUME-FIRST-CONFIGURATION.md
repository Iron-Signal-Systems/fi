# Volume-First Configuration Declaration (Development)

**Date:** 2026-11-08  
**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Parsed and normalized in source; NOT a supported installed FI runtime/installer configuration.

## Boundary and intent

`go/internal/config/volume_v2.go` introduces a separate declaration parser (`ParseVolumeV2`) and canonical serializer (`CanonicalVolumeV2`). The existing `config.Parse` continues to accept the legacy `1.0/1.1` root-centric operational configuration only. In particular, `fi-install.exe` **does not** accept `2.0` as its native deployment/configuration authority yet. This separation is deliberate: merely parsing a proposed enrollment must never turn a newly discovered volume into a monitored or audited source.

This is the target volume **scope** declaration, not the complete sender/receiver/PKI/operational configuration. A future integrated `2.0` configuration must bind these exact volume and policy semantics to every existing operational setting and installer approval/digest contract.

## Declaration syntax

```text
version_id: 2.0

volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407

volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637

policy.finance.volume = data
policy.finance.root = \Shares\Finance
policy.finance.depth = security

policy.software.volume = system
policy.software.root = \Program Files\SW
policy.software.depth = metadata
```

Here `volume.<id>` is an explicitly operator-enrolled logical volume, not an automatic discovery result. The GUID is a native Windows locator; the serial is the full 64-bit `FILE_ID_INFO` value as canonical unsigned decimal. Neither alone proves continuity after a format or replacement. Journal ID and cursor belong to the separate per-volume checkpoint model.

A policy root is **volume-relative** and not a drive-letter, UNC or arbitrary NT object path. The native installer and runtime must later prove the resolved exact root identity, file-system type, reparse status, approved parent volume and trusted handle. The parser alone cannot authorize source reads.

## Parsing and normalization constraints implemented now

- Exactly one initial `version_id: 2.0`; unknown settings, duplicate fields, incomplete declarations, invalid identifiers, malformed GUIDs, noncanonical/zero 64-bit serials, and values exceeding uint64 fail.
- At least one explicit volume; zero governed policies is valid for minimal source-change observation.
- Each policy references an enrolled volume. The depth declaration is limited to `metadata`, `security`, or `content`; the operational meanings and native permissions are not implemented by this parser.
- Relative roots prohibit traversal, duplicate separators, ambiguous trailing separators/periods/whitespace, UNC paths and drive-letter paths.
- The same exact root on one volume cannot be declared under multiple policy IDs. Descendant/ancestor policy overlaps remain allowed; native policy precedence remains to be implemented.
- Enrollments and policies are emitted in stable ID order. Canonical serialization re-parses and verifies an exact round trip; a mutated, invalid model cannot be rendered into a usable approval artifact.
- Limits in this development parser: 128 volumes and 4096 policies, and a maximum individual scanned line of 64 KiB.

The future installer must create an approval digest over both normalized requested configuration **and** freshly rediscovered native volume and policy identities; it must reject stale approvals and scope broadening. A text-file hash is never sufficient for consent to access any NTFS volume.

## Implementation and test state

- Pure-Go parser, validation and canonicalization are implemented under `go/internal/config/volume_v2.go`; tests are under `go/internal/config/volume_v2_test.go`.
- Local isolated-module unit tests, race detector, repeated test runs and vet ran on Linux; these establish parser behavior only. Repository GitHub CI validation is recorded separately by the actual workflow outcomes.
- Implemented separately: read-only Windows GUID/NTFS discovery, branch-only installer inventory/preflight, and a new path-free enrollment-ID USN broker mode with same-handle full-width NTFS serial checking. See `WINDOWS-VOLUME-FIRST-DISCOVERY.md` and `WINDOWS-VOLUME-FIRST-USN-BROKER.md`. These features do **not** activate volume-wide collection.
- Not implemented: complete v2 operational installer approval, application of v2 configuration to FICollector or FIUSNReader's service startup, per-volume scheduler/custody, governed policy/SACL enforcement, installation reconciliation/rollback, new source records, and FreeBSD database/projector changes.
- No automatic edits, service changes or FISender start on `ISS-FS-22A`. All actual Windows engineering/integration and native host tests are assigned to `adminbox`.

See `docs/architecture/ADR-0002-WINDOWS-VOLUME-FIRST.md`, `docs/development/WINDOWS-VOLUME-FIRST-INSTALLER-CONTRACT.md`, `docs/development/WINDOWS-VOLUME-FIRST-SCOPE-REVIEW.md` (read-only change review and stale-plan checks), and `docs/development/WINDOWS-VOLUME-FIRST-VALIDATION-MATRIX.md`. This document is not a deployment guide.
