# Windows FI Volume-First — Native Governed-Root Attestation

**Branch:** `dev/windows-volume-first-20261108`  
**Status:** Read-only native directory identity observation staged, with pure and Windows-runner tests. Integrated only into the installer **opt-in read-only `-inspect-policy-roots` inventory command**; NOT wired to FICollector, installer mutation/approval, FIObjReader or any running FI service. Native `adminbox` acceptance remains NOT RUN.

## Scope

`go/internal/windows/policyroot` selects only the policy roots declared on one explicitly enrolled volume. Its pure target builder checks the canonical v2 scope, rejects unlisted volumes and produces an ordered chain of exact directory prefixes anchored at the Windows volume GUID root. Volume-relative root `\` is supported. A cross-volume mount, junction, symbolic link, traversal segment, drive-letter alias, excessive depth or oversized path cannot silently widen this chain.

`AttestEnrolledVolumeRoots` is **observation only**, not an approval API. It first requires that native Windows volume discovery matches the selected enrollment's GUID and full-width NTFS serial, then opens every prefix for attributes only with `FILE_FLAG_OPEN_REPARSE_POINT`, rejects reparse and non-directory handles, and reads the full-width `FILE_ID_INFO` volume serial and 128-bit file identity on each open handle. It holds ancestor handles without `FILE_SHARE_DELETE` until the chain is complete, preventing namespace rename/substitution of those held ancestors during the short inspection. A missing root, denied directory or changed serial fails the selected volume closed; no partial binding array is returned.

Other enrolled volumes may be offline and cannot by themselves invalidate a healthy selected volume. The returned `policyassociation.RootBinding` values may be passed to `NewVolumePlan` for a deterministic **point-in-time** policy association, but they are never FIObjReader authorizations. After the read handles close, namespace changes and reparse/rename races at later use boundaries remain possible. Future code must re-attest immediately before protected-object reads.

## Evidence and limitations

Pure tests cover deterministic sorting, zero/one/multiple roots, volume isolation, invalid scope, path constraints and bounded walks. Windows tests use isolated temporary directories to verify `FILE_ID_INFO`, wrong-serial refusal, skipped ancestor refusal, regular-file rejection and reparse denial when symlink creation is permitted. These tests do **not** establish installer issuer trust, live root historical containment, USN V2 64-bit-to-FILE_ID_128 mapping, protected file authorization, Windows service-gMSA rights or production server acceptance.

The `AttestEnrolledVolumeRoots` API currently accepts a caller-supplied v2 declaration. A valid declaration and matching native volume **do not prove authenticated operator consent**. It must not be called from production startup or used to grant helper privilege until the native protected grant store and authenticated installer handoff exist. The privileged volume broker still fails closed.

Actual file history requires time-qualified evidence. A current directory ancestor is not proof of membership at a past USN event, especially for rename, delete and hard links. Report unknown rather than inventing historical paths.

Required continuation: runtime installed-grant authority, native `adminbox` tests, volume-owned journal capture/custody and checkpoint state, time-aware parent link resolution, FICollector wiring, installer updates and backend source/projector changes. Validation rows V04-V07, V11, V14-V19 are NOT RUN. `main`, ISS-FS-22A and FISender remain unchanged.

## Read-only preflight caller (2026-11-09)

The Windows installer `-list-volumes -volume-config <scope> -inspect-policy-roots` command now invokes this native observer for each currently matched enrolled volume, validates returned root bindings with `policyassociation.NewVolumePlan`, and reports ordered 128-bit root identities or explicit independent failures. It is **not** a signature, authority token, source-history proof, installer create/apply path or service activation. See `WINDOWS-VOLUME-FIRST-ROOT-PREFLIGHT.md`.
