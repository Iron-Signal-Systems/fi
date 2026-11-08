# Windows Volume-First Engineering Implementation Inventory

**Status:** Planning inventory — no code, installer or backend refactor complete
**Branch:** `dev/windows-volume-first-20261108`
**Windows work machine:** `adminbox`

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
