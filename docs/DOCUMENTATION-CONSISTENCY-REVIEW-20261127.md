# FI Documentation Consistency Review — November 27, 2026

**Scope:** FI repository documentation at `main` commit `0738bd7e26ed3ab3603170f8800e79f7f7d9d669`, including documentation updates proposed on branch `docs/full-consistency-audit-20261127`.

**Project status:** Pre-alpha. Initial pilot target August 2028–2029. **No production release or Gate 6 acceptance is implied.**

## Method and limits

- Inventoried the complete 2,000-blob Git tree available at the baseline revision; found **75 tracked Markdown, reStructuredText, and text documentation files** (including tool and example README files).
- Retrieved all 75 files to verify the existence of **relative Markdown link targets** against repository paths. The scan found no missing targets among the Markdown links it recognized. This does **not** check external URLs, fenced-code references, implicit paths, anchor IDs, generated assets at runtime, or the behavior of linked tools.
- Examined the living product definition, roadmap, installer, FreeBSD/C220 architecture and deployment contracts, Windows collector/USN references, governance documents, SQL dictionaries, and dated test/acceptance records for stale implementation claims. The database dictionaries and lengthy governance/validation files were reviewed for specific inconsistencies, **not** independently regenerated line-by-line from the running system.
- Compared the three September Gate 3 migration files `0001`–`0003` with the September source revision: the Git blob hashes are identical. Verified the presence and content of the additional `0004` and `0005` migration source. Verified the active Go module declares **Go 1.27.4**.
- Documentation changes do **not** run live C220 diagnostics, execute the source-lock binary rebuild, validate the Windows installer on a fresh target, or perform a complete database schema-to-Go regeneration.

## Document authority and status

| Subject | Current source of truth | Status and limitation |
|---|---|---|
| Why FI exists and its customer-facing scope | [Product definition](PRODUCT-DEFINITION.md) and [root README](../README.md) | Living product definition; FI remains pre-alpha |
| Active C220 two-jail receiver/SoR topology | [C220 backend architecture](architecture/FI-C220-CURRENT-BACKEND.md), [as-built](deployment/C220-FREEBSD-AS-BUILT-20261127.md), and [deployment tooling](../tools/deployment/freebsd/README.md) | As observed on 2026-11-27; the live host was not re-audited in this documentation pass |
| C220 source provenance and binary identity | [C220 source-lock record](deployment/C220-LIVE-RUNTIME-LOCK-20261127.md) | Three candidate source revisions and installed SHA-256 values recorded; complete successful reproducibility-verifier run **not evidenced** |
| Windows source behavior and supported install approach | [Windows collector contract](COLLECTOR-CONTRACT.md), [Windows installer](WINDOWS-INSTALLER.md), and [operator guide](WINDOWS-INSTALLER-OPERATOR-GUIDE.md) | Existing exact-build acceptance is historical; new volume-first sender and integrated fresh install still require acceptance |
| Gate 1–3 evidence | [Acceptance records](acceptance/README.md), [verification](VERIFICATION-RECORD.md), and [performance reports](performance/README.md) | Historical, environment-specific and artifact-specific; do not rewrite, extend, or silently revoke these results |
| Gate 3 relational dictionary | [PostgreSQL data dictionary](database/POSTGRESQL-DATA-DICTIONARY.md) and [Go traceability map](database/POSTGRESQL-JSON-GO-TRACEABILITY.md) | September 2026 schema/Go mapping snapshot; not complete current-main certification after 0004/0005 |
| Classification, projected query views, and user experience | [Phase 4](../fi-roadmap/docs/roadmap/phase-04-classification-and-enrichment.md), [Phase 5](../fi-roadmap/docs/roadmap/phase-05-projection-query-and-user-experience.md), and [projection contract](PUBLISHED-FI-PROJECTION-CONTRACT.md) | Design/roadmap boundaries; Gate 4 and Gate 5 acceptance not established |
| One integrated FI customer installation, upgrades, DR | [Phase 6](../fi-roadmap/docs/roadmap/phase-06-integrated-deployment-and-release.md) | Intended configuration-driven product lifecycle; fresh deployment/recovery and release acceptance pending |

## Corrections made in this review

**Current deployment and binary evidence:** clarified the C220 two-jail authority, located the source-lock verifier, and distinguished recorded binary hashes from a *completed* bit-for-bit reproduction test.

**Windows installer:** replaced the stale October branch/toolchain description with the dated active-main Go 1.27.4 implementation baseline, without claiming earlier signed packages were rebuilt or retested; clarified example gMSA, audit-policy, SACL, and local ACL scripts are not normal post-install instructions.

**Former Linux ingest path:** marked Phase 3 CLI examples and Linux service notes as historical; removed references to a Linux deployment directory that is absent from current main; kept the historical Gate 3 acceptance intact.

**Source collection:** separated original accepted root/USN behavior from the redesigned volume-first sender currently under development and still requiring fresh-install acceptance.

**Schema and traceability:** corrected both SQL dictionaries to distinguish the September 0001–0003 snapshot from today's additional 0004/0005 migrations. The old counts and field mappings remain preserved rather than silently guessed.

**Roadmap and architecture:** Phase 4 and 5 marked planned/unaccepted, Phase 6 aligned with FreeBSD C220 as an implemented development backend and **one** future configuration-driven FI product, and the superseded FreeBSD ADR retained as a historical proposal.

**Documentation navigation:** maintained the mission-focused root README, with technical detail in `docs/`, the roadmap, and tool-specific references.

## Work still requiring separate engineering evidence

These items must remain open instead of being declared resolved by documentation edits:

1. Run and retain an accepted transcript for `tools/deployment/freebsd/operations/verify_c220_live_sources.sh` on the required FreeBSD amd64 build environment, with exact binary comparisons, without modifying running services.
2. Regenerate and audit the PostgreSQL schema dictionary/Go field-to-column traceability against **all five** current migrations and actual current writer code (and validate migration application on the intended DB). No table/column/index count for live C220 was remeasured here.
3. Complete and accept the volume-first Windows sender redesign and one complete fresh configuration-driven installation across the selected exact Windows builds.
4. Complete the C220 host/jail/PF/ZFS configuration capture and verify a fresh installation, backup, restore, and recovery against the final integrated customer deployment model.
5. Implement, security-test, and accept the planned classification, published projections, user-facing query/API/UX, and release lifecycle according to their own gates.

## Governing distinction

**Current implementation, historical acceptance, future design, and unverified claims are different states.** A past PASS is still evidence of that past test; it is not proof of the running system after later changes. FI's normal C1 pipeline is internal backlog/catch-up processing, not a separately marketed product capability. The intended customer experience is one configurable and supportable FI system, not manual integration of its internal services.

This document tracks a **repository-documentation consistency review**, not a certification that all prose is permanently current or that any live acceptance gate has passed.
