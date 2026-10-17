# FI Integrated Acceptance Records

These are dated, scope-limited, operator-observed acceptance records. They do not replace Phase/Gate signoff, release artifacts, or the authoritative System of Record. For preexisting runtime and installer characterization, see `docs/WINDOWS-SERVER-VALIDATION.md`, `docs/WINDOWS-INSTALLER.md`, and `docs/WINDOWS-INSTALLER-ACCEPTANCE-2026-10-09.md`.

| Date | Scope | Result | Record |
|---|---|---|---|
| 2026-10-12 | Windows Server 2019 build 17763; signed M22K4N first-run installation, object-history reconstruction, FreeBSD/PostgreSQL ingest, and reboot persistence | **PASS (bounded functional test); open findings retained** | [Windows Server 2019 M22K4N](WINDOWS-SERVER-2019-M22K4N-2026-10-12.md) |
| 2026-10-17 | Windows Server 2022 build 20348; signed M22K4Q FISender reconciliation, five running services, authenticated receiver activation, FreeBSD/PostgreSQL ingest | **PASS (bounded activation and ingest test); later release gates remain** | [Windows Server 2022 M22K4Q](../WINDOWS-INSTALLER-ACCEPTANCE-2026-10-17.md) |

The associated [`sql/`](sql/) and [`powershell/`](powershell/) files are read-only verification scripts. They are not installer mutations or CI assertions unless explicitly integrated into a test runner and executed against the corresponding lab environment.
