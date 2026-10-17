# FI Windows Server 2022 Installer Acceptance — 2026-10-17

## Scope and result

**Result: PASS — Windows installer activation and end-to-end PostgreSQL ingest.**

This record covers the native FI installer on `iss-fs-22b.iss.local`,
Windows Server 2022 Standard Evaluation, build `20348`.

Backend: `fi-backend-b`, with FI receiver, ingest worker, and
PostgreSQL System of Record.

The acceptance is specific to this installed source and lab run.
It does not constitute full FI production-release acceptance.

## Source and release identity

Source branch: `windows-2019-containment-fallback-20261012`

Pre-checkpoint source HEAD:

`c96d3bc270738f5849e992e334478e1e6af32c65`

The successful release candidate was built from the local working tree
including uncommitted Windows audit/SACL implementation and the
collector-readiness correction. This acceptance record and those
source changes are committed together as the reproducible checkpoint.

Release ID:

`m22k4q-readiness-lab-20261017-20261017-033042`

Signed installer SHA-256:

`4D81789E29F7816088CD9B8839640CDDD081E7A4F9C7AED897011D4954FA6919`

The package used the authorized development release signer.
Development Authenticode signatures are not timestamped.

All five signed runtime payload hashes matched the previously
installed executables. No package replacement was required.

## Defect corrected

A prior sender-only Approval 2 transaction attempted to require
current-transaction `ServiceStarted` and `WindowsSecurityCatchUp`
records from an FICollector that had not been restarted.

The readiness wait failed, causing the installer to roll back
FISender activation.

The correction makes collector runtime readiness conditional on
an approved plan that creates, restarts, or replaces the collector,
rather than requiring a new collector startup record for unrelated
FISender-only reconciliation.

Sender-only reconciliation retains service-stability validation.

The correction was covered by regression tests and the full
Windows installer and supporting application package tests.

## Approved mutation set

The accepted plan contained two `RECONCILE` actions:

- FISender SCM startup: Manual to Automatic.
- FISender runtime: Stopped to Running.

FICollector, FIUSNReader, FIObjReader, FICRLRefresher, installed
runtime payloads, Windows audit/SACL prerequisites, configuration,
release trust, and existing enrollment required no change.

Receiver name: `fi-receiver.iss.local`
Receiver address: `192.168.1.219:8443`
Source identity: `iss-fs-22b.iss.local`

Receiver mutual-TLS activation passed before Approval 2.

## Installer result

Approval 2: PASS.

Authoritative post-mutation discovery: converged.

Final installer discovery: PASS.

Final installer result: PASS.

Successful installation transaction:

`C:\ProgramData\FI\install\install-20261017T075450.476525800Z.json`

Transaction SHA-256:

`33028D28A4A3C80D23375C152CABE915D383FB80716B9E9F213BD140ADD802F4`

## Final Windows service state

| Service | Startup | State | PID |
| --- | --- | --- | ---: |
| FICollector | Automatic | Running | 4180 |
| FIUSNReader | Automatic | Running | 1048 |
| FIObjReader | Automatic | Running | 3224 |
| FICRLRefresher | Automatic | Running | 2524 |
| FISender | Automatic | Running | 3076 |

FISender ran under `ISS\gFI-FS22B$`.

The four services already running retained their PIDs during
FISender activation.

## FreeBSD backend and PostgreSQL verification

Backend source status:

- Receiver registered: true.
- Ingest registered: true.
- Configurations identical: true.

The authoritative `fi.ingest_journal` query for
`iss-fs-22b.iss.local` showed:

| Generation timestamp (UTC) | Accepted (UTC) | Records committed |
| --- | --- | ---: |
| 2026-10-16 21:55:04 | 2026-10-17 06:21:48 | 286 |
| 2026-10-17 06:21:45 | 2026-10-17 06:22:01 | 618 |
| 2026-10-17 07:54:51 | 2026-10-17 07:55:03 | 114 |
| 2026-10-17 08:04:51 | 2026-10-17 08:05:02 | 15 |

Total: 4 accepted generations, 1,033 committed records.

After successful installer activation:
2 accepted generations, 129 committed records.

Every listed terminal journal entry had:

`outcome=Accepted`
`stage=AuthoritativeRecord`

`records_seen` equaled `records_committed` for each generation.

The corresponding `Incomplete / AttemptStarted` journal events
were followed by successful terminal `Accepted` records.

## Acceptance conclusion

The observed lab run proves successful:

1. Signed installer authentication and release authorization.
2. Approved FISender-only reconciliation.
3. Preservation of the four already-running FI services.
4. All five FI services running with Automatic startup.
5. Receiver mutual-TLS activation and source registration.
6. Generation delivery to the FreeBSD backend.
7. Authoritative PostgreSQL ingestion.
8. Continued ingestion after installer completion.

## Remaining release gates

This record does not establish:

- long-duration sender and receiver stability;
- cold-reboot and outage-recovery acceptance for this candidate;
- Windows Server 2019 or 2025 acceptance of these changes;
- approval for a production release.

Those boundaries remain separate from this successful
Windows Server 2022 installer and end-to-end ingest acceptance.
