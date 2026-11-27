# FI M22K4F Windows Server 2019 / FreeBSD backend acceptance — 2026-10-10

## Scope and status

This is an operator-observed integration and outage-recovery record for the
M22K4F fresh Windows Server 2019 installation on `ISS-FS-19`, using the
FreeBSD FI receiver and PostgreSQL ingest backend on `fi-backend-b`.

**Result:** collection, generation sealing, authenticated transfer, durable
receiver recording and acknowledgement, relational ingest, and Windows sender
retirement **PASS after coordinated backend lab reset**.

**Release gate:** remains **OPEN**. The receiver lifecycle defect exposed by
an authentication-only TLS probe and the persistent mixed-source custody
startup failure require separate engineering fixes and repeat acceptance.

This document records observed deployment behavior. It does not represent a
source-code fix, a new installer build, or full release approval.

## Environment

- Windows source: `iss-fs-19.iss.local` (Windows Server 2019).
- Windows package: `m22k4f-fresh2019-20261010-package`.
- FreeBSD backend host: `fi-backend-b`.
- Production jails: `fi-receiver`, `fi-ingest`, `fi-sor-db`.
- PostgreSQL database: `fi`, containing 49 existing relational tables.
- The existing Windows FISender spool and sealed generation backlog were
  preserved throughout FreeBSD backend recovery.

## Defects exposed before backend reset

The receiver was running at the installer mTLS activation check. At
`2026-10-10T20:43:25Z`, it logged:

```text
ERROR: receive authenticated FI transport transaction:
read FI authenticated transport magic: EOF
```

The receiver was subsequently observed stopped. Source review showed that
the receiver command exits unsuccessfully on the transport error and the
installed receiver supervisor exits on a nonzero child status. This is a
strong explanation for the outage, but the precise original process-exit
event was not independently captured. Reproduce under controlled conditions
before closing the defect.

After the host reboot, receiver startup instead failed during durable custody
reconciliation: a historical generation identified
`adminbox.iss.local`, while the current enrolled source was
`iss-fs-19.iss.local`. The persistent generation and recorded-receipt
directories each contained 575 historical files. The separate acceptance
generation and recorded-receipt directories each contained four files.

The identity check correctly failed closed. However, prior-source custody
must not prevent an independently enrolled source from being recovered on
an eventual multi-source backend.

The host's `jail_enable=NO` policy is intentional: FI uses its dedicated
`fi_pf` / `fi_jails` lifecycle controller. Do not interpret this setting
alone as a missing automatic jail startup configuration.

## Coordinated lab data reset

The operator executed a guarded FreeBSD test-data reset after checking
host identity, active jails, ZFS dataset mountpoints, enrolled source,
historical custody counts, and the 49-table schema.

Before removing test data, the procedure stopped ingest, created a
consistent PostgreSQL custom-format logical dump, stopped PostgreSQL,
and took six ZFS snapshots.

Backup:

```text
/var/db/fi/backups/fi-m22k4f-pre-reset-20261010T215249Z.dump
SHA256 8ee08fea3ff5f3f7ec40e368cb13682d8eb3808dfa974d06336250e45100ed9c
```

Snapshot suffix on the six designated datasets:

```text
@fi-m22k4f-pre-reset-20261010T215249Z
```

Snapshots covered generation custody, transport custody, recorded receipts,
ready markers, source acceptance data, and PostgreSQL PGDATA.

The reset cleared the four main custody/recorded/ready/transport data
directories and four matching acceptance data directories, then truncated
all 49 tables in the `fi` schema with identity reset. It **retained**
the PostgreSQL schema, installed programs, certificates, source enrollment,
jail/network configuration, `fi-dev`, and Windows sender state.

Post-reset receiver startup at `2026-10-10T21:52:52Z` reported:

```text
GenerationStartup: discovered=0 new=0 already_recorded=0
ready_published=0 ready_warnings=0 removed_provisional=0
```

PostgreSQL, `fi_ingest_worker` (PID 16390), and `fi_receiver`
(PID 26964) were running during the verification.

## End-to-end recovery proof

Verification completed at `2026-10-10T21:56:02Z`.

The receiver accepted the source using TLS 1.3, mutual TLS, authorized
source identity, and authorized batch signing. The received generations
were recorded with `GenerationACK: recorded`.

The PostgreSQL query found **8 accepted generations and 127 committed
records** for `iss-fs-19.iss.local` after the reset:

| Generation (short timestamp) | Batches | Committed records |
| --- | ---: | ---: |
| `20261010T204328.558354800Z-4ac27fe9dea7bf4f` | 2 | 13 |
| `20261010T205328.568622300Z-3d382204db9426d3` | 12 | 30 |
| `20261010T210328.567986500Z-25eb12cc438141b1` | 9 | 9 |
| `20261010T211328.568510100Z-038747aa72edfef5` | 13 | 18 |
| `20261010T212328.567906600Z-06c484114d1d7607` | 12 | 13 |
| `20261010T213328.568732500Z-dabef050ec6975e7` | 12 | 13 |
| `20261010T214328.568270600Z-8f1cdf03f7b14e52` | 13 | 15 |
| `20261010T215328.567989400Z-5bb6ce1212576cf8` | 12 | 16 |

Each generation was logged by the ingest worker as `outcome=Accepted`,
with `records_seen` equal to `records_committed`. The post-ingest ready
marker count was zero. The `21:53` generation was received and committed
after the initial backlog recovery, demonstrating ongoing delivery.

A subsequent Windows-side check confirmed `FISender` running and no
sealed generation directories remaining in
`C:\ProgramData\FI\stage\generations`. Only the active
`.fi-generation-build` work directory was listed. This proves sender
retirement of the observed backlog; the work directory is not a sealed
backlog item and must not be removed as cleanup.

## Acceptance conclusion and open work

**Passed for this observed lab run:**

- Windows-side generation collection, rollover, and sealed spool retention;
- replay of generations queued during receiver unavailability;
- TLS 1.3 / mutual authentication and authorized receiver recording;
- receiver generation acknowledgements;
- authoritative PostgreSQL ingest of 8 generations / 127 records;
- active sender-queue retirement after acknowledgement; and
- renewed generation delivery following backlog recovery.

**Not yet accepted for release:**

1. Receiver availability following a TLS-only connection that closes before
   an FI transaction. Resolve the receiver/supervisor contract and verify
   authentication-only probes do not terminate the listening service.
2. Mixed-source durable custody startup behavior. Preserve strict
   source-identity validation while establishing correct multi-source
   recovery/isolation.
3. Repeat cold-reboot and ongoing multi-generation acceptance after the
   receiver lifecycle fix, without requiring another manual backend reset.

No source-code remediation for these open items is included in this record.
