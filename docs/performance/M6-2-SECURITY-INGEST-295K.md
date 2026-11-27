# M6.2 — Security-heavy relational ingest comparison

## Status

**PASS — isolated ingestion and relational acceptance**

Recorded 2026-10-25. Repository commit:
`38d31686549700d12c6d64bc33152853350063ce`.

## Workload

Source: `iss-fs-22a.iss.local`

Generation:
`20261018T132957.268168000Z-c1a645d67c2f036c`

Immutable signed generation replayed into separate, freshly
initialized PostgreSQL 18 databases.

- Recorded source records: 295,067
- Recorded batches: 201
- WindowsSecurityEvent: 275,005
- WindowsSecurityCoverage: 196
- USNObjectObservation: 19,861
- USNReadBoundary: 5
- Security event scopes: 275,005
- Security event fields: 4,125,077

## Controlled comparison

Both runs used the same source commit, executable bytes,
signed generation and PostgreSQL major version.

| Measurement | Original schema | Migration 0004 |
| --- | ---: | ---: |
| Wall time | 222.66 s | 209.22 s |
| Ingest engine | 200.882 s | 186.625 s |
| Security field COPY | 73.017 s | 59.908 s |
| Security event COPY | 13.046 s | 12.805 s |
| WAL | 1,590.02 MiB | 1,294.04 MiB |
| WAL-buffer-full events | 15,920 | 2,160 |
| Committed records | 295,067 | 295,067 |
| Outcome | Accepted | Accepted |

Migration 0004 removes the unused
`windows_security_event_field_name_idx` while preserving
the composite primary key and relational constraints.

Observed field COPY improvement: approximately 18.0%.
Observed end-to-end improvement: approximately 6.0%.

## Remaining relational work

The corrected-schema run recorded 4,675,087 index scans
against `windows_security_event_pkey`.

This is consistent with intensive parent-record validation
during event and child-row insertion. Index-scan counts alone
do not establish the time consumed by individual checks.

The field-name index was absent in the corrected run.
The composite field primary key remained present.

Historic USN rows in this generation used legacy capture
bindings. This workload does not independently establish
acceptance of modern source-bound USN capture.

## Live deployment

On 2026-10-25, the existing committed migration 0004
was applied to the live SOR with DROP INDEX CONCURRENTLY.

The live post-migration checks confirmed:

- field-name index absent;
- composite primary key retained;
- foreign key retained;
- subsequent generations accepted.

Protected pre-migration ZFS snapshot:

`zroot/fi/sor/postgres@fi-m62-pre-0004-20261025`

Hold: `fi-m62-0004`.

Retain this recovery point pending separate retention review.

## Interpretation

The tested isolated workload exceeded 1,000 source
records per second end to end.

These results characterize this hardware, database setup,
generation, and run conditions. They are not universal
production capacity or sustained-backlog guarantees.

No foreign keys, primary keys, durability guarantees,
or signed-custody contracts were relaxed.
