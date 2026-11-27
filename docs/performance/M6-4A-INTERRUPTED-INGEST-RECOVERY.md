# M6.4A — Interrupted Ingestion and Recovery

## Status

**PASS — isolated transactional recovery acceptance**

Date: 2026-10-25

Repository baseline:
`cb8cea09884a84904f7965fe9d32b0a45c83d3ed`

Ingest binary SHA-256:
`35a56cb3b94af9ced1f2ffd3987227bd60c9a0676bb87ff6bed69f3195cd0efb`

## Environment

- FreeBSD fi-dev
- PostgreSQL 18
- Private PostgreSQL cluster and Unix socket
- Migration 0004 applied
- fsync enabled
- synchronous_commit enabled
- full_page_writes enabled
- Original immutable signed custody retained
- No live SOR modification

## Test Procedure

1. Accept signed generation 1.
2. Start ingesting signed generation 2.
3. Observe an active PostgreSQL Security field COPY.
4. Terminate the isolated FI ingester using SIGKILL.
5. Verify PostgreSQL transaction rollback.
6. Verify generation 1 remains unchanged.
7. Verify the interrupted attempt journal remains.
8. Retry generation 2 from immutable custody.
9. Accept generation 3.
10. Replay generation 2 to verify AlreadyAccepted.
11. Verify cumulative relational and journal state.

## Observed Interruption

The isolated FI ingest process was terminated while
PostgreSQL reported an active COPY into:

`fi.windows_security_event_field`

Observed tuples_processed: 15,360.

This confirms interruption during active Security field
insertion rather than before database write activity.

## Rollback Verification

After SIGKILL:

- Generation 2 had no authoritative recorded generation.
- Generation 2 had no partially committed source records.
- Generation 1 remained fully authoritative.
- The interrupted AttemptStarted journal entry remained.
- The source custody objects remained available for replay.

## Recovery Verification

Generation 2 was subsequently accepted from its original
immutable custody and recorder receipt.

Generation 3 was accepted successfully.

An exact repeat of generation 2 returned AlreadyAccepted
without committing duplicate source records.

## Final Relational State

| Measurement | Result |
| --- | ---: |
| Authoritative generations | 3 |
| Recorded batches | 607 |
| Source records | 862,498 |
| Security events | 806,279 |
| Security field rows | 12,094,187 |
| Database bytes | 2,827,728,575 |
| Security field relation bytes | 1,420,656,640 |

## Final Journal State

| Outcome | Entries |
| --- | ---: |
| Accepted | 3 |
| AlreadyAccepted | 1 |
| Incomplete / AttemptStarted | 5 |
| Failed | 0 |

The five incomplete entries represent attempt-start events,
including the interrupted attempt, successful attempts and
duplicate replay. They do not represent five rejected
or partially authoritative generations.

## Acceptance Conclusion

**PASS**

The controlled interruption did not result in partial
authoritative relational materialization.

The signed generation could be retried successfully, and
the eventual database matched the expected aggregate
record counts.

Exact duplicate replay preserved idempotent acceptance.

## Scope Limitation

This test exercised the standalone ingester with controlled
manual retry.

It does not establish automatic ingest-worker recovery,
restart scheduling, or backlog drain during concurrent
arrival of additional generations.

Those behaviors remain for M6.4B.

## Retained Test Results

`/home/jwood/fi-m64-isolated-results-20261025-killcopy`
