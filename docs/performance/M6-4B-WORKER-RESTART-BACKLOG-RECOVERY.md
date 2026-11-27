# M6.4B — Worker Restart and Backlog Recovery

## Status

**PASS — actual ingest-worker recovery acceptance**

Date: 2026-10-25

Repository baseline:
`f20a816191798597d3be28aa0aa464353e02597d`

Worker binary SHA-256:
`bb9dd9c9a8ccd73dbd9dcb1709ce7d8900249e19ad57e85f5ecc7972d9b63241`

## Objective

Verify that the FI ingest worker can resume after forced
process termination, recover pending immutable generations,
and process additional READY-notified work without partial
relational authority or duplicate generation acceptance.

## Environment

- FreeBSD fi-dev
- Actual fi-ingest-worker compiled from pinned source
- PostgreSQL 18 in a dedicated isolated cluster
- Unix-socket-only PostgreSQL access
- fsync, synchronous_commit and full_page_writes enabled
- Schema migration 0004 applied
- Private worker singleton lock
- Private custody, recorder, staging and READY roots
- Three previously verified signed FIGT generations
- No live SOR modification

## Procedure

1. Stage and accept generation 1 through fi-ingest-worker.
2. Stage generation 2 and start the worker.
3. Observe active PostgreSQL Security field COPY.
4. Terminate the isolated worker using SIGKILL.
5. Verify PostgreSQL rollback and durable attempt history.
6. Restart the actual worker with a supervisor-style launch.
7. Verify startup reconciliation resumes generation 2.
8. During generation 2 ingestion, stage generation 3.
9. Publish its durable, zero-byte, mode 0600 READY marker.
10. Allow the worker to drain pending and READY work.
11. Stop the restarted worker gracefully.
12. Verify final relational, journal and READY queue state.

## Interruption and Recovery

**PASS**

The worker was terminated during active insertion into:

`fi.windows_security_event_field`

PostgreSQL rolled back the unfinished transaction.

Generation 1 remained authoritative, and generation 2
had no partially committed generation or source records.

The interrupted AttemptStarted journal event remained.

After the worker restarted, startup reconciliation
identified and ingested the pending generation 2.

## READY Notification

**PASS**

Generation 3 arrived in the isolated custody and recorder
directories while generation 2 was being ingested.

Its source-specific READY marker was published and verified.

The running worker completed generation 2, processed
generation 3, and retired its READY marker.

The final source-specific READY directory was empty.

## Final Relational State

| Measurement | Result |
| --- | ---: |
| Accepted generations | 3 |
| Source batches | 607 |
| Source records | 862,498 |
| Security events | 806,279 |
| Security field rows | 12,094,187 |
| Database bytes | 2,827,368,127 |
| Security field relation bytes | 1,420,451,840 |

### Generation Distribution

| Generation | Records | Batches |
| --- | ---: | ---: |
| 13:29 UTC | 295,067 | 201 |
| 13:39 UTC | 288,104 | 202 |
| 13:49 UTC | 279,327 | 204 |

## Journal Verification

| Outcome | Entries |
| --- | ---: |
| Accepted | 3 |
| Incomplete / AttemptStarted | 4 |
| Failed | 0 |
| AlreadyAccepted | 0 |

The four AttemptStarted events represent the original
generation attempts plus the restarted attempt for
generation 2.

The interrupted journal event remains durable. It does
not confer authoritative acceptance.

No duplicate acceptance was observed.

## Acceptance Conclusion

**PASS**

The real FI ingest worker recovered a pending generation
following process termination and external restart.

An additional signed generation, introduced during backlog
processing, was subsequently accepted through the worker's
READY notification path.

Final relational totals matched the expected signed
generation counts, with no partially accepted generation.

## Scope Limitations

- Restart was performed by the isolated test harness,
  not the installed FreeBSD service supervisor.
- Generation 3 was staged from an existing signed fixture;
  a live Windows sender was not used.
- The campaign used three generations, not sustained
  indefinite arrivals.
- CPU, memory and sustained storage limits were not
  independently characterized by this acceptance.
- Duplicate-safe replay was separately demonstrated
  in M6.4A, not repeated in M6.4B.

## Retained Results

`/home/jwood/fi-m64b-isolated-results-20261025-workerrestart`
