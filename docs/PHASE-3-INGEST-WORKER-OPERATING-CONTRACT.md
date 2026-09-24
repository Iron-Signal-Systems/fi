# Phase 3 Ingest Worker Operating Contract

## Scope

This document records the Phase 3 operating contract for the Linux relational
ingest worker.

The singleton boundary is a backend-host concern, not a Windows-source-count
limit.

The current Phase 3 acceptance worker is source-scoped through `-source`; that
does not define the final multi-source backend topology. A later deployment may
aggregate multiple Windows sources into one worker or use another explicitly
coordinated local model.

Regardless of that local source topology, distributed coordination becomes
necessary only when more than one backend host can contend for active ingest
ownership.

## Current active-worker model

Phase 3 supports one active relational ingest-worker host per backend deployment.

The current worker acquires:

```text
/run/fi/fi-ingest-worker.lock
```

with a non-blocking exclusive `flock()`.

That lock protects against two worker processes accidentally running on the same
Linux host.

It does not provide distributed coordination across backend hosts.

For example, this is outside the current Phase 3 operating contract:

```text
receiver-a                         receiver-b
worker #1                          worker #2
     \                                /
      \---------- PostgreSQL --------/
```

PostgreSQL uniqueness and generation-identity constraints remain important
last-line integrity protections, but they are not an election, lease, or
cluster-singleton mechanism.

Receiver/backend HA or automatic cross-host ingest failover must add an
authoritative distributed coordination mechanism before more than one backend
host may contend for active ingest ownership. A PostgreSQL session-level advisory
lock or equivalent database-backed lease is the preferred design direction.

The host-local `flock()` should remain even after distributed coordination is
added. The two controls solve different problems:

```text
host-local flock
    -> prevents duplicate worker processes on one backend host

authoritative distributed lock/lease
    -> prevents multiple backend hosts from simultaneously owning ingest
```

A future distributed lock must be reacquired after PostgreSQL reconnect before
reconciliation or ingest resumes.

## Normal operational discovery

Normal generation ingestion is notification-driven:

```text
immutable recorder receipt
        |
        v
READY marker
        |
        v
bounded READY discovery
        |
        v
cheap relational identity check
        |
        v
ingest if pending
        |
        v
retire READY marker
```

READY state is operational and non-authoritative. The immutable recorder receipt
remains authoritative.

Rejected source records are scheduled independently from the append-only ingest
journal. A known durable `SOURCE_RECORD_REJECTED` state is not evidence that READY
or repair discovery failed.

## Authoritative repair reconciliation

The full recorded-receipt sweep is a repair and confidence mechanism. It is not
the normal generation-discovery path.

Worker startup performs an immediate full authoritative **operational**
reconciliation. This is not the separate expensive deep-audit reconciliation
path.

After startup, repair cadence is adaptive:

```text
startup
    |
    v
immediate operational reconcile
    |
    v
Validation mode
1 hour x 6 clean repair sweeps
    |
    v
Intermediate mode
12 hours x 1 clean repair sweep
    |
    v
Steady mode
24-hour repair sweeps
```

Any repair anomaly resets the cadence to Validation mode with a zero clean count.

The cadence state is non-authoritative and is intentionally not persisted. A
worker restart safely returns to Validation mode.

A future successful PostgreSQL reconnect must also:

1. revalidate PostgreSQL runtime identity and relational/security boundaries;
2. perform an immediate authoritative operational reconciliation; and
3. reset repair cadence to Validation mode.

## Repair anomaly classification

A full repair sweep is clean when it finds no relational conflict and no pending
generation that lacks an expected operational explanation.

These pending states do **not** reset repair cadence:

- the exact immutable receipt still has a valid READY marker and is awaiting the
  normal operational path; or
- the generation has durable `SOURCE_RECORD_REJECTED` retry state in the ingest
  journal.

These conditions are anomalies and reset cadence:

- a pending authoritative generation has neither a READY marker nor durable
  rejection state;
- relational conflict is detected; or
- repair/reconciliation cannot complete successfully.

The worker determines this classification from the repair plan before the repair
plan mutates relational state. A generation found only by the full repair sweep
therefore resets confidence even if that same sweep safely ingests it.

Normal new FI activity does not reset repair cadence.

## Authority rule

Repair cadence never becomes FI authority.

It does not replace:

- immutable recorder receipts;
- exact FIGT custody;
- the append-only ingest journal;
- PostgreSQL relational identity constraints; or
- explicit conflict handling.

Loss of cadence state changes only how soon the next safety sweep occurs.
