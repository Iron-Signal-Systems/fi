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

A successful PostgreSQL reconnect:

1. revalidates PostgreSQL runtime identity and relational/security boundaries;
2. performs an immediate authoritative operational reconciliation before READY
   or durable retry processing resumes; and
3. resets repair cadence to Validation mode.

The worker retains its host-local singleton lock across PostgreSQL availability
failures and reconnect backoff. Availability retries use bounded exponential
backoff, while authentication, database identity, schema/foundation, privilege,
relational-conflict, and other non-availability errors remain fail-closed.

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

## Permanent Linux service packaging

The Phase 3 permanent ingest worker is a systemd-managed Linux service running as
`fi-receiver`.

The service owns process lifecycle; the worker continues to own PostgreSQL
availability and authoritative ingest recovery.

The permanent service contract is:

```text
service user/group             fi-receiver
runtime directory              /run/fi
runtime directory mode         0700
worker binary                  /opt/fi/bin/fi-ingest-worker
site configuration             /etc/fi/fi-ingest-worker.env
process restart                on-failure
restart delay                  5 seconds
restart-storm window           60 seconds
restart-storm burst            3
```

`/run/fi` is created by systemd through `RuntimeDirectory=fi`. Manual runtime
directory creation is not part of permanent operation.

The unit must not use a hard PostgreSQL lifecycle dependency such as
`Requires=postgresql...` or `BindsTo=postgresql...`. A database outage must not
cause systemd to stop/restart an otherwise healthy ingest worker. The worker's
accepted internal reconnect/backoff path retains the host-local singleton while
PostgreSQL is unavailable.

The service filesystem boundary keeps immutable generation custody and recorder
receipts read-only to the worker and grants write access only to the
non-authoritative READY root plus the worker runtime directory.

An unexpected worker-process failure may be restarted by systemd. A permanent
configuration, runtime-identity, database-identity, schema/foundation,
privilege-boundary, or other fail-closed startup error must not create an
unrestricted restart storm.

Phase 3 service acceptance must prove the installed unit, systemd-created runtime
directory, singleton behavior, normal startup reconciliation, bounded crash
restart, bounded permanent-failure behavior, and clean operator-requested stop.
The already accepted PostgreSQL reconnect campaign remains the authority for
same-process database-loss/reconnect semantics.


### Accepted service-runtime behavior

The permanent service completed controlled runtime acceptance on 2026-09-24.

The accepted behavior includes:

```text
manual-to-systemd cutover with an explicit ownership gap
systemd-owned /run/fi at mode 0700
RuntimeDirectoryPreserve=yes for stable lock-path/inode ownership
unexpected SIGKILL followed by bounded systemd restart
same lock inode across failure/restart
PostgreSQL-unavailable startup handled in-process without systemd restart
bounded permanent PostgreSQL/authentication failure reaching start-limit-hit
clean operator stop with no Restart=on-failure restart
explicit operator start returning to authoritative startup reconciliation
```

The first cutover attempt is retained as failed acceptance history. It exposed
that deleting `/run/fi` after a singleton-conflict exit could unlink the lock
file while another process still held the original inode, allowing a later
service restart to create a different lock inode. `RuntimeDirectoryPreserve=yes`
is therefore part of the accepted host-local singleton operating contract, not a
cosmetic packaging setting.
