# FI Phase 3 Linux Ingest-Worker Packaging

This directory contains the permanent Linux service packaging for the Phase 3
relational ingest worker.

This packaging is deliberately narrower than Phase 6 integrated product
installation. It exists to close the Phase 3 permanent ingest-runtime gate.

## Runtime contract

The service runs:

```text
User=fi-receiver
Group=fi-receiver
RuntimeDirectory=/run/fi
RuntimeDirectoryMode=0700
binary=/opt/fi/bin/fi-ingest-worker
configuration=/etc/fi/fi-ingest-worker.env
```

The current pilot service has one configured source ID. The current worker is
still source-scoped through `-source`; this packaging does not define the final
multi-source backend topology.

The service uses the accepted Phase 3 defaults/cadence:

```text
READY batch                     64
durable retry batch             64
repair validation interval      1 hour
poll interval                   2 seconds
source-record retry delay       15 minutes
PostgreSQL reconnect initial    1 second
PostgreSQL reconnect maximum    30 seconds
```

## PostgreSQL ownership

The systemd unit intentionally has no hard `Requires=postgresql...`,
`BindsTo=postgresql...`, or equivalent database lifecycle dependency.

Temporary PostgreSQL availability is owned by the worker's internal reconnect
state machine:

```text
PostgreSQL unavailable
    -> worker process remains alive
    -> host-local singleton remains held
    -> bounded reconnect backoff
    -> PostgreSQL boundary revalidated
    -> repair confidence reset to Validation
    -> immediate authoritative operational reconcile
    -> READY / durable retry processing resumes
```

Systemd owns process failure, not database availability.

## Restart policy

`Restart=on-failure` handles an actual worker-process failure.

The unit also uses:

```text
RestartSec=5s
StartLimitIntervalSec=60s
StartLimitBurst=3
```

This allows crash recovery while preventing an immediate permanent
configuration/schema/identity failure from becoming an unrestricted restart
storm.

A normal `systemctl stop` sends `SIGTERM`. The Go worker converts SIGTERM/SIGINT
to context cancellation and exits without treating the requested stop as a
runtime failure.

## Filesystem boundary

The worker receives read-only service access to:

```text
/var/lib/fi/custody/generation
/var/lib/fi/custody/recorded
```

It receives write access only where its current runtime requires it:

```text
/var/lib/fi/custody/ready
/run/fi
```

`/run/fi` is created and owned by systemd for the service. Manual creation of the
runtime directory is not part of the permanent operating procedure.

The unit sets `RuntimeDirectoryPreserve=yes`. The lock namespace therefore stays
stable across service failures, restart backoff, and explicit service stops.
This matters because another same-host process may still hold the lock file:
removing `/run/fi` while that process is alive would unlink the locked inode and
allow a recreated pathname to refer to a different, unlocked file.

`/run` remains transient across host reboot; systemd recreates `/run/fi` on the
next service start.

The PostgreSQL Unix socket remains externally managed by PostgreSQL. Connecting
to that socket does not make PostgreSQL lifecycle ownership part of this unit.

## Install without starting

Build the reviewed worker candidate first, then install it:

```bash
cd go
go build -o /tmp/fi-ingest-worker ./cmd/fi-ingest-worker

sudo tools/deployment/linux/Install-FI-Ingest-Worker.sh \
  --binary /tmp/fi-ingest-worker \
  --source iss-fs-01.iss.local \
  --enable
```

The installer does not start, stop, or restart the service. This is deliberate:
initial cutover from the current manually started acceptance worker must be an
explicit operator action.

## Static package validation

Run:

```bash
tools/deployment/linux/Validate-FI-Ingest-Worker-Package.sh
```

Before installation, `systemd-analyze verify` may report only that
`/opt/fi/bin/fi-ingest-worker` does not yet exist. The static validator accepts
that one exact preinstall diagnostic and rejects any other verification error.

The installer performs strict `systemd-analyze verify` after the reviewed binary
has been installed at its permanent path. It also checks the Phase 3 service
invariants, including the absence of hard PostgreSQL service coupling.

## Initial cutover acceptance

Before Gate 3 closure, the permanent service must prove:

```text
normal service start
systemd-created /run/fi ownership and mode
host-local singleton ownership
authoritative startup reconciliation
PostgreSQL unavailable at worker start without a systemd restart loop
unexpected worker death followed by bounded systemd restart
permanent configuration/database-boundary failure reaches visible failed state
without unrestricted restart churn
successful normal stop through SIGTERM/context cancellation
```

The already accepted isolated PostgreSQL reconnect campaign remains the proof for
same-process live database-loss recovery, revalidation, Validation reset,
reconciliation-before-READY, and exactly-once later acceptance.

Do not rewrite that historical proof merely because the worker is later run
under systemd.
