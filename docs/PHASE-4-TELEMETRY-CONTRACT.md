# Phase 4 Operational Telemetry Contract

Status: **PLANNED DESIGN CONTRACT — NOT YET IMPLEMENTED**

Phase: **Phase 4 — Classification & Enrichment**

Work package: **4A — Operational Telemetry Foundation**

Repository baseline when this contract was written:

```text
0b3eed58dbc0b7eb5a52dc3bbe32ff0423aae8ec
merge: add FIObjReader privilege boundary and receiver compatibility
```

## Purpose

FI telemetry answers:

> **What was FI and the infrastructure supporting FI doing while FI collected,
> transported, recorded, ingested, classified, or queried information?**

That is deliberately different from FI's primary product question:

> **What do we know about this file?**

The distinction is architectural:

```text
FI System of Record
    file/source history
    security and activity history
    classification results
    derived file intelligence

FI Telemetry
    host operational state
    process resource use
    storage behavior
    network behavior
    FI subsystem state
    queue/backlog state
    receiver/ingest/database behavior
    classification operational load
```

Telemetry is operational information. It is not authoritative governed-file
history and does not become a second FI System of Record.

## Fundamental failure rule

```text
TELEMETRY FAILURE
        MUST NOT BECOME
FI HISTORY FAILURE
```

Telemetry database failure, telemetry receiver failure, telemetry spool
exhaustion, telemetry service failure, or telemetry-reader failure must not stop
or silently invalidate the ordinary FI collection, custody, transport, recorder,
relational-ingest, or classification-history paths.

When telemetry itself is incomplete, that incompleteness must remain explicit.

## Phase ownership

Phase 4 remains **Classification & Enrichment**. Telemetry does not redefine the
Gate 4 product outcome.

Telemetry is the first Phase 4 work package because FI should establish permanent
operational visibility before adding protected source-content streaming,
classification, archive/container inspection, and deeper content work.

```text
Phase 3 / Gate 3 complete
        |
        v
4A Operational Telemetry Foundation
        |
        v
4B Protected Classification Contracts
        |
        v
4C Protected Classification Streaming
        |
        v
4D Windows Bounded Content Reader
        |
        v
4E Classification Engine
        |
        v
4F Deep Inspection
        |
        v
4G Classification Result Ingest
        |
        v
Gate 4
```

## Telemetry coverage boundary

Permanent telemetry covers both sides of FI:

1. Windows/source hosts running FI source components.
2. Backend hosts running receiver, custody, recorder/ingest, PostgreSQL, and
   later classification/projection components.

A source-only telemetry implementation is incomplete because a healthy source
can coexist with an overloaded receiver, storage layer, ingest worker, or
PostgreSQL instance.

## Logical architecture

```text
WINDOWS SOURCE HOST

FICollector   FIUSNReader   FIObjReader   FISender   future source components
     \             |            |            /
      +------------+------------+-----------+
                       |
                       v
                fi-telemetry
             non-administrative
                       |
            local authenticated IPC
            only where required
                       |
                       v
          fi-telemetry-reader
          narrowly privileged

                       |
                       | authenticated/encrypted
                       | telemetry transport
                       v

FI BACKEND HOST

fi-receiver   custody/receipts   fi-ingest-worker   PostgreSQL   future classifier
      \             |                  |                |            /
       +------------+------------------+----------------+-----------+
                                |
                                v
                         fi-telemetry
                                |
                                v

TELEMETRY BACKEND

fi-telemetry-receiver
        |
        v
durable telemetry custody
        |
        v
fi-telemetry-recorder
        |
        v
separate PostgreSQL telemetry database
```

The implementation may reuse common FI transport/custody packages where their
semantics fit. It must not collapse telemetry authority into the ordinary FI
historical record path merely because reusable transport machinery exists.

## Existing operation resource journal

FI already has a Windows process-resource journal in
`go/internal/windows/resourcejournal`.

Its current record families include:

```text
ExecutableStart
ResourceSample
ResourceSummary
```

Its operation-correlated observations include CPU, working/private memory,
peaks, process I/O, elapsed time, executable identity, operation identity, and
scope identity.

This mechanism remains useful and is not replaced merely because continuous
telemetry is added.

The semantic split is:

```text
resourcejournal
    resource cost associated with one bounded FI operation

fi-telemetry
    continuous operational state of FI and supporting infrastructure
```

Existing resource-journal data should eventually be represented in the central
telemetry plane while preserving its operation identity and semantics.

## Source-host measurements

The source telemetry service should collect only measurements needed to explain
FI behavior and source impact.

### Host

At minimum:

```text
host identity
sample timestamp
CPU utilization
logical CPU count
available memory
used/committed memory
memory load
uptime/boot identity where useful
```

### Volumes

For relevant governed and FI-owned volumes:

```text
volume identity
capacity
free bytes
read bytes
write bytes
read operations
write operations
read latency
write latency
queue depth
```

### Network

At bounded interface scope:

```text
interface identity
link state
link speed/capacity
RX bytes
TX bytes
RX packets
TX packets
errors
drops
```

This is operational measurement, not packet capture, flow collection, or a SIEM
function.

## FI process telemetry

Telemetry tracks relevant FI process instances, including currently expected
components such as:

```text
FICollector
FIUSNReader
FIObjReader
FISender
fi-receiver
fi-ingest-worker
```

Future inventory may include:

```text
FITelemetry
FITelemetryReader
FIClassifier
FIContentReader
FIClassificationRelay
projection/query workers
```

Useful process measurements include:

```text
CPU
working set
private memory
read bytes/operations
write bytes/operations
other I/O where meaningful
thread count
handle/file-descriptor count
process start time
service state where applicable
```

## Process-instance identity

PID is not process identity.

A process instance is associated with a stable observation identity using facts
such as:

```text
HostID
ComponentKind
ServiceName
PID
ProcessStartTime
ExecutablePath
ExecutableSHA256
ExecutableVersion
ServiceIdentity
FirstObservedAt
LastObservedAt
```

PID reuse therefore does not merge two different process instances.

## Executable integrity observation

Telemetry physically reads and SHA-256 hashes observed FI executables.

Expected behavior:

```text
telemetry startup
    physically read/hash discovered FI executables

new FI process discovered
    physically read/hash immediately

periodically
    physically re-read and rehash
```

The engineering starting point previously discussed for periodic rehash was
approximately 15 minutes. That interval is not yet a frozen production default.

File timestamp or metadata equality is not a substitute for physical hashing.

## Configuration integrity observation

Configuration identity is a first-class telemetry fact.

Telemetry observes configuration; it does not control configuration.

A configuration observation must be capable of preserving:

```text
host_id
component identity
observed_at
configuration_version
configuration_path
configuration_sha256
software/deployment version
parse_status
effective_configuration_identity
```

Two separate facts must remain distinguishable:

```text
configuration_sha256
    exact bytes of the configuration artifact FI loaded

effective_configuration_identity
    canonical identity of the successfully parsed effective settings
```

This allows a textual configuration change that produces the same effective
settings to remain distinguishable from an actual effective configuration
change.

A later query may derive that the configuration changed by comparing consecutive
observations. Telemetry does not rewrite the earlier observation.

## Backend host telemetry

Backend telemetry includes the same host, storage, network, and process classes
used on source systems where applicable.

The generic telemetry model must remain portable across the currently accepted
Linux engineering runtime and the proposed future FreeBSD backend direction.

FreeBSD/ZFS-specific observations may later add typed fields for useful pool,
device, capacity, and ARC behavior without making the generic host/volume model
ZFS-dependent.

## FI application-level backend telemetry

Operating-system counters alone are insufficient. FI must report its own
operational state.

### Receiver

Useful measurements include:

```text
accepted generations
rejected generations
receiver transaction rate
receiver transaction latency
bytes received
records received
active receiver work
receiver failures
```

### Durable custody / receipts

Useful measurements include:

```text
durable generation count
durable bytes
receipt creation rate
oldest unprocessed generation age
custody failures
```

### Ingest worker

Useful measurements include:

```text
READY backlog
oldest READY age
generations ingested
records ingested
records per second
ingest transaction duration
Accepted
AlreadyAccepted
Rejected
Failed
retry state
PostgreSQL reconnect/backoff state
```

### Reconciliation / repair

Telemetry observes, but does not own, authoritative repair behavior.

Useful state includes:

```text
current repair cadence
last repair start
last repair completion
pending authority
conflicts detected
repair reset events
last clean authoritative sweep
```

The accepted Phase 3 adaptive repair progression remains observable:

```text
1-hour validation
    -> six clean receipt-set sweeps
    -> 12-hour intermediate
    -> 24-hour steady

problem detected
    -> return to 1-hour validation
```

## PostgreSQL telemetry

Useful PostgreSQL operational observations include:

```text
connection utilization
transaction rate
transaction latency
commits
rollbacks
database size
database growth
WAL generation
checkpoints
locks
waits
deadlocks
database errors
FI ingest transaction timing
```

If PostgreSQL statistics require SQL access, use a separate minimum-rights
read-only monitoring identity. That identity has no write authority to either
the FI System of Record or telemetry database.

## Telemetry custody and transport

Telemetry has its own bounded private source custody and downstream custody
semantics.

The design reuses FI engineering principles:

```text
authenticated transport
encrypted transport
bounded batches
durable source custody
durable receiver custody
acknowledgement only after custody
retry safety
duplicate safety
exact identity/hash binding
oldest-first recovery
bounded local retention
explicit continuity gaps
```

Sampling frequency and transmission frequency are separate.

Engineering starting points discussed before implementation were approximately:

```text
sample_every       5s
transmit_every     15s
executable_rehash  15m
```

These are characterization values, not frozen production defaults.

## Telemetry continuity

A telemetry backend outage must not stop FI.

```text
telemetry receiver unavailable
        |
        v
FI continues normal work
        |
        v
telemetry remains in bounded private local custody
        |
        v
receiver restored
        |
        v
oldest telemetry drains first
```

If telemetry cannot retain expected measurements, FI records an explicit
`TelemetryContinuityGap` rather than inventing coverage.

A gap should be capable of preserving:

```text
host/component identity
gap start
gap end
reason
samples lost if known
bytes discarded if known
spool condition
```

Reason vocabulary is part of implementation contract work and must be bounded,
versioned, and validated.

## Backend retention objective

Backend telemetry is not infinite historical authority.

It is retained long enough to support post-deployment operational review,
troubleshooting, sizing, upgrade comparison, and workload characterization.

The design objective is:

```text
minimum useful review horizon    30 days
normal planning horizon          60 days
preferred review horizon         90 days
```

This does not freeze one production retention setting yet. Exact defaults,
rollup/downsampling behavior, and storage consumption require characterization.

Normal policy expiration of previously accepted telemetry is not a continuity
gap. A continuity gap means expected telemetry was never successfully preserved.

## Telemetry database boundary

Telemetry uses a **separate PostgreSQL database**, not merely a schema inside the
FI System-of-Record database.

Mandatory authority rules:

```text
FI System-of-Record PostgreSQL database
    separate authority

FI telemetry PostgreSQL database
    separate database
    separate credentials
    no FI System-of-Record write access
```

The rule is symmetrical:

```text
telemetry database/runtime identities
    cannot mutate FI System of Record

FI System-of-Record runtime identities
    cannot mutate telemetry
```

This contract freezes database separation. It does not require a separate
PostgreSQL server/VM/host; physical instance placement remains a deployment
decision unless a later security or availability contract makes it stricter.

Correlation later occurs through deliberately shared identifiers, timestamps,
operation identity, software identity, and configuration identity rather than
shared write authority.

## Telemetry backend authority

The intended path is:

```text
fi-telemetry
        |
        v
fi-telemetry-receiver
        |
        v
durable telemetry custody
        |
        v
fi-telemetry-recorder
        |
        v
telemetry PostgreSQL database
```

Authority:

```text
fi-telemetry
    NO SQL write authority

fi-telemetry-reader
    NO SQL authority

fi-telemetry-receiver
    NO SQL authority

fi-telemetry-recorder
    minimum required telemetry-database write authority
```

Compromise of the telemetry database or recorder must not grant source-server
administration, Domain Admin, governed-source write authority, or FI
System-of-Record mutation authority.

## Relationship to classification

Once Phase 4 classification exists, telemetry can add typed operational
measurements such as:

```text
classification queue depth
active classifications
classification rate
classification duration
bytes inspected
content-read requests
content-read bytes
archive/container recursion activity
classifier failures
throttling state
classifier process CPU/RAM/I/O
```

The boundary remains:

```text
ClassificationResult
    -> FI System of Record

classifier CPU / queue / throughput
    -> FI telemetry
```

## Historical performance tooling

Permanent telemetry is intended to replace the need for temporary external live
monitoring during normal FI operation.

It does not delete or invalidate historical reproducibility artifacts such as:

```text
fi.exe -perf-root
tools/gate1/
100K acceptance reports
250K characterization reports
historical performance charts
historical validation scripts
```

Where an old CSV/performance sampler remains available, one controlled overlap
may compare the permanent telemetry stream to the existing measurement method.
If the old sampler is unavailable, direct Windows/OS performance counters can be
used for parity characterization.

## Operational priority

The existing FI priority remains:

```text
normal server workload
        >
FI background completion speed
```

Telemetry itself must therefore remain bounded, low-overhead, failure-isolated,
and non-disruptive.

## Not frozen by this contract

The following require implementation and representative characterization before
they become production constants:

```text
final sampling cadence
final transmission cadence
final telemetry retention default
rollup/downsampling strategy
CPU/RAM/disk thresholds
exact privileged telemetry-reader rights/API
final PostgreSQL table shapes
final ZFS-specific counters
```

The architecture, authority boundaries, failure isolation, source/backend scope,
separate telemetry database, configuration/executable integrity observations,
and explicit continuity behavior are deliberate Phase 4 design decisions.
