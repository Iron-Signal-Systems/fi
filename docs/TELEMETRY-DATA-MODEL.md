# FI Telemetry Data Model

Status: **PLANNED DESIGN CONTRACT — NOT YET IMPLEMENTED**

This document defines the conceptual relational model for the Phase 4 Operational
Telemetry Foundation. Exact table/column names may change during schema review,
but the identities and semantic separations in this document are intentional.

## Relational rule

Telemetry follows the same preference for typed relational state used by the FI
System of Record.

Do not implement the core telemetry database as an opaque arbitrary-metric JSON
store merely because telemetry contains many measurements.

Platform-specific details may use typed extension tables where necessary.

## Database boundary

Telemetry is stored in a **separate PostgreSQL database** with separate runtime
credentials from the FI System of Record.

## Core identity families

### Host

Conceptual object:

```text
telemetry.host
```

Stable host identity should support source and backend hosts without depending
solely on mutable display names.

Useful attributes may include:

```text
host_id
hostname/platform display facts
operating-system family
first/last observation metadata
```

### Volume / storage target

Conceptual objects:

```text
telemetry.volume
telemetry.volume_sample
```

Identity must distinguish volumes/devices/pools according to platform while
preserving a portable higher-level storage identity.

### Network interface

Conceptual objects:

```text
telemetry.network_interface
telemetry.network_sample
```

Interface identity must survive ordinary sampling without treating a friendly
name alone as immutable identity.

### Process instance

Conceptual objects:

```text
telemetry.process_instance
telemetry.process_sample
```

PID alone is never process identity.

Process instance identity uses a combination of host, component/service identity,
PID, start time, executable identity, and observation lifecycle.

### Executable observation

Conceptual object:

```text
telemetry.executable_observation
```

Preserves physical SHA-256 observations of the executable bytes associated with
an FI component/process instance.

Repeated rehashing produces additional observations; it does not mutate an
older observation.

### Configuration observation

Conceptual object:

```text
telemetry.configuration_observation
```

At minimum it must be able to represent:

```text
host_id
component/process association
observed_at
configuration_version
configuration_path
configuration_sha256
software/deployment version
parse_status
effective_configuration_identity
```

Exact artifact hash and effective parsed configuration identity are separate
facts.

## Sample families

### Host sample

Conceptual object:

```text
telemetry.host_sample
```

Candidate typed measurements include CPU, available/used/committed memory,
memory load, and uptime/boot association.

### Volume sample

Conceptual object:

```text
telemetry.volume_sample
```

Candidate measurements include capacity/free bytes, read/write bytes and
operations, read/write latency, and queue depth.

### Network sample

Conceptual object:

```text
telemetry.network_sample
```

Candidate measurements include link state/capacity, RX/TX bytes and packets,
errors, and drops.

### Process sample

Conceptual object:

```text
telemetry.process_sample
```

Candidate measurements include CPU, working/private memory, I/O bytes/operations,
thread count, handle/file-descriptor count, and service state where meaningful.

## FI component samples

Generic OS process samples do not replace FI application-level telemetry.

Conceptual objects may include:

```text
telemetry.fi_component
telemetry.fi_component_sample
telemetry.receiver_sample
telemetry.custody_sample
telemetry.ingest_sample
telemetry.reconciliation_sample
telemetry.postgresql_sample
```

Use typed tables when a metric has stable FI semantics.

Examples:

```text
READY backlog
oldest READY age
receiver accepted/rejected generations
receipt creation rate
ingest records/second
generation ingest total duration
generation load duration
relational ingest duration
relational transaction duration
reconnect/backoff state
repair cadence
last clean repair sweep
PostgreSQL WAL/checkpoint/lock/wait state
```

Do not reduce these to unvalidated arbitrary `name/value` pairs when the meaning
is part of the product contract.

## Ingest timing semantics

`telemetry.ingest_sample` must be capable of representing the end-to-end FI
generation-ingest operation separately from narrower relational/database spans.

Conceptually useful fields include:

```text
source identity
generation identity
observed/attempt time

generation_source_bytes
generation_encoded_bytes
batch_count
record_count

generation_ingest_total_duration
generation_load_duration
relational_ingest_duration
relational_transaction_duration

source_prepare_duration
source_record_sql_duration
identity_resolution_duration
projection_duration
coverage_validation_duration
journal_duration
commit_duration
rollback_duration

sql_operations_total
sql_operations_by_family

outcome
failure_stage
```

The top-level semantic distinction is mandatory:

```text
generation_ingest_total_duration
    complete FI attempt from generation load/verification through the returned
    authoritative ingest outcome

relational_transaction_duration
    only the PostgreSQL transaction scope
```

A historical end-to-end ingest measurement must therefore never be interpreted
as pure PostgreSQL execution time without a separately measured transaction
span.

Internal timing spans may be nested. Before implementation, each duration field
must define whether it is inclusive or exclusive so subspans are not assumed to
sum to a parent duration unless that relationship is explicitly guaranteed.

Resource use remains a separate semantic family. CPU, RAM, process I/O, and
other operation-correlated resource measurements belong in
`telemetry.operation_resource_sample` / `telemetry.operation_resource_summary`
and may be correlated to the ingest attempt through stable operation/generation
identity.

## Operation resource history

Existing Windows `resourcejournal` records should map into central telemetry
without losing operation identity.

Conceptual objects:

```text
telemetry.operation_resource_sample
telemetry.operation_resource_summary
```

Relationship:

```text
operation identity
      |
      +---- many operation_resource_sample
      |
      +---- terminal/summary observation(s)
```

Resource telemetry remains operational history; it does not become governed-file
source history.

## Telemetry custody lineage

The telemetry plane needs durable custody and ingest lineage separate from the FI
historical generation tables.

Conceptual objects may include:

```text
telemetry.recorded_generation
telemetry.source_batch
telemetry.source_record
telemetry.ingest_journal
```

Exact names are not frozen, but the semantics must include:

```text
source identity
telemetry generation identity
record/batch totals
hash/size identity
custody/receipt identity
ingest attempt history
duplicate-safe acceptance
conflict rejection
```

## Continuity gaps

Conceptual object:

```text
telemetry.continuity_gap
```

A gap records telemetry that FI expected to observe/preserve but does not possess.

Candidate fields include:

```text
host/component identity
gap start
gap end
reason
samples lost if known
bytes discarded if known
spool/retention condition
```

Normal backend retention expiration of successfully preserved telemetry is not a
continuity gap.

## Retention metadata

The telemetry database is operational, not infinite historical authority.

Retention policy and any future rollup/downsampling must preserve enough metadata
to distinguish:

```text
raw sample retained
sample summarized by policy
sample expired by policy
sample never captured/preserved
```

The last condition is continuity loss; the others are retention lifecycle.

## 30/60/90-day review objective

The operational design supports:

```text
30-day minimum useful review horizon
60-day normal planning horizon
90-day preferred review horizon
```

Exact production retention and rollup defaults remain subject to storage and
workload characterization.

## Cross-plane correlation

The telemetry and FI historical databases may later be correlated through stable
references such as:

```text
host identity
source identity
component/process identity
operation identity
timestamps
software/executable identity
configuration identity
```

Correlation does not grant either database write authority over the other.
