# FI Telemetry Trust Boundary

Status: **PLANNED DESIGN CONTRACT — NOT YET IMPLEMENTED**

This document defines the intended trust and authority boundaries for the Phase 4
Operational Telemetry Foundation.

## Security objective

Telemetry must be able to observe FI and supporting infrastructure without
becoming an administrative path into governed Windows sources, the FI System of
Record, or backend operating systems.

The controlling rule is:

```text
observability authority
    !=
administrative authority
```

## Components

Planned logical components are:

```text
source/backend fi-telemetry service
optional Windows fi-telemetry-reader helper
fi-telemetry-receiver
telemetry durable custody
fi-telemetry-recorder
separate telemetry PostgreSQL database
optional read-only PostgreSQL statistics identity
```

Names are architectural identifiers and do not claim those executables/services
already exist.

## `fi-telemetry` service

Normal telemetry collection should run non-administratively.

It may own:

```text
sampling and scheduling
FI process discovery
host/volume/network observations available to its identity
executable physical hashing where readable
configuration observations where readable
FI application metrics exposed through bounded interfaces
local telemetry spool/custody
telemetry transport client state
telemetry self-health
```

It must not receive broad local Administrator rights merely for implementation
convenience.

## Optional privileged Windows reader

A privileged telemetry helper is permitted only for specific Windows
measurements that cannot be safely obtained under the normal telemetry service
identity.

Before adding a privileged operation, implementation must establish:

1. the operational question being answered;
2. why the non-admin telemetry identity cannot obtain the fact;
3. the minimum Windows right/API needed;
4. the bounded request and response shape;
5. abuse and malformed-request behavior; and
6. how compromise is prevented from becoming a general administrative API.

Good conceptual operations are narrow:

```text
QueryHostCounters
QueryVolumeCounters
QueryProtectedProcessCounters
```

Interfaces such as the following are prohibited:

```text
OpenProcess
ReadMemory
ReadFile
RunCommand
Execute
ArbitraryQuery
```

IPC must be local, authenticated, fixed/versioned, and independently authorize
the expected caller service identity. Remote invocation is not part of the
boundary.

## Receiver boundary

`fi-telemetry-receiver` authenticates and durably accepts telemetry batches.

It must not have PostgreSQL write authority.

Receiver compromise must not expose:

```text
FI System-of-Record database credentials
source-server administrative credentials
Domain Admin credentials
telemetry recorder database credentials
```

Durable custody is established before an acknowledgement permits source-side
retirement of the acknowledged telemetry unit.

## Recorder boundary

`fi-telemetry-recorder` is the only normal telemetry component with write
authority to the telemetry PostgreSQL database.

Its database identity receives only the permissions required to append/materialize
accepted telemetry according to the telemetry schema.

It has no FI System-of-Record write authority.

## PostgreSQL separation

Telemetry uses a separate PostgreSQL database, not only a separate schema.

```text
FI System of Record database
    historical FI authority

FI telemetry database
    operational telemetry authority
```

Separate database credentials are mandatory.

Telemetry runtime/DB identities cannot mutate the FI System of Record.
FI System-of-Record runtime identities cannot mutate telemetry.

A later query/projection layer may correlate data by stable identifiers and time.
Correlation does not create cross-database write authority.

## PostgreSQL statistics observation

Backend telemetry may require PostgreSQL operational statistics.

If SQL is necessary, create a dedicated minimum-rights **read-only** monitoring
identity. It is distinct from the telemetry recorder identity.

The monitoring identity must not:

```text
INSERT
UPDATE
DELETE
TRUNCATE
ALTER
CREATE runtime application objects
write FI System-of-Record state
write telemetry state
```

## Source credentials

Telemetry must not store reusable domain administrative credentials.

Where a Windows service identity is required, use a dedicated service identity
with only the rights required for the telemetry component.

Backend compromise must not grant the backend the ability to invoke a privileged
Windows telemetry helper remotely.

## Executable and configuration hashing

Physical executable/configuration hashing is observation, not authorization.

A hash establishes:

```text
these bytes were observed at this time
```

It does not by itself establish:

```text
these bytes were approved
these bytes were signed by an approved publisher
this configuration was administratively authorized
```

Those are separate policy/deployment questions.

## Failure isolation

Failure or compromise of the telemetry plane must not be allowed to stop or
rewrite FI historical state merely to make telemetry appear healthy.

Telemetry is allowed to report:

```text
Partial
Unavailable
ContinuityGap
```

It is not allowed to fabricate coverage.

## Required privilege-boundary validation

Before Gate 4 can rely on telemetry operationally, validate at minimum:

```text
service identities
local group membership
assigned privileges
filesystem ACLs
named-pipe/IPC authorization if helper exists
remote rejection
protocol bounds
malformed request handling
timeouts
service restart behavior
backend outage behavior
telemetry spool exhaustion behavior
telemetry database authority
FI System-of-Record non-authority
```
