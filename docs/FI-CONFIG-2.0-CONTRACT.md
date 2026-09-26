# FI Configuration 2.0 Contract — Phase 4 Planning

Status: **PLANNED DESIGN CONTRACT — PARSER SUPPORT NOT YET IMPLEMENTED**

The checked-in operational configuration example and parser currently implement
FI configuration version `1.1`.

This document defines the Phase 4 direction for a future `version_id: 2.0`.
It does **not** authorize changing `config/fi.conf.example` to 2.0 before parser,
validation, tests, and runtime consumers support the new contract.

## Purpose

Configuration version 2.0 is intended to introduce Phase 4 telemetry and later
classification settings without creating separate ad-hoc configuration systems.

The configuration remains explicit and fail-closed.

## Compatibility rule

Existing supported versions retain their defined behavior.

A 2.0 file must not be accepted by a 1.1-only parser.

A binary that declares 2.0 support must validate the complete required 2.0
contract before starting dependent services.

## Strict parsing rule

Preserve current behavior:

```text
unknown directive
    -> startup/configuration failure

duplicate directive
    -> startup/configuration failure

invalid value
    -> startup/configuration failure
```

Do not silently ignore a misspelled telemetry or classification directive.

## Telemetry settings

The following names are the current design direction and should be reviewed with
implementation before becoming frozen public configuration syntax:

```text
telemetry.enabled
telemetry.sample_every
telemetry.transmit_every
telemetry.process_discovery_every
telemetry.executable_rehash_every
telemetry.spool_max_bytes
telemetry.spool_max_age
telemetry.receiver.address
telemetry.receiver.name
telemetry.receiver.timeout
storage.telemetry_spool_dir
```

Configuration must keep sampling cadence separate from transmission cadence.

Engineering starting points previously discussed are approximately:

```text
sample_every       5s
transmit_every     15s
executable_rehash  15m
```

These are not frozen production defaults.

## Telemetry retention

Backend retention has a 30/60/90-day operational-review objective, but an exact
`telemetry.retention` setting/default is not frozen by this document.

Retention, rollup, and downsampling behavior require storage characterization
before they become runtime defaults.

## Classification settings

Configuration 2.0 is also the intended home for Phase 4 classification/deep
inspection controls.

The detailed classification contract is separate, but expected categories
include settings such as:

```text
classification.enabled
classification.max_file_bytes
classification.max_stream_bytes
classification.max_archive_depth
classification concurrency/throttle limits
classifier/policy version selection where appropriate
```

Exact directive names and defaults must be frozen only when the corresponding
classification contracts are ready.

## Configuration observation

Telemetry physically observes the configuration artifact used by FI.

The telemetry record should preserve:

```text
configuration path
configuration version
physical SHA-256
parse status
effective configuration identity
software/deployment version
observation time
component/host association
```

Telemetry does not modify the configuration.

## Effective configuration identity

The physical file hash and effective configuration identity are distinct:

```text
physical hash
    exact bytes loaded

effective configuration identity
    canonical successfully parsed settings
```

This permits later operational analysis to distinguish comments/formatting-only
changes from effective setting changes without rewriting history.

## Troubleshooting/override philosophy

Existing fail-closed troubleshooting override principles remain in force.

Phase 4 must not introduce a generic telemetry/classification override that can
silently bypass configuration authority or privilege boundaries.
