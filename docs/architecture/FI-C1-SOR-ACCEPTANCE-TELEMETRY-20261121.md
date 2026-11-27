# FI C1 acceptance telemetry — retain established backend cadence

**Date:** 2026-11-21. **Status:** Development acceptance telemetry contract,
pending C220 runtime discovery and wiring. Frozen ingest revision:
`f42ec639ffeccba31f2a2d4de82f20294c90cd40`.

## Established telemetry architecture — DO NOT replace

The separately developed FI backend telemetry system previously used:

- **15-second samples** for host/process/resource metrics;
- a **bounded, durable local JSONL spool** for delivery/retry;
- an **independent uploader every 300 seconds (5 minutes)**, with
  oldest-first recovery and duplicate-safe delivery;
- the distinct PostgreSQL database **`fi_telemetry`** and its
  **`telemetry.entry`** and **`telemetry.delivery_receipt`** records.

The telemetry architecture is:
`fi-telemetry-receiver -> durable telemetry custody ->
fi-telemetry-recorder -> fi_telemetry`.
The existing 15-second sampling and five-minute upload are **independent**;
do not poll every second or insert every sample directly into the canonical
`fi` System of Record. Interruption must be explicit telemetry-gap history,
never silently counted as zero usage.

The October 29 telemetry recorder/uploader demonstration occurred on an
earlier backend. C220 availability, file paths, runtime cadence and recorder
status **must be verified before claiming the telemetry pipeline is live**.

## Mandatory coverage for the complete populated-development-SoR acceptance

1. **Host/jails:** C220 CPU utilization and CPU time, available/free memory,
   swap pressure, process identity/start time, RSS/peak and CPU/I/O for FI
   ingest, PostgreSQL, receiver, telemetry recorder/uploader and verifier.
2. **Storage:** per-pool `fast`, `work`, `zroot` ZFS I/O rates, waits/latency,
   capacity, ARC and per-device I/O; record the device/pool basis. Do not
   misstate host aggregate or ZFS writes as PostgreSQL-only traffic.
3. **Network:** actual relevant interface RX/TX rates and errors; FI payload
   counters labeled separately from total host traffic.
4. **PostgreSQL (real populated SoR):** source/child rows, ingest journal,
   commits/checkpoints, WAL generated and buffer pressure, buffer cache,
   relation I/O, lock/wait state, autovacuum and backend process usage,
   database size. Collect only metrics available under approved identities;
   any unavailable counter is `NOT_OBSERVED`, not zero. No special
   PostgreSQL logging or 1-second polling to alter the benchmark.
5. **C1 workload telemetry:** exact signed generation identity, source revision,
   run/attempt ID, five family record counts/buffer peaks/handoff counts,
   shared SQL pool min/max/peak, single SourceParent writer COPY/commit,
   bounded USN queue/fence state, read/ingest rates, backpressure, error/gap
   and stage durations. These are emitted as **lifecycle events** on transition
   rather than relying on 15-second sample boundaries.
6. **Verifier and acceptance:** separate independent B start/end, per-group
   proofs, full-generation proof, original SoR record counts before/after,
   accepted-journal state, retained existing identities, publication/commit
   and rollback/retry results. No ACCEPTED metric until the actual canonical
   transaction commits and the Accepted journal is read back.

Attach **one run ID** to every sample/event and link to the C1 source commit,
the exact immutable signed generation and original receiver custody receipt.
Do not poll PostgreSQL every second simply to mimic earlier profiling runs.

## Acceptance evidence and delivery proof

A successful SoR acceptance must report both (1) signed relational/Accepted
correctness in the real SoR, and (2) telemetry completeness in the separate
`fi_telemetry` database. Verify delivery receipts and oldest/newest sample
times; ingestion must remain correct if telemetry upload is delayed.
Preserve previous high-frequency 8 GiB and full-clone temporary telemetry
archives as historical benchmark evidence, not a standing one-second service.

Before starting the acceptance, run
`go/cmd/fi-backlog-recover/diagnostics/fi_c1_sor_telemetry_discovery_c220.sh`
to determine whether the current C220 actually hosts the expected SoR jail
and telemetry service/DB. Read-only discovery does not start the jail, alter
credentials, create PostgreSQL schemas or write telemetry.
