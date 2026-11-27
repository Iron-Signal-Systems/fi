# FI backend telemetry rebuild — 2026-11-27

Status: DEVELOPMENT, not installed/accepted on the C220.

## Why rebuilt
The 2026-10-29/30 telemetry source processes were host-local prototypes
and were NOT committed to the FI development branch before the physical
FreeBSD server was repurposed. The C220 retains fi_telemetry historical
entries (54,986) and delivery receipts (377) through October 30. The
November 27 real C1 runs lacked telemetry coverage. Do not claim those
runs were resource-instrumented.

## Reconstructed plane
- FreeBSD Go source collector (15 seconds) runs unprivileged on C220 host.
- Optional second unprivileged fi-sor source collects its jail processes
  and PostgreSQL statistics through a dedicated read-only monitor identity.
  If a metric is blocked, store status NOT_OBSERVED, never zero.
- Fixed native FreeBSD command probes: CPU, VM/swap, per-pool ZFS
  capacity/read/write/latency, ARC, process and NIC state. Bounded commands
  (3s/256KiB each), no shell, no third-party agent.
- One durable JSON file per observation, private group spool with
  content SHA-256 identity, fsync, atomic rename and directory fsync,
  capped at 20,000 entries; does not delete uncommitted samples.
- Independent uploader in fi-sor every 300 seconds, writes ONLY
  fi_telemetry.telemetry_v2 and delivery receipts in a transaction.
  Retires samples ONLY after a committed receipt. Oldest-first,
  duplicate-safe insert; stops on tamper/invalid local custody.
- Explicit operator-provided historical continuity gap event; never
  invent count of unobserved samples or fill with zeros.
- No SQL write identity or credentials in the collector. Upload role
  cannot write canonical fi; monitor can only read pg_stat views.
- No logging of SQL DSNs or secrets. PG connection values are read from
  a root-only config and passed via environment, not argv.
- Preserve legacy telemetry.entry and telemetry.delivery_receipt intact.
  New versioned schema telemetry_v2 is additive because the lost v04
  original writer/schema source cannot be reproduced exactly.

## Existing database installation
Run the audited SQL in tools/deployment/freebsd/runtime.d/
fi-telemetry-v2-schema.sql ONLY against database fi_telemetry,
never fi. The file refuses the wrong database. A PostgreSQL DBA must
grant separate minimum rights to fi_telemetry_recorder on ONLY the v2
schema and tables. Host/jail file access requires matched group IDs and
a private ZFS spool mounted into fi-sor; collector and recorder must
remain separate UIDs. No default privileged users or mounts are made.

## Acceptance gates
1. Check exact GitHub SHA, compile FreeBSD, pass custody tests.
2. Install both disabled FreeBSD rc services and private spool; ensure
   collector and recorder identities exist and source file access works.
3. Verify source 15s cadence, durable files, uploader 5m cadence.
4. Verify new telemetry_v2.entry and delivery_receipt rows have
   fresh timestamps, source identities, exact JSON payloads and no gaps.
5. Verify PostgreSQL monitoring read-only, uploader denied INSERT
   into fi.source_record, collector denied INSERT into telemetry_v2.
6. Verify restart/SQL outage/recovery, duplicate upload, corruption
   refusal, spool-full behavior, and low overhead.
7. Capture C1 lifecycle proof events and correlate run identity to
   real ingest. No claim of fully telemetry-accepted performance until
   this lifecycle correlation is proven.
8. Only then enable continuous C1 sender intake with fresh signed
   generation and independent B / canonical Accepted proof.

The old 2026-10-29/30 telemetry data is intentionally left untouched.
