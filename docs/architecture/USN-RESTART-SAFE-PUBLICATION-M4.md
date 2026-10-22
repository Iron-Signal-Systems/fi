# M4: USN spool publication crash guard (inactive)

## Problem

FI's spool writer may publish one USN capture segment as multiple data/manifest
pairs. A crash can occur after one or all pairs are published and before the
independent `processed.json` capture-processing cursor advances. Re-running
NTFS re-observation and publishing again can generate duplicate logical
observations. In addition, FISender can atomically freeze the active spool
and send or retire the original manifests between worker operations.

## Implemented safety boundary

1. The worker atomically publishes a source-, root- and correlation-bound
   **publication intent** in the durable capture queue before emitting its
   first FI spool record.
2. Each M4 USN object observation carries the exact source batch SHA-256,
   alongside the source-bound `USNReadBoundary` record. The same source range
   cannot be reconstructed merely from coincidental File-IDs or timestamps.
3. On restart, an intent blocks a second publisher. The recovery path acquires
   FI's existing machine-wide spool publication boundary and checks the active
   spool for manifests whose **every** record names the exact source batch.
4. The existing FI manifest/data verification and strict source-record coverage
   checks must succeed across the complete manifest set. The Windows adapter
   rebuilds its observed-SID set from the verified NTFS records and merges that
   state before committing `processed.json`, under the same boundary lock.
5. Empty, partial, corrupt, mixed-source or relocated publications are never
   treated as proof. A matching intent persists and FI reports
   `ErrPublicationPending`, leaving the processing cursor unchanged. The
   operator must investigate; a blind rerun is forbidden.

## Limits / release blockers

This patch **does not** provide full end-to-end idempotent restart recovery.
A source's manifests may have left the active spool in a sender generation, may
be in transport custody, or may have been acknowledged and retired. Finding no
active manifests does **not** mean nothing was published. An integrated
source-bound generation/receiver acknowledgement ledger or a deterministic
transactional outbox is still required to resolve that state automatically.

The queue remains inactive in the FI service. Native Windows tests, replay
across raw/sealed/transported generation states, crash-injection at every
publication boundary, authoritative historical-scope correlation and installer
migration are required before activation. This change does not modify any
runtime service registration or the existing Windows USN checkpoint.
