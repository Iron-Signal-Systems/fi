# M5E — Complete captured-range preflight before sender retirement

Status: **INACTIVE DEVELOPMENT CODE**. No FISender entry point, service activation,
checkpoint migration, or new receiver protocol is part of this delivery.

## Contract

- Require an explicit list of source-bound USN ranges from one capture Store.
- Read the frozen raw FI generation's original, verified spool manifests and
  count every source-bound `USNReadBoundary` record.
- Reject missing, duplicate, unaccounted, legacy-unattributed, or malformed
  boundary records, and reject duplicate manifest claims by candidates.
- Reverify each original source-manifest inventory, the complete frozen
  canonical content, signed-generation metadata, encoded payload and decoded
  canonical digest using M5D; write each handoff only after verification.
- Fail closed on a partial set or interrupted verification. Re-execution is
  idempotent for already recorded, identical M5D handoffs.
- Never advance the capture or processing cursor, delete raw data, or claim a
  receiver acknowledgement or source trust authorization.

## Why M5D changes

The M5D receipt's previous processing-cursor equality guard prevented a
multi-range frozen generation from recording a receipt for a later pending
segment. It now checks that the source segment is immutable, exists in the
local capture queue, and lies between the processing and capture cursors.
That is a source-custody validation, not an authorization to skip processing.

## Remaining blockers

1. FISender build, recovery, and raw deletion paths must all call a
   coordinated pre-retirement gate. The active services still do **not**.
2. A raw generation can contain source ranges from multiple governed-root
   stores. A sender-level coordinator must aggregate all stores and hold a
   cross-process lifetime lock; this API validates one Store's candidate set
   and conservatively rejects missing/extra USN boundaries.
3. Repeated canonical verification per candidate is correctness-first and
   requires a single-pass generation verification optimization before an
   operational, high-volume sender integration.
4. Persist a durable handoff/custody decision that can be recovered after raw
   deletion, sealing promotion, transport acknowledgement and retirement.
5. Complete full trust-chain/revocation checks and exactly-once receiver
   linkage before advancing the processing cursor from transported custody.
6. Governed-root historical ancestry, safe checkpoint migration and complete
   live Windows integration are still required for service activation.

The M5E zip is complete source files, not a Git patch. It replaces the M5D
`sealed_handoff.go` and adds the preflight API and tests.
