# USN captured-batch processing and verified FI spool bridge — M3 (2026-10-20)

**Status: development adapter only. NOT ACTIVE. NOT DEPLOYABLE.**

M1 established durable USN capture and distinct File-ID work; M2 added a
non-authoritative ancestry-hint cache. M3 adds a separate Windows consumer path
and a manifest-bound processing-commit test contract. No collector service
worker, Windows installer, on-disk migration, backend schema, sender, receiver,
or existing live USN checkpoint is changed or activated by M3.

## Processing path

1. `Store.Next()` verifies the immutable, full volume-wide captured source batch.
2. `Store.Correlate()` builds and checks the M2 derived File-ID correlation cache
   for the *caller-verified* governed-root identity.
3. `usn.ReobserveCapturedJournaledStaged()` invokes FI's existing bounded
   `NTFS.CollectFileReference`/`FIObjReader` fallback and containment checks on
   the **cached batch**. It does not re-read the NTFS journal or manufacture a
   new `USNRead` lifecycle operation. Current-state metadata is never claimed
   as exact historical state at the USN event time.
4. The inactive adapter writes the same `USNReadBoundary` and
   `USNObjectObservation` FI spool record kinds, with the original source
   changes, a capture-batch hash and correlation hash on the boundary. Every
   distinct source File-ID is explicitly represented, even unavailable or
   outside the *current* governed root. All M2 scope hints remain unresolved
   until historical membership is proven; neither a current path nor an M2
   ancestry hint is an authoritative exclusion proof.
5. The manifest verifier checks each actual FI batch manifest and data bytes,
   binds the boundary to the exact original batch/correlation, and requires
   exactly one object observation per captured File-ID carrying **every** source
   change. Missing/duplicate objects, missing statuses, and source mismatch
   fail closed. Source changes are not deduplicated.
6. Only after this verified FI spool publication and relevant SID-state update
   does `Store.CommitVerifiedSpool()` write a proof receipt and move
   `processed.json`. The original `capture.json` is unchanged. The receiver and
   CRL/network state are not involved in this local custody boundary.

## Explicit limits blocking production use

- **Idempotent publication on restart is incomplete.** After the FI spool has
  been published, a crash before the processing cursor advances may cause a
  replay that publishes a second equivalent generation with different batch
  IDs. M3 fails closed on proof loss; it does not claim exactly-once output.
  A replay-resolvable publication intent/receipt linking source segment to FI
  spool generations, including receiver rollover and retirement, is needed.
- The Windows adapter still inspects *all distinct IDs in a captured
  volume-wide source batch*, not just historically proven governed objects.
  This deliberately preserves unresolved source facts but is **not** the final
  efficient governed-root filter. A durable cross-batch ancestry, hard-link,
  rename/move/deletion and ID-sequence history index is required before safe
  scope-exclusion and reduced NTFS re-observation work.
- Capture, processing and baseline do not yet have the new per-root ownership,
  queue initialization and migration protocol. No service startup orchestration
  or installer gates have been implemented for these interfaces.
- The existing FI spool publisher and sender generation rollover must be
  serialized for proof validation plus cursor advancement. The inactive
  adapter acquires the existing spool publication boundary after writer close;
  if the sender rolls over first, proof verification fails closed. Restart
  recovery across this boundary still requires the prior item.
- Native Windows end-to-end acceptance and FreeBSD ingest compatibility must
  be proved before any pilot. In particular, the additional optional
  `USNReadBoundary` fields and explicit unresolved/outside-scope records need
  verified backend compatibility and projection semantics.
- Temporary staged NTFS observation cleanup after abnormal process termination
  and Windows power-loss durability of the two cursor files require testing.
- Queue capacity remains bounded and is independent of the 4 GiB NTFS journal.
  Reaching it is an alert/fail-closed condition, not permission to skip history.

## Verification

Local sandbox, with only the `go` directive temporarily lowered from 1.27.2
for the available Go 1.23.2 compiler (restored before patch creation):

- `go test -count=1 ./internal/usncapture ./internal/spool` — PASS.
- `go test -race -count=1 ./internal/usncapture ./internal/spool ./internal/records` — PASS.
- `go vet ./internal/usncapture ./internal/spool` — PASS.
- Full Windows compile and native tests are **not** claimed. Sandboxed Go
  module dependencies and Go 1.27.2 are unavailable here; run the full
  native Windows test suite on ADMINBOX with M1+M2+M3 applied.

No repository commit, push, deployment, or modification of the live FI lab.
