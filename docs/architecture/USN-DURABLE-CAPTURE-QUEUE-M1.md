# USN durable capture queue — M1 foundation (2026-10-20)

Status: **implemented foundation, NOT wired to Windows service, NOT deployable**.

This note describes the new source files under `go/internal/usncapture` and the
inactive adapter `go/cmd/fi/usn_capture_windows.go`. No installed configuration,
checkpoint, Windows service, installer, sender, receiver, or existing FI spool
has been changed by M1. This is deliberately a reviewable foundation; it is NOT
an assertion that FI can now withstand full-volume USN rollover.

## Problem shown by the 2026-10-19 10M-file campaign

A volume-wide USN batch was read in seconds, but its re-observation took
roughly 14–18 minutes while NTFS continued appending to the 4 GiB journal.
The last observed durable FI checkpoint was 2,391,823,656; the volume's FirstUSN
had advanced to 3,221,225,472, making `CheckpointAgedOut` unavoidable for the
existing synchronous reader. Transport was independently unavailable because
of expired CRL material, but transport must not govern local journal capture.

## Required eventual pipeline

1. Capture: read sequential F: journal batches, validate journal/volume identity
   and continuity, and derive a distinct File-ID/Parent-ID work index. Do not
   deduplicate historical USN events.
2. Publish: write the complete source batch plus work index into a durable,
   checksummed, immutable capture segment. Advance **capture.json** only after
   file sync and write-through segment publication. Stop on cache exhaustion;
   never silently jump ahead to the current journal head.
3. Correlate: asynchronously resolve historical governed-root membership,
   preserving both unresolved and out-of-scope-suspected records until ancestry,
   moves, hard links, and File-ID sequence reuse are accounted for. The recorded
   file name and a *current* parent are not sufficient historical proof.
4. Re-observe: deduplicate heavyweight NTFS reads per object **within a
   processing batch**, preserving source records, and use the existing
   FICollector/FIObjReader rules for metadata, hashes, streams, DACL/SACL,
   reparse details and fallback. Log unavailable/deleted objects explicitly.
5. Spool: durably finalize/verify FI batch manifests and update any supporting
   identity state. Only then record an attributable spool publication receipt,
   advance the independent **processed.json**, and eventually reclaim captured
   source segments. A receiver/network/CRL outage must not block capture.

## M1 implemented interface

- `usncapture.Initialize(path, anchor)`: exclusive, explicit initialization at
  a *verified* original checkpoint/baseline; never reset to bypass a gap.
- `usncapture.Open(path, maxPendingBytes)`: verifies all remaining segments and
  cursor agreement, recovers a committed segment if crash occurred before
  capture cursor publication, rejects lost/corrupt/overlapping source history.
- `Store.Append(batch)`: full volume-wide `records.USNReadBatch`, SHA-256,
  distinct work index, durable file + independent capture cursor.
- `Store.Next()`: oldest unprocessed full source batch, independent of whether
  Windows has already retired the original journal range.
- `Store.CommitProcessed(segment, publishedProof)`: accepts only nonempty
  caller-provided verified FI publication reference and advances processing
  cursor after recording a durable receipt. The caller **must independently
  verify** FI spool custody. M1 does not itself validate the named spool proof.
- `Store.ReclaimAcknowledged()`: explicitly deletes only segments with matching
  on-disk receipts and a processing cursor beyond them; receipts are retained.
- `DistinctWork(batch)`: all distinct File IDs, unique observed parent IDs and
  all triggering USNs; scope defaults to `Unresolved`.
- `captureUSNOnce`: Windows-only capture adapter with source continuity checks;
  NOT registered as a collector service worker or operator command yet.

`capture.json` and `processed.json` are distinct from the existing
`root-...-usn.json`. Existing checkpoint semantics are unchanged.

Queue root needs installer-managed owner-only ACLs and a separate capacity
budget; the 64 GiB package default is an upper limit, **not** a promised
retention window and not a request to create files or folders in the live lab.
If the queue is exhausted, FI must fail closed with an explicit alert rather
than advancing its source checkpoint. Source segment retention after completion
is deliberate until a separately authorized purge policy is implemented.

## Remaining work BEFORE activation

- Complete a historical ancestry/scope correlation engine with durable
  identity index, hard link coverage, rename/move/deletion handling and
  unresolved-work semantics, tested with existing FI lifecycle fixtures.
- Connect queue `Next()` to the existing bounded re-observation stage and
  existing verified FI spool publisher; do not synthesize `USNRead` operations
  for replayed cache records. Define a verified spool publication receipt API,
  not an arbitrary proof string.
- Migrate the existing per-root *processed* checkpoint into the new queue only
  after checkpoint/baseline verification. Reconcile queue capture vs processed
  state on every startup and after interruption, without deleting custody.
- Coordinate with existing configured root lock and reconciliation operations;
  capture must continue during slow baseline where safe, and no second
  checkpoint owner is allowed. Per-volume journal sharing across several
  governed roots needs explicit efficiency/ordering design.
- Introduce reviewed operator configuration (queue location, size, capture
  cadence, worker budgets), installer support and matched binary version
  checks. The existing 5-minute sender generation rollover is unrelated.
- Define custody durability for Windows directory creation, rename and ACL
  inheritance on supported NTFS volumes. Extend fault injection to partial
  write, Rename, Sync, metadata corruption, queue saturation and power loss.
- Full native Go 1.27.2 Windows test suite and large-scale acceptance tests:
  1M/10M objects; 4 GiB journal wrap; source changes during re-observation;
  10-hour disconnected receiver; replay after kill/power outage; 8 MiB and
  64 MiB readers; cross-source isolation; sender and CRL failure.

## M1 verification performed in isolated sandbox

The eight initial queue tests plus distinct-work and reclaim tests pass under
Go 1.23.2 by temporarily adapting a sandbox copy of the repository's `go`
version directive, then restoring the original `go 1.27.2`. The new queue
also cross-compiles for Windows amd64. The full FI suite and the Windows
adapter's native tests have **not** been run in this sandbox: the actual
repository requires Go 1.27.2, native Windows APIs, and external modules.
No user repository commit, GitHub push, install, or host mutation occurred.

## M1 acceptance principle

M1 being present in a checkout must have **zero change** in active FI collector
behavior. Only after the correlation/publisher lanes, migration gates and
native Windows acceptance exist should this feature be enabled in a lab.
