# FI receiver recorded-custody restart recovery — 2026-10-29

## Status

**Candidate implementation; FreeBSD runtime acceptance outstanding.**
Branch: `work/receiver-recorded-fast-recovery-20261029`, based on `work/ingest-copy-call-latency-20261028`.
Do not install on the production/test receiver until FreeBSD tests, a controlled restart,
and custody/acknowledgment verification pass. Existing durable state must not be cleared.

## Incident and observed root cause

During the Windows 10-million-object test, one sender transport generation contained
approximately 65.48 GiB canonical bytes but only 1.45 GiB encoded bytes. The receiver
rejected its admission offer because its configured canonical limit was 64 GiB.
Temporary lab receiver and ingest-worker limits were raised to 70 GiB.
The long-term sender generation-partitioning fix is a **separate** engineering task.

The receiver restart exposed another bottleneck: 5,918 historical FIGT custody
objects and 5,918 recorder receipts occupying about 6.2 GiB. The receiver did
not listen on TCP/8443 during its recovery pass, and consumed around one
logical core. The existing `RecoverGenerationStartup` loop called
`RecordDiscoveredCustodyDurably` for **all** discovered FIGT objects. That
function decompressed each payload and replayed every collector artifact before
an already-recorded receipt could be recognized. Matching total directory counts
alone do not prove identical object identities.

The old FreeBSD regression test checked `AlreadyRecorded` disposition but did
**not** prove that inner semantic replay was avoided.

## Recovery contract

1. Inspect the durable FIGT directory with existing exact-path, type, mode,
   structural, symlink and provisional-state safety checks.
2. Resolve source enrollment and honor disabled-source deferral before using
   either recorded or unrecorded paths.
3. Look up the deterministic, source/generation-bound immutable recorder receipt.
4. **Present receipt:** parse and validate bounded canonical receipt bytes; verify
   exact signed metadata, current batch-signing trust and source authorization,
   exact complete FIGT transfer SHA-256, encoded payload SHA-256, framing, length,
   immutable object identity, and all receipt-to-transfer binding fields. Do
   **not** decompress or replay JSONL/manifest semantics. Record disposition
   `ALREADY_RECORDED`.
5. **Absent receipt:** execute the existing full decompression, canonical SHA-256,
   artifact semantic validation and immutable recorder publication. Only this
   path may create a `NEW` recorded receipt.
6. **Present but conflicting/corrupt receipt:** fail closed. Never silently
   overwrite or downgrade to a new-record path. Preserve all files for review.
7. Preserve all existing custody and recorded objects. No sender ACK is produced
   by startup recovery. The receiver listener starts only after successful
   startup recovery; this change does not weaken that security gate.
8. Forward the operating-system shutdown context into the recovery loop and
   streaming reads. SIGTERM should cancel with bounded delay instead of waiting
   for an entire multi-GiB generation.
9. Report progress every 128 completed or deferred objects and at completion.

A full FIGT outer SHA-256 necessarily streams the compressed bytes from disk;
it does not need uncompressed memory or semantic replay. Metadata/file-mode
checks are not substitutes for the exact content hash.

## Source changes

- `go/internal/transportgeneration/custody_recorded_fast.go`: stream and verify
  the exact FIGT identity, encoded payload hash and signed/current-trust metadata.
- `go/internal/generationrecorder/restart_recorded_fast.go`: validate the exact
  immutable receipt and bind it to the computed transport identity.
- `go/internal/transportreceiver/generation_startup_freebsd.go`: receipt-first
  selection, strict full-replay fallback, cancellation, progress callback.
- `go/internal/transportgeneration/custody_restart.go` and
  `go/internal/generationrecorder/restart.go`: cancelable fallback stream.
- `go/cmd/fi-receiver/main_freebsd.go`: signal-aware startup and progress logging.
- `go/internal/transportreceiver/generation_startup_freebsd_test.go`: recovery
  regression tests and proof of semantic-replay avoidance.
- `.github/workflows/ci.yml`: additional FreeBSD cross-compilation gate.

## Acceptance checklist

- [ ] Existing Linux and Windows CI tests pass.
- [ ] FreeBSD cross-compilation succeeds.
- [ ] FreeBSD runtime `go test -count=1` passes in
      `./internal/transportgeneration`,
      `./internal/generationrecorder`,
      `./internal/transportreceiver`, and `./cmd/fi-receiver`.
- [ ] Recovered receipt test passes with semantic manifest limit set too small
      to permit a full replay (proves no semantic reprocessing).
- [ ] Missing receipt results in full semantic validation and durable NEW receipt.
- [ ] Corrupt receipt, corrupted compressed FIGT, mismatched transfer hash and
      invalid signing authorization fail closed and preserve state.
- [ ] Pre-canceled startup returns `context.Canceled`.
- [ ] Controlled service stop is prompt during startup verification.
- [ ] Receiver starts with existing historical inventory; report actual examined,
      already-recorded, new and deferred counts and startup duration.
- [ ] TCP/8443 listener appears only after successful recovery.
- [ ] Windows queued generations progress through recorded ACK, sender retirement,
      ready queue and PostgreSQL ingest without data loss or duplicates.
- [ ] Measure CPU, RSS, disk read throughput, elapsed startup and load.
- [ ] Keep current receipt/custody history; no deletion, renaming, or reset.

## Deployment and rollback

Prefer a disposable test environment or FreeBSD `fi-dev` jail for validation.
Build using the branch above and run the complete receiver tests.
Stage a new FreeBSD receiver binary without modifying custody files.
Only deploy when the recorded-fast recovery tests and baseline gate pass.
Keep the previous receiver executable under a timestamped rollback path,
then change only that executable via the existing approved installation flow.
Do not redeploy `fi-backend-install` or reset managed service configuration.
On failure restore the binary and preserve custody for forensic comparison;
be aware the previous binary still performs expensive full startup replay.

## Separate unresolved issue

Windows generation construction must enforce independent 250 MiB encoded and
16 GiB canonical ceilings, partitioning backlogs while preserving source/custody
coverage. Those limits are proposed, not part of this receiver fix.
