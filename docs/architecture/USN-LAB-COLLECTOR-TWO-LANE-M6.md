# FI M6 — Explicit two-lane USN collection lab

**Scope:** Windows FICollector lab only. Not a production release or acceptance proof.

## Goal

Replace only the synchronous USN capture/re-observation service lane with
separate goroutines for durable journal capture and cached NTFS processing.
FI continues Windows Security collection and supporting-source refresh.
The verified FI spool remains the only downstream source for FISender.

## Ownership and continuity

- No automatic migration. `fi-collector.exe -usn-pipeline-lab-init <configured-root>`
  must run with the collector stopped. It refuses an absent, changed or aged-out
  checkpoint and refuses an existing capture queue.
- The old checkpoint is recorded as immutable `legacy-anchor.json` under
  `<state_dir>/usn-capture-<scope_id>`. Its USN is never advanced by lab mode.
- The lab capture and processing cursors are separate durable files. USN
  capture advances only after its complete source batch is durably queued;
  processing advances only after verified FI spool publication and SID merging.
- FICollector uses lab mode only when its service process environment contains
  `FI_USN_PIPELINE_LAB=1`. Missing or other values do not activate lab mode.
- If a queue exists but lab mode is absent, the legacy USN/root collection
  fails closed; there is no automatic rollback to the original USN cursor.
- All configured roots must be explicitly initialized before lab-mode startup.
  FI checks the old checkpoint and source volume/journal identity on startup.
- A loss of journal continuity relative to the **capture** cursor, queue
  corruption/capacity failure or spool-publication uncertainty stops the lane.
  No checkpoint is reset or advanced to conceal a gap.

## Scheduling

- Capture drains one bounded USN batch at a time without waiting for an NTFS
  observation. It sleeps 200 ms only when already at the journal head.
- The processing worker consumes durable captured batches in order using
  existing M3–M5E bounded NTFS workers and verified FI spool publication.
- A telemetry entry with `record_kind=USNPipelineLab`, `lab_scope_id`,
  `lab_capture_next_usn`, `lab_processing_next_usn` is written to the normal
  service-runtime journal every 10 seconds.
- The old configured-root baseline/reconciliation lane is not run in lab
  mode. The usual `ConfiguredCollection` status is **Partial**, not Complete,
  because this mode does not represent a completed baseline.

## Acceptance gates before a generator run

1. Install these **complete source files** into the approved Windows development
   worktree and run focused and full native Windows Go suites. No service changes
   until both pass.
2. Review sender rollover risk and keep FISender stopped/disabled during the
   first isolated pilot. The M5D–M5E sealed handoff is not a working retirement
   coordination mechanism.
3. Use a clean, fully baselined configured test root whose old FI checkpoint
   is still continuous. The 2026-10-19 aged-out F: cursor is NOT safe for
   migration without authoritative reconciliation.
4. Test ~10K then ~100K operations first. Confirm the capture cursor advances
   while the processing cursor lags, verified FI spool manifests appear, the
   queue stays below the disk ceiling and service RAM is bounded.
5. Simulate a controlled collector restart and confirm queued source ranges
   resume without duplicate spool publication.
6. Only then consider repeating the 10M-object test. Record NTFS journal
   First/NextUSN, capture/processing cursors, queue capacity, spool throughput,
   process peak working set, failures and pending publication state.

## Known nonproduction limitations

- FISender's sealed/retired-generation recovery is not coordinated with this
  lab pipeline. Running sender rollover concurrently can leave processing
  fail-closed; do NOT claim end-to-end custody from this test alone.
- Historical governed-root membership is unresolved for moved/deleted/hard-
  linked objects. Cached candidates are conservatively included, which may
  cause extra volume-wide NTFS re-observations.
- The queue's per-batch file accounting and restart scan may create scaling
  overhead at very high backlog depth. Measure before extrapolating throughput.
- There is no automatic path from the independent queue back to the old
  checkpoint. Do not delete the queue or remove the lab flag to "roll back";
  establish an explicit, verified handback or fresh authoritative baseline.
- Lab mode does not alter Windows installer configuration, service account,
  ACLs, signing trust, FISender, or FreeBSD receiver code.
