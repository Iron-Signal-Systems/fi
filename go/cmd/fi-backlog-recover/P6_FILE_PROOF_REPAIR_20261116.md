# FI P6 — original FileObservation validation-proof repair

**Development state: source fix committed; C220 compilation, race tests, W512
relational replay and end-to-end performance acceptance NOT YET RUN.**

## Original failure, retained without edits

The first P6 attempt used pinned controller
`6cdb591fb52a3eccf8f75fa5821dedef27211ed1` and failed at:

```text
FI typed window: FileObservation validation count mismatch source=0 reused=0 expected=52519
```

P6 processed W512 window 1 and reported 499,052 input records, including
52,519 FileObservation rows; the original optimized seed's typed window
validator rejected it before SQL commit. Private PostgreSQL stopped cleanly,
and signed seed remained unchanged. The failed version is preserved on the
`experiment/fi-atomic-family-buffers-p6-20261116` branch.

## Exact C220 optimized-seed evidence

Read-only diagnostic
`go/cmd/fi-backlog-recover/diagnostics/read_p6_file_validation_c220.sh`
confirmed these real, existing seed interfaces:

- `validateSourceFileObservation(ntfs.Observation)` produces a
  `*validatedSourceFileObservation`, containing `observation`.
- `fileBulkRecordFromValidatedSource(sourceID, sourceRecordID, ordinal,
  validated, hashes, bytes)` constructs an approved
  `fileObservationBulkRecord` and rejects a nil validation proof.
- The optimized bulk projector checks `validatedSource`, increments
  `FileBulkValidationReused` only when the original proof is consumed,
  and retains its existing SQL parent/child projection.
- The existing source admission path increments
  `ntfsStageTimingCounters.FileSourceValidated` after validation.
- The existing W512 commit gate *requires*
  `FileSourceValidated == familyCounts["FileObservation"]` and
  `FileBulkValidationReused == FileSourceValidated`.
- Window 1 actually had 52,519 FileObservation rows; window 2's
  expected count from the accepted P5 source total is 52,311.

P6 originally bypassed the validated-source constructor with an ordinary
`fileObservationBulkRecord`. That could write relational children but
could not establish the optimized seed's actual validation provenance.

## Corrected P6 design (private clone only)

- New branch:
  `experiment/fi-p6-file-proof-repair-20261116`.
- Replace the P6 NTFS module, keeping all existing SQL writes inside the
  original window transaction and all file parent/child/FK tables.
- After the independent P5 worker produced a signed `SourceRecord`,
  preserve its original decoded FileObservation; strictly validate
  `ntfs.Observation` with the seed's actual
  `validateSourceFileObservation`.
- Bind the validation object to the original SQL source FK, signed scope,
  ordinal, source ID, and content hashes via the seed's real
  `fileBulkRecordFromValidatedSource` constructor.
- Reject nil token, wrong original source ID, invalid FK, or scope mismatch.
- Admit the proven record into the real bounded bulk-state projector,
  then and only then increment `FileSourceValidated`.
- **Never increment `FileBulkValidationReused` in P6 code.**
  Only the original optimized bulk COPY implementation may increment it
  after consuming `validatedSource` and writing relational rows.
- Verify actual counter *deltas* for each P6 NTFS family handoff:
  source and bulk reused must each equal its number of real file rows.
- Retain the original W512 commit gate and all other child/FK checks.

## Tests and acceptance

New `private_p6_file_proof_test.go` uses a complete valid NTFS replay
observation, exercises original validator and constructor, verifies that
two distinct source FKs have distinct proof instances, and rejects
malformed NTFS payloads, wrong signed scope, missing source ID/FK,
nil validated proof, and missing W512 validation counters. A test also
proves that mere proof construction **does not fabricate** source or bulk
reuse counts.

The C220 pinned replay must first pass its Go/race test suite; only then
copy a private PostgreSQL seed and perform signed W512 ingestion.

For exactly the original two source windows, the runner additionally
requires:

```text
FI FILE VALIDATION WINDOW index=1 source_validated=52519 bulk_reused=52519
FI FILE VALIDATION WINDOW index=2 source_validated=52311 bulk_reused=52311
FI P6 VERIFIED FILE SOURCE AND BULK REUSE PASS windows=2 validated=104830 reused=104830 signed_kind=FileObservation
```

This new proof gate does not replace any of the other acceptance tests:
431 byte-identical signed batches, 997,434 original records, full 13-kind
typed parent completeness, original relational/FK validations, exact window
completion, 2 P5 worker pools, zero SoR or Accepted writes, and clean SQL
shutdown are still mandatory.

## Pinned sources for the first corrected C220 attempt

- Source+patcher+regression tests:
  `adab0afdd9648f8d26832a19512e4b78717311b6`
- C220 private runner:
  `3e997641a2775409ac397a08ba49f7aa3a1ddf66`
- Top-level P6 controller:
  `dbed92318250da04d06ae0f89dba8efbc9027e76`
- Original signed seed:
  `20261115T153532Z`
- Accepted P5 control SHA256:
  `7f8f1fadfe8bc48529dfffc654fd08fd06aed5ac767d480a52bf99d2f52e184a`

No evidence from this correction currently justifies P6 acceptance or a
10-window benchmark. P5 remains the accepted private control at
4,190.987 records/s until the new P6 passes all two-window gates.
