# FI P6 — canonical FileObservation proof fixture correction

**Status:** P6 still unaccepted. Go fixture repaired and repinned; the corrected
private C220 two-window test has not yet been run.

## What C220 rejected on 2026-11-16

The first attempt to run the native FileObservation proof regression tests
stopped during `go127 test`, before private PostgreSQL startup:

```text
--- FAIL: TestPrivateP6FileProofUsesOriginalValidationAndBindsSource
    FI P6 proof fixture must be fully valid: InvalidTimestamp: observed_at
--- FAIL: TestPrivateP6FileProofRejectsMalformedAndScopeMismatch
--- FAIL: TestPrivateP6FileProofRequiresOriginalWindowCounters
--- FAIL: TestPrivateP6FileProofDoesNotPreIncrementReuse
FI C220 PRIVATE TRUST PATCH STOP: tests/build failed
FI W512 PILOT FINISHED exit=1
```

Failed private output:
`/var/tmp/fi-window-chunks-family-p3-20261116T225644Z`.
Original signed seed unchanged.

## Root cause and exact fix

I incorrectly authored the deterministic fixture timestamp using
`time.RFC3339Nano`. Go strips redundant trailing zeros in this format,
so a whole-second timestamp becomes `2026-11-16T12:00:00Z`.
FI's canonical `records.validateTimestamp` requires precisely

```text
2006-01-02T15:04:05.000000000Z
```

The corrected fixture uses the explicit nine-digit layout and invokes
`records.ValidateObservedAt(now)` before constructing the NTFS test row.

No application validation code, File/NTFS record handling, foreign-key
rule, schema, original signed seed, or accepted P5 source was changed
for this correction. A local Go check confirmed canonical round-trip
and the noncanonical `time.RFC3339Nano` result.

## Frozen test pins

- Branch: `experiment/fi-p6-file-proof-repair-20261116`.
- Corrected source + previous native validation-proof repair:
  `be622cf547f750ba20b111720219e82a44eaa56c`
- C220 clone runner:
  `9bc02d154fb1ecf710a20d0f1643db75a5e6347d`
- C220 comparison controller:
  `0c3532e850e10b7319bfcaba07fbee3e830273cf`
- Original signed seed: `20261115T153532Z`.
- Accepted P5 metrics archive SHA256:
  `7f8f1fadfe8bc48529dfffc654fd08fd06aed5ac767d480a52bf99d2f52e184a`

The preflight remains database-free. The full controller must pass Go unit
tests, race tests, signed-source checks, all 104,830 native FileObservation
source-validation and reuse proofs, 13-kind relational/FK checks, 431
byte-identical signed batches, atomic W512 windows and clean PostgreSQL
shutdown before accepting any P6 performance result.

**Do not rerun prior controller pin
`dbed92318250da04d06ae0f89dba8efbc9027e76`; it contains the bad
fixture. Do not weaken FI's timestamp validator or SQL integrity gates.**
