# FI original-H16 paired ten-window trial: combined vs five lanes

**Development-only, 2026-11-13.** Branch `work/fi-joined-private-performance-20261102`.
The authenticated real signed backlog is replayed into **two separate disposable**
PostgreSQL 18.6 clones on FreeBSD `fi-backend-b` / `fi-dev`. The authoritative
SoR and receiver are NEVER written to. This is not a release criterion.

## Workload and source invariants

- Two **sequential** runs, **combined first** and **five-lane second**; do not
  overlap runners (both require their own clone on port 55981).
- Exactly W3..W12, ten W128 SQL transactions per run, 566 original signed
  FIGT batches per run, 1,297,765 new records per run.
- Independently established accepted checkpoint `13|1688152|12` from prior
  real signed W3..W12 tests; prefix W0..W2 is 390,387 records.
- Identical frozen historical H16 source, P3 Security, F3H16 File hash
  limits, SHA-once, strict Security JSON-once, K32 input chunks, one
  atomic SQL commit per W128 and 1 GiB WAL / 4 MiB wal_buffers.
- Same combined Security/File/coverage/USN buffering. Five-lane adds only
  independent File source versus File projection drain policy and the
  dependency-safe coordinating drains already accepted on signed W3/W4.
- Do NOT enable `GODEBUG=gctrace=1`, CPU profiling, changed
  `track_wal_io_timing`/PostgreSQL settings, source reinsertion, or
  postrun manual VACUUM in just one variant: these would contaminate the
  paired timing. Both runners retain the identical 5-second host and PG
  monitors from the earlier H16 two-window measurements.

## Immutable implementation references

- Original accepted combined K32/W128 patch:
  `58f5d7341ba728b4696d05ba31199cb38226befc`.
- Five-lane File source/projection coordinator:
  `394e06ca35a61e559c16909fae296d425ef8bb19`.
- Identical AB10 verifier commit:
  `2069a3a49d102b9d58125c8cf300a14ee29ad3b7`
  (script Git blob `636cf3fcae5567cb49b12027fcfbb1888f2dafd8`).
- Combined ten-window runner:
  `go/cmd/fi-backlog-recover/run_private_h16_combined_ab10_host.sh`;
  Git blob `c20ffe9789d0513185be575e57a0a945c174167c`.
- Five-lane ten-window runner:
  `go/cmd/fi-backlog-recover/run_private_h16_five_lane_ab10_host.sh`;
  Git blob `f28cbea5150a12f09c2a5cac2abc6f8291129086`.
- Optional sequential host coordinator:
  `go/cmd/fi-backlog-recover/run_private_h16_ab10_pair_host.sh`.
- CI: `.github/workflows/fi-h16-ab10-pair-source.yml`.
  The GitHub source test reconstructs original H16, applies the original
  SHA+JSON+buffer overlays, compiles BOTH variants for FreeBSD and checks
  benchmark script syntax/immutable verifier references. It cannot run
  the real FI signed backlog on GitHub.

**Private ten-window stop edit**: the historically accepted
`-test-stop-after-windows=10` extension is applied only to each temporary
archived H16 source after exact single-anchor comparison. The ordinary CLI
limit 1..2 and other recovery/release source code are not updated.

## Hard postrun acceptance (each variant independently)

The shared `validate_signed_ab10.sh` refuses acceptance unless:

1. The timed worker exits zero after exactly W3..W12 (10 unique typed
   stage, SHA reuse, route, dependency, and durable markers; no duplicates).
2. All 566 signed original batch data files and manifests are byte-identical
   to the original verified 8,399-batch authenticated cache.
3. New records equal 1,297,765; SQL checkpoint is exactly
   `13|1688152|12`; all source/typed/artifact descriptors match; SQL
   projection rows and per-window Security events/fields reconcile; zero
   canonical/Accepted writes.
4. Private W3..W12 field leaves retain the existing insert-vacuum policy;
   seed W1/W2 leaves and baseline data stay unchanged.
5. Security JSON-once event counts match typed counts in all ten windows,
   with exact known W3 116,357 / W4 116,522.
6. Each window has correct Security event/source COPY proof, Security
   coverage and USN dependency counters, and verified K32/W128 route.
7. Five-lane variant also proves independent File source/projection lanes
   for each signed W128, with nonzero known W3/W4 deferrals.
8. CPU, iostat, vmstat, PostgreSQL WAL/IO/checkpointer and per-window
   timed metrics exist, and the observer logs report no errors.

The verifier executes after the timed worker and excludes signed payload
bytes, SQL dumps and PostgreSQL data from the compressed metrics archives.

## How results will be assessed

Prior **two-window W3/W4** values (not ten-window expectations):
original H16 92.554 s, combined 92.090 s, five lane 96.950 s.
Old **ten-window** original H16 reference was 475.149 s, not a paired
November-13 environment control for these variants.

The paired AB10 experiment measures signed records/sec, committed
duration, worker CPU user+sys, peak RSS, host CPU, guest disk IOPS,
write MiB/s, busy%, `pg_stat_io` counts, WAL bytes, buffer-full events,
checkpoints, autovacuum, Security/field COPY, and actual File source
versus deferred projection counts. CPU is process-specific; host
`vmstat` is host-wide; PostgreSQL WAL/IO counters are clone-specific.
These must not be conflated.

A single order-fixed pair can identify differences but cannot establish
a repeatable throughput improvement or a causal benefit. If near-tied
or noisy, repeat in reversed order with fresh disposable fixtures before
promoting one buffer model to the working H16 configuration. If either
fails its signed/SQL gates, stop, preserve diagnostics, and do not treat
its throughput as an accepted candidate.
