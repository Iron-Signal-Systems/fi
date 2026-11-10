# FI private hash-copy H16 experiment — signed W128, W3–W12

**2026-11-10 | Development experiment only | Branch:** `experiment/fi-file-validation-once-20261108`

## Why this change exists

The **accepted 20-window W3–W22** signed replay (`fi-vacuum-candidate20-20261110T103933Z.tar.gz`) spent 25.41 seconds in PostgreSQL's `fi_recovery_projection.content_hash_observation` COPY calls. The first ten windows took 8.607s, the last ten 16.799s, despite a smaller relative increase in FileObservation rows. The accepted **F3** profile uses `8192` rows / `8 MiB` as the hash buffer cap; 283,061 hash rows crossed PostgreSQL in 43 COPY calls during the 20-window profile.

The concrete hypothesis is that raising ONLY the hash buffer's permitted batch size to `16384` rows / `16 MiB` can reduce repeated COPY startup/network overhead while keeping the same database rows, FK, unique/partial indexes, validated source, and transaction behavior. **This is not yet a measured speedup.** Fewer COPY calls do not necessarily mean less PostgreSQL index/FK or WAL work.

## Actual Go changes

- `go/internal/recordingest/file_bulk_profiles.go`: exported context helper `WithPrivateFileHashH16` is fail-closed unless the input is the exact original **F3** profile; it creates an immutable derived context named **F3H16** with only `HashMaxRows` and `HashMaxBytes` doubled. No production `F1` or baseline `F3` settings or globals are modified.
- `go/cmd/fi-backlog-recover/main_freebsd.go`: explicit `-private-hash-h16` flag accepted **only with** the separately validated `-deferred-verified-clone` opt-in. The existing deferred-clone guard requires real signed W128, P3/F3, 32768-row chunks, private-field-partitions, private writes, verified cache, and start at W3. Other modes fail closed. The selected hash profile prints a fixed, auditable marker.
- `go/internal/recordingest/private_file_hash_h16_test.go`: tests profile scoping and immutability; non-F3 rejection; exact 8192/16384 row caps; exact 8/16-MiB byte flush boundaries; an equality digest over the eight COPY column values in canonical order between F3 and F3H16; failed `CopyFrom` must never claim rows committed or discard the buffer. No test touches production SQL or copies signed payloads.
- `go/internal/recordingest/content_hash_copy.go` **is intentionally unchanged**. Its bounded COPY source, row shape, SQL ordering and rollback behavior are still authoritative.

The two changed Go source files differ from accepted source SHA `b01ff0d8cb6559797de052f34b18bd84a395dc4c` only by the new helper and guarded CLI option. Pinned overlay SHA, including the test file: `e47b5383e19140090d691b7c20e8d6ef6e0113fa`.

## Matched real signed comparison

Runner: `go/cmd/fi-backlog-recover/run_private_hash_h16_ab10_host.sh` (pinned run code from the experiment branch).

It executes one of **two** fixed modes: `baseline` or `h16`. Both modes:

- Clone the same original **W0–W2** signed-seed database into a new, stopped-after-test, disposable PostgreSQL 18.6 instance with `fi-sor-db` strictly separate.
- Build the same accepted Go commit + exactly the two pinned experimental Go source files (and test file). **Go unit tests run before seed clone provisioning**. The only runtime variation is that `h16` adds `-private-hash-h16`; `baseline` omits the flag. A log marker must prove the flag selection.
- Apply the **same** previously tested private Security field leaf `autovacuum_vacuum_insert_threshold=-1` SQL fixture (commit `dc556813d450f7ab79121d05e10e54c6d2732d01`). This is held constant; it is NOT a second variable.
- Use real signed **W3–W12** exactly ten new windows, 1,297,765 new source records; expected W0–W12 checkpoint `13|1688152|12`. New field leaves exactly `10|10`, old W1/W2 leaves `2|0`. Canonical SoR and Accepted journal must remain zero.
- Retain P3 and all other F3 settings, 32768-row processing chunks, `max_wal_size=1GiB`, `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`, global autovacuum on. All 10 committed windows, staged-source/typed/verified descriptor hashes, partition constraints, independent signed batch-and-manifest byte comparisons, single-pass selection and 20-window provenance must pass.
- Capture complete stage and processing-chunk profiles, per-table synchronous COPY, dedicated `HASH_COPY_PER_WINDOW.tsv` with hash rows/calls/latency for each of ten windows, with a fail-closed equality gate comparing the reported hash-copy rows against the independently validated FileObservation source counts, PostgreSQL relation autovacuum/autoanalyze counters, WAL/checkpointer/IO counters, GC, RSS and host IO. The 10 private field leaves receive a separate post-run measured `VACUUM (ANALYZE)` in **both** variants.

The same-profile control is deliberately freshly replayed, not substituted with historical 15/20-window data. Run variants **sequentially**, never concurrently, and do not change SQL parameters or the input between them. The source build may be reconstructed in a different temporary directory, so “same binary” means equivalent pinned build inputs rather than claiming byte-identical executable hashes across runs.

## Execution and acceptance

On `fi-dev` as `jwood`:

```sh
cd /home/jwood/fi-deferred-experiment || exit 1
git fetch origin experiment/fi-file-validation-once-20261108 || exit 1
git show bbe90168ed6807d348a9550a4a282fdce89c33d1:go/cmd/fi-backlog-recover/run_private_hash_h16_ab10_host.sh > /home/jwood/fi-hash-ab10.sh || exit 1
sh -n /home/jwood/fi-hash-ab10.sh || exit 1
```

On `fi-backend-b` as root, after syntax check:

```sh
jail_root=$(jls -j fi-dev path) || exit 1
sh "${jail_root%/}/home/jwood/fi-hash-ab10.sh" baseline || exit 1
sh "${jail_root%/}/home/jwood/fi-hash-ab10.sh" h16
```

Both runs must print `FI HASH AB10 ACCEPTED` and exit zero, with matched SQL counts and signed readback. Each produces a metrics-only `fi-hash-ab10-baseline-*.tar.gz` or `fi-hash-ab10-h16-*.tar.gz`. The A/B **decision must use actual** throughput, total per-table hash COPY duration and call counts, File projection duration, peak RSS/GC, WAL/autovacuum/autoanalyze and postrun maintenance. Do not retain H16 if the call reduction does not reduce total cost, if memory/GC regresses substantially, or if any signed-data/integrity test fails.

### Status

**Source and tests staged; unit tests, FreeBSD `sh -n`, and paired signed runs have not yet been executed on the host.** The runner explicitly runs its Go tests before it starts the seed database. This does not touch the FI main branch, installers or production defaults. No performance benefit has been asserted.


## Current implementation commits and evidence limits

- Go opt-in hash context: `8b8d42121ceb909f4d1d73cd595571925bad2200`.
- CLI guarded flag: `778110987550bfe18b57a0f30a30262789a8f685`.
- Hash-specific Go unit tests with valid Error-state byte-boundary row: `e47b5383e19140090d691b7c20e8d6ef6e0113fa` (pinned source overlay).
- Paired signed-data runner with exact W3–W12 source counters, per-window hash COPY calls and FileObservation source-row equality: `bbe90168ed6807d348a9550a4a282fdce89c33d1`.

The original accepted `go/internal/recordingest/content_hash_copy.go` and all original production SQL indexes/foreign keys are unchanged. The H16 unit tests AND the existing F1/F3 profile, hash COPY row/byte bounds and COPY failure/latency regression tests must pass in the disposable source tree on the operator's FreeBSD jail *before the seed is started*. The runner's static source and acceptance checks were reviewed, but the actual Go test/SQL runs have not yet been executed.
