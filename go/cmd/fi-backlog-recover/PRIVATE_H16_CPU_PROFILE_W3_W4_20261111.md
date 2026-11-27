# FI: isolated H16 CPU profile of signed W3-W4

Status: **staged development diagnostic; not yet run on fi-backend-b**. No throughput or performance claim is implied by a successful compile or static audit.

## Motivation and frozen control

The accepted post-migration H16 W3-W12 replay committed 1,297,765 real signed records in **475.149 s (2,731.3 records/s)**. The target of 3,000 records/s requires **432.588 s** or less. Controlled WAL experiments with a 4 GiB limit and 16/64 MiB buffers did not improve throughput.

The accepted control retains 1 GiB `max_wal_size`, 4 MiB `wal_buffers`, single worker, 32,768-record inner processing chunks, W128 outer windows, P3/F3, and `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`. Do not promote this profiler's timing as a replacement baseline.

## Diagnostic design

Runner: `go/cmd/fi-backlog-recover/run_private_h16_cpu_profile_w3_w4_host.sh`.

1. Root on `fi-backend-b` preflights the dev jail, authoritative SoR liveness (read-only), 8,399 verified cached signed batches, and absence of extra dev PostgreSQL postmasters.
2. Inside `fi-dev`, reconstitutes source commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`, overlay `e47b5383e19140090d691b7c20e8d6ef6e0113fa`, and original validated W0-W2 PostgreSQL seed. Uses the tested relay executable-path guard fix.
3. Adds `runtime/pprof` instrumentation only to the **fresh disposable extracted source**, guarded by an absolute, exclusively created CPU-profile destination, private writes, deferred verified cache, field partitions, W3 start and an **exactly-two-window durable stop**. The checked-out Git worktree and normal FI binaries are not modified.
4. Replays precisely original signed **W3–W4** into a separate disposable PostgreSQL clone, preserving H16 configuration and all durability settings. Profiling stops on controlled durable exit.
5. Independently verifies private checkpoint `5|649565|4`, **259,178 newly committed records**, typed source records, **8,111,457 expected cumulative Security fields**, no canonical/Accepted rows, matching descriptor hashes, and byte-identical real signed batch files/manifests.
6. Produces Go flat/cumulative CPU top reports from the matching instrumented binary, per-window stage snapshots, PostgreSQL and host read-only counters, and a metrics-only tarball. The copied signed payloads, clone cluster, private keys and full source tree are **not** included in the tarball.

## Interpretation

- `cpu.pprof` identifies sampled CPU time in Go; it does **not** directly measure PostgreSQL disk waits or network stalls. Compare inclusive stage timings, postgres snapshots, and host samples separately.
- CPU profiling and Go-source instrumentation change runtime overhead. Neither W3–W4 throughput nor this run's RSS is suitable to accept a performance candidate. Make and validate a separate code optimization before re-running ten-window H16 acceptance.
- Profiling must not disable source validation, signature checks, SQL checks, or PostgreSQL durability.
- Runner output is retained in a fresh timestamped directory; the PostgreSQL clone/seed are stopped by the existing cleanup trap.

## Operator workflow

Within the existing **jwood@fi-dev SSH session**, retrieve the runner from GitHub via HTTPS at the exact reviewed commit. Verify Git blob SHA against GitHub and run `sh -n`. In the existing **root@fi-backend-b** window execute `sh "$runner" h16` using the jail-root path returned from `jls -j fi-dev path`. Do not run benchmark workers inside the jail, change branches, or reconfigure canonical SoR.

The result is accepted only after `FI H16 CPU PROFILE ACCEPTED`, `FI H16 CPU METRICS BUNDLE PASS`, and `FI EFFICIENCY FINISHED exit=0`. Any failed gate is a development diagnostic failure, not a passing performance result.
