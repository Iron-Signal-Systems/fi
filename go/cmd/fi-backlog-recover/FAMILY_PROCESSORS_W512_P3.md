# FI W512 independent family preparation P3 — private C220 candidate

**Status (2026-11-16): corrected family P3 overlay passed C220 original-seed anchor audit (11 edits), isolated Go build/tests including race tests, and private PostgreSQL startup. The first ingestion attempt then stopped BEFORE ingest when the relay rejected disallowed port `55984`. The pinned runner now uses the same allowed `55983` port as the accepted header-first C220 control and prints relay errors automatically. NOT yet benchmark-accepted or released.** No authoritative SoR, original signed-cache, or seed changes.

## Why this candidate exists

The accepted C220 H16 two-preparer W512 baseline processed 997,434 authenticated signed records in **285.831 s**; the accepted header-first block reader used **285.709 s**. The header-first read stage dropped from 13.351 s to 2.215 s, but overall throughput was unchanged, and host CPU remained about 94% idle. The next A/B must move preparation work off the serial writer, not merely accelerate input reads.

The prior private header-first branch and its accepted 431-batch signed readback remain immutable controls.

## Implemented in the new candidate

- Keep the 4 MiB header-first block parser and exact authenticated JSONL bytes; reject malformed or noncanonical source (do not silently fall back).
- Dispatch each record by its canonical `record_kind` into an independent work channel: Security (two goroutines), File (one), Coverage (one), USN/dependencies (one), Other (one). **Six total Go preparation goroutines**, one reader, one SQL writer.
- A global **32-record credit limit** prevents unbounded reordering. An independent **256 MiB budget covers owned raw input bytes admitted but not yet delivered to the writer**; it is **not** a claimed all-in heap cap. Log the per-signed-batch budget peak and unreleased bytes.
- Security uses the existing validated single-pass typed fast path. File payload decoding and preliminary NTFS validation now run on the File worker; the serial SQL writer reuses those decoded values but preserves the C220 seed's pre-existing optimized File validation and scope checks. **Do not claim that every validation stage was removed from the writer.** Coverage typed decoding and validation run in its own lane and the writer reuses the decoded value, retaining its SQL-side validation.
- USN/dependency and Other records use independent *preparation* lanes, but continue to use the existing authoritative typed projection functions and dependency guards on the serial writer. This is **not yet five fully SQL-ready projection pipelines**.
- Writer delivery uses the exact original signed source ordinals. The existing H16 Security/File/USN/coverage bounded SQL buffers, dependency rules, SQL transactions, and W512 atomic commits remain. No buffer is flushed on 4 MiB read-block boundaries.
- The original Candidate A selection log still reports its historical 2-worker / 4-credit selector. It is **not the P3 runtime topology**. The P3-specific `FI FAMILY P3 SCHEDULER` messages and pinned 32-credit stream establish the actual six-worker preparation topology.

## Explicit limitations for this stage

- One SQL writer and existing PostgreSQL COPY/child projection remain serialized.
- Security, File, and USN buffers retain their verified K32/W512 checkpoint drains; unaudited Other kinds still use conservative ordering barriers. Cross-W512 carry is not implemented because this first A/B preserves the original atomic SQL boundary.
- A 256 MiB raw-record admission budget does not include PostgreSQL cache, payload decoding allocations, or downstream typed COPY buffers.
- Six workers/32 credits differs from H16's two workers/four credits. A throughput change cannot be attributed solely to per-family scheduling without further matched worker-count controls.
- No acceptance, speedup or safety claim is permitted before the full C220 result and its signed-readback/SQL-integrity checks.

## Frozen source pins

- Source / patcher **`e34787344b93b26ca695bbb14982d79dbb0f6215`**
- C220 runner **`410f454a79b6f4fb02f48670eadcef154c46a4a7`**
- Branch: `experiment/fi-family-processors-w512-20261115`
- Seed: `20261115T153532Z` (the accepted private W512 seed, offline only)
- All Git files are read by exact commit using the existing `fi-dev` staging checkout; no switching or editing that checkout.
- The new runner audits the original optimized source anchors read-only, stages source and tests into a disposable private copy, runs its family tests under the Go race detector, verifies the original pinned trust source, tests/builds Go 1.27 before it clones PostgreSQL, runs a single socket-only PostgreSQL 18.6 private clone, and stops it at the end. It leaves the authenticated signed cache and original seed untouched.

## C220 test procedure (root@c220)

```sh
(
set -eu
repo=/home/jwood/fi-w512-c220-stage
branch=experiment/fi-family-processors-w512-20261115
sourcepin=e34787344b93b26ca695bbb14982d79dbb0f6215
runnerpin=410f454a79b6f4fb02f48670eadcef154c46a4a7
runner=/var/tmp/fi-w512-family-p3-initial-c220.sh

jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}"
test ! -e "$runner"
jexec -U jwood fi-dev git -C "$repo" show \
  "$runnerpin:go/cmd/fi-backlog-recover/run_private_family_w512_c220_p3_host.sh" \
  > "$runner"
chmod 0700 "$runner"
sh -n "$runner"
grep -Fq "sourcecommit=$sourcepin" "$runner"

echo "===== FAMILY P3 C220 PREFLIGHT ====="
sh "$runner" preflight 20261115T153532Z

echo "===== PRIVATE TWO-WINDOW BENCHMARK ====="
# Run only after the preflight succeeds. Go integrated tests and race tests
# execute BEFORE any private PostgreSQL seed is copied.
sh "$runner" family 20261115T153532Z

)
```

If preflight or Go tests/build fails, **stop**. Do not bypass patch anchors, skip tests, modify the seed, disable signing or SQL checks, or switch to authoritative SoR.

## Required acceptance

The runner must observe:

1. All 7 source assets at the frozen source commit, patcher syntax compilation, canonical dispatcher standalone tests, and integrated Go tests including `TestPrivateFamilyP3*` before copying PostgreSQL.
2. `FI FAMILY P3 W512 PRIVATE PATCH PASS`, source tree confined to disposable clone, original trust adaptation only, and original durability settings (`fsync`, `synchronous_commit`, `full_page_writes` all on).
3. Exactly 431 signed batches with `FI FAMILY P3 SCHEDULER lanes=5 workers=6 ... credits=32`, per-batch family dispatch counts summing to source records, and `FI FAMILY P3 BUDGET` with peak ≤ 268435456 and remaining=0 for each completed signed batch.
4. Exact **997,434** new records in exactly two W512 windows, original seed window/digest unchanged, zero authoritative generations or Accepted publications, correct source/typed/artifact SQL counts.
5. **`FI W512 SIGNED READBACK PASS batches=431 byte_identical=true manifests_identical=true`** and `FI C220 W512 FAMILY P3 TWO-WINDOW ACCEPTED`, then successful private PostgreSQL shutdown.
6. Preserve `iostat`, `vmstat`, PostgreSQL WAL/checkpointer/I/O before-after, per-window stages and COPY timing in the archived output. Compare to H16 (285.831s), header-first (285.709s), and their observed ~94% CPU idle.

Only after acceptance should we propose deeper SQL-ready processing for Coverage, USN, Other and independently capacity-driven SQL handoff across durable W512 source boundaries, then a 10-window private replay.

## First C220 stop and read-only diagnostic (2026-11-15)

The first attempted source pin `ed8ab373d6dea4bdc7c5d17fca7c9be1b5c3fab7` compiled its patcher and passed the independent C220 host and canonical dispatcher preflights. The disposable overlay then failed with `FI FAMILY P3 PATCH STOP: anchor go/internal/recordingest/postgres_ingest.go count=0 wanted=1`. No PostgreSQL clone was started. The original private W512 seed was unchanged.

Because there are several intended edits to `postgres_ingest.go`, the old error does not distinguish which one differed. The new P3 patcher has an explicit read-only `audit` mode for the exact original seed path `/home/jwood/fi-window-bench-w512-20261115T153532Z/optimized-source`. It verifies all ordered source anchors in-memory, emits each mismatching expected fragment and related source lines, and stops without writing any file. The runner now invokes this before its preflight can pass. **Do not retry a SQL run until the audit passes.** The failing source shape must be inspected and the overlay patcher updated/pinned to the real C220 source; never weaken or silently bypass an anchor to force a benchmark.

## Second C220 read-only audit and corrected patcher

The second preflight enumerated **exactly two** failed File validation anchors in `postgres_ingest.go`: `if err := ntfs.ValidateObservation(value.NTFS); err != nil {` and `if value.NTFS.GovernedRoot.ScopeID != item.prepared.Record.ScopeID {`. Its nearby-source output showed the C220 seed uses `validated.observation.GovernedRoot.ScopeID` instead. All other anchored edits passed the read-only simulation.

The patcher no longer tries to inject a second wrapper around an old validator; it retains the seed's existing optimized File validation and scope behavior. It still injects a *pure* File worker-side typed preparation and reuses the decoded value at the verified JSON-decode insertion point. This is a correctness-first trial, **not yet proof of lower writer-side validation cost**. The exact read-only preflight gate still runs before copying the private PostgreSQL seed.

Pinned corrective source: `e34787344b93b26ca695bbb14982d79dbb0f6215` and pinned runner: `410f454a79b6f4fb02f48670eadcef154c46a4a7`. Re-run preflight and then the isolated two-window candidate only if preflight passes. If Go compilation, race detector, SHA, SQL, or byte-for-byte signed readback fails, stop and investigate; do not bypass.

## Third C220 stop: relay port (2026-11-16)

The private benchmark stopped just after `FI C220 CLONE-ONLY PRIVATE OUTPUT PASS`. Its retained `relay.log` states `FI PG relay: unexpected disposable cluster port family`. The P3 runner was using `port=55984`, which the pinned relay binary rejects. The previously accepted C220 header-first P2 control used `port=55983` successfully. This is a runner-port regression, not an ingestion or database correctness result.

The corrective runner at commit `410f454a79b6f4fb02f48670eadcef154c46a4a7` uses `55983` without modifying any seed or relay executable. It also tails `relay.log` on a relay crash or startup timeout so further failures are not hidden. Re-fetch the fixed runner into a **new filename**, verify its source pin `e34787344b93b26ca695bbb14982d79dbb0f6215`, run `preflight` and then `family` only if preflight passes. The full SQL/signed readback gates must still pass before acceptance.
