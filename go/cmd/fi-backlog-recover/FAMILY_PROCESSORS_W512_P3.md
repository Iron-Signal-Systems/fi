# FI W512 independent family preparation P3 — private C220 candidate

**Status (2026-11-15): source, isolated patcher, tests and benchmark runner committed. NOT C220-compiled, NOT benchmark-accepted, NOT released.** No production or authoritative SoR changes.

## Why this candidate exists

The accepted C220 H16 two-preparer W512 baseline processed 997,434 authenticated signed records in **285.831 s**; the accepted header-first block reader used **285.709 s**. The header-first read stage dropped from 13.351 s to 2.215 s, but overall throughput was unchanged, and host CPU remained about 94% idle. The next A/B must move preparation work off the serial writer, not merely accelerate input reads.

The prior private header-first branch and its accepted 431-batch signed readback remain immutable controls.

## Implemented in the new candidate

- Keep the 4 MiB header-first block parser and exact authenticated JSONL bytes; reject malformed or noncanonical source (do not silently fall back).
- Dispatch each record by its canonical `record_kind` into an independent work channel: Security (two goroutines), File (one), Coverage (one), USN/dependencies (one), Other (one). **Six total Go preparation goroutines**, one reader, one SQL writer.
- A global **32-record credit limit** prevents unbounded reordering. An independent **256 MiB budget covers owned raw input bytes admitted but not yet delivered to the writer**; it is **not** a claimed all-in heap cap. Log the per-signed-batch budget peak and unreleased bytes.
- Security uses the existing validated single-pass typed fast path. File payload decoding and full NTFS validation now run on the File worker; the serial SQL writer reuses those validated typed values and does not decode or validate the same File payload again. Coverage typed decoding and validation run in its own lane and the writer reuses the decoded value, retaining its SQL-side validation.
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

- Source / patcher **`01996c6d5b22f122c58a699cd40509bef5a3dfb1`**
- C220 runner **`8f2b87f762f48d4f5649b3d648ccc06c63ea52d0`**
- Branch: `experiment/fi-family-processors-w512-20261115`
- Seed: `20261115T153532Z` (the accepted private W512 seed, offline only)
- All Git files are read by exact commit using the existing `fi-dev` staging checkout; no switching or editing that checkout.
- The new runner stages source and tests into a disposable private copy, verifies the original pinned trust source, tests/builds Go 1.27 before it clones PostgreSQL, runs a single socket-only PostgreSQL 18.6 private clone, and stops it at the end. It leaves the authenticated signed cache and original seed untouched.

## C220 test procedure (root@c220)

```sh
(
set -eu
repo=/home/jwood/fi-w512-c220-stage
branch=experiment/fi-family-processors-w512-20261115
sourcepin=01996c6d5b22f122c58a699cd40509bef5a3dfb1
runnerpin=8f2b87f762f48d4f5649b3d648ccc06c63ea52d0
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

echo "===== FAMILY P3 PRIVATE TWO-WINDOW TEST ====="
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
