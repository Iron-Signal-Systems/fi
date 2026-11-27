# FI C220 — four workers per non-Security family

**Status: source + runner + tests committed; not executed or C220-accepted.**

## Exact experiment

Retain the signed header-first 4 MiB reader, one PostgreSQL writer,
the **32 in-flight record credit** ceiling, 256 MiB admitted raw-byte ceiling,
and existing atomic W512 SQL/readback gates.

The test changes ONLY the number of non-Security preparation workers:

| | Accepted A8 control | G4 candidate |
|---|---:|---:|
| Security | 8 | 8 |
| File | 2 | 4 |
| Coverage | 2 | 4 |
| USN/Dependency | 2 | 4 |
| Other | 2 | 4 |
| General total | 8 | 16 |
| All preparation | 16 | 24 |
| In-flight records | 32 | 32 |
| PostgreSQL writers | 1 | 1 |

The accepted A8 control processed 997,434 records in **246.481s**
(**4046.697 records/s**) with all 431 signed batches byte-identical.

This is **fixed-worker scheduling**, not the separate requested
*priority-fill/weighted-lane* design. Keeping those changes separate
means a throughput change can be attributed to adding the four general
lane workers rather than combining two scheduling changes.

The new source permits only existing accepted topologies (8/8 and 16/8)
and the candidate 8/16. Its source tests run canonical signed streams
for 8/16 with exact ordinal, digest, byte identity, 32-credit admission
and per-family per-worker totals. Invalid combinations are rejected.
The AWK reporter accepts the matching explicit general count and
prints all workers, even if a family received no records.

## Pinned Git artifacts

- Branch: `experiment/fi-general-four-each-w512-20261116`.
- Source/test/worker-report commit:
  `4d80ce2ce03e73dbff7c8637a5226a6a18a12311`.
- Single clone runner commit:
  `7a0702f94bac17810a2495ca1948c47e26f17249`.
- Baseline comparison controller commit:
  `6ce4d9694888611c694193b5b007e06ed741f206`.
- Control bundle:
  `/var/tmp/fi-window-chunks-family-p3-20261116T104459Z/fi-w512-family-p3-pilot2-20261116T104459Z.tar.gz`.
- Control SHA256:
  `e25589dd23cbd50514b613cee35ff37760f818eb32942a884d0dee83583a8895`.
- Original signed W512 seed: `20261115T153532Z`.
- Relay: approved port `55983`.

## C220 procedure — root@c220

```sh
(
set -eu
repo=/home/jwood/fi-w512-c220-stage
branch=experiment/fi-general-four-each-w512-20261116
pin=6ce4d9694888611c694193b5b007e06ed741f206
controller=/var/tmp/fi-w512-general-four-baseline-20261116.sh

jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pin^{commit}"
test ! -e "$controller"
jexec -U jwood fi-dev git -C "$repo" show \
  "$pin:go/cmd/fi-backlog-recover/run_private_general_four_each_w512_c220_host.sh" \
  > "$controller"
chmod 0700 "$controller"
sh -n "$controller"
sh "$controller" preflight 20261115T153532Z
sh "$controller" baseline 20261115T153532Z
)
```

Preflight is read-only against the seed, and verifies original edit anchors,
the canonical dispatch fixtures and the exact new AWK reporter including
zero-work families. The replay goes only to a new disposable private
PostgreSQL clone; authoritative SoR and signed cache are untouched.
Original PostgreSQL durability and signed-readback gates remain enforced.
On failure, stop; don't bypass guards or repeat an altered seed.

The comparison controller refuses to continue without the original
SHA-verified A8 control and acceptance receipts. It prints and saves
`COMPARISON.tsv` and `FAMILY_COMPARISON.tsv` and requires new
997,434-record SQL acceptance, 431 signed byte-identical batches,
24-worker report, clean private Postgres shutdown and original seed
unchanged.

## Priority-fill scheduling, separate next design

After this measured G4 baseline, evaluate an optional **work-conserving**
lane scheduler rather than fixed worker fan-out. A priority worker processes
immediately; additional workers activate on backlog/queue-wait thresholds,
not because they have waited for a complete batch. Worker queues must be
bounded and adapt without starving File/Coverage/USN/Other. Signed ordinal
reassembly, family independence, USN ordering, memory limits, and atomic
W512 commit stay invariant. Test fixed-8 Security/four-general versus
adaptive using identical 32 credits. Do not claim the fixed baseline already
implements priority-fill.

Do not mix this scheduler experiment with database parallelism. Completing
independent SQL-ready family processing and buffers remains the next
architecture task after the worker-only baseline.
