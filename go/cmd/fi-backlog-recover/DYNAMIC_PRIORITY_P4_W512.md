# FI dynamic priority-fill P4 — private C220 W512 experiment

**Development-only. Implemented and pinned in GitHub; C220 compilation,
Go race tests, signed replay and performance acceptance NOT YET RUN.**
No production or authoritative FI change.

## Requested worker policy

This experiment applies the same dynamic **2–16 workers PER FAMILY** policy
to all five independent preparation lanes:

| Lane | Initial workers | Maximum worker goroutines |
|---|---:|---:|
| Security | 2 | 16 |
| File | 2 | 16 |
| Coverage | 2 | 16 |
| USN / dependency | 2 | 16 |
| Other | 2 | 16 |

Thus the pipeline starts with ten actual preparation goroutines (two per
family), and can create up to 80 across all families **if demand justifies
it**. This is **not** a fixed 80-worker pool. The global signed-source
admission limit is still 32 in-flight records / 256 MiB raw bytes, so the
workload is not expected to keep all 80 busy simultaneously.

### Priority-fill semantics

- Dispatch an available signed record immediately to the *lowest-index idle
  worker* in its own family: worker 0 before 1, and so on.
- If all currently spawned workers in that family are busy and another
  record is ready, spawn exactly one additional worker, up to 16. **Do not
  wait until a per-worker batch fills.**
- If every family worker is busy at the maximum, hold records in that
  family's independently bounded queue. The global 32-credit mechanism and
  raw byte budget enforce bounded admission and backpressure.
- Once overflow workers finish, they become idle and are only reused when
  needed. **Goroutines are currently retired at the end of their signed
  batch**, not after an arbitrary idle timer. Every new signed batch starts
  with the minimum two workers per family. That avoids early idle-retirement
  races and does not make records wait for an activation timer.
- Family schedulers cannot consume another family's workers. All prepared
  results rejoin the original signed ordinal sequence before reaching the
  existing single SQL writer.

This changes **preparation scheduling only**. Existing H16 downstream
Security/File/USN/Coverage buffers, dependency barriers and atomic W512
SQL transactions are still unchanged. It is **NOT** the complete
continuous SQL-ready family buffer redesign and does **NOT** implement
parallel PostgreSQL transactions.

## Source and test pins

- Branch: `experiment/fi-dynamic-priority-2-16-w512-20261116`
- Pinned source, patcher, tests and AWK report:
  `d3f4de42880d91cefdb96e2a1149fce049c5bcdb`
- Pinned private C220 runner:
  `ff297e880be9537c6087765ee4e8b13f37d4e2a4`
- Pinned controller:
  `1601c946309a6795da6ef6193b4b42a2204b619b`
- Pinned signed two-window W512 seed: `20261115T153532Z`
- Allowed PostgreSQL relay port: `55983`

The separate fixed A8/B16 and G4 development branches stay untouched.
Accepted A8 reference: 997,434 records, 246.481s (4,046.697 records/s),
8 Security + 2 each general, 32 in-flight, one SQL writer. The
fixed four-each G4 branch has not been acceptance-tested by this P4
controller; it should not be presented as an accepted control.

## Test / acceptance

1. Read-only exact original seed anchor audit and canonical signed-dispatch
   standalone tests, before allocating a private SQL clone.
2. A pinned AWK fixture test proving all five family rows (including
   zero-activity families) and correct 2–16 worker scales, before clone.
3. Disposable source overlay including both new
   `private_family_dynamic_p4.go` and `_test.go`, full Go tests and
   Go race-detector tests (`TestPrivateDynamicP4*`), **before PostgreSQL
   seed copy**. Failure stops.
4. Exactly 431 scheduler/topology receipts, 431 memory receipts and 2,155
   dynamic family receipts, each with signed source/prepared identity
   checks, 2–16 spawned workers, valid scaling counts and no unconsumed
   source.
5. Original SQL source, typed window and artifact descriptor integrity
   gates; 997,434 signed source records; W512 atomic commits and zero
   authoritative/Accepted writes.
6. Byte-for-byte source payload and manifest readback for all 431 signed
   batches; clean private PostgreSQL shutdown.
7. Compare two-window elapsed and records/s with accepted A8 and retain
   `FAMILY_DYNAMIC_SUMMARY.tsv`, per-lane/per-worker output, vmstat,
   iostat and PostgreSQL WAL/checkpointer/I/O profiles.

Go source and configuration have been statically checked but actual C220
compilation and independent acceptance are still REQUIRED. The presence of
a metrics bundle alone is not proof of acceptance.

## Procedure: root@c220

```sh
(
set -eu
repo=/home/jwood/fi-w512-c220-stage
branch=experiment/fi-dynamic-priority-2-16-w512-20261116
pin=1601c946309a6795da6ef6193b4b42a2204b619b
controller=/var/tmp/fi-w512-dynamic-priority-p4-c220.sh

jexec -U jwood fi-dev git -C "$repo" fetch origin \
  "refs/heads/$branch:refs/remotes/origin/$branch"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$pin^{commit}"
test ! -e "$controller"
jexec -U jwood fi-dev git -C "$repo" show \
  "$pin:go/cmd/fi-backlog-recover/run_private_dynamic_priority_p4_w512_c220_host.sh" \
  > "$controller"
chmod 0700 "$controller"
sh -n "$controller"

sh "$controller" preflight 20261115T153532Z
sh "$controller" dynamic 20261115T153532Z
)
```

Preflight will not start PostgreSQL. A normal dynamic run stops immediately
if C220 Go tests, race tests, expected source/SQL identities, dynamic worker
telemetry or signed readback differ. Never bypass safety gates, alter
live FI settings, switch the staging Git checkout, or write to authoritative
SoR.

## Engineering sequence after P4

Finish separate per-family SQL-ready buffers for all record kinds,
capacity-triggered handoff, ordered USN-dependency resolution and safe
durable window completion **before** any 2/3/4-lane PostgreSQL writing
experiment. Then measure the complete design with two and ten W512 windows
and all five family reports.
