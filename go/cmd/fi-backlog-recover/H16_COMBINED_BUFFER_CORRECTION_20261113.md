# FI H16: surgical Security/coverage buffer correction — 2026-11-13

## Scope and conclusion

**Development branch only. No authoritative SoR, receiver, Windows sender, database
schema, signed-custody, SHA-once, Security JSON-once, or H16 PostgreSQL durability
change.** Keep accepted H16 as the comparison baseline. No performance promotion
until an actual original-signed W3–W4 replay proves it.

The verified real signed W3–W4 baseline projected 259,178 original records in
**89.931 seconds**, including 232,879 Security events. There were exactly 52
Security event/source COPY calls in W3 and 54 in W4, equal to the number of
Security coverage records per window. This is evidence that coverage-induced
premature flushes should be investigated; it does not by itself prove all 106
COPY calls were caused by coverage.

The mixed-only candidate finished at 92.891 seconds without reducing Security
COPY counts. A dependency-buffer attempt took 96.927 seconds, but its active
buffer counters did not demonstrate the intended effect. The subsequent
source-first continuous family redesign completed correctly at 192.338 seconds,
while changing staging, source reads, SQL transactions and replay receipts. It
was not a controlled buffering-only comparison and **must not be treated as
the successor to H16**.

## Corrective implementation

Reuse the **historically pinned** H16 SHA-once / Security JSON-once code, its
existing K32 work-unit scheduler, original PostgreSQL bulk COPY callbacks and
single atomic W128 typed transaction.

The existing private mixed/dependency code already:
- permits independent bounded Security (P3), File (F3), coverage and ordered
  source-bound USN buffers without emptying Security on a coverage event;
- preserves exact source batch/ordinal keyed SQL lookup for sparse ordinals;
- retains original signed hashes, strict decoders, file/NTFS projection,
  child fields and original W128 relational verification.

The surgical correction changes one piece: an **opt-in private combined-buffer
policy** makes a K32 boundary only an input/telemetry boundary. It does not
empty partially filled typed family COPY buffers. Those buffers drain at their
existing capacity, required audited relational dependencies, or the **end of
the W128 transaction**, whichever comes first. The latter is essential for
the existing W128 typed atomic commit and its complete SQL checkpoint. This
candidate DOES NOT claim that typed buffers cross an atomic W128 commit; doing
so requires an explicit separate durability redesign and is not needed to
test the suspected coverage COPY bottleneck.

Implementation files:
- `go/internal/recordingest/backlog_typed_chunks.go`:
  `h16FamilyDrainAtBoundary` (private mode only);
- `go/internal/recordingest/backlog_typed_window_postgres.go`:
  the existing K32 scheduler retains family state until final W128 source
  batch; chunk counters still advance at each K32;
- `go/internal/recordingest/h16_combined_family_buffers_test.go`:
  original baseline behavior, no K32 drain, W128 mandatory final drain,
  coverage independent of Security/File and conservative USN gap fencing;
- `go/cmd/fi-backlog-recover/patchers/h16_combined_buffer/main.go`:
  anchored private-only overlay against the exact historically pinned H16
  archive, not an edit to the production worktree;
- `go/cmd/fi-backlog-recover/run_private_h16_combined_buffers_w34_host.sh`:
  disposable PostgreSQL 18 benchmark fixture; no new SQL schemas.

The new runner composes the pre-existing H16 historical replay runner with
the exact opt-in changes above. It validates the Git-pinned patch source,
compiles/tests the real historical code, and requires signed source readback
and the same SQL integrity invariants. It also hard-fails if the actual
Security COPY call counts do not decrease below **52 for W3** and **54 for W4**,
or if the coverage-to-Security avoided-flush counters remain zero.

## Proofs and limitations

Source audit checked that all three new historical-source patch anchors match
exactly once **after** the previously pinned dependency overlay. The new
**FI Frozen H16 Combined Buffer Source Gate** GitHub Actions workflow passed
on 2026-11-13: it reconstructs the actual historical H16 archive, applies
the exact historical SHA-once, JSON-once, mixed and dependency overlays,
then patches the two original-H16 source files, runs Go unit tests and
cross-compiles the FreeBSD recovery executable. Log evidence includes
`FI H16 COMBINED BUFFER PATCH PASS files=2 edits=3` and
`FI FROZEN H16 COMBINED SOURCE PASS`.

The host runner's disposable archive MUST remain under
`/home/jwood/fi-window-bench-combined-*/optimized-source` because the
original SHA-once patcher checks that invariant. No real signed W3–W4
throughput result exists for this revised H16 candidate yet. The user must first run the isolated candidate and compare:

1. Original source record and Security child counts, including 8,111,457
   total Security field rows with the W0–W2 seed;
2. Security source/event COPY counts, exact P3 capacity and remaining
   conservative barrier flushes;
3. Existing K32 work-unit count and **zero partial K32 family drains**;
4. Complete signed W3–W4 byte-identical readback for all 111 selected batches,
   original SHA-once evidence and private SQL checkpoint `5|649565|4`;
5. 0 canonical generation writes, 0 Accepted journal outcomes, full typed
   source/relational integrity;
6. Elapsed committed window time, WAL/I/O, CPU, memory against 89.931 seconds.

**The continuous-family experiment remains separate and unpromoted.** Do not
run ten windows or alter H16 until the surgical W3–W4 comparison is reviewed.

## 2026-11-13 W3–W4 private source preflight regression and correction

The isolated combined-H16 replay on `fi-backend-b` reached signed batch
index 161 and stopped **before any typed W3 records committed**:

```text
FI PRIVATE BUFFER ROUTE STOP: signed batch 161:
FI PRIVATE BUFFER ROUTE STOP: private H16 profile context changed
```

This was a **candidate-only gating defect**, not failed signed verification,
SQL corruption, or a security failure. Original H16 intentionally uses
`WithPrivateFileHashH16` to transform the fixed `F3` profile into
`F3H16`, changing only content-hash COPY bounds from 8,192 rows/8 MiB
to 16,384 rows/16 MiB. The private mixed/dependency context is selected
before that transformation, but the old per-batch validator incorrectly
insisted on the literal `F3` name.

The patched **historical private replay code** now validates the entire
exact F3 or F3H16 profile structure, including source, observation,
hash and child row/byte limits. The function still rejects any modified
bound or another name, absent Security field partition context, or a
missing active K32 typed buffer. It does **not** change trust, COPY
execution, row identity, W128 atomicity or the content-hash optimization.

Private patcher commit: `ff4cc5cd5f04fcca5f2f5be83a9da05281761092`.
The frozen-H16 source runner is pinned to code/test commit
`58f5d7341ba728b4696d05ba31199cb38226befc`; host-runner
content blob `2b9391227724126ebedec5889d89af96e035e92e`.
The **frozen historical source GitHub Actions gate** successfully
reconstructed and applied all 5 edits across 3 source files, ran
the new H16 route-context limit-mutation tests and compiled the
FreeBSD binary. Disposable mixed/dependency asset and PostgreSQL relay
path tests also passed.

**No new real signed W3–W4 acceptance result yet.** Do not interpret
the source test as measured throughput. The authoritative SoR remains
untouched; the next signed trial still requires exact SQL/signed
readback and reduced Security COPY calls before performance comparison.
