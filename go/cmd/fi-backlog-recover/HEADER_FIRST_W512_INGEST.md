# FI header-first W512 ingestion — development experiment

Status: **first runnable W512/P2 private A/B overlay staged, NOT C220-accepted.** The header-first reader is now available inside a disposable clone using the original H16 SQL writer. This is an intermediate routing/read-block experiment, not yet the independent SQL-ready family processor redesign.

## Intent

Use the canonical spool header `record_kind` (second top-level JSON key) as an early dispatch key, before examining payload content. Read verified JSONL in reusable byte blocks, walk completed lines in an inner loop, and immediately hand each line to the owning record processor. **No input read-block boundary may force a PostgreSQL COPY flush or commit.**

- Security, File, Coverage, USN/dependencies, and an explicit Other/fallback processor group own the existing 13 recognized typed record kinds. Other is essential: the four family lanes do not cover every supported FI kind.
- Family processors are responsible for producing SQL-ready rows from the original validated Windows spool values. The dispatcher never deeply decodes a payload and never recalculates file-content MD5, SHA-1, or SHA-256.
- The three file-content digests from Windows are different from the computed SHA-256 of the exact JSONL record bytes, and different again from the authenticated batch SHA-256 in the manifest.
- Maintain a fixed global memory budget. A callback must not retain a view into the reusable read block; it must create stable typed values or clone only what it actually retains.
- Only genuine database foreign-key/dependency relationships require ordering among otherwise independent families. Source batch identity and ordinal still retain original evidentiary order.

## Code in this stage

`go/internal/recordingest/private_canonical_spool_dispatch.go` and its unit tests are an isolated, unconnected prototype. They do not modify the verified cache, ingest scripts, SQL schema, receiver, Windows sender, or H16 benchmark.

The block scanner:
1. reads fixed-size blocks from an `io.Reader`;
2. accumulates only records that cross blocks;
3. identifies the bounded, canonical `record_kind` prefix without reading payload fields;
4. dispatches each complete LF-terminated record **once** to a synchronous processor callback;
5. records per-family stream statistics, and rejects oversized/incomplete/unknown/noncanonical headers.

The canonical-only constraint is intentional for this early proof. The established path can accept some noncanonical historical JSON. Do **not** silently replace it with this stricter scanner until signed-cache equivalence is established and fallback policy is explicitly reviewed.

## Acceptance gates before connecting PostgreSQL

1. `gofmt`, `go test`, race tests, and fuzz/property tests for LF framing, boundary splits, escaping, failures, and byte preservation.
2. Read-only classification of the actual authenticated W512 cache: compare all source counts, record kinds, byte totals, and exact original bytes against the established signed manifests. No reported success on partial or unknown records.
3. Wire one real processor at a time, beginning with `WindowsSecurityEvent`: extract its existing SQL column values exactly once, retain stable memory, and compare output row-for-row with original H16 on a disposable PostgreSQL clone.
4. Extend to File, Coverage, USN/dependency, and all other kinds. Preserve source `(batch,ordinal,record SHA-256)` evidence and all typed columns/relationships. No duplicate file hashes or source inserts.
5. Use independently bounded family buffers. A family flushes on row/byte capacity or a demonstrated FK dependency, **not** an unrelated family's arrival or a read-block boundary.
6. Keep the original W512 SQL transaction semantics in the first A/B. A committed window cannot leave unwritten records in RAM. Cross-window carry would need an explicitly verified checkpoint/transaction redesign; do not conflate a read window with an accepted SQL checkpoint.
7. Re-run exact two-window W512 input (997,434 records; historical C220 H16 P2 285.831 s / 3,489.59 records/sec), compare signed readback, SQL digests/coverage, memory peak, allocations and throughput. Only then run ten windows.

## Isolation

Never run against authoritative SoR. Keep `fsync`, `synchronous_commit`, and `full_page_writes` enabled for all clone comparison runs. Do not change `experiment/fi-candidate-a-w512-2g-20261113`, the accepted H16 signed-cache control, `main`, or live jails as part of this stage.

This document records work implemented so far and remaining gates, not successful end-to-end performance qualification.

## C220 private run procedure — exact pinned sources

This runner uses the existing accepted two-window W512 seed from `20261115T153532Z`. The initial private attempt stopped before PostgreSQL startup because its patcher used a gofmt-sensitive whitespace anchor; the updated pin matches the unique Go struct declaration instead. The second attempt exposed a malformed comment in the patcher that hid the Go edits declaration. The new pinned patcher compiles in C220 preflight. The next run then exposed a missing `canonicalDispatchFixture` test helper: the runner staged the header-first tests but omitted the canonical dispatcher's fixture-bearing test file. The latest runner stages both files and runs the dispatcher's tests during preflight, before the private clone; it now defers copying the private PostgreSQL seed until after integrated Go test/build succeeds. **These changes have not yet passed C220 end-to-end acceptance.** It **does not** touch authoritative SoR, Accepted publication, signed cache, or the live FI worker. It copies the private seed to an entirely new PostgreSQL clone and requires the existing signed-data readback, source and projection counts, immutable checkpoint digests, and original durability settings.

The runner is committed to branch `experiment/fi-header-first-ingest-20261115`. It is designed to be launched as root on C220 only, after `fi-dev` has the pinned Git objects. Run the preflight first.

```sh
# root@c220
repo=/home/jwood/fi-w512-c220-stage
sourcepin=eec914ee309a2c4e9e34e4441ce3011b85ed42c2
runnerpin=5b6f7d7f378805376dc7769dfe1f9d3108d2c3ef
branch=experiment/fi-header-first-ingest-20261115
runner=/var/tmp/fi-w512-header-first-p2-fixturechecked.sh

# Fetch objects only; DO NOT switch C220's existing working checkout.
jexec -U jwood fi-dev git -C "$repo" fetch origin "refs/heads/$branch:refs/remotes/origin/$branch"
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$sourcepin^{commit}" || exit 1
jexec -U jwood fi-dev git -C "$repo" cat-file -e "$runnerpin^{commit}" || exit 1
jexec -U jwood fi-dev git -C "$repo" show "$runnerpin:go/cmd/fi-backlog-recover/run_private_header_first_w512_c220_p2_host.sh" > "$runner" || exit 1
chmod 0700 "$runner"
sh -n "$runner" || exit 1
sh "$runner" preflight 20261115T153532Z || exit 1

# Run only AFTER the preflight passes, not if other private PG runs are active.
sh "$runner" hf 20261115T153532Z
```

**Important**: The C220 staging repository is a Git checkout inside `fi-dev`. Git is invoked as its owner `jwood`, not through an unsafe root-owned working tree. Any missing pinned object, private seed, accepted source SHA, signed input, copy-on-write requirement, or off-host trust input stops before the SQL run.

Expected successful first-run evidence:
- `FI HEADER FIRST PATCHER COMPILE PREFLIGHT PASS`
- `FI HEADER FIRST DISPATCH TEST PREFLIGHT PASS`
- `FI HEADER FIRST POST-BUILD PRIVATE SEED COPY PASS`
- `FI HEADER FIRST ISOLATED OVERLAY READY`
- `FI HEADER FIRST BLOCK STREAM` entries matching the original signed batch count
- All original `FI PRIVATE PARALLEL PREP BATCH`, `FI PRIVATE STAGE PROFILE`, and committed-window acceptance checks
- `FI W512 SIGNED READBACK PASS batches=431`
- `FI C220 W512 HEADER FIRST TWO-WINDOW ACCEPTED windows=2 new_records=997434`

The command may reject noncanonical historical input instead of silently falling back. If so, preserve the error; review the signed spool and add an explicitly tested fallback. **Do not modify signed cache or disable verification.**

## Architectural limitations of this first runnable A/B

The private header-first reader uses 4 MiB read blocks and dispatches based on top-level canonical `record_kind` without parsing the payload. For a controlled A/B, it intentionally retains Candidate A's **two preparation workers, four in-flight record credits, original family buffering and one SQL writer**. It decodes data through the existing per-type code after dispatch. This isolates the effect of read batching and classification from the later, more invasive processor refactor.

**It does not yet implement** zero-copy SQL-ready family processors, replacement of the four-credit scheduler, or cross-W512 partial-buffer carry. Those changes require their own verified A/B after this run. No backend performance improvement is claimed until C220 records it.
