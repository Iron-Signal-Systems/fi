# FI header-first W512 ingestion — development experiment

Status: **first-stage code committed, NOT integrated with the SQL ingest path, NOT C220-accepted.**

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
