# FI SHA-256 provenance: verified cache, clone and ingest (2026-11-11)

**Status:** development investigation, read-only proof-of-speed only; not an accepted optimization.

## Code and provenance audited

The accepted H16 source is historical commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c` with overlay `e47b5383e19140090d691b7c20e8d6ef6e0113fa`. The pinned W3–W12 H16 replay is **475.149 seconds**, **2,731.3 records/sec** across **1,297,765 real signed records**, on a separate PostgreSQL clone. This remains the frozen control.

There are several distinct SHA-256 obligations:

1. **Transport and cache:** the complete authenticated FIGT data and manifests were previously verified, and the cache was atomically published under its receipt-bound marker. This trust is valid for the data **at the time it was checked**, not necessarily for a later changed file.
2. **Signed batch byte stream during private replay:** `ingestSourceBatch` in `postgres_ingest.go` currently streams the exact LF-terminated records into a new SHA-256 state and requires that final digest, byte count and record count match the original signed manifest. This is one SHA-256 **per source batch as it is ingested**; the same batch is not hashed anew at each W128 window boundary.
3. **Individual source record evidence:** `record.go` and `security_single_pass_candidate.go` compute SHA-256 over each exact LF-terminated record to populate `record_sha256`. These digests cannot be used to reconstruct the existing SHA-256 of concatenated original batch bytes.
4. **Joined SQL source digest:** `backlog_joined_source.go` accumulates a separate canonical hash of source-row identifiers, original metadata, byte counts and record digests; independent SQL readback verifies the rows stored in PostgreSQL.
5. **Security raw XML:** where present, the Security event's raw XML has its own digest and separate semantic purpose.

The existing deferred COW handoff copies from the receipt-bound cache to a new inode using FreeBSD `copy_file_range` clone semantics. The code checks source/clone identity, size and later file identity/mtime. A newly cloned file **has not itself been cryptographically verified** until `ingestSourceBatch` reads and compares its bytes against the manifest. Replacing that check with prior cache trust would be a weaker assumption and would require an explicitly reviewed immutability, integrity and restart protocol. Do not simply delete the batch hasher.

## Evidence

A private W3–W4 CPU profile accepted on 2026-11-11: **259,178 real signed records**, exactly **111 published batches**, SQL checkpoint `5|649565|4`, signed readback byte-identical, canonical and Accepted writes both zero. Flat `crypto/internal/fips140/sha256.blockGeneric` consumed **16.58 of 54.72 sampled CPU seconds (30.3%)**. Both per-record and batch SHA calls contribute. The per-window `batch_hash` stage counted 3.54277s W3 + 3.70697s W4 = **7.24974s** wall-clock on the timed profile. Removing required cryptographic checks merely to win a benchmark is not acceptable.

## First experiment: equivalent SHA implementation, no FI code-path change

`testdata/sha256_engine_probe_freebsd.go` is a **read-only, standalone, FreeBSD amd64** Cgo test comparing Go's SHA-256 with the host's OpenSSL `libcrypto` implementation. The exact signed-cache data is read, bounded to at most 32 batches, every chosen batch is checked against the original manifest SHA and record count, and every record and every streamed batch digest is verified byte-for-byte against Go SHA-256 before timing.

It then measures both engines on the **same immutable-in-memory LF-terminated records and batch streams**, alternating execution order across three rounds. It does not connect to PostgreSQL, modify cache files, bypass any signature, alter the accepted H16 source, or touch the authoritative SoR.

Build the single Go file **inside fi-dev**, where the FreeBSD Go 1.27.3 toolchain already exists. Run the resulting FreeBSD binary **on fi-backend-b**, where the verified cache is available at the original host path. Check for `cc`, `CGO_ENABLED=1`, and system OpenSSL development headers. If unavailable, report the dependency and do not install packages on the benchmark host without explicit review.

This probe is **not** proof that integrating OpenSSL will improve end-to-end ingestion: Cgo calling costs, transport/SQL stall, source-record mixing, and instrumented profile overhead still matter. Only if digest equivalence and a substantial throughput improvement hold should we build a private H16 candidate, run focused Go tests and fault-injection cases, then a two-window signed A/B and finally ten-window accepted verification.

## Security acceptance for an eventual candidate

Every record SHA-256 remains byte-identical, all 8,399 signed cached batches remain the same signed payload, each ingested batch must still match its signed manifest over bytes actually read, projected typed SQL/checkpoints and row coverage remain identical, original artifact readback must pass, and any failed cryptographic operation must fail closed. Clone durability keeps `fsync=on`, `synchronous_commit=on` and `full_page_writes=on`. Source-of-record and Windows sender behavior remain untouched.

No benchmark rate, improvement or deployability is claimed until measured and reviewed on FreeBSD. 
