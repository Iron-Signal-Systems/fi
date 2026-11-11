# H16: verify signed batch once, reuse digest across private COW handoff

Status: **development performance candidate only; unexecuted on FreeBSD**. User-requested direction: don't compute another full-batch SHA-256 after a batch is already authenticated. Preserve authoritative integrity and make the trust boundary explicit.

## Existing behavior and source audit

The existing accepted H16 source is historical commit `b01ff0d8cb6559797de052f34b18bd84a395dc4c`, overlaid only with pinned H16 changes at `e47b5383e19140090d691b7c20e8d6ef6e0113fa`. The accepted post-migration reference is 1,297,765 real signed W3-W12 records in 475.149 seconds (2,731.3 records/s). This control is unmodified.

In `postgres_ingest.go`, `ingestSourceBatch` streams each LF-terminated record to a `sha256.New()` batch state, then compares its final digest to `batch.Manifest.DataSHA256`. The `record.go` and private Security envelope paths also compute **individual record SHA-256**, for distinct persisted source-row evidence. SQL source-row hashing proves durable relational identity. Those operations must not be conflated.

The preauthenticated verified cache was established by complete signed FIGT verification and an atomic receipt-bound marker. The isolated benchmark creates disposable independent-inode COW clones *from that cache* using FreeBSD `copy_file_range` clone-only semantics, verifies exact source/clone sizes and file identity, then ingests from the clone. This is the path the candidate optimizes.

## Candidate

- `testdata/fi_private_batch_hash_once_freebsd.go`: checks that a batch is being read from an open file descriptor whose exact dev/inode/size/mtime and path match the sourceFiles entry registered by the private COW handoff. Only contexts carrying the unexported verified-cache deferred-window proof qualify. The helper does **not** rehash the cloned data.
- `testdata/patch_private_batch_hash_once.go`: patches a freshly archived historical H16 source tree after validating unique insertion anchors. If no proof exists, the original complete batch SHA-256 still executes. If proof exists, the batch hash is reused, but exact signed record and byte counts are still checked, the file identity is checked before and after ingest, and per-record source SHA-256 and SQL source-row digests are unchanged.
- `testdata/fi_private_batch_hash_once_test.go`: isolated tests reject unsigned/unproved contexts, different paths, different manifest byte counts and changed/replaced clone metadata.
- `run_private_h16_batch_hash_once_w3_w4_host.sh`: a disposable W3-W4 replay against exactly 111 real signed cached batches, on a fresh private PostgreSQL clone. It enforces **111 evidence-reused batches**, **259,178 signed records**, exact SQL checkpoint `5|649565|4`, expected Security rows, zero canonical/Accepted writes, and independent byte-for-byte signed data and manifest readback after the timing window.

The original accepted H16 runner and source commit remain untouched. The candidate does not change the actual signed batch data, the source cache, PostgreSQL durability parameters, or the authoritative SoR. No signature checks, individual record hashes, projected row digests, or SQL integrity gates are disabled.

## Important trust distinction

A previously verified cache digest plus a registered same-filesystem COW handoff is **provenance evidence**. Dev/inode/size/mtime checks are metadata checks, not a cryptographic proof that a malicious actor cannot change clone contents while preserving metadata. The eliminated hash was independently protecting against that residual category of mutation.

The user's desired trust-once design makes this a conscious integrity-model decision; this candidate is accordingly **private benchmark only** until the trust-boundary model is reviewed, fault-injection tests pass, and acceptance demonstrates identical signed source and typed SQL. The independent post-run byte comparison is deliberately outside replay timing; it detects discrepancies for candidate rejection but does not make ingestion-time data hashing equivalent.

The nondeferred or unproved ingest path still hashes each batch; it is not silently marked verified. Applying trust-once to future normal, noncached or canonical ingest requires a durable proof generated **at the first cryptographic verification**, a persistent authoritative signed digest and a defined immutability/rollback protocol. Do not broaden this private COW optimization without those controls.

## Engineering acceptance

1. Static Go patch anchors, exact pinned source and input asset blobs must match.
2. Private Go proof tests and the accepted H16 unit tests must pass on `fi-dev`, FreeBSD with Go 1.27.3.
3. W3-W4 real-signed candidate: 111 proof reuses, byte counts, row counts, full SQL integrity, signed byte-identical readback, and clean PostgreSQL shutdown.
4. Compare with a fresh matched **unprofiled** W3-W4 control before claiming speed. The previous W3-W4 CPU-profile run is not a fair throughput control because it sampled Go.
5. Only after a promising controlled pair attempt W3-W12 H16 A/B. Keep the accepted 475.149-second reference frozen until complete acceptance.

This is not production-ready and does not change the Windows sender.
