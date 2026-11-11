# H16 batch-SHA-once: signed W3–W12 replay

**Status:** 10-window candidate staged and statically checked, **not yet run on FreeBSD**. Private development experiment only; no accepted H16 baseline change or production claim.

## Motivation and accepted W3–W4 paired evidence

- Original unprofiled H16 control: `259,178` records in `110.747s`, with complete batch hash during ingest.
- SHA-once unprofiled H16 candidate: same `259,178` records in `102.534s`, trusted digest reuse for all `111` private COW batches.
- Observed improvement: `8.213s` less elapsed time / `7.42%` shorter window duration on one sequential control-candidate pair. Not yet a repeatable or ten-window gain.
- Measured batch-hash timer: original `7.259s` across W3–W4; SHA-once `0s`. Stage metrics are nested and cannot be added.
- Both runs passed SQL checkpoint `5|649565|4`, signed data/manifest readback, expected record and Security counts, zero canonical/Accepted writes, and clean private PostgreSQL shutdown.

## Ten-window diagnostic

Runner: `run_private_h16_batch_sha_once_ab10_host.sh`, staged at commit `9030f26645b6272f425a8e79a75c85c429639615`; reviewed Git blob SHA `c1c19d60cf5ef9eace4f11ec7408e8ddeaae52f5`. It reuses the three exact assets from the previously accepted two-window SHA-once test, requiring their Git blob hashes before the private seed is started.

Frozen inputs: historical source `b01ff0d8cb6559797de052f34b18bd84a395dc4c`, H16 overlay `e47b5383e19140090d691b7c20e8d6ef6e0113fa`, original three-window signed seed, receipt-bound verified cache of 8,399 real signed batches, W128 outer windows, K32 internal chunks, P3/F3, single worker, 1 GiB `max_wal_size`, 4 MiB `wal_buffers`, and unmodified PostgreSQL durability. Go GC trace and host/PostgreSQL observers match the original H16 ten-window instrumentation.

Required gates: exact W3..W12 durable stop; `1,297,765` new and `1,688,152` cumulative source records; exactly `566` proof-reused signed source batches; `13|1688152|12` checkpoint; source, typed and artifact descriptor equivalence; zero canonical/Accepted writes; all ten new field-leaf options and unaffected seed; independent byte-identical comparison of every published data and manifest artifact against original cache; File source-validation/hash COPY row equality; ten per-window stage and source-family exports; post-run private VACUUM (ANALYZE) and unchanged checkpoint; full bundle and clean shutdown.

The 10-window acceptance is **functional**, not a performance claim. Compare its committed-window total against the accepted post-migration H16 reference of `475.149s` / `2731.3 records/s`, then consider matched repeat A/B controls to distinguish environment noise. The 3,000 records/s target requires `432.588s` or less.

## Integrity boundary / limitations

The cache-to-COW trusted-digest path deliberately stops recalculating a complete SHA-256 during ingestion, but retains every per-record SHA-256, row identity digest, count and size checks. It checks cloned file identity/size/mtime before and after ingestion. Metadata equality **does not cryptographically establish equal data content** if a malicious mutation preserves metadata. The separately executed byte-identical readback validates this private trial after replay timing but does not replace real-time cryptographic proof. Do not deploy or expand the trust-once code to canonical/full-backlog ingest until its durable trust-proof and threat model are separately accepted. This benchmark changes nothing in the Windows sender or SoR.
