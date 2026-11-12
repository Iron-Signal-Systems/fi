# FI H16 — independent Security, File, coverage and USN dependency buffers

**Status:** branch-only development experiment. Source and exact-pin audit completed; **Go compilation, PostgreSQL integration, real signed W3–W4 replay and performance are not yet verified on FreeBSD**. Do not promote to main, canonical ingestion, production or the accepted H16 benchmark.

## Measurement that motivated this work

Previous accepted H16 + trusted batch SHA-once + Security JSON-once on real signed W3–W4:
- 259,178 records, 89.931 s committed time (~2,882 records/s).
- W3: 116,357 Security events, 52 coverage records, 52 Security source/event COPY calls.
- W4: 116,522 Security events, 54 coverage records, 54 Security source/event COPY calls.
- Both original and private mixed Security/File experiments showed exactly the same Security COPY counts. That is strong evidence of a flush-on-coverage limitation, not yet an experimentally proven root cause.
- Mixed Security/File experiment: 92.891 s, SQL integrity and signed-data readback passed, **not a performance promotion**.

## Actual implementation

The selected private W128/K32/P3/F3 candidate now has **four bounded families** (although the conceptual architecture is three processing paths):

| Family | Buffer | Flush trigger |
| --- | --- | --- |
| Security events | existing P3 up to 4,096 events/16 MiB | own record/byte cap or K32 finish |
| File observations | existing F3 up to 8,192 source records/32 MiB | own record/byte cap, required prerequisite for USN dependency drain, or K32 finish |
| WindowsSecurityCoverage | **already existing** 512 records/8 MiB | coverage's own cap or final W128 flush |
| USN read boundaries + USN object observations | **new private** 512 records/8 MiB | own cap, K32 finish, or conservative ordering fence |

A Security↔File transition does not flush either family. **Coverage and the two USN dependent kinds do not flush Security or File**. The coverage projector is already a bounded buffer; the new path disables the unnecessary flush on every subsequent noncoverage record. A USN queue drain invokes File flush first if needed, because its existing relational projector may need NTFS identities, but never flushes unrelated Security or coverage.

USN entries are queued in **original signed batch index + record ordinal order**. The SQL-generated `source_batch_id` and `source_record_id` are not used to sort the queue. When the queue drains, the existing `fi.source_record` insertion and full `ProjectSourceRecord` USN projector execute in custody order. Existing source-bound/legacy boundary validations, counts, cross-window restore, identity mapping and child insertion are retained. Invalid/missing/forward references return an error and roll back the entire W128 transaction. A future boundary cannot retroactively satisfy an earlier dependent object.

Record families not specifically audited for independent ordering (including `USNContinuityGap`) conservatively flush Security, File **and queued dependencies** before their own source insert/projection. This experiment does not silently relax those order contracts.

The source-copy lookup still uses the exact original signed batch/ordinal key when per-family buffers produce gaps. It never infers contiguous database-generated source IDs.

## Durability, trust and scope

- One ordered PostgreSQL writer; one atomic W128 SQL transaction; K32 chunks have no independent commit.
- Verified signed-cache custody and the existing trusted-COW SHA-once evidence are unchanged. Per-record hashes and typed strict decoders remain in place.
- No additional goroutines, SQL transactions, sender or receiver changes.
- No authoritative SoR changes, no `Accepted` journal outcome, no canonical promotion.
- Source/branch modifications gated by **both** `-private-mixed-family-buffers` and `-private-dependency-buffers`. The latter is forbidden outside the isolated continuous-private W128/K32/P3/F3 signed-cache benchmark. The accepted 89.931 s runner and the 92.891 s mixed-only runner are unchanged.

## Tests and fixed source gates

Runner: `go/cmd/fi-backlog-recover/run_private_h16_dependency_buffers_w34_host.sh`.

Stage exact Git blobs under `/home/jwood/fi-h16-dependency-buffer-assets`:

| Filename | Git blob |
| --- | --- |
| `private_dependency_buffers.go` | `089bbf0af7ef50d1c5815cbd59e13833068236c2` |
| `private_dependency_buffers_test.go` | `1b3b4deed8a9ee02047b06d4b0dbe76b514b1148` |
| `private_mixed_family_buffers.go` | `5dbf8d3d62ed6e21580128a8041630bc8bac7384` |
| `patch_private_dependency_buffers.go` | `709eba3e28d81f6f5888a36c5bdb931ff261dca6` |

The last file is `go/cmd/fi-backlog-recover/patchers/private_dependency_buffers/main.go`, renamed when staged.

The old mixed-buffer assets remain under `/home/jwood/fi-h16-mixed-buffer-assets`. The new runner reuses those pinned original assets, and stages its new dependency sources/patcher **immediately after the initial mixed patch and before `gofmt`**, so the historical source anchors are unchanged.

The new patcher has **17 source edits across four original historical files**, with an exact-one-match gate for every edit. An independent source simulation verified the original mixed patch anchors and all 17 subsequent dependency patch anchors match their pinned historical source. The shell runner itself is not an accepted result until the FreeBSD host runs it.

Go gates include six existing private mixed-buffer tests, five dependency-buffer tests, strict signed-order tests independent of SQL sequence IDs, and existing legacy/source-bound USN capture contract tests. The host first fails on missing/modified assets, patch anchors, Go tests or compilation.

The signed SQL test must then prove:
- W3/W4 record totals 129,435 + 129,743 = 259,178.
- W3/W4 one-pass Security rows 116,357 + 116,522 = 232,879.
- W3 dependency records **0**; W4 dependency records **29** (28 USN objects + 1 boundary).
- Nonzero coverage-to-Security premature flushes avoided in both windows, and the active SQL COPY call counts.
- Verified source batch reuse for 111 batches with no redundant full-batch rehash.
- SQL checkpoint `5|649565|4`, expected signed Security field row count, no Accepted or authoritative writes.
- 111 original signed batch data and manifest files byte-identical on readback.
- One PostgreSQL clone stopped cleanly even on failure.

## Review/acceptance limitations

This is a **candidate**, not proof that PostgreSQL is disk-I/O-bound and not proof of throughput improvement. The new USN queue uses direct source-row INSERT for a small dependent family before relational projection; it is not a fully bulk-COPY dependency writer. The current USN projector still contains historical source-record-ID precedence checks; the private single-writer queue preserves relative USN order for them, but a future general/parallel ingest architecture must replace that assumption with explicit original signed identities across all call sites.

Do not generalize from the small W4 USN sample. Repeat malformed/forward-reference and cross-window USN integration tests in detached PostgreSQL fixtures before any architectural expansion. Preserve K32 and W128 defaults and the accepted H16 version until an independently repeated W3–W12 result demonstrates improvement without weakening custody, SQL integrity, or rollback.
